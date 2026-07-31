package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests pin how a request BODY is framed on the wire and what happens to it across
// a redirect. Before them, no test anywhere in this repository issued an HTTP request
// with a body through the client: the only body-shaped matches were a bytes.Reader
// feeding an HTML parser (common/httpx/domains_test.go), a raw-request STRING parse
// (common/httputilz/httputilz_test.go) and XML readers (common/inputformats). Framing
// decides whether the origin sees the intended bytes at all, so a defect here corrupts
// every POST-based probe silently while every other test stays green.
//
// Two layers are used, and the choice is dictated by what has to be observed rather than
// by preference:
//
//   - A loopback httptest server for the SERVER-OBSERVED framing (Content-Length versus
//     Transfer-Encoding: chunked). That distinction is produced by net/http's request
//     serializer and only exists once bytes have crossed a real socket, so a transport
//     mock - which intercepts ABOVE serialization - cannot express it. This stays
//     hermetic: httptest binds 127.0.0.1, nothing is resolved and nothing egresses.
//   - The scripted mock transport for the REDIRECT cases, because those need the per-hop
//     request stream with cloned headers and buffered bodies, which only
//     common/httpx/mocktransport_test.go provides.
//
// Division of labour with the sibling files, so no assertion is duplicated:
// common/httpx/redirect_test.go owns redirect POLICY - the five-status method-rewriting
// sweep (TestRedirectMethodAndBodyRewriting) and the GetBody discriminator
// (assertRedirect307308ReplayRequiresRewindableBody). This file owns the
// BODY-FRAMING consequence, and asserts it for the two representative status codes only:
// one that preserves the method and must replay the payload, one that rewrites the method
// and must drop it.
//
// No test here uses t.Parallel(): New sets the process-global GODEBUG variable on the
// HTTP/1.1 path (common/httpx/httpx.go:157), which is unsafe to race, and the whole
// package is sequential by convention.

const (
	// requestBodyPayload is the payload for the loopback framing tests. Its length is
	// asserted as a precondition in every test that uses it, so a future edit to the
	// literal cannot silently invalidate the byte-count assertions built on it.
	requestBodyPayload = "hello, world!" // 13 bytes

	// requestBodyRedirectPayload is the payload for the redirect tests, deliberately a
	// different length from requestBodyPayload so a cross-wired assertion fails loudly.
	requestBodyRedirectPayload = "payload" // 7 bytes

	// requestBodyEchoContentType is pinned so the response body is never subject to MIME
	// sniffing and DecodeData never transcodes it: the echoed bytes must come back
	// byte-identical to what was sent.
	requestBodyEchoContentType = "application/octet-stream"

	// The scripted two-hop chain. Both authorities are synthetic, live only inside the
	// mock transport's route map and are never resolved by DNS.
	requestBodyOriginA = "http://origin.example/a"
	requestBodyOriginB = "http://origin.example/b"

	// requestBodyRedirectBody and requestBodyFinalBody distinguish the two scripted hops,
	// so the response body alone proves WHICH hop produced the result the caller holds.
	requestBodyRedirectBody = "redirect"
	requestBodyFinalBody    = "final"

	// requestBodyMaxRedirects is comfortably above the one redirect these scenarios take,
	// so the budget guard at common/httpx/httpx.go:104 is never what ends the chain; the
	// budget boundary itself is owned by TestRedirectMaxRedirectsBudget.
	requestBodyMaxRedirects = 10
)

// opaqueBodyReader hides everything about its payload except how to read it.
//
// It is a struct rather than a type alias so the concrete type exposes ONLY Read: it has
// no Len, no Size, no Seek and is not a *bytes.Reader, *strings.Reader or io.ReadSeeker,
// which are the cases readerutil.NewReusableReadCloser special-cases. That is exactly the
// point of TestRequestBodyBufferedRegardlessOfReaderType: a body whose length cannot be
// discovered without consuming it is the only body for which chunked framing would be the
// natural choice, so it is the case that proves buffering happens.
type opaqueBodyReader struct {
	r io.Reader
}

// Read forwards to the wrapped reader and is deliberately the only method on this type.
func (o opaqueBodyReader) Read(p []byte) (int, error) {
	return o.r.Read(p)
}

// capturedRequest is the server's view of one inbound request, as a value type.
//
// It carries no mutex, so it can be returned and compared by value without tripping
// govet's copylocks check; requestBodyRecorder owns the lock. The fields are exactly the
// wire-framing facts an observer on the connection could see, matching the capturedHello
// idiom in common/httpx/tls_impersonate_test.go.
type capturedRequest struct {
	Method     string
	RequestURI string
	Proto      string
	// ContentLength is net/http's parsed framing value: the declared length, or -1 when
	// the message was close- or chunk-delimited.
	ContentLength int64
	// ContentLengthHdr is the raw header as received. Unlike a CLIENT-side request, a
	// server-side Request.Header does retain the Content-Length line, so this and
	// ContentLength are two independent views of the same framing decision.
	ContentLengthHdr string
	// TransferEncoding is nil for a length-delimited message and []string{"chunked"} for
	// a chunked one. It is copied so the recording cannot alias server-owned state.
	TransferEncoding []string
	// Body holds every byte the handler read from r.Body.
	Body []byte
}

// requestBodyRecorder captures the server's view of the requests an echo server received.
//
// The mutex is required because the handler runs on a goroutine owned by the httptest
// server while the assertions run on the test goroutine. Pointer receivers are used
// throughout so the lock is never copied.
type requestBodyRecorder struct {
	mu sync.Mutex
	// calls counts inbound requests, so a test can assert that exactly one request
	// reached the server - a silent retry or an unexpected redirect would otherwise make
	// the captured framing describe a request the test never meant to inspect.
	calls int
	last  capturedRequest
	// readErr holds the first body-read failure. It is stored rather than asserted in
	// place because require's FailNow calls runtime.Goexit, which on a server goroutine
	// would abandon the response instead of failing the test; result() re-raises it on
	// the test goroutine where FailNow is safe.
	readErr error
}

// record drains the request body, stores the framing snapshot and returns the bytes read
// so the handler can echo them back.
//
// Draining r.Body fully is mandatory: a handler that never reads the body would capture
// zero bytes and every "exact bytes" assertion built on it would pass vacuously.
func (rec *requestBodyRecorder) record(r *http.Request) []byte {
	body, readErr := io.ReadAll(r.Body)

	rec.mu.Lock()
	defer rec.mu.Unlock()

	rec.calls++
	if readErr != nil && rec.readErr == nil {
		rec.readErr = readErr
	}
	rec.last = capturedRequest{
		Method:           r.Method,
		RequestURI:       r.RequestURI,
		Proto:            r.Proto,
		ContentLength:    r.ContentLength,
		ContentLengthHdr: r.Header.Get("Content-Length"),
		// append to a nil slice preserves nil for an absent Transfer-Encoding, which is
		// the value the length-delimited cases assert; a chunk-delimited request is
		// recorded as the one-element slice []string{"chunked"}.
		TransferEncoding: append([]string(nil), r.TransferEncoding...),
		Body:             body,
	}
	return body
}

// result returns the single request the server observed, failing the test if the body
// could not be read or if the request count is anything other than one.
func (rec *requestBodyRecorder) result(t *testing.T) capturedRequest {
	t.Helper()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	require.NoError(t, rec.readErr, "the handler must be able to read the whole request body, otherwise the captured bytes are not the bytes that were sent")
	require.Equal(t, 1, rec.calls,
		"exactly one request must reach the server: a retry or a redirect would leave the captured framing describing a different request")
	return rec.last
}

// newRequestBodyEchoServer starts a loopback server that records the framing of each
// request and echoes the received body back verbatim.
//
// Echoing is what turns the response into an INDEPENDENT protocol-visible witness: the
// caller-visible Response.Data can only hold the payload if those exact bytes reached the
// origin and came back, which is a second proof that does not share a mechanism with the
// server-side capture.
//
// The server is returned WITHOUT a registered cleanup, matching the repository's own
// newWellKnownTestServer (runner/wellknown_recipes_test.go:111), so every caller pairs it
// with a visible `defer ts.Close()` at the site that owns its lifetime.
func newRequestBodyEchoServer(t *testing.T, rec *requestBodyRecorder) *httptest.Server {
	t.Helper()
	require.NotNil(t, rec, "newRequestBodyEchoServer: a recorder is required, there is nothing to assert without one")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := rec.record(r)
		// Pin the content type so the response body is never MIME-sniffed and DecodeData
		// never transcodes it; the echo has to return the exact bytes.
		w.Header().Set("Content-Type", requestBodyEchoContentType)
		_, _ = w.Write(body)
	}))
}

// TestRequestBodyForwardedExactly verifies that a POST body reaches the origin byte for
// byte, length-delimited, with the method intact.
//
// This is the "precise bytes consumed from a stream" assertion: the 13 supplied bytes are
// compared against the 13 bytes the handler read, the declared length is compared against
// the same number twice (the parsed framing field and the raw header line), and the echoed
// response is compared against the payload a third time on a path that shares no mechanism
// with the first two.
//
// MEASURED against the code as it stands: Method POST, r.ContentLength 13,
// Content-Length: 13, TransferEncoding nil, HTTP/1.1, request-target "/", body
// "hello, world!"; response 200 with ContentLength 13 and the payload echoed back.
// Length-delimited framing for a body of known size is what RFC 9112 section 6 prescribes,
// so the measurement and the specification agree here and the expectations are not merely
// transcribed from current output.
func TestRequestBodyForwardedExactly(t *testing.T) {
	require.Len(t, requestBodyPayload, 13, "precondition: the request payload is exactly 13 bytes")

	rec := &requestBodyRecorder{}
	ts := newRequestBodyEchoServer(t, rec)
	defer ts.Close()

	ht := newLocalHTTPX(t)
	// newLocalHTTPX does not release the disk-backed fastdialer history New allocates, so
	// register it here; leaving one behind makes every later New slower (see
	// registerDialerCleanup in common/httpx/mocktransport_test.go).
	registerDialerCleanup(t, ht)

	req, err := retryablehttp.NewRequest(http.MethodPost, ts.URL, strings.NewReader(requestBodyPayload))
	require.NoError(t, err)
	require.Equal(t, int64(13), req.ContentLength,
		"the constructor buffers the body and computes its length before the request is ever serialized")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	got := rec.result(t)

	// The wire, as the origin observed it.
	require.Equal(t, []byte(requestBodyPayload), got.Body,
		"the origin must receive exactly the bytes the caller supplied, byte for byte")
	require.Len(t, got.Body, 13, "the origin must receive the whole payload and nothing more")
	require.Equal(t, "13", got.ContentLengthHdr,
		"the declared length on the wire must equal the payload size exactly")
	require.Equal(t, int64(13), got.ContentLength,
		"net/http parsed the declared length as 13, so the message was length-delimited rather than close-delimited")
	require.Empty(t, got.TransferEncoding,
		"a body of known size must be length-delimited, so no transfer coding may be applied")
	require.NotContains(t, got.TransferEncoding, "chunked",
		"chunked framing would mean the length was unknown at serialization time, which contradicts the declared Content-Length")
	require.Equal(t, http.MethodPost, got.Method, "the method must reach the origin unchanged")
	require.Equal(t, "/", got.RequestURI, "the request-target must be the server root the caller addressed")
	require.Equal(t, "HTTP/1.1", got.Proto, "the request must be serialized as HTTP/1.1")

	// The caller-visible response. The echo is an independent witness: Data can only hold
	// the payload if those exact bytes reached the origin and were written back.
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(requestBodyPayload), resp.Data,
		"the echoed body proves the exact payload completed the round trip")
	require.Equal(t, resp.Data, resp.RawData, "no transcoding applies, so the undecoded body is the same bytes")
	require.Equal(t, 13, resp.ContentLength, "the caller-visible length is the echoed payload size")
	require.Equal(t, "13", resp.GetHeader("Content-Length"),
		"the echoed response declares the same 13 bytes back to the caller")
	require.Equal(t, requestBodyEchoContentType, resp.GetHeader("Content-Type"))
}

// TestRequestBodyBufferedRegardlessOfReaderType is the counter-intuitive result that makes
// this file valuable: for a payload of NON-ZERO length, a length-bearing reader and a reader
// that exposes NO length produce byte-for-byte IDENTICAL framing on the wire, and chunked
// framing never occurs for either. The table then pins the single input class that IS
// chunked, which is what keeps the "never chunked" rows a real discrimination rather than an
// unfalsifiable slogan.
//
// WHY, precisely. retryablehttp's constructor does not hand the caller's reader to
// net/http. getReusableBodyandContentLength (retryablehttp-go@v1.3.18/util.go:31-73) wraps
// ANY body in readerutil.NewReusableReadCloser, which buffers every input kind into a
// bytes.Buffer (projectdiscovery/utils@v0.11.1/reader/reusable_read_closer.go, including the
// generic io.Reader case), and then measures the length by draining that buffer with
// io.Copy. So for a body of non-zero length an exact Content-Length is available by the time
// net/http serializes the request, and net/http therefore needs no transfer coding.
//
// THE ONE EXCEPTION, measured and pinned by the last two rows: a body that is NOT nil but
// buffers to ZERO bytes is sent with Transfer-Encoding: chunked and no Content-Length line
// at all. Buffering alone is therefore not what guarantees a declared length - a buffered
// body of non-zero length is. The mechanism is entirely inside the standard library and has
// nothing to do with streaming:
//
//   - Request.outgoingLength (go1.26.5 net/http/request.go:1552-1560) cannot tell "length 0,
//     known" apart from "length unknown" on a non-nil Body, so it maps
//     (Body != nil && ContentLength == 0) to -1, meaning unknown.
//   - newTransferWriter (net/http/transfer.go:95-96) takes that -1 and consults
//     shouldSendChunkedRequestBody (net/http/transfer.go:170-191), which returns true at
//     :190 WITHOUT probing the body for a POST, because requestMethodUsuallyLacksBody
//     (net/http/request.go:1569-1575) covers only GET/HEAD/DELETE/OPTIONS/PROPFIND/SEARCH.
//
// RFC 9112 section 6.3 leaves no alternative once the length is unknown: a request whose
// message declares neither a length nor a transfer coding has no body at all, so chunked
// framing is the only correct way to send one. The behaviour is therefore CORRECT, not a
// defect, and it is pinned here rather than reported - the same divergence protocol the
// sibling per-hop framing assertions use. The measured raw wire, captured on a bare
// net.Listen socket, is exactly:
//
//	POST /probe HTTP/1.1\r\nHost: 127.0.0.1:...\r\nUser-Agent: Go-http-client/1.1\r\n
//	Transfer-Encoding: chunked\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n0\r\n\r\n
//
// httpx's own scanning path cannot reach it: runner/runner.go:1912 and :1939 attach a body
// only when scanopts.RequestBody != "", and HTTPX.NewRequestWithContext
// (common/httpx/httpx.go:465-482) passes a nil body. A LIBRARY CALLER can reach it, and a
// silent framing change on this path is the same class of defect as an unwanted chunked body
// anywhere else - some origins and WAFs reject chunked requests - so it is asserted rather
// than merely described.
//
// That makes the assertions below sharp rather than incidental. If someone replaced the
// buffering with a streaming body - passing the caller's reader straight through - the length
// of every non-empty row would become unknown, net/http would fall back to
// Transfer-Encoding: chunked and report ContentLength -1, and those rows would fail
// immediately. The control sub-test proves that is a real, observable alternative and not a
// hypothetical: the SAME opaqueBodyReader carrying the SAME 13 bytes, sent through net/http
// WITHOUT the retry layer against the same kind of loopback server, was MEASURED to arrive
// chunked with ContentLength -1 and no Content-Length header at all.
//
// MEASURED per row - client-side length / Content-Length line at the origin / length parsed
// at the origin / transfer coding:
//
//	length-bearing reader        13 / "13" / 13 / none
//	opaque reader with no length 13 / "13" / 13 / none
//	nil body                      0 / "0"  /  0 / none
//	empty non-nil reader          0 / ""   / -1 / chunked
//	empty non-nil opaque reader   0 / ""   / -1 / chunked
//
// The nil-body row is worth stating explicitly - net/http emits Content-Length: 0 rather
// than omitting the header, which RFC 9110 section 8.6 permits for a bodyless request with
// a method that defines body semantics - and, read against the two rows below it, it is what
// shows the discriminator is nil-ness rather than size: a nil body takes the Body == nil
// branch of outgoingLength and is length-delimited, while a non-nil body of the same zero
// size is not.
func TestRequestBodyBufferedRegardlessOfReaderType(t *testing.T) {
	require.Len(t, requestBodyPayload, 13, "precondition: the request payload is exactly 13 bytes")

	cases := []struct {
		name string
		// newBody builds a fresh body per row. It is a constructor rather than a value
		// because a reader is consumed by the request that uses it.
		newBody func() io.Reader
		// wantRequestBodyPresent is whether the constructed request carries a body at all.
		// It is the discriminator the whole framing decision hinges on: outgoingLength
		// returns a definite 0 for a nil Body and -1 (unknown) for a non-nil Body whose
		// length is 0, which is why the nil row is length-delimited and the empty non-nil
		// rows are chunked.
		wantRequestBodyPresent bool
		// wantContentLengthHdr is the exact Content-Length line the origin must observe;
		// empty for a chunk-delimited message, which declares no length at all.
		wantContentLengthHdr string
		// wantContentLength is the length the CONSTRUCTOR computes on the client request,
		// before anything is serialized. Because the server echoes the body back verbatim it
		// is also the caller-visible length of the response, so it is asserted at both ends.
		wantContentLength int64
		// wantOriginContentLength is the framing value net/http PARSED at the origin: the
		// declared length for a length-delimited message, -1 for a chunk-delimited one. It
		// differs from wantContentLength only for a body that is non-nil yet empty.
		wantOriginContentLength int64
		// wantTransferEncoding is the transfer coding the origin must observe: nil for a
		// length-delimited message, []string{"chunked"} for a non-nil empty body.
		wantTransferEncoding []string
		wantBody             []byte
	}{
		{
			name:                    "length-bearing reader",
			newBody:                 func() io.Reader { return strings.NewReader(requestBodyPayload) },
			wantRequestBodyPresent:  true,
			wantContentLengthHdr:    "13",
			wantContentLength:       13,
			wantOriginContentLength: 13,
			wantBody:                []byte(requestBodyPayload),
		},
		{
			// The discriminating row: the concrete type offers neither Len nor Size, so
			// nothing short of consuming it can reveal the length - and the framing is
			// nonetheless identical to the row above.
			name:                    "opaque reader with no length",
			newBody:                 func() io.Reader { return opaqueBodyReader{r: strings.NewReader(requestBodyPayload)} },
			wantRequestBodyPresent:  true,
			wantContentLengthHdr:    "13",
			wantContentLength:       13,
			wantOriginContentLength: 13,
			wantBody:                []byte(requestBodyPayload),
		},
		{
			name:                    "nil body",
			newBody:                 func() io.Reader { return nil },
			wantRequestBodyPresent:  false,
			wantContentLengthHdr:    "0",
			wantContentLength:       0,
			wantOriginContentLength: 0,
			wantBody:                []byte{},
		},
		{
			// The divergent row, and the reason the rows above are a real discrimination:
			// this body is NOT nil but buffers to zero bytes, so outgoingLength reports its
			// length as unknown and net/http frames the request as chunked. It is the ONLY
			// input class this client chunks, it is the one dimension the framing rule above
			// does not cover, and an unnoticed change here would be exactly as harmful as an
			// unwanted chunked body on any other path - which is why it is asserted.
			name:                    "empty non-nil reader",
			newBody:                 func() io.Reader { return strings.NewReader("") },
			wantRequestBodyPresent:  true,
			wantContentLengthHdr:    "",
			wantContentLength:       0,
			wantOriginContentLength: -1,
			wantTransferEncoding:    []string{"chunked"},
			wantBody:                []byte{},
		},
		{
			// The same zero-length payload behind a type that exposes no length. Its framing
			// is identical to the row above, which shows the divergence is driven by the
			// buffered SIZE and not by the reader's concrete type - the same conclusion the
			// two 13-byte rows establish for the length-delimited case.
			name:                    "empty non-nil opaque reader",
			newBody:                 func() io.Reader { return opaqueBodyReader{r: strings.NewReader("")} },
			wantRequestBodyPresent:  true,
			wantContentLengthHdr:    "",
			wantContentLength:       0,
			wantOriginContentLength: -1,
			wantTransferEncoding:    []string{"chunked"},
			wantBody:                []byte{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh recorder, server and client per row: a shared recorder would make
			// the request count cumulative and the captured framing ambiguous.
			rec := &requestBodyRecorder{}
			ts := newRequestBodyEchoServer(t, rec)
			defer ts.Close()

			ht := newLocalHTTPX(t)
			registerDialerCleanup(t, ht)

			// A typed nil io.Reader would be a non-nil interface holding a nil value, and
			// the constructor would try to buffer it; the nil row has to pass an interface
			// that is genuinely nil.
			var body io.Reader
			if b := tc.newBody(); b != nil {
				body = b
			}
			req, err := retryablehttp.NewRequest(http.MethodPost, ts.URL, body)
			require.NoError(t, err)
			require.Equal(t, tc.wantContentLength, req.ContentLength,
				"the length is computed by the constructor, before serialization, whatever the reader's concrete type")
			require.Equal(t, tc.wantRequestBodyPresent, req.Body != nil,
				"whether a body object exists at all is what net/http reads a zero length as: a definite 0 for a nil Body, an unknown length for a non-nil one (net/http/request.go:1552-1560)")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			got := rec.result(t)

			require.Equal(t, http.MethodPost, got.Method, "the method must reach the origin unchanged")
			require.Equal(t, tc.wantBody, got.Body,
				"the origin must receive exactly these bytes regardless of the reader's concrete type")
			require.Equal(t, tc.wantContentLengthHdr, got.ContentLengthHdr,
				"the declared length on the wire follows the buffered size alone: identical for the length-bearing and the opaque reader of the same size, and absent entirely on the chunk-delimited rows")
			require.Equal(t, tc.wantOriginContentLength, got.ContentLength,
				"net/http parsed exactly this framing value at the origin: the buffered length for a body of non-zero size, and -1 for the non-nil empty body whose length it treats as unknown")
			require.Equal(t, tc.wantTransferEncoding, got.TransferEncoding,
				"the transfer coding the origin observes must be exactly this: none for a length-delimited message, chunked only for the non-nil empty body")
			if len(tc.wantTransferEncoding) == 0 {
				require.Empty(t, got.TransferEncoding,
					"the retry layer buffers every body to make it rewindable, so for a body of non-zero length a length is always declared and no transfer coding is applied")
				require.NotContains(t, got.TransferEncoding, "chunked",
					"chunked framing must never appear for a body of non-zero length: it would mean the caller's reader was streamed straight through instead of buffered")
			} else {
				// The mirror of the assertion above, stated positively so the divergent rows
				// carry their own explicit protocol-visible expectation rather than relying
				// on the table comparison alone.
				require.Contains(t, got.TransferEncoding, "chunked",
					"a non-nil body of zero length is the one input class net/http frames as chunked, because outgoingLength reports its length as unknown (see the mechanism above)")
			}

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, tc.wantBody, resp.Data,
				"the echoed body proves the same bytes completed the round trip")
			require.Equal(t, int(tc.wantContentLength), resp.ContentLength)
		})
	}

	t.Run("control: the same opaque reader streamed without the retry layer frames as chunked", func(t *testing.T) {
		// This control asserts net/http's fallback, not this client's behaviour, and it is
		// here for one reason: it proves the length-delimited rows above distinguish two
		// genuinely reachable states at this very server rather than restating something
		// that could not have come out otherwise. Read it together with the two empty
		// non-nil rows: chunked framing on its own does NOT imply the retry layer was
		// bypassed, because the retry layer also produces chunked framing for a non-nil
		// body of zero length. What identifies a streaming regression is chunked framing
		// for a body of NON-ZERO length, which is precisely what this control reproduces -
		// the SAME 13 bytes the rows above send length-delimited. It is hermetic - a
		// dedicated transport aimed at the same loopback address, with its own pool closed
		// afterwards so no global state is touched.
		rec := &requestBodyRecorder{}
		ts := newRequestBodyEchoServer(t, rec)
		defer ts.Close()

		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport}

		req, err := http.NewRequest(http.MethodPost, ts.URL, opaqueBodyReader{r: strings.NewReader(requestBodyPayload)})
		require.NoError(t, err)
		require.Equal(t, int64(0), req.ContentLength,
			"net/http cannot discover the length of an opaque reader, so it leaves the declared length unset and the framing unknown")

		resp, err := client.Do(req)
		require.NoError(t, err)
		echoed, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		got := rec.result(t)

		require.Equal(t, []string{"chunked"}, got.TransferEncoding,
			"an unbuffered body of unknown length is chunk-delimited, which is exactly the state the non-zero-length rows above must never reach")
		require.Equal(t, int64(-1), got.ContentLength,
			"chunked framing reports an unknown length as -1, the value a streaming regression would produce for these 13 bytes")
		require.Equal(t, "", got.ContentLengthHdr,
			"a chunked message declares no Content-Length at all")
		require.Equal(t, []byte(requestBodyPayload), got.Body,
			"the payload still arrives intact, so the difference asserted here is framing and nothing else")
		require.Equal(t, []byte(requestBodyPayload), echoed,
			"the echo confirms the control exercised the same server as the rows above")
	})
}

// requestFraming holds the transport-level framing fields of one outbound hop.
//
// recordedRequest deliberately stores the method, URL, cloned header and buffered body but
// NOT the framing fields, because Content-Length is not a header on a client-side request -
// net/http serializes it from Request.ContentLength. Capturing these separately in the
// handler is therefore the only way to assert per-hop framing, and it is the same technique
// the sibling TestRedirectMethodAndBodyRewriting uses in common/httpx/redirect_test.go.
type requestFraming struct {
	ContentLength    int64
	TransferEncoding []string
	// GetBodyPresent records whether the hop could be replayed at all: net/http will only
	// carry a body across a 307 or 308 when Request.GetBody is populated.
	GetBodyPresent bool
}

// runRequestBodyRedirect drives one POST carrying requestBodyRedirectPayload through a
// scripted two-hop chain whose first hop answers with firstHopStatus, and returns the
// caller-visible response, the per-hop request snapshots and the per-hop framing.
//
// Every call builds its OWN transport and its OWN client, so the two callers cannot observe
// each other's hop counts or option values. The framing slice is appended from the handler,
// which net/http invokes synchronously on the goroutine that called Do, so no lock is
// needed here - unlike the loopback echo handler, which genuinely runs on a server
// goroutine and therefore uses a mutex.
func runRequestBodyRedirect(t *testing.T, firstHopStatus int) (*Response, []recordedRequest, []requestFraming) {
	t.Helper()
	require.Len(t, requestBodyRedirectPayload, 7, "precondition: the request payload is exactly 7 bytes")

	script := scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: firstHopStatus, location: "/b", body: requestBodyRedirectBody},
		"origin.example/b": {status: http.StatusOK, body: requestBodyFinalBody},
	})

	var framing []requestFraming
	rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		framing = append(framing, requestFraming{
			ContentLength: r.ContentLength,
			// Copied so a later hop cannot alias an earlier observation; append to nil
			// preserves nil for an absent transfer coding.
			TransferEncoding: append([]string(nil), r.TransferEncoding...),
			GetBodyPresent:   r.GetBody != nil,
		})
		return script(r)
	})

	// Redirect mode must be set BEFORE construction: New freezes the option values into the
	// CheckRedirect closure it builds (common/httpx/httpx.go:97-114), so newMockHTTPX runs
	// this mutator before New. It also installs the transport on both HTTP clients, which is
	// what guarantees no path escapes to the network.
	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = requestBodyMaxRedirects
	}, rt)

	req, err := retryablehttp.NewRequest(http.MethodPost, requestBodyOriginA, strings.NewReader(requestBodyRedirectPayload))
	require.NoError(t, err)
	require.Equal(t, int64(7), req.ContentLength, "precondition: the caller's request declares the whole 7-byte payload")
	require.NotNil(t, req.GetBody,
		"precondition: the buffered constructor populates GetBody, which is what makes a body replayable at all")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 2, rt.callCount(),
		"exactly one redirect must be followed, so exactly two requests reach the transport")
	hops := rt.requests()
	require.Len(t, hops, 2, "two round trips must have been recorded, one per hop")
	require.Len(t, framing, 2, "framing must have been captured for both hops")

	require.Equal(t, requestBodyOriginA, hops[0].URL, "the first hop is the caller's own target")
	require.Equal(t, requestBodyOriginB, hops[1].URL, "the second hop is the scripted Location, resolved against the first")

	return resp, hops, framing
}

// TestRequestBodyReplayedOn307 verifies that a 307 preserves the method AND replays the
// exact payload on the second hop, which is only possible because the body was buffered
// into a rewindable form.
//
// RFC 9110 section 15.4.8 defines 307 Temporary Redirect precisely so that the method and
// body are NOT altered, and the measurement agrees: both hops leave as POST carrying the
// same 7 bytes with the same declared length.
//
// The per-hop view is trustworthy only because the harness snapshots the body and clones
// the header BEFORE delegating (invariant 1 in common/httpx/mocktransport_test.go): net/http
// mutates and reuses request objects while following a redirect, so a mock that stored
// pointers would report the final state for every hop and this test would pass vacuously.
//
// MEASURED: callCount 2; methods POST then POST; bodies "payload" then "payload";
// Request.ContentLength 7 then 7; TransferEncoding nil on both; response 200 with body
// "final", a two-item chain, codes [307 200] and last URL http://origin.example/b.
func TestRequestBodyReplayedOn307(t *testing.T) {
	resp, hops, framing := runRequestBodyRedirect(t, http.StatusTemporaryRedirect)

	require.Equal(t, http.MethodPost, hops[0].Method, "the caller's own request must leave as a POST")
	require.Equal(t, http.MethodPost, hops[1].Method,
		"a 307 must not rewrite the method, so the redirected hop is still a POST")

	require.Equal(t, []byte(requestBodyRedirectPayload), hops[0].Body,
		"the first hop carries the exact payload the caller supplied")
	require.Equal(t, []byte(requestBodyRedirectPayload), hops[1].Body,
		"the redirected hop carries the exact same payload, replayed from the buffered body")
	require.Equal(t, hops[0].Body, hops[1].Body,
		"the buffered body must be genuinely rewindable across a 307: both hops are byte-identical")
	require.Len(t, hops[1].Body, 7, "the replayed payload is the whole 7 bytes, not a partially consumed remainder")

	require.Equal(t, int64(7), framing[0].ContentLength, "the first hop declares the full payload length")
	require.Equal(t, int64(7), framing[1].ContentLength,
		"the replayed hop declares the same length, so the origin is told to expect the whole payload again")
	require.Empty(t, framing[0].TransferEncoding,
		"the buffered 7-byte body has a known, non-zero length, so the first hop is length-delimited")
	require.Empty(t, framing[1].TransferEncoding,
		"the replayed body is equally known in length, so the redirected hop is length-delimited too")
	require.NotContains(t, framing[1].TransferEncoding, "chunked",
		"a replayed body of non-zero length must never fall back to chunked framing")
	require.True(t, framing[1].GetBodyPresent,
		"GetBody survives onto the redirected hop, which is what allowed net/http to rewind and resend the body")

	// MEASURED DIVERGENCE, pinned deliberately. Content-Length is absent from the
	// client-side header map on BOTH hops: net/http serializes it from
	// Request.ContentLength and never writes it into Request.Header, which is why the
	// framing assertions above read the field instead. The sibling
	// TestRedirectMethodAndBodyRewriting pins the same absence.
	require.Equal(t, "", hops[0].Header.Get("Content-Length"),
		"a client-side request carries its length in Request.ContentLength, not in the header map")
	require.Equal(t, "", hops[1].Header.Get("Content-Length"),
		"the redirected hop is framed the same way, from the field rather than from a header")

	require.Equal(t, http.StatusOK, resp.StatusCode, "the redirect was followed through to the 200")
	require.Equal(t, []byte(requestBodyFinalBody), resp.Data,
		"the caller receives the final hop's body, not the redirect's")
	require.Len(t, resp.Chain, 2, "one redirect plus one final response is a two-item chain")
	require.Equal(t, []int{http.StatusTemporaryRedirect, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, requestBodyOriginB, resp.GetChainLastURL(),
		"the final URL after the chain is the redirect target the payload was replayed to")
}

// TestRequestBodyDroppedOn302 verifies the other half of the contract: a 302 rewrites the
// method to GET and the payload is dropped, so the second hop carries no bytes and declares
// a length of exactly zero - not an unknown length, which would frame as chunked.
//
// RFC 9110 section 15.4.3 notes that user agents historically change a 302 POST to GET, and
// net/http does exactly that; the measurement agrees. Asserting the drop matters as much as
// asserting the replay: a defect that carried the payload onto a rewritten GET would send a
// body the origin never expects on a method with no body semantics.
//
// Scope note: the five-status method-rewriting sweep lives in
// TestRedirectMethodAndBodyRewriting (common/httpx/redirect_test.go). This test asserts the
// BODY-FRAMING consequence for the representative rewriting status only, and deliberately
// does not repeat that sweep.
//
// MEASURED: callCount 2; methods POST then GET; bodies "payload" then none at all (the
// recorded body is empty); Request.ContentLength 7 then 0; TransferEncoding nil on both;
// GetBody present on the first hop and absent on the second; response 200 with body
// "final", a two-item chain, codes [302 200] and last URL http://origin.example/b.
func TestRequestBodyDroppedOn302(t *testing.T) {
	resp, hops, framing := runRequestBodyRedirect(t, http.StatusFound)

	require.Equal(t, http.MethodPost, hops[0].Method, "the caller's own request must leave as a POST")
	require.Equal(t, http.MethodGet, hops[1].Method,
		"a 302 rewrites the method, so the redirected hop must leave as a GET")

	require.Equal(t, []byte(requestBodyRedirectPayload), hops[0].Body,
		"the first hop still carries the exact payload the caller supplied")
	require.Empty(t, hops[1].Body,
		"the rewritten GET must carry no payload at all: the body is dropped, not forwarded")
	require.Len(t, hops[1].Body, 0, "zero bytes reach the redirect target")

	require.Equal(t, int64(7), framing[0].ContentLength, "the first hop declares the full payload length")
	require.Equal(t, int64(0), framing[1].ContentLength,
		"the rewritten GET declares zero bytes, which is how the dropped body is visible in the framing")
	require.Empty(t, framing[0].TransferEncoding, "the first hop is length-delimited")
	require.Empty(t, framing[1].TransferEncoding,
		"a bodyless GET needs no transfer coding, so none may be applied")
	require.NotContains(t, framing[1].TransferEncoding, "chunked",
		"a dropped body must not become an empty chunked stream")
	require.False(t, framing[1].GetBodyPresent,
		"with the body dropped there is nothing left to rewind, so the rewritten hop exposes no GetBody")

	// MEASURED DIVERGENCE, pinned deliberately. The dropped body is NOT announced as
	// "Content-Length: 0" in the client-side header map either: net/http keeps the length in
	// Request.ContentLength, which the framing assertion above reads as exactly 0.
	require.Equal(t, "", hops[0].Header.Get("Content-Length"),
		"a client-side request carries its length in Request.ContentLength, not in the header map")
	require.Equal(t, "", hops[1].Header.Get("Content-Length"),
		"the rewritten hop is no different: its zero length lives in the field, not in a header")

	require.Equal(t, http.StatusOK, resp.StatusCode, "the redirect was followed through to the 200")
	require.Equal(t, []byte(requestBodyFinalBody), resp.Data,
		"the caller receives the final hop's body, not the redirect's")
	require.Len(t, resp.Chain, 2, "one redirect plus one final response is a two-item chain")
	require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, requestBodyOriginB, resp.GetChainLastURL(),
		"the final URL after the chain is the redirect target the rewritten GET reached")
}
