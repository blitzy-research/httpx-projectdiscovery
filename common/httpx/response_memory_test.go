package httpx

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// newLocalHTTPX builds an HTTPX instance suitable for hitting a local test
// server only (no external network, CDN checks disabled).
func newLocalHTTPX(t *testing.T) *HTTPX {
	t.Helper()
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 5 * time.Second
	options.RetryMax = 0
	// NB: relies on DefaultOptions.MaxResponseBodySizeToRead being non-zero
	// (see TestDefaultOptionsHasNonZeroReadSize) so the body is actually read.

	ht, err := New(&options)
	require.NoError(t, err)
	return ht
}

// doLocal issues a GET against a local httptest server and returns the parsed
// httpx Response.
func doLocal(t *testing.T, ht *HTTPX, url string) *Response {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	return resp
}

// legacyWordsLines reproduces the exact word/line computation that existed
// before the refactor, so we can assert the new byte-based path is equivalent.
func legacyWordsLines(body []byte) (words, lines int) {
	s := string(body)
	if s != "" {
		words = len(strings.Split(s, " "))
		lines = len(strings.Split(strings.TrimSpace(s), "\n"))
	}
	return
}

// TestDefaultOptionsHasNonZeroReadSize guards against the package var-init
// ordering regression where DefaultOptions was initialized before
// DefaultMaxResponseBodySize, leaving MaxResponseBodySizeToRead at 0 (which made
// LimitReader read zero bytes and produced empty bodies for library users).
func TestDefaultOptionsHasNonZeroReadSize(t *testing.T) {
	require.NotZero(t, DefaultMaxResponseBodySize)
	require.Equal(t, DefaultMaxResponseBodySize, DefaultOptions.MaxResponseBodySizeToRead)
}

func TestDoBodyNoDecodePreservesRawAndData(t *testing.T) {
	body := []byte("hello world\nsecond line\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, body, resp.Data, "decoded data must equal body")
	require.Equal(t, body, resp.RawData, "raw data must equal undecoded body")

	wantWords, wantLines := legacyWordsLines(body)
	require.Equal(t, wantWords, resp.Words)
	require.Equal(t, wantLines, resp.Lines)
}

func TestDoBodyEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)
	require.Empty(t, resp.Data)
	require.Empty(t, resp.RawData)
	require.Equal(t, 0, resp.Words)
	require.Equal(t, 0, resp.Lines)
}

// TestDoBodyGBKDecodeKeepsRawUndecoded ensures that when DecodeData actually
// transcodes the body, RawData still holds the original (undecoded) bytes while
// Data holds the decoded UTF-8 bytes.
func TestDoBodyGBKDecodeKeepsRawUndecoded(t *testing.T) {
	utf8Body := "<html><head></head><body>你好世界 测试</body></html>"
	gbkBody, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(utf8Body))
	require.NoError(t, err)
	require.NotEqual(t, []byte(utf8Body), gbkBody, "precondition: gbk bytes differ from utf8")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=gbk")
		_, _ = w.Write(gbkBody)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, gbkBody, resp.RawData, "RawData must hold the original undecoded bytes")
	require.Equal(t, []byte(utf8Body), resp.Data, "Data must hold the decoded UTF-8 bytes")
}

// TestDoBodyNoDecodeSharesBacking documents the memory optimization: on the
// no-decode hot path RawData and Data share the same backing array (no extra
// full-body copy is made).
func TestDoBodyNoDecodeSharesBacking(t *testing.T) {
	body := []byte("shared backing array body")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.NotEmpty(t, resp.Data)
	require.NotEmpty(t, resp.RawData)
	require.Equal(t, resp.Data, resp.RawData)
	require.Same(t, &resp.Data[0], &resp.RawData[0],
		"RawData and Data should share the backing array on the no-decode path")
}

// TestWordsLinesEquivalence is the core guard for the refactor: the byte-based
// counting used on the hot path must be identical to the previous
// strings.Split-based counting for a wide range of inputs and edge cases.
func TestWordsLinesEquivalence(t *testing.T) {
	cases := []string{
		"",
		"a",
		"a b c",
		"   ",                        // only spaces
		"a  b",                       // consecutive spaces
		"line1\nline2\nline3",        // multiple lines
		"\n\n\n",                     // only newlines
		"  leading and trailing  ",   // surrounding whitespace
		"\n  mixed \t whitespace \n", // tabs/newlines around
		"trailing newline\n",
		"word",
		"tab\tseparated values",
		"unicode \u00a0 nbsp space",
		"emoji 😀 and spaces ",
	}

	for _, c := range cases {
		body := []byte(c)
		wantWords, wantLines := legacyWordsLines(body)

		var gotWords, gotLines int
		if len(body) > 0 {
			gotWords = bytes.Count(body, []byte{' '}) + 1
			gotLines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
		}

		require.Equalf(t, wantWords, gotWords, "words mismatch for %q", c)
		require.Equalf(t, wantLines, gotLines, "lines mismatch for %q", c)
	}
}

// TestBodyMetricsCountingDoesNotAllocate locks in the optimization: the
// byte-based word/line counting used on the hot path must not allocate (the
// previous string(respbody) + strings.Split approach allocated O(len(body))).
// If someone reintroduces a full-body string copy or Split-based counting, this
// test fails.
func TestBodyMetricsCountingDoesNotAllocate(t *testing.T) {
	body := bytes.Repeat([]byte("lorem ipsum dolor sit amet\n"), 40000) // ~1MB
	var words, lines int

	allocs := testing.AllocsPerRun(50, func() {
		// identical expressions to the hot path in Do()
		words = bytes.Count(body, []byte{' '}) + 1
		lines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
	})

	require.NotZero(t, words)
	require.NotZero(t, lines)
	require.Zerof(t, allocs, "word/line counting must not allocate, got %v allocs/op", allocs)
}

// TestDoBodyReadCapTruncatesOversizeBody verifies that a declared body larger than
// the read cap is returned as a truncated response rather than rejected for a
// Content-Length mismatch. Do marks the upstream length unknown before
// serialization, while the caller-facing ContentLength is reconstructed from the
// preserved Content-Length header.
//
// The cases straddle the strict > guard: lengths at or below the cap retain declared
// framing; lengths above it are close-delimited. This catches an off-by-one change
// without relying only on retained body bytes.
func TestDoBodyReadCapTruncatesOversizeBody(t *testing.T) {
	// 100 bytes whose first 10 are recognizable, so the assertions prove the cap
	// kept the PREFIX rather than merely N bytes from somewhere in the body.
	body := []byte("0123456789" + strings.Repeat("x", 90))
	require.Len(t, body, 100, "precondition: the origin declares and delivers exactly 100 bytes")

	// Raw lengths, all measured. Untruncated:  17 (status line) + 19
	// (Connection: close) + 21 (Content-Length: 100) + 26 (Content-Type: text/plain)
	// + 37 (Date) + 2 (blank line) + N (body). Truncated: the same minus the
	// 21-byte Content-Length line, which the dump can no longer honour.
	for _, tc := range []struct {
		name                string
		readCap             int64
		wantData            []byte
		wantRaw             int
		wantRawHeader       int
		wantDeclaredFraming bool
	}{
		{name: "below the cap", readCap: 200, wantData: body, wantRaw: 222, wantRawHeader: 122, wantDeclaredFraming: true},
		{name: "exactly at the cap", readCap: 100, wantData: body, wantRaw: 222, wantRawHeader: 122, wantDeclaredFraming: true},
		{name: "one byte over the cap", readCap: 99, wantData: body[:99], wantRaw: 200, wantRawHeader: 101},
		{name: "far over the cap", readCap: 10, wantData: body[:10], wantRaw: 111, wantRawHeader: 101},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Pin Content-Type so raw lengths do not depend on MIME sniffing;
				// Content-Length drives the declared-length branch under test.
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write(body)
			}))
			defer ts.Close()

			ht := newLocalHTTPX(t)
			// One client per row means one disk-backed dialer history per row, so
			// register its release immediately after construction.
			registerDialerCleanup(t, ht)
			ht.Options.MaxResponseBodySizeToRead = tc.readCap

			// doLocal's no-error assertion requires capped responses to remain usable.
			resp := doLocal(t, ht, ts.URL)

			require.Equal(t, http.StatusOK, resp.StatusCode, "a truncated body is still a successful response")
			require.Equal(t, tc.wantData, resp.Data,
				"the read cap must retain exactly the first MaxResponseBodySizeToRead body bytes")
			require.Equal(t, resp.Data, resp.RawData, "the undecoded body is the same retained prefix")
			require.Equal(t, 100, resp.ContentLength,
				"ContentLength is recomputed from the origin's own Content-Length header, not from the retained bytes")
			require.Equal(t, "100", resp.GetHeader("Content-Length"),
				"the declared length stays visible to the caller through the response headers")

			require.Len(t, resp.Raw, tc.wantRaw, "the full dump is the headers plus exactly the retained body bytes")
			require.Len(t, resp.RawHeaders, tc.wantRawHeader, "the header-only dump is the full dump minus the retained body")
			require.Equal(t, len(resp.Data), len(resp.Raw)-len(resp.RawHeaders),
				"the body section of the dump must be exactly the bytes the cap retained")
			require.True(t, strings.HasSuffix(resp.Raw, string(tc.wantData)),
				"the dump must end with the retained prefix, got %q", resp.Raw)

			if tc.wantDeclaredFraming {
				require.Contains(t, resp.Raw, "\r\nContent-Length: 100\r\n",
					"an untruncated body must still be framed by the length the origin declared")
			} else {
				// Once the upstream length is unknown, the dump must be close-delimited;
				// the cloned response header must remain unchanged for caller-visible
				// metadata.
				require.NotContains(t, resp.Raw, "Content-Length",
					"a truncated body must not be framed by a declared length")
			}
			require.Contains(t, resp.Raw, "\r\nConnection: close\r\n",
				"the scanner disables keep-alives, so every response is close-delimited")

			require.Equal(t, 1, resp.Words)
			require.Equal(t, 1, resp.Lines)
		})
	}
}

// TestDoBodyReadCapChunkedTruncation verifies the cap for an undeclared-length
// response. net/http reports a chunked response with ContentLength -1, so the
// declared-length guard is inert; because no Content-Length header exists, the
// caller-facing value falls back to the retained body length.
func TestDoBodyReadCapChunkedTruncation(t *testing.T) {
	// Each 25-byte unit makes the 100-byte cap end on a line boundary, so the word and
	// line counts are exact.
	payload := bytes.Repeat([]byte("chunked response payload\n"), 1600)
	require.Len(t, payload, 40000, "precondition: the origin delivers exactly 40000 bytes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: writing well past the server's buffer without one is
		// what makes net/http chunk the response, which is the whole point here.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	ht := newLocalHTTPX(t)
	registerDialerCleanup(t, ht)
	ht.Options.MaxResponseBodySizeToRead = 100

	resp := doLocal(t, ht, ts.URL)

	require.Equal(t, payload[:100], resp.Data,
		"the read cap must retain exactly the first 100 bytes of the chunked body")
	require.Equal(t, resp.Data, resp.RawData, "the undecoded body is the same truncated prefix")
	require.Equal(t, 100, resp.ContentLength,
		"with no Content-Length header the length falls back to the number of bytes actually read")
	require.Equal(t, "", resp.GetHeader("Content-Length"),
		"a chunked response declares no length, which is why the fallback is used")

	// 17 (status line) + 19 (Connection: close) + 28 (Transfer-Encoding: chunked)
	// + 26 (Content-Type: text/plain) + 37 (Date) + 2 (blank line)
	// + 111 (chunk framing: "64\r\n" + 100 bytes + "\r\n" + "0\r\n\r\n") = 240.
	require.Len(t, resp.Raw, 240, "the chunked dump length is unchanged from the pre-guard baseline")
	require.Len(t, resp.RawHeaders, 129, "the header-only dump excludes the chunk-framed body")
	require.Contains(t, resp.Raw, "\r\nTransfer-Encoding: chunked\r\n",
		"the truncated body is re-serialized with chunked framing")
	require.Contains(t, resp.Raw, "\r\n\r\n64\r\n",
		"the single chunk declares 0x64 = 100 bytes, the capped length")
	require.True(t, strings.HasSuffix(resp.Raw, "\r\n0\r\n\r\n"),
		"the dump must close with the terminating zero-length chunk, got %q", resp.Raw)

	// 100 retained bytes are exactly four 25-byte units: 4x2 spaces + 1 = 9 words,
	// and TrimSpace drops the trailing newline leaving 3 + 1 = 4 lines.
	require.Equal(t, 9, resp.Words)
	require.Equal(t, 4, resp.Lines)
}

// TestDoBodyNotModifiedSkipsBodyRead verifies the 304 branch of shouldSkipBodyRead. A
// conforming 304 has no message body (RFC 9110 §15.4.5), and net/http suppresses
// Content-Type, Content-Length and Transfer-Encoding; this fixture's dump therefore
// contains Connection: close, Date, Etag and the header terminator.
//
// GetHeader requires the stored MIME spelling "Etag". The mock subtest supplies
// non-conforming body bytes because a loopback net/http server suppresses them; this
// distinguishes skipping the read from merely receiving no body.
func TestDoBodyNotModifiedSkipsBodyRead(t *testing.T) {
	const validator = `"abc123"` // a quoted entity-tag, per RFC 9110 section 8.8.3

	t.Run("conforming origin sends no body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", validator)
			w.WriteHeader(http.StatusNotModified)
		}))
		defer ts.Close()

		ht := newLocalHTTPX(t)
		registerDialerCleanup(t, ht)
		resp := doLocal(t, ht, ts.URL)

		require.Equal(t, http.StatusNotModified, resp.StatusCode)
		require.Empty(t, resp.Data, "a 304 body is never read")
		require.Empty(t, resp.RawData, "a 304 body is never read, decoded or otherwise")
		require.Equal(t, 0, resp.ContentLength)
		require.Equal(t, 0, resp.Words)
		require.Equal(t, 0, resp.Lines)

		require.Equal(t, resp.RawHeaders, resp.Raw,
			"with no body section the full dump equals the header-only dump")
		require.Len(t, resp.Raw, 101,
			"27 (status line) + 19 (Connection: close) + 37 (Date) + 16 (Etag) + 2 (blank line)")
		require.True(t, strings.HasSuffix(resp.Raw, "\r\n\r\n"),
			"the dump must stop at the header terminator, got %q", resp.Raw)

		require.Equal(t, validator, resp.GetHeader("Etag"),
			"the validator must survive the skipped body read under its canonical key")
		require.Equal(t, "", resp.GetHeader("ETag"),
			"GetHeader is a raw map read: a non-canonical spelling finds nothing")
		require.Equal(t, "", resp.GetHeader("Content-Length"),
			"RFC 7232 section 4.1: a 304 carries no Content-Length")
		require.Equal(t, "", resp.GetHeader("Content-Type"),
			"RFC 7232 section 4.1: a 304 carries no Content-Type")
	})

	t.Run("body smuggled behind the status is not read", func(t *testing.T) {
		// A non-conforming 304 that does carry bytes, contradicting RFC 9110
		// section 15.4.5. Only the mock transport can present one.
		const smuggled = "should-never-be-read"

		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			return mockResponse(r, http.StatusNotModified,
				http.Header{"Etag": {validator}}, smuggled), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/cached", nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)

		// The bytes reached the client - the dump proves it serialized them - and Do
		// still refused to read them into the body. Drop the status from
		// shouldSkipBodyRead and the smuggled payload lands in Data instead.
		require.Contains(t, resp.Raw, smuggled,
			"precondition: the origin really did put bytes behind the 304")
		require.Equal(t, http.StatusNotModified, resp.StatusCode)
		require.Empty(t, resp.Data, "the skipped read must leave the body empty even when bytes are present")
		require.Empty(t, resp.RawData, "the undecoded body must be empty too")
		require.Equal(t, 0, resp.ContentLength, "no bytes read means no length to report")
		require.Equal(t, 0, resp.Words)
		require.Equal(t, 0, resp.Lines)
		require.Equal(t, validator, resp.GetHeader("Etag"))
		require.Equal(t, 1, rt.callCount(), "a skipped body read must not provoke a second request")
	})
}

// TestDoBodyGzipInvalidHeaderRetriesWithIdentity verifies that an invalid gzip body
// causes one retry with Accept-Encoding: identity. The mock injects gzip.ErrHeader
// because transparent decompression normally occurs in the replaced http.Transport, and
// the initial request sets gzip explicitly for the same reason.
//
// The first subtest pins the caller-visible mutation of req.Header. The second returns
// two decode failures so the !gzipRetry guard must surface the second error instead of
// issuing a third request.
func TestDoBodyGzipInvalidHeaderRetriesWithIdentity(t *testing.T) {
	const plainBody = "plain-not-gzipped-x" // exactly 19 bytes, never gzip-compressed
	require.Len(t, plainBody, 19, "precondition: the payload is exactly 19 bytes")

	invalidGzip := func(r *http.Request) *http.Response {
		resp := mockResponse(r, http.StatusOK,
			http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/plain"}}, "")
		resp.Body = &errReadCloser{err: gzip.ErrHeader}
		resp.ContentLength = -1 // a body that yields no byte cannot satisfy a declared length
		return resp
	}

	t.Run("identity retry recovers the body", func(t *testing.T) {
		// Routing on the request's own Accept-Encoding, rather than on a call
		// counter, ties each reply to what the client actually asked for: the origin
		// serves the plain payload only once identity has been negotiated.
		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Accept-Encoding") == "identity" {
				return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, plainBody), nil
			}
			return invalidGzip(r), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/encoding", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)

		require.Equal(t, 2, rt.callCount(), "the encoding retry must reissue the request exactly once")
		hops := rt.requests()
		require.Len(t, hops, 2)
		require.Equal(t, []string{"gzip", "identity"},
			[]string{hops[0].Header.Get("Accept-Encoding"), hops[1].Header.Get("Accept-Encoding")},
			"hop 1 carries the caller's encoding, hop 2 the identity Do substituted")
		require.Equal(t, hops[0].Method, hops[1].Method, "the retry replays the same method")
		require.Equal(t, hops[0].URL, hops[1].URL, "the retry replays the same target")

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, []byte(plainBody), resp.Data, "the identity reply's bytes are what the caller receives")
		require.Len(t, resp.Data, 19)
		require.Equal(t, 19, resp.ContentLength)
		require.Equal(t, "", resp.GetHeader("Content-Encoding"),
			"the surviving response is the unlabelled one, so no encoding is reported")
		require.True(t, strings.HasSuffix(resp.Raw, "\r\n\r\n"+plainBody),
			"the dump must carry the identity reply's body, got %q", resp.Raw)

		require.Equal(t, "identity", req.Header.Get("Accept-Encoding"),
			"the retry rewrites the caller's own request header, an observable side effect")
	})

	t.Run("the retry is one-shot", func(t *testing.T) {
		// Fail the first two attempts, then succeed. A guarded client never asks a
		// third time, so it never sees this payload; its presence in the response is
		// exactly the symptom of a retry loop.
		const recovered = "third-attempt-body"

		var rt *mockTransport
		rt = newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			if rt.callCount() > 2 {
				return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, recovered), nil
			}
			return invalidGzip(r), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/always-invalid", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})

		require.Equal(t, 2, rt.callCount(),
			"the retry must fire once and only once, even when the second attempt fails too")
		require.Error(t, err, "a second undecodable body must surface rather than trigger another retry")
		require.ErrorContains(t, err, "gzip: invalid header",
			"the surfaced error must be the decode failure itself")
		require.Nil(t, resp, "no response is produced when the retried attempt also fails")

		hops := rt.requests()
		require.Len(t, hops, 2)
		require.Equal(t, []string{"gzip", "identity"},
			[]string{hops[0].Header.Get("Accept-Encoding"), hops[1].Header.Get("Accept-Encoding")},
			"the single retry still negotiates identity before giving up")
	})
}

// TestDoReleasesTransportBodyOnEveryPath asserts that the body the transport handed back
// is closed exactly once on every path through Do, which is the state of the connection
// after the call returns.
//
// The body is the only handle on the underlying connection, and Do replaces the
// Response.Body field repeatedly: the read cap wraps it in io.NopCloser(io.LimitReader(...)),
// which discards the original closer outright, and the response dump then swaps in an
// in-memory reader, so the explicit close near the end of Do can no longer reach the
// connection. Three paths never read the body to completion at all - a capped body, a
// body-skip status, and a content-encoding retry that abandons the response mid-flight -
// so nothing else releases it either. Without the release Do performs on the handle it
// keeps, every one of the sub-tests below observes zero closes, and a scan leaves one
// unreleased connection per response.
//
// Each sub-test also asserts the caller-visible outcome, so a regression that released
// the body by consuming the whole response - defeating the read cap - would fail here
// too.
func TestDoReleasesTransportBodyOnEveryPath(t *testing.T) {
	const origin = "http://origin.example/release"

	// trackedTransport answers with the caller's response after substituting a
	// close-tracking body, and returns both so the test can assert reads, closes and the
	// per-hop request stream together. Bodies are returned in the order they were served.
	trackedTransport := func(t *testing.T, reply func(*http.Request, int) (*http.Response, io.Reader)) (*mockTransport, func() []*closeTrackingBody) {
		t.Helper()

		var (
			mu     sync.Mutex
			served []*closeTrackingBody
		)
		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			attempt := len(served)
			mu.Unlock()

			resp, reader := reply(r, attempt)
			tracked := newCloseTrackingBody(reader)
			resp.Body = tracked

			mu.Lock()
			served = append(served, tracked)
			mu.Unlock()
			return resp, nil
		})
		return rt, func() []*closeTrackingBody {
			mu.Lock()
			defer mu.Unlock()
			return append([]*closeTrackingBody(nil), served...)
		}
	}

	t.Run("declared length above the read cap", func(t *testing.T) {
		const body = "0123456789abcdefghij" // 20 bytes declared, 10 of them read
		rt, bodies := trackedTransport(t, func(r *http.Request, _ int) (*http.Response, io.Reader) {
			resp := mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, body)
			// The declared length stays at 20 while the cap stops the read at 10, which
			// is the case the read cap has to survive without failing the request.
			return resp, strings.NewReader(body)
		})

		ht := newMockHTTPX(t, func(options *Options) {
			options.MaxResponseBodySizeToRead = 10
		}, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, origin, nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)
		require.Equal(t, []byte(body[:10]), resp.Data, "the cap must retain exactly the first 10 bytes")

		served := bodies()
		require.Len(t, served, 1, "one response was served, so one body was acquired")
		require.Equal(t, 1, served[0].closeCount(),
			"the capped body must be released exactly once: the limited wrapper drops the original closer, so only the handle Do keeps can free the connection")
		require.LessOrEqual(t, served[0].bytesRead(), 20,
			"releasing the body must not turn into draining it: the cap exists to bound what is read")
	})

	t.Run("unknown length above the read cap", func(t *testing.T) {
		body := strings.Repeat("z", 4096)
		rt, bodies := trackedTransport(t, func(r *http.Request, _ int) (*http.Response, io.Reader) {
			resp := mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, body)
			// -1 is what net/http reports for a chunked response, so this row covers the
			// framing the declared-length guard cannot see.
			resp.ContentLength = -1
			return resp, strings.NewReader(body)
		})

		ht := newMockHTTPX(t, func(options *Options) {
			options.MaxResponseBodySizeToRead = 64
		}, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, origin, nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)
		require.Len(t, resp.Data, 64, "an undeclared length is capped by the same limit")

		served := bodies()
		require.Len(t, served, 1)
		require.Equal(t, 1, served[0].closeCount(),
			"a close-delimited body that was never read to completion must still be released exactly once")
	})

	t.Run("body skip status", func(t *testing.T) {
		// 101 and 304 both skip the body read, and they take different routes through the
		// response dump: the 1xx branch returns before touching the body at all.
		for _, tc := range []struct {
			name   string
			status int
		}{
			{name: "switching protocols", status: http.StatusSwitchingProtocols},
			{name: "not modified", status: http.StatusNotModified},
		} {
			t.Run(tc.name, func(t *testing.T) {
				const smuggled = "never-read"
				rt, bodies := trackedTransport(t, func(r *http.Request, _ int) (*http.Response, io.Reader) {
					resp := mockResponse(r, tc.status, http.Header{"Upgrade": {"websocket"}}, smuggled)
					resp.ContentLength = -1 // the skipped read cannot satisfy a declared length
					return resp, strings.NewReader(smuggled)
				})

				ht := newMockHTTPX(t, nil, rt)
				req, err := retryablehttp.NewRequest(http.MethodGet, origin, nil)
				require.NoError(t, err)

				resp, err := ht.Do(req, UnsafeOptions{})
				require.NoError(t, err)
				require.Equal(t, tc.status, resp.StatusCode)
				require.Empty(t, resp.Data, "the body read is skipped for this status")

				served := bodies()
				require.Len(t, served, 1)
				require.Equal(t, 1, served[0].closeCount(),
					"a skipped body read still has to release the connection: nothing drains or closes it on this path")
			})
		}
	})

	t.Run("content encoding retry", func(t *testing.T) {
		const recovered = "plain-body"
		rt, bodies := trackedTransport(t, func(r *http.Request, attempt int) (*http.Response, io.Reader) {
			if r.Header.Get("Accept-Encoding") == "identity" {
				return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, recovered),
					strings.NewReader(recovered)
			}
			// A response labelled gzip whose body cannot be decoded: the dump fails, Do
			// abandons this response and reissues the request with identity.
			resp := mockResponse(r, http.StatusOK, http.Header{"Content-Encoding": {"gzip"}}, "")
			resp.ContentLength = -1
			return resp, &errReadCloser{err: gzip.ErrHeader}
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, origin, nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)
		require.Equal(t, []byte(recovered), resp.Data, "the identity attempt supplies the caller's body")

		served := bodies()
		require.Len(t, served, 2, "the retry acquires a second body, so both must be accounted for")
		require.Equal(t, 1, served[0].closeCount(),
			"the abandoned gzip attempt must be released before the retry is issued, not left to the garbage collector")
		require.Equal(t, 1, served[1].closeCount(),
			"the surviving attempt must be released exactly once as well")
	})

	t.Run("content encoding retry exhausted", func(t *testing.T) {
		rt, bodies := trackedTransport(t, func(r *http.Request, _ int) (*http.Response, io.Reader) {
			resp := mockResponse(r, http.StatusOK, http.Header{"Content-Encoding": {"gzip"}}, "")
			resp.ContentLength = -1
			return resp, &errReadCloser{err: gzip.ErrHeader}
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, origin, nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})
		require.ErrorContains(t, err, "gzip: invalid header",
			"the second decode failure is surfaced instead of provoking a third request")
		require.Nil(t, resp)

		served := bodies()
		require.Len(t, served, 2, "the one-shot retry acquires exactly two bodies")
		require.Equal(t, 1, served[0].closeCount(),
			"the first failed attempt must be released even though the call ends in an error")
		require.Equal(t, 1, served[1].closeCount(),
			"the second failed attempt must be released on the error return path too")
	})
}

// TestDoNonPositiveReadCapDisablesTheCap pins the one response-body configuration the
// read-cap tests above never reach: a zero or negative MaxResponseBodySizeToRead.
// DefaultOptions carries DefaultMaxResponseBodySize (TestDefaultOptionsHasNonZeroReadSize),
// so this state exists only when a caller passes -rstr 0 or a library user zeroes the
// field - which is exactly why it needs pinning rather than assuming.
//
// Three independent contracts are asserted per row:
//
//   - The transport body is released EXACTLY ONCE. This extends the resource contract
//     TestDoReleasesTransportBodyOnEveryPath states for the capped paths to the uncapped
//     one, and it is the assertion that motivated the else branch in Do's read-cap block.
//     MEASURED before that branch existed: the close count on both non-positive rows was
//     2, because skipping the limiter left pdhttputil.DumpResponseHeadersAndRaw holding
//     the transport body itself - httputil.DumpResponse drains and CLOSES what it is
//     given before substituting its in-memory copy - and the deferred release then closed
//     it a second time. A net/http body tolerates that; a body that does not - a
//     connection wrapper, a test double, a future implementation - would not, and
//     "released exactly once" is the contract every other release assertion in this file
//     states.
//   - A non-positive cap DISABLES the cap rather than bounding the read at zero: the dump
//     consumes the whole body, so resp.Raw carries all of it. MEASURED and PINNED AS
//     MEASURED, NOT FIXED. Bounding this read, or defining a zero cap as "no body", would
//     change what every -rstr 0 user sees in Raw output and in saved responses; that is a
//     behaviour change to a pre-existing opt-out rather than a bug fix, and this work may
//     only touch this source file for the two disclosed defects. The resource consequence
//     is real - an uncapped read is unbounded memory for a hostile response - so it is
//     stated here as an exact byte count instead of being left implicit.
//   - The caller-visible body is nevertheless EMPTY, because the post-dump read is
//     io.LimitReader(body, cap) and a non-positive limit reports io.EOF immediately. Data,
//     RawData, Words and Lines all stay at zero while Raw holds the full payload - a
//     divergence between the two views of one response that only an exact assertion makes
//     visible.
//
// The positive-cap control row proves the first two properties follow from the cap's sign
// and not from the fixture: the same oversized body over the same scripted route yields a
// bounded read and a non-empty Data.
func TestDoNonPositiveReadCapDisablesTheCap(t *testing.T) {
	// A recognizable 10-byte prefix, so a bounded read is proved to have kept the START of
	// the body rather than some 64 bytes from elsewhere in it.
	body := "0123456789" + strings.Repeat("u", 4086)
	require.Len(t, body, 4096, "precondition: the origin delivers exactly 4096 bytes")

	for _, tc := range []struct {
		name    string
		readCap int64
		// wantBytesRead is how much of the transport body the client consumed: the whole
		// body when the cap is disabled, the cap when it is not.
		wantBytesRead int
		// wantDataLen is how much of it reached the caller.
		wantDataLen int
	}{
		{name: "a zero cap disables the cap", readCap: 0, wantBytesRead: 4096, wantDataLen: 0},
		{name: "a negative cap disables the cap", readCap: -1, wantBytesRead: 4096, wantDataLen: 0},
		{name: "a positive cap bounds the read", readCap: 64, wantBytesRead: 64, wantDataLen: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tracked *closeTrackingBody
			rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
				// mockResponse declares the full 4096 bytes on the response, so the
				// declared-length guard in the read-cap branch is live on the control row;
				// the close-tracking body replaces the delivered reader so the release and
				// the consumed byte count are both observable.
				resp := mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, body)
				tracked = newCloseTrackingBody(strings.NewReader(body))
				resp.Body = tracked
				return resp, nil
			})

			ht := newMockHTTPX(t, func(options *Options) {
				options.MaxResponseBodySizeToRead = tc.readCap
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/uncapped", nil)
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err,
				"a cap that reads nothing must still produce a response: dropping the target from output would be the read-cap defect this suite already pins for the declared-length case")
			require.Equal(t, 1, rt.callCount(), "one request reached the transport, so there is exactly one body to account for")
			require.Equal(t, http.StatusOK, resp.StatusCode)

			require.Equal(t, 1, tracked.closeCount(),
				"the transport body must be released exactly once: 0 leaks the connection, 2 means two owners closed the same handle")
			require.Equal(t, tc.wantBytesRead, tracked.bytesRead(),
				"how much of the body the client consumed is the whole point of the cap, and a non-positive cap consumes all of it")

			require.Len(t, resp.Data, tc.wantDataLen,
				"the caller-visible body is whatever io.LimitReader yields for this cap, which is nothing at all when the limit is not positive")
			require.Len(t, resp.RawData, tc.wantDataLen, "the undecoded body follows the same limit")
			require.Equal(t, tc.wantDataLen, resp.ContentLength,
				"with no Content-Length header to recover the length from, the caller-facing value is the retained byte count")
			require.Equal(t, "", resp.GetHeader("Content-Length"),
				"the scripted response declares its length on the response struct only, so the header the recomputation looks for is genuinely absent")

			require.Equal(t, tc.wantBytesRead, len(resp.Raw)-len(resp.RawHeaders),
				"the body section of the dump is exactly what the dump was allowed to read, which is the full payload when the cap is disabled")
			require.True(t, strings.HasSuffix(resp.Raw, body[:tc.wantBytesRead]),
				"the dump must end with the leading bytes of the payload, not with an arbitrary window of it")

			if tc.wantDataLen == 0 {
				require.Equal(t, 0, resp.Words, "the metrics are derived from Data, which is empty")
				require.Equal(t, 0, resp.Lines, "the metrics are derived from Data, which is empty")
			} else {
				require.Equal(t, 1, resp.Words, "the payload has no space, so the retained prefix is one word")
				require.Equal(t, 1, resp.Lines, "the payload has no newline, so the retained prefix is one line")
			}
		})
	}
}
