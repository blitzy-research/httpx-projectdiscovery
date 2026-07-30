package httpx

// mocktransport_test.go is the shared hermetic test harness for this package.
//
// It deliberately contains NO Test, Benchmark or Fuzz functions: it is scaffolding
// that the behaviour-focused test files in this directory build on. A _test.go
// file holding only helpers is the language's own convention for shared test
// support inside the package under test, and keeping the harness in one place
// means a defect in it is fixed once instead of nine times.
//
// WHY A ROUND TRIPPER AND NOT A LOOPBACK SERVER
//
// Everything below intercepts HTTP at the http.RoundTripper boundary, which is
// the seam the package's own tests already use (see switchingProtocolsRoundTripper
// in common/httpx/httpx_test.go:136-152). Replacing the transport bypasses DNS
// resolution, TCP dialling and the TLS handshake outright rather than stubbing
// them, so no test built on this harness can reach the network: the fastdialer
// that New allocates (common/httpx/httpx.go:70) is never invoked.
//
// For two of the behaviours under test the mock is not merely convenient, it is
// the only mechanism that can express the scenario at all. FollowHostRedirects
// compares URL.Hostname() between the first and the redirected request
// (common/httpx/httpx.go:123-127); two httptest servers both bind 127.0.0.1, so
// a loopback-only setup cannot produce a genuine cross-host redirect. The
// synthetic authorities used with scriptedRedirects - origin.example,
// other.example, slow.example - exist only inside the handler and are never
// resolved or dialled.
//
// Conversely, three facts genuinely require a socket and therefore must NOT be
// faked here: the peer address observed per request, the Close flag on the
// request the server received, and the negotiated protocol string. Tests needing
// those stand up their own httptest.NewServer on loopback, following the
// existing pattern in common/httpx/response_memory_test.go:66-70.
//
// HOW CONSUMERS MUST READ HEADERS BACK (Invariant 4)
//
// Response.Headers is a plain map[string][]string (common/httpx/response.go:15),
// not an http.Header, so it performs no canonicalisation on lookup and
// Response.GetHeader (:42-48) is a raw, case-sensitive map read that joins
// multiple values with a single space. Header assertions must therefore go
// through GetHeader / GetHeaderPart using canonical MIME spellings - "Etag",
// never "ETag" or "etag"; "Www-Authenticate", never "WWW-Authenticate".
//
// Note also that Response.Headers is cloned from the upstream response before
// the response is dumped (common/httpx/httpx.go:275), whereas Response.Raw and
// Response.RawHeaders are produced by the dump afterwards. net/http's
// Response.Write derives the Content-Length line from the ContentLength FIELD,
// so a mock response that sets no Content-Length header still shows one in Raw
// while GetHeader("Content-Length") reads back empty. Both behaviours are real;
// assert whichever one the test is actually about.
//
// NO PARALLELISM
//
// No helper here is safe to use from a t.Parallel() test and none of this
// package's tests opts into parallelism. Beyond matching the local convention it
// is a hard requirement: forcing HTTP/1.1 makes New mutate process-global state
// via os.Setenv("GODEBUG", "http2client=0") (common/httpx/httpx.go:157).
//
// WHY EVERY DECLARATION CARRIES //nolint:unused
//
// This file is scaffolding: every symbol below is called from a sibling
// _test.go file and none is called from here. The repository's lint gate runs
// staticcheck's unused check, which resolves reachability from Test functions,
// so a helper-only file with no Test function of its own reads as dead code even
// though every helper is live in the built test binary. The directives record
// that, deliberately and per declaration rather than for the whole file, so the
// check still catches a helper that genuinely stops being used. They are the
// only concession made to the linter - nothing is excluded in configuration,
// and no lint rule is disabled repository-wide.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordedRequest is an immutable snapshot of one outbound request, taken by
// mockTransport.RoundTrip at the moment of the round trip.
//
// It is a value type, and that is the whole point. net/http mutates and reuses
// request objects while it follows a redirect chain, so a recorder that stored
// *http.Request pointers and inspected them after the call would report the
// FINAL state of the chain for every hop - silently reducing a per-hop assertion
// to a tautology. Fields are exported so consumers read them directly, matching
// capturedHello in common/httpx/tls_impersonate_test.go:22-28.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
type recordedRequest struct {
	// Method is the request method as sent on this hop. It is worth capturing
	// per hop because net/http rewrites POST to GET when it follows a 301, 302
	// or 303 (RFC 9110 15.4) while preserving it across a 307 or 308.
	Method string

	// URL is r.URL.String() captured before delegating: the absolute request
	// target for this hop.
	URL string

	// Host is r.Host, which is what net/http writes into the Host header. It can
	// legitimately differ from the authority in URL - SetCustomHeaders assigns it
	// directly for a custom Host header (common/httpx/httpx.go:500-504).
	Host string

	// Header is r.Header.Clone(): an independent copy, never an alias of the live
	// request's map. Always non-nil, so a consumer can call Get or Values on it
	// unconditionally.
	Header http.Header

	// Body holds the request body bytes observed on this hop, or nil when the
	// hop carried no body. The bytes are buffered and the body is re-provisioned
	// before the handler runs, so recording is transparent to the delegate.
	Body []byte
}

// mockTransport is a recording http.RoundTripper: it snapshots every request it
// is handed and then delegates the response decision to handler.
//
// RoundTrip is defined on the pointer receiver, so the zero value is usable only
// through a pointer - construct it with newMockTransport or as
// &mockTransport{handler: fn}. A value receiver would copy the embedded mutex on
// every call, which go vet reports as copylocks.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
type mockTransport struct {
	// mu guards recorded. http.Client is entitled to call RoundTrip from a
	// goroutine other than the test's, so the recorder is locked rather than
	// assumed single-threaded. The pattern mirrors the mutex-guarded capture in
	// common/httpx/tls_impersonate_test.go:57-71.
	mu sync.Mutex

	// recorded holds the snapshots in hop order: index 0 is the first request
	// the client made, the last index is the request that produced the response
	// the caller received.
	recorded []recordedRequest

	// calls counts RoundTrip invocations and is read and written only through
	// sync/atomic. It is intentionally separate from len(recorded): the counter
	// is incremented before any early return, so it stays truthful even for an
	// invocation that fails before it can record anything.
	calls int64

	// handler decides the response for a request. It may inspect the request
	// freely - branching on r.URL.Path, r.Header.Get("Accept-Encoding") or
	// r.Context() is exactly how the scripted, encoding-retry and slow variants
	// documented at the bottom of this file are built.
	handler func(*http.Request) (*http.Response, error)
}

// newMockTransport returns a recording transport that answers every request
// through handler.
//
// Unlike the assertion helpers in this package it deliberately takes no
// *testing.T: it performs no assertion and has no failure mode, so a t parameter
// would be dead weight. The precedent is the parameterless
// switchingProtocolsRoundTripper{} literal in common/httpx/httpx_test.go:163.
// A nil handler is not a panic - RoundTrip reports it as a descriptive error, so
// a consumer that forgets to script the transport gets a readable failure
// instead of a nil dereference inside net/http.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func newMockTransport(handler func(*http.Request) (*http.Response, error)) *mockTransport {
	return &mockTransport{handler: handler}
}

// RoundTrip records the request, then delegates to the handler.
//
// The ordering of the four steps below is load-bearing and must not be
// rearranged.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func (m *mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// (1) Count the invocation FIRST, ahead of anything that can return early.
	// This is what lets a test distinguish "the client never reached the
	// transport" from "the transport was reached and answered", which is the
	// only way to prove that a client-level deadline is a single wall-clock
	// budget for the whole call rather than a per-attempt one: the retry loop
	// keeps advancing its attempt counter while every attempt after the deadline
	// short-circuits before the transport is touched.
	atomic.AddInt64(&m.calls, 1)

	// (2) Buffer the request body and hand the handler an equivalent, unread
	// one. The http.RoundTripper contract explicitly permits consuming and
	// closing the request body, and re-provisioning it keeps that consumption
	// invisible: the delegate - and the retryable client, which replays a
	// buffered body rather than rewinding this reader - still sees the bytes.
	// http.NoBody is skipped so a bodyless request records nil rather than an
	// empty non-nil slice.
	var body []byte
	var bodyErr error
	if r.Body != nil && r.Body != http.NoBody {
		// io.ReadAll returns the bytes read so far alongside any error, so the
		// snapshot stays as informative as possible even on a failing reader.
		body, bodyErr = io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// (3) Snapshot before delegating. Header.Clone() is what makes the per-hop
	// view honest; it returns nil only for a nil header, which net/http never
	// produces, but normalising keeps the field unconditionally usable.
	header := r.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	snap := recordedRequest{
		Method: r.Method,
		URL:    r.URL.String(),
		Host:   r.Host,
		Header: header,
		Body:   body,
	}
	m.mu.Lock()
	m.recorded = append(m.recorded, snap)
	m.mu.Unlock()

	// A request body that cannot be read is a broken test fixture, not a
	// protocol outcome, so it is surfaced as a transport error - after the hop
	// has been recorded, so the failing hop is still visible in requests().
	if bodyErr != nil {
		return nil, fmt.Errorf("mockTransport: reading request body for %s %s: %w", r.Method, r.URL, bodyErr)
	}

	// (4) Delegate last, so the snapshot exists even if the handler fails.
	if m.handler == nil {
		return nil, fmt.Errorf("mockTransport: no handler configured for %s %s", r.Method, r.URL)
	}
	return m.handler(r)
}

// requests returns the recorded hops in order, as a deep copy.
//
// The copy is deliberate: handing back the live slice - or aliasing the recorded
// header maps - would let a later hop, or a consumer that mutates what it read,
// change values another assertion has already inspected. Copying keeps each
// snapshot exactly as it was on the wire.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func (m *mockTransport) requests() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]recordedRequest, len(m.recorded))
	for i, rec := range m.recorded {
		out[i] = recordedRequest{
			Method: rec.Method,
			URL:    rec.URL,
			Host:   rec.Host,
			Header: rec.Header.Clone(),
			Body:   bytes.Clone(rec.Body),
		}
		if out[i].Header == nil {
			out[i].Header = http.Header{}
		}
	}
	return out
}

// callCount returns how many times RoundTrip has been entered.
//
// Consumers assert this as an exact number - 1 for a call that never retried,
// 2 for the one-shot content-encoding retry, 3 for three sequential requests -
// because "how many times did this actually leave the client" is a
// protocol-visible fact that no response field records.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func (m *mockTransport) callCount() int64 {
	return atomic.LoadInt64(&m.calls)
}

// mockClientTimeout is the wall-clock budget newMockHTTPX gives the client.
//
// It is short on purpose: every request is answered in-process, so a test that
// takes anywhere near this long is misconfigured and should fail fast rather
// than stall the package. The value matches the nearest existing precedent,
// common/httpx/httpx_test.go:157. Tests about timeout behaviour shorten it
// further through the option mutator.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
const mockClientTimeout = 2 * time.Second

// newMockHTTPX builds an HTTPX whose only route to the network has been replaced
// by rt, optionally reconfigured by mut.
//
// Three properties of this constructor are load-bearing.
//
// 1. THE MUTATOR RUNS BEFORE New. New calls Options.parseCustomCookies()
// internally (common/httpx/httpx.go:78), which is what turns
// Options.CustomHeaders["Cookie"] into the []*http.Cookie slice that
// setCustomCookies (:522-531) later injects. A mutator applied after
// construction would leave Options.customCookies empty and setCustomCookies
// would silently no-op, so every cookie assertion downstream would pass
// vacuously. The same ordering matters for the redirect policy: New captures
// FollowRedirects and FollowHostRedirects into one of three mutually exclusive
// CheckRedirect closures (:92-143) at construction time, so flipping those
// options afterwards has no effect at all.
//
// 2. rt IS INSTALLED ON BOTH OF THE RETRYABLE CLIENT'S HTTP CLIENTS, exactly as
// common/httpx/httpx_test.go:164-165 does. Unless HTTP/1.1 is forced, New leaves
// HTTPClient and HTTPClient2 as distinct clients (:187-189, asserted by the
// existing TestDefaultProtocolKeepsRetryableHTTP2FallbackClient), and
// retryablehttp's Do retries through HTTPClient2 when the first attempt fails
// with a malformed-HTTP-version error. Installing on only one of them therefore
// leaves a live path that can escape to the network - it is not a style choice.
// The separate httpx.client2 built at :191-204 is deliberately left alone: Do
// never uses it.
//
// 3. DefaultOptions IS COPIED BY VALUE. New stores the pointer it is given
// (:76), so ht.Options aliases the local copy and post-construction tweaks such
// as ht.Options.MaxResponseBodySizeToRead = 10 are safe; taking &DefaultOptions
// instead would let one test corrupt the package-level default for every test
// that follows.
//
// Two option defaults are worth knowing about. CdnCheck is forced to "false" so
// the CDN branch at :209-215 never constructs a cdncheck client and no external
// data source is consulted. MaxResponseBodySizeToRead is left at its non-zero
// default because Do reads the body through io.LimitReader with that value
// (:318) - a mutator that sets it to 0 yields an empty body rather than an
// unlimited read. Options.Unsafe is never set: it would route the request
// through doUnsafeWithOptions (:423-431) into rawhttp, which performs a real
// network call and bypasses the transport entirely.
//
// RandomAgent stays at its DefaultOptions value of true. That is inert here
// because Do never calls SetCustomHeaders; a test that calls SetCustomHeaders
// itself and wants a deterministic User-Agent must set RandomAgent = false
// through the mutator (see common/httpx/httpx.go:513-516).
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func newMockHTTPX(t *testing.T, mut func(*Options), rt http.RoundTripper) *HTTPX {
	t.Helper()

	// A nil transport is not an inert default - net/http falls back to
	// http.DefaultTransport, which dials for real. Reject it outright so a
	// hermeticity breach can never be introduced by omission.
	require.NotNil(t, rt, "newMockHTTPX requires a round tripper; a nil transport would fall back to http.DefaultTransport and reach the network")

	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = mockClientTimeout
	options.RetryMax = 0

	if mut != nil {
		mut(&options)
	}

	ht, err := New(&options)
	require.NoError(t, err)

	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	return ht
}

// mockResponse builds a well-formed *http.Response for the request r.
//
// The request is the first parameter rather than an afterthought so the back
// reference cannot be forgotten. It is not decoration: pdhttputil.GetChain
// (projectdiscovery/utils@v0.11.1 http/chain.go:20), which Do calls to
// reconstruct the redirect chain (common/httpx/httpx.go:396-402), walks
// Response.Request and then Request.Response, and dumps each request it finds.
// A nil Request there does not degrade the chain - it panics. The protocol
// fields matter for the same reason: pdhttputil.DumpResponseHeadersAndRaw
// (:295) serialises the response through net/http, which needs a version to
// write onto the status line. net/http also resolves a relative Location header
// against Response.Request.URL, so redirect scripting depends on it too.
//
// The declared length always matches the delivered bytes. That is not tidiness:
// DumpResponseHeadersAndRaw re-serialises the whole response, and net/http
// refuses to write a body shorter than its declared ContentLength with
// "http: ContentLength=N with Body length M", which fails the call outright and
// produces no response at all. A mock must deliver what it declares.
//
// hdr may be nil for a response with no headers; it is cloned so a caller can
// reuse one header map across hops without the hops aliasing each other. No
// Content-Encoding and no Content-Length header are synthesised - a response
// carries exactly the headers the caller asked for.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func mockResponse(r *http.Request, status int, hdr http.Header, body string) *http.Response {
	header := hdr.Clone()
	if header == nil {
		header = http.Header{}
	}

	// Mirror net/http's own fallback for a status code it has no text for, so the
	// status line is always well formed.
	text := http.StatusText(status)
	if text == "" {
		text = fmt.Sprintf("status code %d", status)
	}

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, text),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}
}

// errorBodyReadCloser is a response body whose first read fails with a fixed
// error. It exists so a test can reproduce a response that is readable at the
// header level but not at the body level, which is the shape of the
// content-encoding edge case Do retries.
//
// It is a distinct type from blockingReadCloser in
// common/httpx/httpx_test.go:126-134 on purpose: that one blocks forever to
// prove Do does not hang, this one fails immediately to prove Do retries.
// Neither is a substitute for the other and neither is modified.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
type errorBodyReadCloser struct {
	err error
}

// Read always fails with the configured error and never yields a byte, which is
// what makes the failure deterministic: the caller sees it on the first read
// rather than after some prefix of the body has already been consumed.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func (e *errorBodyReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

// Close succeeds. A body that fails to read is still a body that closes
// cleanly, so Do's close-error handling stays on its normal path and the test
// observes the read failure rather than a close failure.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func (e *errorBodyReadCloser) Close() error {
	return nil
}

// mockResponseWithBodyError builds a response whose headers serialise cleanly
// but whose body read fails with readErr.
//
// The canonical use is the one-shot content-encoding retry: an origin that
// labels a response Content-Encoding: gzip but sends uncompressed bytes makes
// net/http install a gzip reader that fails on first read, and Do reacts by
// setting Accept-Encoding: identity on the caller's request and reissuing it
// once (common/httpx/httpx.go:304-308). Reproducing that through a mock
// transport means producing the read failure directly, because the automatic
// decompression that would otherwise create it lives in the real
// http.Transport this harness replaces. Pass an error whose text contains
// "gzip: invalid header" to reach that branch.
//
// ContentLength is set to -1, meaning "unknown". This is the one place where the
// declared length is not the delivered length, and it is required rather than
// sloppy: a body that never yields bytes cannot satisfy a positive declaration,
// and -1 is how net/http already spells an unknown length.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func mockResponseWithBodyError(r *http.Request, status int, hdr http.Header, readErr error) *http.Response {
	resp := mockResponse(r, status, hdr, "")
	resp.Body = &errorBodyReadCloser{err: readErr}
	resp.ContentLength = -1
	return resp
}

// hopSpec describes the response the scripted transport returns for one hop.
//
// A zero-value status is rejected at construction time rather than silently
// written onto the wire, because a status line of "0" is not something any
// origin can produce and would make every downstream assertion meaningless.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
type hopSpec struct {
	// status is the HTTP status code for this hop.
	status int

	// location, when non-empty, is written as the Location header. It may be
	// relative - net/http resolves it against the request URL - or absolute,
	// which is how a cross-origin redirect is expressed.
	location string

	// header holds any additional response headers, for example
	// Strict-Transport-Security for the HSTS upgrade path or Set-Cookie for
	// cookie scenarios. It may be nil.
	header http.Header

	// body is the response body for this hop, delivered verbatim.
	body string
}

// scriptedRedirects returns a handler that answers each request from a
// path-keyed script, and fails loudly for any request the script does not cover.
//
// Keys are matched most specific first: "host/path" (the authority exactly as
// URL.Host renders it, including a port when one is present) and then "/path".
// Host-qualified keys are what make a genuine origin change expressible -
// "origin.example/a" and "other.example/a" are different hops, which no pair of
// loopback servers could ever be, since both bind 127.0.0.1 and
// FollowHostRedirects compares URL.Hostname() (common/httpx/httpx.go:123-127).
// Plain path keys are the convenient form for a single-origin chain.
//
// An unscripted request is reported and answered with an error rather than a
// default response. Returning some benign 200 for anything unmatched would let a
// redirect test pass while following an entirely different chain than the one it
// claims to test.
//
//nolint:unused // harness API: consumed by the sibling behaviour tests, not by this file.
func scriptedRedirects(t *testing.T, script map[string]hopSpec) func(*http.Request) (*http.Response, error) {
	t.Helper()

	require.NotEmpty(t, script, "scriptedRedirects requires at least one scripted hop")

	// Copy the script so a later edit to the caller's map cannot change what the
	// handler serves mid-test, and precompute a sorted key list for diagnostics
	// so no message this file emits depends on map iteration order.
	hops := make(map[string]hopSpec, len(script))
	keys := make([]string, 0, len(script))
	for key, spec := range script {
		require.NotZero(t, spec.status, "scriptedRedirects: hop %q has no status code", key)
		hops[key] = spec
		keys = append(keys, key)
	}
	slices.Sort(keys)
	scripted := strings.Join(keys, ", ")

	return func(r *http.Request) (*http.Response, error) {
		spec, ok := hops[r.URL.Host+r.URL.Path]
		if !ok {
			spec, ok = hops[r.URL.Path]
		}
		if !ok {
			// t.Errorf, not require: net/http may run this handler on a
			// goroutine other than the test's, where require's FailNow would
			// call runtime.Goexit on the wrong goroutine and leave the test
			// hanging instead of failing. Errorf marks the failure safely, and
			// the returned error unwinds the client call.
			t.Errorf("scriptedRedirects: no hop scripted for %s %s (scripted keys: %s)", r.Method, r.URL, scripted)
			return nil, fmt.Errorf("scriptedRedirects: no hop scripted for %s %s", r.Method, r.URL)
		}

		header := spec.header.Clone()
		if header == nil {
			header = http.Header{}
		}
		if spec.location != "" {
			header.Set("Location", spec.location)
		}

		return mockResponse(r, spec.status, header, spec.body), nil
	}
}

// The four transport variants the behaviour tests need are all compositions of
// the primitives above; none of them justifies another type. Build them like
// this rather than hand-rolling a new round tripper, so every test inherits the
// recorder and the invariants with it.
//
// Single fixed response - for header, body and status assertions on one hop:
//
//	rt := newMockTransport(func(r *http.Request) (*http.Response, error) {
//		return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/html"}}, "hello"), nil
//	})
//	ht := newMockHTTPX(t, nil, rt)
//
// Scripted multi-hop - for redirect policy, chain accessors, cookie and auth
// propagation, and body replay. Enable the policy through the mutator, because
// New freezes the redirect closure at construction time:
//
//	rt := newMockTransport(scriptedRedirects(t, map[string]hopSpec{
//		"origin.example/a": {status: http.StatusFound, location: "http://other.example/b"},
//		"other.example/b":  {status: http.StatusOK, body: "final"},
//	}))
//	ht := newMockHTTPX(t, func(o *Options) { o.FollowRedirects = true }, rt)
//
// Slow - for the timeout taxonomy. Sleeping past the deadline and then returning
// the request context's error reproduces what a real transport does when the
// client's wall-clock budget expires. Pair it with callCount(): the counter is
// incremented at the top of RoundTrip, so it proves whether later retry attempts
// ever reached the transport at all:
//
//	rt := newMockTransport(func(r *http.Request) (*http.Response, error) {
//		select {
//		case <-r.Context().Done():
//			return nil, r.Context().Err()
//		case <-time.After(3 * time.Second):
//			return mockResponse(r, http.StatusOK, nil, "too late"), nil
//		}
//	})
//	ht := newMockHTTPX(t, func(o *Options) { o.Timeout = 300 * time.Millisecond }, rt)
//
// Content-encoding retry - branch on the request's Accept-Encoding so the first
// attempt fails at the body and the retry succeeds, then assert the per-hop
// Accept-Encoding values from requests() and callCount() == 2:
//
//	rt := newMockTransport(func(r *http.Request) (*http.Response, error) {
//		if r.Header.Get("Accept-Encoding") == "identity" {
//			return mockResponse(r, http.StatusOK, nil, "plain payload"), nil
//		}
//		return mockResponseWithBodyError(r, http.StatusOK,
//			http.Header{"Content-Encoding": {"gzip"}}, errors.New("gzip: invalid header")), nil
//	})
//
// A real socket, finally, is not this file's business: tests that assert a peer
// address, a Close flag or a negotiated protocol version stand up their own
// httptest.NewServer on loopback in the file that needs it, following
// common/httpx/response_memory_test.go:66-70.
