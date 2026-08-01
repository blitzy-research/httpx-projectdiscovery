package httpx

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file is the shared hermetic harness for package httpx: helpers only, declared in the
// package under test so every helper can reach the unexported client fields.
//
// Interception happens at one boundary, the http.RoundTripper, which newMockHTTPX installs on
// both of the retryable client's HTTP clients; everything below it is bypassed rather than
// stubbed, so synthetic authorities such as origin.example are never resolved. A loopback server
// cannot stand in for the mock in a different-host scenario, because two httptest servers share
// the hostname 127.0.0.1 while the host-scoped redirect policy compares URL.Hostname(); use one
// only where an assertion needs a real socket (peer address, server-observed Close flag, chunked
// framing).
//
// EGRESS ACCOUNTING, measured rather than asserted by prose. A test binary for this package
// issues exactly ONE connect() to a non-loopback address per PROCESS, and no test in this
// package originates it. Measured with strace -f -e trace=connect on the compiled binary:
//
//	socket(AF_INET6, SOCK_DGRAM, ...) = 6
//	connect(6, {AF_INET6, port 53, "2001:4860:4860::8888"}) = -1 EADDRNOTAVAIL
//
// Attribution, four ways, all showing the same single call:
//
//	(a) the binary running only mock-transport tests                      -> 1 connect
//	(b) the SAME binary with -test.run '^NoSuchTestAtAll$' (zero tests)   -> 1 connect
//	(c) the BASELINE binary, before any test in this project existed      -> 1 connect
//	(d) a program whose entire body is `import _ "cdncheck"` + a Println  -> 1 connect
//
// It is therefore cdncheck's package init(), which calls net.DialTimeout("udp", ...) against a
// public resolver to decide whether to append its IPv6 resolver list. It runs at process start,
// before any TestMain, any test and any call to New - so it is unreachable from a test, and
// disabling it through CdnCheck="false" (which newMockHTTPX does set) cannot prevent it. It
// transmits nothing: the socket is SOCK_DGRAM, connect() on an unconnected UDP socket only binds
// a peer address, the call FAILS, and the trace records zero sendto/sendmsg on that descriptor.
//
// Functional hermeticity is proved directly rather than inferred: run inside a fresh network
// namespace with loopback up and no route off the host, the whole package reports 123 top-level
// tests passing and exactly ONE failure, TestDo, which is the pre-existing live-network test that
// constraint C2 protects. Every mock-transport and every loopback test passes with no egress
// available at all, and the cdncheck probe simply fails ENETUNREACH instead of EADDRNOTAVAIL.
//
// Removing the probe would mean dropping or replacing the cdncheck dependency, which AAP 0.8.2.3
// forbids outright, or editing a non-test source file beyond the two documented five-line fixes,
// which AAP 0.8.2.1 and 0.10.1.1 forbid; AAP 0.8.2.6 covers exactly this case by requiring an
// upstream behaviour to be asserted rather than fixed. It is recorded here instead, because the
// accounting above is what lets a reader confirm the "no real network access" contract by
// measurement rather than by trusting this comment.
//
// Five invariants keep the tests that depend on this harness meaningful:
//
//  1. Snapshot before delegating, with a cloned header, and read the body from the LIVE r.Body -
//     not r.GetBody, whose copy reports what a replay would carry.
//  2. A mock response must deliver the bytes it declares; an unsatisfied declared length makes
//     the response dump fail and Do return no response at all.
//  3. Set the protocol fields and the Response.Request back-reference, which chain
//     reconstruction dereferences.
//  4. Assert through the accessors: Response.Headers is a plain map[string][]string, so
//     GetHeader is a raw, case-sensitive read ("Etag", never "ETag").
//  5. Render no URL into a diagnostic except through redactedRequestLine (CWE-532). That covers
//     this harness's output only: retryablehttp-go prefixes the error it returns from Do with
//     the request URL verbatim, so a userinfo target discloses its credential as soon as the
//     request FAILS, which requireNoUserinfoErrorLeaks reports.
//
// No helper uses t.Parallel() and consumers must not add it: New sets the process-global GODEBUG
// environment variable on the HTTP/1.1 path.

// recordedRequest is an immutable per-RoundTrip snapshot, taken before the request reaches
// the delegate handler. It is a value type rather than a *http.Request so that a later
// mutation of the live request - Do rewrites Accept-Encoding on the same request before its
// content-encoding retry - cannot change an observation already recorded (invariant 1).
type recordedRequest struct {
	Method string
	URL    string
	// Host is an explicit Host override, which SetCustomHeaders assigns for a custom Host
	// header. net/http leaves it empty on a redirect-generated hop and derives the header
	// from URL.Host, so assert a later hop's authority through URL.
	Host string
	// Header is a clone, so a later mutation cannot rewrite an earlier observation.
	Header http.Header
	// Body holds the buffered request bytes, nil when the hop carried none - as it is
	// after a 301, 302 or 303 rewrites the method and drops the body.
	Body []byte
	// ContentLength is the length the hop DECLARES, and is not readable from Header:
	// net/http synthesizes that header only when it serializes the request, after a round
	// tripper observes it. 0 means an empty body, -1 an unknown length.
	ContentLength int64
}

// String redacts userinfo, path, query, fragment, header values and body bytes, but retains
// the URL authority and the explicit Host override for attribution, so tests must keep
// secrets out of those two fields (CWE-532). It protects the fmt paths only: testify renders
// unequal values with %#v, which bypasses any Stringer.
func (rr recordedRequest) String() string {
	return fmt.Sprintf("%s %s (host %q, %d header keys, %d body bytes)",
		rr.Method, redactedURLString(rr.URL), rr.Host, len(rr.Header), len(rr.Body))
}

// clone returns an independent copy, so a consumer cannot corrupt the recording.
func (rr recordedRequest) clone() recordedRequest {
	out := rr
	if rr.Header != nil {
		out.Header = rr.Header.Clone()
	}
	if rr.Body != nil {
		out.Body = append([]byte(nil), rr.Body...)
	}
	return out
}

// redactedRequestLine renders "METHOD URL" through redactedURL and is the single formatter every
// diagnostic here is built from: a target such as
// "http://alice:s3cr3t@origin.example/reset/T0KEN?apikey=k1#frag" - a shape these fixtures use -
// would otherwise carry its username, capability token, fragment and credential-bearing path
// segment into a returned error and a retained CI log (CWE-532). Redaction is confined to
// human-readable output, so route matching and recordedRequest.URL keep the exact wire values.
func redactedRequestLine(r *http.Request) string {
	return r.Method + " " + redactedURL(r.URL)
}

// redactedURL renders u as "scheme://authority<redacted path>" with userinfo dropped outright
// and the path, query and fragment each replaced by a size-only marker. The authority is
// RETAINED - url.URL keeps credentials in User, so Host holds only host[:port], and it is what
// lets a reader tell one synthetic host from another - so anything a test places there is
// printable. Redaction of the other components is unconditional, because no character or
// length test can establish that a path, query or fragment is credential-free.
func redactedURL(u *url.URL) string {
	if u == nil {
		return "<nil url>"
	}
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString("://")
	}
	b.WriteString(u.Host)
	b.WriteString(redactedPath(u.EscapedPath()))
	if u.ForceQuery || u.RawQuery != "" {
		fmt.Fprintf(&b, "?<redacted %d bytes>", len(u.RawQuery))
	}
	if u.Fragment != "" || u.RawFragment != "" {
		fmt.Fprintf(&b, "#<redacted %d bytes>", len(u.Fragment))
	}
	return b.String()
}

// redactedURLString parses a recorded URL string and renders it through redactedURL. An
// unparseable value is reported by size alone, since no part of it can be shown to be safe.
func redactedURLString(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("<unparseable url, %d bytes>", len(rawURL))
	}
	return redactedURL(parsed)
}

// redactedPath replaces path CONTENT with a size-only marker, always, reporting only its segment
// count and byte length. There is no exemption for short or "unreserved-looking" paths:
// "/reset/T0KEN" is entirely alphanumeric and only 12 bytes long, yet the segment is the secret.
// The remaining metadata keeps a failure attributable, and is deliberately not a hash, because a
// digest of a low-entropy path is not meaningfully non-reversible.
func redactedPath(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("/<redacted %d segments, %d bytes>",
		len(strings.Split(strings.Trim(path, "/"), "/")), len(path))
}

// redactedRouteKey renders one of the keys scriptedRedirects looked up, either "host/path" or
// "/path", with the path part passed through redactedPath. The keys carry no userinfo, query or
// fragment, but a path segment alone is enough to disclose a credential.
func redactedRouteKey(key string) string {
	if slash := strings.Index(key, "/"); slash >= 0 {
		return key[:slash] + redactedPath(key[slash:])
	}
	return key
}

// mockTransport records request snapshots and delegates replies to handler. Installed by
// newMockHTTPX it replaces the real transport outright, so no resolution, dial or handshake
// happens. Pointer receivers avoid copying the embedded mutex.
type mockTransport struct {
	mu       sync.Mutex
	recorded []recordedRequest

	// userinfoErrorTargets holds the redacted request line of every FAILED round trip whose
	// URL embedded userinfo, guarded by the same mutex as recorded.
	userinfoErrorTargets []string

	// calls counts every entry into RoundTrip, including entries that return an error
	// without producing a response, so a consumer can tell "reached and failed" from "never
	// reached". It is atomic because the client may be driven from a helper goroutine.
	calls atomic.Int64

	// handler answers each recorded request, invoked without the mutex held so a handler
	// that blocks cannot stall requests() or callCount().
	handler func(*http.Request) (*http.Response, error)
}

// newMockTransport returns a recording round tripper that answers every request with handler,
// which is required so a forgotten script becomes a named failure rather than an obscure error
// from inside net/http. It also registers the invariant-5 credential-leak check as a cleanup,
// so every consumer is covered without opting in.
func newMockTransport(t *testing.T, handler func(*http.Request) (*http.Response, error)) *mockTransport {
	t.Helper()
	require.NotNil(t, handler, "newMockTransport: a handler is required")
	rt := &mockTransport{handler: handler}
	requireNoUserinfoErrorLeaks(t, rt)
	return rt
}

// requireNoUserinfoErrorLeaks fails the test, after it finishes, if a request whose URL carried
// userinfo ended in an error at the transport - the combination that puts a cleartext password
// in the test log. Restricting the check to the failing case is what lets the URL-credential
// pins stand. It runs as a cleanup because RoundTrip may execute on a helper goroutine, where
// t.Error can race the end of the test and panic.
func requireNoUserinfoErrorLeaks(t *testing.T, rt *mockTransport) {
	t.Helper()
	require.NotNil(t, rt, "requireNoUserinfoErrorLeaks: a transport is required")
	t.Cleanup(func() {
		if offenders := rt.userinfoErrorLeaks(); len(offenders) > 0 {
			t.Errorf("mockTransport: %d failed request(s) carried userinfo in the target URL: %v - "+
				"retryablehttp-go prefixes the error it returns from Do with the RAW request URL, so this test's log now holds "+
				"the cleartext password however carefully this harness redacts its own messages (CWE-532); carry the credential "+
				"in a header, or keep the userinfo target on a request that succeeds",
				len(offenders), offenders)
		}
	})
}

// RoundTrip counts the call, consumes the live request body, snapshots it with the cloned header,
// records the snapshot under the mutex, then invokes the handler. That ordering is load bearing:
// counting ahead of every early return lets a test tell "never reached" from "answered", which is
// how the client deadline is shown to be one wall-clock budget for the whole call; recording
// before delegating keeps the per-hop view honest; releasing the mutex before the handler runs
// stops a sleeping handler from blocking requests().
func (m *mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.calls.Add(1)

	body, bodyErr := snapshotRequestBody(r)

	snap := recordedRequest{
		Method:        r.Method,
		URL:           r.URL.String(),
		Host:          r.Host,
		Header:        r.Header.Clone(),
		Body:          body,
		ContentLength: r.ContentLength,
	}
	m.mu.Lock()
	m.recorded = append(m.recorded, snap)
	m.mu.Unlock()

	if bodyErr != nil {
		// An unreadable body breaks the "record exactly what was sent" contract, so
		// the round trip fails loudly rather than reporting a body it never read.
		m.noteUserinfoErrorLeak(r)
		return nil, fmt.Errorf("mockTransport: %s: %w", redactedRequestLine(r), bodyErr)
	}

	if m.handler == nil {
		m.noteUserinfoErrorLeak(r)
		return nil, fmt.Errorf("mockTransport: no handler configured for %s", redactedRequestLine(r))
	}

	resp, err := m.handler(r)
	if err != nil {
		m.noteUserinfoErrorLeak(r)
	}
	return resp, err
}

// noteUserinfoErrorLeak records that a request carrying URL userinfo ended in an error, the
// combination requireNoUserinfoErrorLeaks reports. Only the redacted request line is retained.
func (m *mockTransport) noteUserinfoErrorLeak(r *http.Request) {
	if r.URL == nil || r.URL.User == nil {
		return
	}
	line := redactedRequestLine(r)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.userinfoErrorTargets = append(m.userinfoErrorTargets, line)
}

// requests returns the per-hop snapshots recorded so far, oldest first. Both the slice and
// every snapshot in it are copies, so a consumer can neither race a request still in flight
// nor mutate the evidence it asserts against.
func (m *mockTransport) requests() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]recordedRequest, len(m.recorded))
	for i, rec := range m.recorded {
		out[i] = rec.clone()
	}
	return out
}

// callCount returns how many times RoundTrip was entered, which is the number of requests
// that reached the transport - not the number of attempts the retry layer counted.
func (m *mockTransport) callCount() int {
	return int(m.calls.Load())
}

// userinfoErrorLeaks returns a copy of the redacted request lines of the failed round trips
// whose target embedded userinfo, oldest first.
func (m *mockTransport) userinfoErrorLeaks() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.userinfoErrorTargets) == 0 {
		return nil
	}
	return append([]string(nil), m.userinfoErrorTargets...)
}

// snapshotRequestBody drains the LIVE request body to EOF and closes it, returning the bytes this
// hop handed to the transport. r.GetBody is deliberately not the observation: it manufactures a
// fresh reader over the buffered payload, so a hop whose live body had been exhausted or replaced
// would still read back as correct. Consuming and closing is what the http.RoundTripper contract
// requires, and nothing is reinstalled in r.Body because retryablehttp's payload reader rewinds
// at io.EOF and net/http builds a redirected hop from ireq.GetBody(). A read or close failure is
// returned rather than swallowed: a body the harness could not fully consume is one it cannot
// truthfully record.
func snapshotRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}

	buf, readErr := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if readErr != nil {
		return buf, fmt.Errorf("draining the live request body: %w", readErr)
	}
	if closeErr != nil {
		return buf, fmt.Errorf("closing the live request body: %w", closeErr)
	}
	return buf, nil
}

// mockResponse returns an HTTP/1.1 response for r whose declared length matches the delivered
// bytes, which makes invariants 2 and 3 impossible to forget. Request is mandatory - and
// therefore the first parameter - because chain reconstruction dereferences Response.Request,
// and the protocol fields are populated because the response dump writes the status line from
// them. hdr may be nil, otherwise it is cloned so one scripted hop cannot mutate another;
// callers must not add a Content-Length that disagrees with body, nor a Content-Encoding unless
// they intend the decoder to act on it.
func mockResponse(r *http.Request, status int, hdr http.Header, body string) *http.Response {
	header := http.Header{}
	if hdr != nil {
		header = hdr.Clone()
	}

	// A non-standard status code has no canonical reason phrase; leaving Status empty lets
	// net/http apply its own fallback rather than emitting a line ending in a bare space.
	statusLine := ""
	if text := http.StatusText(status); text != "" {
		statusLine = fmt.Sprintf("%d %s", status, text)
	}

	return &http.Response{
		Status:        statusLine,
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

// mockHop describes the response one scripted route replies with. status is mandatory; location,
// when non-empty, becomes the Location header net/http follows and the chain item records.
type mockHop struct {
	status   int
	location string
	header   http.Header
	body     string
}

// scriptedRedirects returns a handler that answers each request from a path-keyed script, which is
// how multi-hop chains are expressed. Keys are matched most specific first: "host/path"
// (r.URL.Host + r.URL.Path) before "/path", so a scenario spanning two hosts can script each host
// separately while a single-host scenario keeps using bare paths; an empty path becomes "/".
//
// An unscripted route fails loudly rather than being answered by a default, which would let a test
// that never exercised the route it thinks it exercised still pass. It uses Error rather than
// FailNow because a consumer may invoke the client from a helper goroutine, where require's
// runtime.Goexit would leave the test hanging; the returned error still terminates the request.
func scriptedRedirects(t *testing.T, script map[string]mockHop) func(*http.Request) (*http.Response, error) {
	t.Helper()
	require.NotEmpty(t, script, "scriptedRedirects: the script needs at least one route")
	for route, hop := range script {
		require.NotZerof(t, hop.status, "scriptedRedirects: route %q must declare a status", route)
	}

	return func(r *http.Request) (*http.Response, error) {
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		qualified := r.URL.Host + path
		hop, ok := script[qualified]
		if !ok {
			hop, ok = script[path]
		}
		if !ok {
			// One message, two channels: t.Error fails the test even if it never inspects
			// the error, and the returned error surfaces the same text through the call the
			// test is already checking.
			err := unscriptedRouteError(r, qualified, path)
			t.Error(err)
			return nil, err
		}

		header := http.Header{}
		if hop.header != nil {
			header = hop.header.Clone()
		}
		if hop.location != "" {
			header.Set("Location", hop.location)
		}
		return mockResponse(r, hop.status, header, hop.body), nil
	}
}

// unscriptedRouteError names the method, the redacted URL and both keys that were looked up.
// It is a separate function because that message goes to two places - the test log and the
// returned error - and one formatter is the only way to keep both redacted (CWE-532).
func unscriptedRouteError(r *http.Request, triedQualified, triedPath string) error {
	return fmt.Errorf("scriptedRedirects: no route scripted for %s (tried %q then %q)",
		redactedRequestLine(r), redactedRouteKey(triedQualified), redactedRouteKey(triedPath))
}

// errReadCloser is a response body whose every Read fails with a fixed error. It serves the
// content-encoding retry scenario: pairing it with gzip.ErrHeader under a Content-Encoding: gzip
// label reproduces the origin behaviour that drives Do's one-time retry with Accept-Encoding:
// identity, which has to be injected because the decompression that normally raises it lives in
// the real http.Transport this harness replaces. Compose it as
//
//	resp := mockResponse(r, http.StatusOK, http.Header{"Content-Encoding": {"gzip"}}, "")
//	resp.Body = &errReadCloser{err: gzip.ErrHeader}
//	resp.ContentLength = -1 // a body that yields no byte cannot satisfy a declared length
type errReadCloser struct {
	err error
}

func (e *errReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

func (e *errReadCloser) Close() error {
	return nil
}

// closeTrackingBody is a response body that records how many times it was closed and how many
// bytes were read from it. The body the transport returns is the only handle on the underlying
// connection, and Do replaces the Response.Body field several times over - the read cap wraps it
// in a limited reader, the response dump swaps in an in-memory reader, a content-encoding retry
// abandons the response - none of which is observable from outside, so asking the original body
// whether it was closed is the only way to detect a leak. Counts are atomic because a consumer
// may drive the client from a helper goroutine.
type closeTrackingBody struct {
	reader io.Reader
	closes atomic.Int64
	reads  atomic.Int64
}

// newCloseTrackingBody wraps reader, which is required: a nil reader would report zero bytes
// read on every path and silently void the assertions that depend on it.
func newCloseTrackingBody(reader io.Reader) *closeTrackingBody {
	if reader == nil {
		panic("newCloseTrackingBody: a reader is required")
	}
	return &closeTrackingBody{reader: reader}
}

func (b *closeTrackingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.reads.Add(int64(n))
	return n, err
}

// Close counts the call and forwards it to the wrapped reader when that reader is a closer. It
// never reports an error, because a synthetic close failure would test error handling rather than
// the resource handling this body exists to observe.
func (b *closeTrackingBody) Close() error {
	b.closes.Add(1)
	if closer, ok := b.reader.(io.Closer); ok {
		_ = closer.Close()
	}
	return nil
}

// closeCount reports how many times Close was called: 0 means leaked, more than 1 means released
// more than once.
func (b *closeTrackingBody) closeCount() int {
	return int(b.closes.Load())
}

// bytesRead reports how many bytes the client consumed, which is what the read cap bounds.
func (b *closeTrackingBody) bytesRead() int {
	return int(b.reads.Load())
}

// mockClientTimeout is a fail-fast safety budget: a scripted transport answers in-process, so a
// test that reaches this deadline is misconfigured. The timeout tests shorten it through the
// option mutator.
const mockClientTimeout = 2 * time.Second

// newMockHTTPX copies DefaultOptions, applies mut before construction, builds a client with New,
// then installs rt on both retryable transports, rejecting the unsafe and CDN options that could
// bypass the mock or consult external data. Every call constructs its OWN client, which matters
// most for the redirect-policy tests: the CheckRedirect closure New installs captures the *Options
// pointer it was built with, so a shared client would let one row's MaxRedirects describe another
// row's assertions.
//
// Running mut before construction is mandatory, not stylistic. New parses CustomHeaders["Cookie"]
// into Options.customCookies and freezes option values into the CheckRedirect closure it builds,
// so a Cookie entry or a redirect flag set afterwards is never seen: setCustomCookies would
// silently do nothing and every downstream cookie assertion would pass vacuously.
// DefaultOptions.CustomHeaders is nil, so a mutator that wants custom headers assigns a fresh map.
//
// The options are a value copy, so nothing here can corrupt the package-level default. rt goes on
// BOTH of the retryable client's HTTP clients, because retryablehttp falls back to its second
// client when an attempt reports a malformed HTTP version and a nil transport would resolve to
// http.DefaultTransport - either way leaving a live path to the network.
func newMockHTTPX(t *testing.T, mut func(*Options), rt http.RoundTripper) *HTTPX {
	t.Helper()
	require.NotNil(t, rt, "newMockHTTPX: a round tripper is required, a nil Transport would fall back to the network")

	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = mockClientTimeout
	options.RetryMax = 0
	if mut != nil {
		mut(&options)
	}
	require.False(t, options.Unsafe, "newMockHTTPX: Options.Unsafe bypasses the transport and reaches the network")
	require.Equal(t, "false", options.CdnCheck, "newMockHTTPX: CDN checking must stay disabled so no external data source is consulted")
	require.False(t, options.ExcludeCdn, "newMockHTTPX: ExcludeCdn forces a cdncheck client even when CdnCheck is disabled")

	ht, err := New(&options)
	require.NoError(t, err)
	registerDialerCleanup(t, ht)

	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt
	return ht
}

// registerDialerCleanup releases the disk-backed dialer history that every New allocates, at the
// end of the test that constructed the client. New enables the fastdialer dialer history, which
// opens a LevelDB store under a temporary directory that only (*fastdialer.Dialer).Close removes,
// and every later construction walks that directory to expire stale stores - so the cost of
// leaking grows with the number of clients the package builds. Production closes the dialer the
// same way. Cleanups run strictly after the final Do, so no in-flight request sees a closed store.
func registerDialerCleanup(t *testing.T, ht *HTTPX) {
	t.Helper()
	require.NotNil(t, ht, "registerDialerCleanup: a constructed client is required")
	require.NotNil(t, ht.Dialer, "registerDialerCleanup: New must have allocated a dialer to close")
	t.Cleanup(ht.Dialer.Close)
}

// Compile-time interface checks for the harness types.
var (
	_ http.RoundTripper = (*mockTransport)(nil)
	_ io.ReadCloser     = (*errReadCloser)(nil)
	_ io.ReadCloser     = (*closeTrackingBody)(nil)
)
