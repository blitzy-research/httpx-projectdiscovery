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

// This file is the shared hermetic harness for package httpx: helpers only, with no
// Test, Benchmark or Fuzz function of its own, declared in the package under test so
// every helper can reach the unexported client fields.
//
// Interception happens at exactly one boundary, the http.RoundTripper, and it is
// installed on both of the retryable client's HTTP clients (see newMockHTTPX).
// Everything below that boundary - DNS resolution, TCP dialling, the TLS handshake,
// the network itself - is bypassed rather than stubbed, so synthetic authorities such
// as origin.example and other.example exist only inside the mock and are never
// resolved. That is not merely convenient: two httptest servers both bind 127.0.0.1
// while the host-scoped redirect policy compares URL.Hostname(), so a loopback setup
// cannot express a cross-host redirect at all. Use a loopback server only for
// assertions that genuinely require a socket - a peer address, the server-observed
// Close flag, real chunked framing.
//
// Five invariants are baked into these helpers, and violating any one silently
// removes the assertion power of the tests that depend on it:
//
//  1. Snapshot before delegating, with a cloned header, so downstream mutation of
//     the live request cannot change an observation already recorded, and take the
//     body from the LIVE r.Body - consumed to EOF and closed, as the real transport
//     does - never from r.GetBody, whose manufactured copy would report what a replay
//     would carry instead of what this hop carried.
//  2. A mock response must deliver the bytes it declares: declaring a length it does
//     not deliver makes the response dump fail and Do return no response at all.
//  3. Set the protocol fields and the Response.Request back-reference, which chain
//     reconstruction dereferences - hence the request being mockResponse's first
//     argument.
//  4. Assert through the accessors. Response.Headers is a plain map[string][]string,
//     so GetHeader is a raw, case-sensitive read: use canonical MIME spellings such
//     as "Etag", never "ETag" or "etag".
//  5. Never render a URL, or any part of one, into a diagnostic without passing it
//     through redactedRequestLine. url.URL.String() serializes userinfo verbatim, and
//     url.URL.Redacted() masks only the password - a username, a capability token in
//     the query, a fragment and a credential-bearing path segment all survive it and
//     would reach a returned error and a retained CI log (CWE-532). The single
//     formatter below therefore drops userinfo entirely and replaces the path, the
//     query and the fragment with size-only markers - unconditionally, with no
//     shape-based exemption, because "this path looks harmless" is not a property any
//     whitelist can decide: a short alphanumeric segment is exactly what a capability
//     token looks like. Consumers follow the same rule by asserting individual
//     snapshot fields rather than formatting a whole recordedRequest, which testify
//     would render with %#v anyway.
//
// The reach of invariant 5 stops at this file's own output, and the boundary is worth
// stating exactly. MEASURED with a target of "http://alice:s3cr3tpw@origin.example/...":
// this harness renders "alice:xxxxx@" and net/http renders "alice:***@", but
// retryablehttp-go prefixes the error it returns from Do with the caller's request URL
// VERBATIM, so the final message reads "GET http://alice:s3cr3tpw@origin.example/...
// giving up after 1 attempts: ...". That prefix is built from the *retryablehttp.Request
// the consumer constructed, which no round tripper can influence.
//
// A userinfo target is therefore legitimate only while its requests SUCCEED - which is
// the case for the two tests that pin URL-credential disclosure deliberately,
// assertChainRetainsURLUserinfoInCallerVisibleOutput in redirect_chain_test.go and
// assertRedirectRefererCrossOriginConfidentiality in redirect_test.go, both of which run
// as sub-tests of their planned parents. The moment such a request fails, the wrapper's prefix puts the cleartext password in the test log
// (CWE-532), and the failure a reader sees says nothing about why. That combination is
// what requireNoUserinfoErrorLeaks reports, in a message that names only the redacted
// request line: a credential that has to travel through a FAILING request belongs in a
// header instead, which is what common/httpx/cookie_auth_test.go does.
//
// One local network syscall survives interception, and it is not a leak in this harness.
// New builds its CDN client through projectdiscovery/cdncheck, which probes IPv6
// availability once by opening a UDP socket towards a well-known resolver address; the
// probe transmits nothing, fails locally when the sandbox has no IPv6 route, and happens
// even with CdnCheck disabled, so it is a capability check rather than a request. Every
// HTTP request still goes through the round tripper installed by newMockHTTPX: a network
// syscall trace of a run of these tests shows zero TCP connects, zero transmitted
// packets and no DNS lookup for origin.example or other.example, and the same tests pass
// with networking removed entirely.
//
// No helper uses t.Parallel() and consumers must not add it: New sets the
// process-global GODEBUG environment variable on the HTTP/1.1 path, which is unsafe
// to race.

// recordedRequest is an immutable per-RoundTrip snapshot, taken before the request
// reaches the delegate handler.
//
// It is a value type rather than a *http.Request so that a later mutation of the live
// request - Do rewrites Accept-Encoding on the same request before its
// content-encoding retry - cannot change an observation already recorded
// (invariant 1). Fields are exported so consumers read them directly, matching
// capturedHello in common/httpx/tls_impersonate_test.go.
type recordedRequest struct {
	Method string
	URL    string
	// Host is an explicit Host override, which SetCustomHeaders assigns for a custom
	// Host header. net/http leaves it empty on a redirect-generated hop and derives
	// the header from URL.Host instead, so assert a later hop's authority through URL.
	Host string
	// Header is a clone, so a later mutation cannot rewrite an earlier observation.
	Header http.Header
	// Body holds the buffered request bytes, nil when the hop carried none - which is
	// also the case after a 301, 302 or 303 rewrites the method and drops the body.
	Body []byte
	// ContentLength is the length the hop DECLARES, which is not readable from Header:
	// net/http carries it in the request field and synthesizes the Content-Length header
	// only when it serializes the request to the wire, which a round tripper intercepts
	// before. Asserting request framing therefore has to read this field - looking for a
	// "Content-Length" header key on a recorded hop always finds nothing.
	//
	// A value of 0 means an empty body and -1 means an unknown length, which is what a
	// body streamed without a discoverable size would report.
	ContentLength int64
}

// String renders the snapshot through the shared URL redactor, so printing one cannot
// copy a credential into a test log (CWE-532, see redactedRequestLine).
//
// It reports header and body SIZES rather than values, because those are the fields
// most likely to carry a credential of their own. It protects the fmt paths only:
// testify renders unequal values with %#v, which bypasses any Stringer, so a
// consumer asserting a header or a payload compares that field directly.
func (rr recordedRequest) String() string {
	return fmt.Sprintf("%s %s (host %q, %d header keys, %d body bytes)",
		rr.Method, redactedURLString(rr.URL), rr.Host, len(rr.Header), len(rr.Body))
}

// clone returns an independent copy of the snapshot, so a consumer that mutates
// the returned header map or body slice cannot corrupt the recording.
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

// redactedRequestLine renders "METHOD URL" for a diagnostic with every part of the URL
// that can carry a credential removed. It is the single formatter every diagnostic in
// this file is built from, and none may format an *url.URL or a route key directly.
//
// url.URL.String() serializes userinfo verbatim, and url.URL.Redacted() is not enough
// either: it masks only the password, so a target such as
// "http://alice:s3cr3t@origin.example/reset/T0KEN?apikey=k1#frag" keeps its username,
// its capability token, its fragment and its credential-bearing path segment, all of
// which would reach a returned error and a retained CI log (CWE-532). The fixtures in
// this package deliberately carry exactly those components.
//
// Redaction is confined to human-readable output: route matching still keys on
// r.URL.Host and r.URL.Path, and recordedRequest.URL still holds the exact wire URL, so
// byte-for-byte assertions are unaffected.
func redactedRequestLine(r *http.Request) string {
	return r.Method + " " + redactedURL(r.URL)
}

// redactedURL renders u as "scheme://authority<redacted path>" with userinfo dropped
// outright and the path, query and fragment each replaced by a size-only marker.
//
// The authority is the only component echoed, and it is safe to echo: url.URL keeps
// credentials in User, so Host holds only host[:port] - which is also the part a reader
// needs in order to tell one synthetic origin from another. Every marker states the byte
// count of what it replaced, never the bytes themselves, matching the size-not-value rule
// recordedRequest.String() already follows.
//
// The contract this file relies on, stated as the output for every URL shape a fixture
// here can produce (this harness declares no Test function of its own, so the shapes are
// recorded where the formatter is defined):
//
//	http://alice:s3cr3t@origin.example/reset/T0KEN?apikey=k1#frag
//	  -> http://origin.example/<redacted 2 segments, 12 bytes>?<redacted 9 bytes>#<redacted 4 bytes>
//	http://origin.example/a          -> http://origin.example/<redacted 1 segments, 2 bytes>
//	http://origin.example/p%2Fq      -> http://origin.example/<redacted 1 segments, 6 bytes>
//	http://origin.example/<74 chars>/second
//	  -> http://origin.example/<redacted 2 segments, 82 bytes>
//	http://origin.example/x?         -> http://origin.example/<redacted 1 segments, 2 bytes>?<redacted 0 bytes>
//	http://origin.example            -> http://origin.example
//
// Read as a table it states the property that matters: userinfo never appears, and a
// short alphanumeric segment, a percent escape, a query token, an empty query and a
// fragment are all replaced rather than echoed - the length of the input changes only
// the byte count in the marker, never whether redaction happens.
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

// redactedURLString parses a recorded URL string and renders it through redactedURL.
//
// A snapshot stores its URL as a string, so a diagnostic built from one has to re-parse
// it. An unparseable value is reported by size alone: it cannot be decomposed, so no
// part of it can be shown to be credential-free.
func redactedURLString(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("<unparseable url, %d bytes>", len(rawURL))
	}
	return redactedURL(parsed)
}

// redactedPath replaces path CONTENT with a size-only marker, always, and reports only its
// segment count and byte length.
//
// It has no exemption for short or "unreserved-looking" paths, because no character or
// length test can establish that a path is credential-free: "/reset/T0KEN" is entirely
// alphanumeric and only 12 bytes long, yet the segment is the secret. An earlier shape-based
// whitelist echoed exactly that class of path verbatim into the unscripted-route diagnostic
// and the test log, which is the CWE-532 exposure this now closes unconditionally.
//
// The metadata that remains is what keeps a failure attributable: two different rejected
// routes with different shapes still produce different messages, so a table-driven failure
// can be traced to its row without disclosing content. It is deliberately not a hash - a
// digest of a low-entropy path is not meaningfully non-reversible - so it states metadata
// only. A caller that needs to identify a route in a message uses the response authority or
// a literal label of its own choosing, never this function's input.
func redactedPath(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("/<redacted %d segments, %d bytes>",
		len(strings.Split(strings.Trim(path, "/"), "/")), len(path))
}

// redactedRouteKey renders one of the keys scriptedRedirects looked up, which is either
// "host/path" or "/path", with the path part passed through redactedPath.
//
// The keys derive from r.URL.Host and r.URL.Path, so neither can carry userinfo, a query
// or a fragment - but the path alone is enough to leak a credential-bearing segment,
// which is why the key is sanitized rather than echoed verbatim. Note that r.URL.Path is
// the DECODED path while redactedURL passes the escaped form, so a percent escape has
// already been resolved by the time it reaches this function; that difference no longer
// matters to the outcome, because path content is replaced by a size-only marker in either
// representation.
func redactedRouteKey(key string) string {
	if slash := strings.Index(key, "/"); slash >= 0 {
		return key[:slash] + redactedPath(key[slash:])
	}
	return key
}

// mockTransport records request snapshots and delegates replies to handler. Installed
// by newMockHTTPX it replaces the real transport outright, so no name resolution, dial
// or handshake ever happens. Pointer receivers avoid copying the embedded mutex.
type mockTransport struct {
	mu       sync.Mutex
	recorded []recordedRequest

	// userinfoErrorTargets holds the redacted request line of every FAILED round trip
	// whose URL embedded userinfo, guarded by the same mutex as recorded. That pairing
	// is the one that defeats the redaction boundary described at the top of this file:
	// the harness redacts its own message, but retryablehttp-go's wrapper echoes the raw
	// URL of any request that ends in an error. Reporting is deferred to the cleanup
	// registered by newMockTransport rather than raised here, because RoundTrip may run
	// on a helper goroutine where a log call racing test completion would panic.
	userinfoErrorTargets []string

	// calls counts every entry into RoundTrip, including entries that return an
	// error without producing a response. It is incremented at the very top of
	// RoundTrip so a consumer can tell "the transport was reached and failed" apart
	// from "the transport was never reached at all", and it is atomic so a consumer
	// that drives the client from a helper goroutine can read it safely.
	calls atomic.Int64

	// handler answers each recorded request. It is invoked without the mutex
	// held, so a handler that blocks cannot stall requests() or callCount().
	handler func(*http.Request) (*http.Response, error)
}

// newMockTransport returns a recording round tripper that answers every request with
// handler, which is required: asserting it here turns a forgotten script into a named
// failure instead of an obscure error raised from inside net/http.
//
// It also registers the credential-leak check described in invariant 5 as a cleanup, so
// every consumer is covered without any of them opting in.
func newMockTransport(t *testing.T, handler func(*http.Request) (*http.Response, error)) *mockTransport {
	t.Helper()
	require.NotNil(t, handler, "newMockTransport: a handler is required")
	rt := &mockTransport{handler: handler}
	requireNoUserinfoErrorLeaks(t, rt)
	return rt
}

// requireNoUserinfoErrorLeaks fails the test, after it finishes, if a request whose URL
// carried userinfo ended in an error at the transport - the one combination that puts a
// cleartext password in the test log.
//
// It deliberately does NOT object to a userinfo target on its own: two tests in this
// package exist to pin what the client does with URL credentials, and their requests
// succeed, so nothing renders the raw URL. Restricting the check to the failing case is
// what lets those pins stand while still catching the leak.
//
// It runs as a cleanup rather than inside RoundTrip on purpose. RoundTrip may execute on
// a helper goroutine - the timeout tests drive the client from one - and a t.Error there
// can race the end of the test, which panics with "Log in goroutine after test has
// completed". A cleanup runs on the test's own goroutine, strictly after the test body
// and strictly before the test is reported, so the failure is attributed correctly and
// cannot race.
//
// The message names only the redacted request line, so reporting the leak cannot itself
// print the password it exists to protect.
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

// RoundTrip counts the call, consumes the live request body, snapshots it with the cloned
// header, records the isolated snapshot under the mutex, then invokes the handler.
//
// That ordering is load bearing. Counting first, ahead of every early return, is what
// lets a test tell "the transport was never reached" from "the transport answered" -
// the only way to prove the client deadline is one wall-clock budget for the whole
// call rather than a per-attempt one. Consuming and closing the body the client really
// sent - never a copy manufactured from GetBody - is what makes the recorded bytes wire
// evidence rather than a restatement of the caller's intent, and it is what the
// http.RoundTripper contract requires of the transport this replaces (see
// snapshotRequestBody). Recording before delegating keeps the per-hop view honest.
// Releasing the mutex before the handler runs stops a sleeping handler from blocking
// requests() for the length of its sleep.
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

// noteUserinfoErrorLeak records that a request carrying URL userinfo ended in an error,
// which is the combination requireNoUserinfoErrorLeaks reports. Only the redacted request
// line is retained, and a request without userinfo is ignored, so the common path costs
// one nil comparison.
func (m *mockTransport) noteUserinfoErrorLeak(r *http.Request) {
	if r.URL == nil || r.URL.User == nil {
		return
	}
	line := redactedRequestLine(r)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.userinfoErrorTargets = append(m.userinfoErrorTargets, line)
}

// requests returns the per-hop snapshots recorded so far, oldest first.
//
// Both the slice and every snapshot in it are copies: handing out the live slice
// would race a request still in flight, and handing out the stored header map would
// let a consumer mutate the evidence it is asserting against.
func (m *mockTransport) requests() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]recordedRequest, len(m.recorded))
	for i, rec := range m.recorded {
		out[i] = rec.clone()
	}
	return out
}

// callCount returns how many times RoundTrip was entered, which is the number of
// requests that actually reached the transport - not the number of attempts the
// retry layer counted.
func (m *mockTransport) callCount() int {
	return int(m.calls.Load())
}

// userinfoErrorLeaks returns the redacted request lines of the failed round trips whose
// target embedded userinfo, oldest first. The slice is copied so the caller cannot mutate
// the recording, matching requests().
func (m *mockTransport) userinfoErrorLeaks() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.userinfoErrorTargets) == 0 {
		return nil
	}
	return append([]string(nil), m.userinfoErrorTargets...)
}

// snapshotRequestBody drains the LIVE request body to EOF and closes it, returning the
// bytes this hop actually handed to the transport.
//
// Reading the live body is the whole point, and r.GetBody is deliberately NOT used as the
// wire observation. GetBody manufactures a fresh reader over the buffered payload, so it
// reports what a replay WOULD carry rather than what this hop carried: a redirected hop
// whose live body had already been exhausted, or replaced with different bytes, would still
// read back as correct through GetBody, which is exactly the defect the per-hop body
// assertions exist to catch. Consumers assert that GetBody EXISTS separately, because that
// is a distinct contract - it is the mechanism net/http replays a 307 with
// (common/httpx/request_body_test.go:596-597, :654-655).
//
// Consuming and closing is also what the http.RoundTripper contract requires of any real
// transport ("RoundTrip must always close the body, including on errors"), so this makes the
// harness behave like the http.Transport it replaces.
//
// Nothing is reinstalled in r.Body afterwards, and that is deliberate too. retryablehttp
// wraps every request payload in a rewindable reader whose Read resets it at io.EOF and
// whose Close is a no-op (projectdiscovery/utils reader.ReusableReadCloser), which is the
// property its retry loop documents and relies on; net/http builds a redirected hop from
// ireq.GetBody(), which returns an independent rewindable reader. Substituting a one-shot
// reader here would therefore be strictly less faithful than leaving the client's own body
// in place. A read or close failure is returned rather than swallowed, because a body the
// harness could not fully consume is a body it cannot truthfully record.
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

// mockResponse returns an HTTP/1.1 response for r whose body length matches the
// delivered bytes, which is what makes invariants 2 and 3 impossible to forget.
//
// Request is mandatory - and therefore the first parameter - because chain
// reconstruction follows Response.Request and dereferences it, so omitting the
// back-reference breaks the redirect chain rather than yielding an empty one. The
// protocol fields are populated because the response dump writes the status line
// from them.
//
// hdr may be nil, in which case a fresh empty header is allocated; otherwise it is
// cloned so one scripted hop cannot mutate another. Callers must not add a
// Content-Length that disagrees with body, and must not add a Content-Encoding
// unless they intend the decoder to act on it.
func mockResponse(r *http.Request, status int, hdr http.Header, body string) *http.Response {
	header := http.Header{}
	if hdr != nil {
		header = hdr.Clone()
	}

	// A non-standard status code has no canonical reason phrase. Leaving Status
	// empty in that case lets net/http apply its own fallback when it writes the
	// status line, rather than emitting one that ends in a bare space.
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

// mockHop describes the response one scripted route replies with.
//
// status is mandatory; location, when non-empty, is written as the Location
// header, which is what net/http follows and what pdhttputil.GetChain records as
// the chain item's Location. header carries any additional response headers -
// Strict-Transport-Security for the HSTS scenario, Set-Cookie for the header
// accessor scenario - and body is the exact payload the hop returns.
type mockHop struct {
	status   int
	location string
	header   http.Header
	body     string
}

// scriptedRedirects returns a handler that answers each request from a
// path-keyed script, which is how multi-hop chains are expressed.
//
// Keys are matched most specific first: "host/path" (r.URL.Host + r.URL.Path) is
// tried before "/path", so a scenario spanning two origins can script
// "origin.example/final" and "other.example/final" separately while a
// single-origin scenario keeps using bare paths. An empty URL path is normalized to
// "/" so a target written without one still matches its route. Those synthetic
// authorities live only inside this map and are never resolved.
//
// An unscripted route fails loudly instead of being answered by a default: a
// silent fallback would let a test that never exercised the route it thinks it
// exercised still pass. Use Error rather than FailNow because a consumer may invoke
// the client from a helper goroutine, where require's runtime.Goexit would leave the
// test hanging instead of failing; the returned error still terminates the request.
// Both channels carry one message built by unscriptedRouteError, so neither can leak
// a URL userinfo password.
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
			// One message, two channels: t.Error fails the test even if it never
			// inspects the error, and the returned error surfaces the same text
			// through the call the test is already checking. Building it once in
			// unscriptedRouteError is what guarantees both are redacted.
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

// unscriptedRouteError names the method, the redacted URL and both keys that were
// looked up, so the missing map entry is obvious from the message alone.
//
// It is a separate function because that message goes to two places - the test log and
// the returned error - and a single formatter is the only way to guarantee both stay
// redacted (CWE-532). Both tried keys go through redactedRouteKey: they carry no
// userinfo, query or fragment, but a path segment on its own is enough to disclose a
// credential, so neither is echoed verbatim.
func unscriptedRouteError(r *http.Request, triedQualified, triedPath string) error {
	return fmt.Errorf("scriptedRedirects: no route scripted for %s (tried %q then %q)",
		redactedRequestLine(r), redactedRouteKey(triedQualified), redactedRouteKey(triedPath))
}

// errReadCloser is a response body whose every Read fails with a fixed error.
//
// It exists for the content-encoding retry scenario, where a response must be
// labelled Content-Encoding: gzip while its body cannot be decoded: pairing this
// reader with gzip.ErrHeader ("gzip: invalid header") reproduces the origin behaviour
// that drives Do's one-time retry with Accept-Encoding: identity. The automatic
// decompression that would otherwise produce that failure lives in the real
// http.Transport this harness replaces, so the failure has to be injected directly.
// The error is supplied by the consumer, so this harness needs no compression import
// of its own. Compose it onto a response as
//
//	resp := mockResponse(r, http.StatusOK, http.Header{"Content-Encoding": {"gzip"}}, "")
//	resp.Body = &errReadCloser{err: gzip.ErrHeader}
//	resp.ContentLength = -1 // a body that yields no byte cannot satisfy a declared length
//
// It is a distinct type from blockingReadCloser (common/httpx/httpx_test.go:127),
// which blocks forever rather than failing, and that existing helper is left
// untouched.
type errReadCloser struct {
	err error
}

// Read always fails with the configured error, never consuming any input.
func (e *errReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

// Close is a no-op: there is nothing to release.
func (e *errReadCloser) Close() error {
	return nil
}

// closeTrackingBody is a response body that records how many times it was closed and
// how many bytes were read from it.
//
// It exists because the body handed back by the transport is the only handle on the
// underlying connection, and Do replaces the Response.Body field several times over:
// the read cap wraps it in a limited reader, the response dump swaps in an in-memory
// reader, and a content-encoding retry abandons the whole response. None of those
// replacements is observable from the outside, so a leaked closer can only be detected
// by asking the body the transport actually returned whether it was ever closed.
//
// Reads and closes are counted atomically so a consumer may drive the client from a
// helper goroutine, and Close is delegated to the wrapped reader when that reader is
// itself a closer, keeping the wrapper faithful. Wrap it around a failing reader to
// track the abandoned attempt of the content-encoding retry:
//
//	body := newCloseTrackingBody(&errReadCloser{err: gzip.ErrHeader})
type closeTrackingBody struct {
	reader io.Reader
	closes atomic.Int64
	reads  atomic.Int64
}

// newCloseTrackingBody wraps reader, which is required: a nil reader would report zero
// bytes read on every path and silently void the assertions that depend on it.
func newCloseTrackingBody(reader io.Reader) *closeTrackingBody {
	if reader == nil {
		panic("newCloseTrackingBody: a reader is required")
	}
	return &closeTrackingBody{reader: reader}
}

// Read delegates to the wrapped reader and accumulates the byte count, so a consumer can
// assert how much of the body the client consumed as well as whether it released it.
func (b *closeTrackingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.reads.Add(int64(n))
	return n, err
}

// Close counts the call and forwards it to the wrapped reader when that reader is a
// closer. It never reports an error: this body models a connection being released, and a
// synthetic close failure would test the caller's error handling rather than its
// resource handling.
func (b *closeTrackingBody) Close() error {
	b.closes.Add(1)
	if closer, ok := b.reader.(io.Closer); ok {
		_ = closer.Close()
	}
	return nil
}

// closeCount reports how many times Close was called: 0 means the body was leaked, and
// more than 1 means it was released more than once.
func (b *closeTrackingBody) closeCount() int {
	return int(b.closes.Load())
}

// bytesRead reports how many bytes the client consumed from this body, which is what the
// response read cap is meant to bound.
func (b *closeTrackingBody) bytesRead() int {
	return int(b.reads.Load())
}

// mockClientTimeout is a fail-fast safety budget: a scripted transport answers
// in-process, so a test that reaches this deadline is misconfigured. The timeout tests
// shorten it through the option mutator.
const mockClientTimeout = 2 * time.Second

// newMockHTTPX copies DefaultOptions, applies mut before construction so
// constructor-derived state such as parsed cookies is initialized correctly, builds a
// client with New, then installs rt on both retryable transports. It rejects the unsafe
// and CDN options that could bypass the mock or consult external data.
//
// Every call constructs its OWN client, so isolation is per test by construction: no
// option a test sets, and no field it mutates afterwards, can be observed by any other
// test. That matters most for the redirect-policy tests, where the CheckRedirect
// closure New installs captures the *Options pointer it was built with
// (common/httpx/httpx.go:76, :92-143) - a client shared between two tests would let one
// row's MaxRedirects describe another row's assertions.
//
// Running mut before construction is mandatory, not stylistic. New parses
// CustomHeaders["Cookie"] into Options.customCookies and freezes the option values
// into the CheckRedirect closure it builds, so a Cookie entry or a redirect flag set
// after construction is never seen: setCustomCookies would silently do nothing and
// every downstream cookie assertion would pass vacuously. DefaultOptions.CustomHeaders
// is nil, so a mutator that wants custom headers assigns a fresh map.
//
// The options are a value copy, so nothing here can corrupt the package-level default
// that every other test reads. rt goes on BOTH of the retryable client's HTTP clients
// because retryablehttp falls back to its second client when an attempt reports a
// malformed HTTP version; installing on only one, or passing a nil transport that
// http.Client resolves to http.DefaultTransport, would leave a live path to the real
// network.
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
	// Release the disk-backed dialer history this construction allocated; see
	// registerDialerCleanup for why leaving it behind slows every later New down.
	registerDialerCleanup(t, ht)

	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt
	return ht
}

// registerDialerCleanup releases the disk-backed dialer history that every New
// allocates, at the end of the test that constructed the client.
//
// New unconditionally sets fastdialerOpts.WithDialerHistory = true
// (common/httpx/httpx.go:64), and fastdialer answers that by opening a LevelDB store
// under a fresh os.MkdirTemp("", "httpx") directory. Nothing reclaims it implicitly:
// only (*fastdialer.Dialer).Close closes the store, and only that close triggers the
// os.RemoveAll that deletes the directory. A test that constructs a client and returns
// therefore leaves one directory behind for the lifetime of the process.
//
// Leaving them behind is not merely untidy, it is quadratic. Every subsequent
// construction re-opens a store, and opening one first walks the whole temporary
// directory and stats every entry whose name contains the executable name, to expire
// stale stores. Each leaked directory therefore makes every later New slower, so a
// package that constructs a handful of clients degrades from milliseconds to seconds
// per construction. Registering the close is what keeps the added suite inside its
// runtime budget as well as inside its resource budget.
//
// (*fastdialer.Dialer).Close returns nothing, so it satisfies t.Cleanup's func()
// directly. Production does exactly the same thing at runner/runner.go:919. Cleanup
// functions run last-in-first-out after the test finishes, which is strictly after the
// final Do, so no in-flight request can observe a closed store.
func registerDialerCleanup(t *testing.T, ht *HTTPX) {
	t.Helper()
	require.NotNil(t, ht, "registerDialerCleanup: a constructed client is required")
	require.NotNil(t, ht.Dialer, "registerDialerCleanup: New must have allocated a dialer to close")
	t.Cleanup(ht.Dialer.Close)
}

// Compile-time proof of the three interface contracts this harness has to satisfy:
// *mockTransport is installed wherever the client expects an http.RoundTripper, and
// *errReadCloser and *closeTrackingBody are substituted for a response body. Asserting
// them at the definition means a signature drift fails the build here rather than at
// every install site.
var (
	_ http.RoundTripper = (*mockTransport)(nil)
	_ io.ReadCloser     = (*errReadCloser)(nil)
	_ io.ReadCloser     = (*closeTrackingBody)(nil)
)
