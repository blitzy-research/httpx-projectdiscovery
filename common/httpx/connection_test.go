package httpx

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/networkpolicy"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Connection policy and the per-request connection lifecycle.
//
// New configures its HTTP/1.1 transport with DisableKeepAlives: true and
// MaxIdleConnsPerHost: -1 (the transport literal at common/httpx/httpx.go:145-154, those
// two fields at :153 and :148). That is a deliberate, scanner-specific choice rather than
// an accident of defaults - net/http's own default is to reuse connections. Every probe
// therefore gets its own connection, so a target cannot correlate probes across one
// socket, per-connection server state cannot leak from one probe into the next, and
// per-connection rate limiting sees one request per connection instead of N. Until this
// file existed no test in the repository named DisableKeepAlives, MaxIdleConnsPerHost or
// RemoteAddr at all, so re-enabling connection reuse - a one-line edit - would have changed
// the observable behaviour of the whole tool without failing anything.
//
// This is the only file in the added suite that binds a real socket, and only because
// three of its assertions are meaningless without one: the peer address each request
// arrives on, the Connection directive and close verdict the origin observes, and the
// protocol version the message was framed in. Those are properties of a TCP connection
// rather than of a round tripper, and a scripted http.RoundTripper cannot express them at
// all - it never opens a connection, so there is no peer address to report. The origin is
// an httptest.Server bound to 127.0.0.1, so the file stays hermetic: no name resolution,
// no egress, nothing outside the loopback interface.
//
// WHY THREE ASSERTION FAMILIES RATHER THAN ONE. Each plausible one-line regression is
// caught by a different family, so no family is redundant. MEASURED by injecting each
// mutation into the transport literal, running these three tests, and reverting:
//
//	mutation of the transport literal    effect on the wire        failing tests
//	DisableKeepAlives: true -> false     Connection: close gone    all three
//	MaxIdleConnsPerHost: -1 -> 2         none                      the field read only
//	both together                        3 connections become 1    all three
//
// The middle row is the reason the field reads exist: changing MaxIdleConnsPerHost alone is
// invisible on the wire, so only the direct field read in
// TestTransportDisablesConnectionReuse catches it. The first row is its mirror: flipping
// DisableKeepAlives alone does NOT collapse the peer addresses, because
// MaxIdleConnsPerHost: -1 independently stops net/http from caching an idle connection, so
// it is the Connection/close assertions that catch it. Only when both change do three
// connections become one, which is what the peer-address assertion catches. Dropping any
// one family opens a hole.
//
// No test here opts into parallel execution. No test in the package does - New sets the
// process-global GODEBUG variable on its HTTP/1.1 path (httpx.go:158), which is unsafe to
// race - and these tests additionally count connections against a shared loopback
// listener, which running them in parallel would make meaningless. For the same reason
// every request is issued SEQUENTIALLY: concurrent requests need separate connections even
// when keep-alives are enabled, so a concurrent version of these tests would pass under
// the very regression they exist to catch.

const (
	// connectionReuseBody and connectionStateBody differ from each other so a body
	// observed in one test can never satisfy an assertion belonging to the other.
	connectionReuseBody = "connection-reuse-body"
	connectionStateBody = "connection-state-body"

	// connectionObserverContentType pins the reply's media type so the body is never
	// MIME-sniffed and DecodeData never transcodes it. The assertions below compare exact
	// bytes, and a transcode would silently replace them.
	connectionObserverContentType = "text/plain"
)

// connectionObservation is the origin's view of one inbound request, as a value type.
//
// It deliberately carries no mutex, so it can be returned and compared by value without
// tripping govet's copylocks check - connectionRecorder owns the lock. That matches
// capturedRequest in common/httpx/request_body_test.go and capturedHello in
// common/httpx/tls_impersonate_test.go. Every field is something an observer on the
// connection could see; nothing here is read back out of the client's own state, which is
// what makes these assertions independent evidence.
type connectionObservation struct {
	// RemoteAddr is the peer address of the connection the request arrived on. Only its
	// DISTINCTNESS across requests is ever asserted, never its shape: the host:port
	// spelling and the ephemeral port range are platform details.
	RemoteAddr string
	// Close is net/http's parsed verdict on the request's Connection directive: true when
	// the client announced that the connection is to be closed once this exchange ends.
	Close bool
	// Connection is the first value of the request's Connection header, which is the field
	// a keep-alive change flips first.
	Connection string
	// ConnectionValues is every value of that header. Header.Get returns only the first,
	// so a duplicated or appended directive would hide behind Connection alone.
	ConnectionValues []string
	// Proto is the protocol version the request was framed in, e.g. "HTTP/1.1".
	Proto string
}

// connectionRecorder collects the origin's view of every request a loopback server
// received.
//
// The mutex is required because the handler runs on a goroutine owned by the httptest
// server while the assertions run on the test goroutine. Pointer receivers are used
// throughout so the lock is never copied, following requestBodyRecorder in
// common/httpx/request_body_test.go.
type connectionRecorder struct {
	mu       sync.Mutex
	observed []connectionObservation
}

// record stores the origin's view of one request.
//
// It performs no assertion of its own on purpose: require's FailNow calls
// runtime.Goexit, which on a server goroutine would abandon the response instead of
// failing the test, so every check is left to the test goroutine.
func (rec *connectionRecorder) record(r *http.Request) {
	obs := connectionObservation{
		RemoteAddr: r.RemoteAddr,
		Close:      r.Close,
		Connection: r.Header.Get("Connection"),
		// Copied rather than aliased: the header map belongs to net/http and must not be
		// read after the handler returns.
		ConnectionValues: append([]string(nil), r.Header.Values("Connection")...),
		Proto:            r.Proto,
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.observed = append(rec.observed, obs)
}

// observations returns a copy of the requests the origin saw, in arrival order.
//
// It reads under the same lock the handler writes with, so an assertion can never race a
// request that is still being recorded, and it copies the slice so a caller cannot mutate
// the recording. It takes no *testing.T because it raises nothing itself, matching
// mockTransport.requests() in common/httpx/mocktransport_test.go.
func (rec *connectionRecorder) observations() []connectionObservation {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]connectionObservation(nil), rec.observed...)
}

// newConnectionObserverServer starts a loopback origin that records the connection-level
// view of every request it receives and answers each one with body.
//
// The server is returned WITHOUT a registered cleanup, matching newRequestBodyEchoServer
// in common/httpx/request_body_test.go and newWellKnownTestServer in
// runner/wellknown_recipes_test.go, so every caller pairs it with a visible
// `defer ts.Close()` at the site that owns its lifetime.
func newConnectionObserverServer(t *testing.T, rec *connectionRecorder, body string) *httptest.Server {
	t.Helper()
	require.NotNil(t, rec, "newConnectionObserverServer: a recorder is required, there is nothing to observe without one")
	require.NotEmpty(t, body, "newConnectionObserverServer: a non-empty body is required, an empty one would make every byte assertion vacuous")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", connectionObserverContentType)
		_, _ = w.Write([]byte(body))
	}))
}

// TestTransportDisablesConnectionReuse pins the transport fields that decide whether the
// client may reuse a connection at all.
//
// This is a white-box read of the constructed transport with no I/O whatsoever, which is
// what makes it the sharpest test in the file: it compares the exact fields a one-line
// edit to the transport literal would change, so a failure names the field rather than a
// downstream symptom. It is possible only because the file is declared `package httpx` -
// ht.client is unexported.
//
// The client comes from newLocalHTTPX, which calls New and installs NOTHING on the
// transport. That is load bearing: newMockHTTPX REPLACES both transports with a scripted
// round tripper, so building the client through it would either fail the type assertion
// below or - far worse - silently assert against the mock and pin nothing about the
// production configuration.
//
// MEASURED against the code as it stands, and confirmed field by field against the
// transport literal at common/httpx/httpx.go:145-154:
//
//	DisableKeepAlives   true   (:153)
//	MaxIdleConnsPerHost -1     (:148)
//	MaxIdleConns        0      - never set by the literal, so the zero value
//	ForceAttemptHTTP2   false  - never set by the literal, so the zero value
//	TLSClientConfig     InsecureSkipVerify true (:150), MinVersion TLS 1.0 (:151)
//	TLSNextProto        nil    - only the HTTP/1.1-forced branch at :159 assigns it
func TestTransportDisablesConnectionReuse(t *testing.T) {
	ht := newLocalHTTPX(t)
	// newLocalHTTPX does not release the disk-backed fastdialer history New allocates, so
	// register it here; leaving one behind makes every later New slower (see
	// registerDialerCleanup in common/httpx/mocktransport_test.go).
	registerDialerCleanup(t, ht)

	tr, ok := ht.client.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok,
		"the HTTP/1.1 client must still carry the *http.Transport New built (found %T): every field asserted below lives on that concrete type, and a replacement would make this test describe something other than production configuration",
		ht.client.HTTPClient.Transport)

	// The two fields that decide connection reuse.
	require.True(t, tr.DisableKeepAlives,
		"keep-alives must stay disabled (httpx.go:153): with reuse enabled several probes share one connection, so a target can correlate them, per-connection server state leaks from one probe into the next, and per-connection rate limiting sees one connection instead of one per request")
	require.Equal(t, -1, tr.MaxIdleConnsPerHost,
		"MaxIdleConnsPerHost must stay -1 (httpx.go:148): a negative limit stops net/http caching an idle connection at all, which is the second and independent guard against reuse - MEASURED, it is what keeps peer addresses distinct even when DisableKeepAlives is flipped, so this field read is the only assertion in the suite that catches a change to it")

	// Two fields the literal deliberately leaves at their zero value.
	require.Equal(t, 0, tr.MaxIdleConns,
		"MaxIdleConns must keep its zero value: the literal caps idleness per host only, so a global allowance appearing here would mean the transport literal had been rewritten")
	require.False(t, tr.ForceAttemptHTTP2,
		"ForceAttemptHTTP2 must keep its zero value - it never appears in the transport literal: because that literal sets a custom DialTLSContext and TLSClientConfig, net/http will not negotiate HTTP/2 over TLS unless this field is true, so its zero value is what keeps this client on HTTP/1.1 while the separate HTTP/2 client handles h2")

	// The TLS posture the same literal establishes.
	require.NotNil(t, tr.TLSClientConfig, "the transport literal sets a TLS config (httpx.go:149-152)")
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify,
		"certificate verification must stay disabled (httpx.go:150): probing hosts that serve expired, self-signed or mismatched certificates is the point of the tool, and verifying would turn those targets into errors instead of results")
	require.Equal(t, uint16(tls.VersionTLS10), tr.TLSClientConfig.MinVersion,
		"the negotiated floor must stay TLS 1.0 (httpx.go:151) so legacy endpoints remain reachable; raising it would silently drop those targets rather than report them")

	// Proof that this client was built on the default protocol path.
	require.Nil(t, tr.TLSNextProto,
		"TLSNextProto must be nil on the default protocol path: only the HTTP/1.1-forced branch assigns it (httpx.go:159), and that branch also mutates the process-global GODEBUG variable (httpx.go:158) - a non-nil value here would mean this test observed a client built on that branch instead of the default one")
}

// TestConnectionNotReusedAcrossRequests pins the observable consequence of that
// configuration: three sequential requests to one origin arrive on three different
// connections, each announcing that it will be closed.
//
// This is the protocol-visible core of the file and it is why a real socket is required -
// a peer address exists only because a connection does. One client issues all three
// requests SEQUENTIALLY on purpose: reuse is only observable when a later request could
// have taken an earlier connection, and concurrent requests would need separate
// connections even with keep-alives enabled, which would make this test pass under the
// very regression it exists to catch.
//
// MEASURED against the code as it stands: three requests reach the origin on three
// distinct peer ports, and on every one of them Close is true, "close" is the single value
// of the Connection header, and the framing is HTTP/1.1; each reply is 200 carrying the
// 21-byte body. Connection: close is what RFC 9110 section 7.6.1 defines for announcing
// that the sender will close the connection once the current message is complete, and it
// is what net/http emits for a transport with keep-alives disabled - so the measurement
// and the specification agree here rather than the expectation having been transcribed
// from whatever the implementation happened to produce.
//
// The header assertions are not decoration. MEASURED by injecting DisableKeepAlives: false
// into the transport literal: the three peer addresses stay distinct, because
// MaxIdleConnsPerHost: -1 independently prevents an idle connection from being cached, and
// the only visible change is that Connection: close disappears. Without the header
// assertions this test would be blind to a keep-alive regression.
func TestConnectionNotReusedAcrossRequests(t *testing.T) {
	rec := &connectionRecorder{}
	ts := newConnectionObserverServer(t, rec, connectionReuseBody)
	defer ts.Close()

	ht := newLocalHTTPX(t)
	// See registerDialerCleanup in common/httpx/mocktransport_test.go: newLocalHTTPX leaves
	// the disk-backed dialer history New allocated behind, which slows every later New.
	registerDialerCleanup(t, ht)

	const wantRequests = 3
	responses := make([]*Response, 0, wantRequests)
	for i := 0; i < wantRequests; i++ {
		responses = append(responses, doLocal(t, ht, ts.URL))
	}
	require.Len(t, responses, wantRequests,
		"precondition: every request must have produced a response before the origin's view is inspected")

	observed := rec.observations()
	require.Len(t, observed, wantRequests,
		"the origin must have seen exactly three requests: a silent retry or an unexpected redirect would make the connection count below describe traffic this test never issued")

	// The protocol-visible core: one connection per request.
	peers := make(map[string]struct{}, len(observed))
	for _, obs := range observed {
		peers[obs.RemoteAddr] = struct{}{}
	}
	require.Len(t, peers, wantRequests,
		"each request must arrive on a fresh connection, so all three peer addresses must differ; a repeated address means net/http served a request from the idle-connection pool and the tool's one-connection-per-probe behaviour is gone")

	// The wire evidence for that, as the origin parsed it. Asserted per request rather
	// than once, because a regression that only affected the second and later hops - the
	// hops that could have been pooled - would otherwise slip through.
	for i, obs := range observed {
		require.Truef(t, obs.Close,
			"request %d: the origin must parse the request as closing the connection after this exchange; Close false means the client offered to keep it alive", i+1)
		require.Equalf(t, "close", obs.Connection,
			"request %d: the request must carry exactly the Connection: close directive (RFC 9110 section 7.6.1), not merely some Connection header", i+1)
		require.Equalf(t, []string{"close"}, obs.ConnectionValues,
			"request %d: close must be the only value of the Connection header - Header.Get returns the first value only, so a duplicated or appended directive would hide behind the assertion above", i+1)
		require.Equalf(t, "HTTP/1.1", obs.Proto,
			"request %d: the exchange must be framed as HTTP/1.1, since the connection semantics asserted here are HTTP/1.1 semantics", i+1)
	}

	// The caller-visible side of the same three exchanges: closing each connection must not
	// cost any part of any response.
	for i, resp := range responses {
		require.Equalf(t, http.StatusOK, resp.StatusCode,
			"response %d: the origin answered 200, so the caller must see 200", i+1)
		require.Equalf(t, []byte(connectionReuseBody), resp.Data,
			"response %d: every response must carry the whole body byte for byte, even though its connection was closed immediately afterwards", i+1)
		require.Equalf(t, len(connectionReuseBody), resp.ContentLength,
			"response %d: the reported length must equal the %d bytes actually delivered", i+1, len(connectionReuseBody))
	}
}

// TestConnectionStateAfterClose pins what a caller still holds once Do has returned and
// the connection it used is gone.
//
// This is the direct realization of the "state of a connection after close" assertion the
// requirements name. Do wraps the body in a limiting reader and registers a deferred
// io.Copy(io.Discard, ...) plus Close (common/httpx/httpx.go:302-310), and closes the body
// explicitly at :348, so by the time Do returns the connection has already been drained
// and released and the caller closes nothing - *Response exposes no Close method at all.
// What the caller is left with therefore has to be self-contained, and this test proves it
// is by fetching a SECOND response and only then asserting on the first.
//
// MEASURED against the code as it stands, with a 21-byte body: the first response still
// holds those exact bytes after the second exchange has completed, reports
// ContentLength 21 and status 200; its Raw is exactly its RawHeaders plus the body; its
// RawHeaders records Connection: close while GetHeader("Connection") is empty - net/http
// consumes the hop-by-hop directive when it sets Response.Close, and the dump re-emits it
// from that flag, so Response.Headers holds only Content-Type, Date and Content-Length;
// and the two responses' byte slices have independent backing arrays.
func TestConnectionStateAfterClose(t *testing.T) {
	rec := &connectionRecorder{}
	ts := newConnectionObserverServer(t, rec, connectionStateBody)
	defer ts.Close()

	ht := newLocalHTTPX(t)
	// See registerDialerCleanup in common/httpx/mocktransport_test.go.
	registerDialerCleanup(t, ht)

	respA := doLocal(t, ht, ts.URL)
	respB := doLocal(t, ht, ts.URL)

	require.Len(t, rec.observations(), 2,
		"both calls must have reached the origin, otherwise the two responses compared below are not two independent round trips")

	// Everything about respA is asserted AFTER respB was fetched, and that ordering is the
	// whole point: the first response must still own its fully drained body once its
	// connection has been closed and a second exchange has come and gone.
	require.Equal(t, []byte(connectionStateBody), respA.Data,
		"the first response must still hold its complete body after its connection was closed and a second request was served: Do drains and closes the body before returning (httpx.go:302-310, :348), so the bytes the caller keeps cannot depend on the connection still being open")
	require.Equal(t, len(connectionStateBody), respA.ContentLength,
		"the first response must report the exact number of bytes delivered")
	require.Equal(t, http.StatusOK, respA.StatusCode, "the first exchange completed with 200")

	// The wire representation the caller retains records the close; the parsed header map
	// does not, because net/http consumed the hop-by-hop directive when it set
	// Response.Close and DumpResponse re-emits it from that flag.
	require.Contains(t, respA.RawHeaders, "Connection: close",
		"the retained wire representation must record that the connection was closed for this exchange")
	require.Equal(t, "", respA.GetHeader("Connection"),
		"the parsed header map must NOT expose the hop-by-hop Connection directive: net/http removes it while deriving Response.Close, so a value appearing here would mean a hop-by-hop header had started leaking into caller-visible metadata")
	require.Equal(t, len(respA.RawHeaders)+len(connectionStateBody), len(respA.Raw),
		"Raw must be exactly the response headers followed by the whole drained body: a short Raw would mean the body was still being read when the connection closed")

	// Nothing is left for the caller to release.
	_, isCloser := any(respA).(interface{ Close() error })
	require.False(t, isCloser,
		"*Response must expose no Close method: the body is drained and closed inside Do before it returns, so a Close appearing on the caller-visible type would mean the connection lifecycle had been handed back to callers who do not close it today")

	// The second exchange, on its own fresh connection, is unaffected by the first.
	require.Equal(t, []byte(connectionStateBody), respB.Data,
		"the second request must succeed on a new connection and deliver the same body")
	require.Equal(t, len(connectionStateBody), respB.ContentLength,
		"the second response must report the exact number of bytes delivered")
	require.Equal(t, http.StatusOK, respB.StatusCode, "the second exchange completed with 200")

	// Guard the pointer comparison below: on an empty body Data[0] would not exist, and a
	// zero-length regression must not be allowed to make the comparison vacuous.
	require.NotEmpty(t, respA.Data, "the first response must hold bytes for the buffer comparison to mean anything")
	require.NotEmpty(t, respB.Data, "the second response must hold bytes for the buffer comparison to mean anything")
	require.NotSame(t, &respA.Data[0], &respB.Data[0],
		"each response must own its own buffer: sharing a backing array across two exchanges would mean a later response could rewrite the bytes an earlier one already handed to its caller")
}

// THE SECOND CONNECTION FAMILY: the two SECONDARY clients New builds.
//
// Everything above describes the primary HTTP/1.1 client, the one every Do goes through.
// New also builds two more clients, and neither of them carries the request policy the
// primary was configured with:
//
//	client                        built at                     reached in production from
//	------------------------------------------------------------------------------------------
//	client.HTTPClient2            retryablehttp NewClient      retryablehttp do.go, when an
//	                              (a library DefaultClient,    HTTP/1.1 round trip fails with
//	                              never touched by httpx.go)   a malformed-HTTP-version error
//	client2 (*http.Client with    common/httpx/httpx.go:192-205 SupportHTTP2, common/httpx/
//	an *http2.Transport)                                       http2.go:55 (the -http2 probe)
//
// The primary's policy is assembled in New: redirectFunc (httpx.go:92-143, which is also
// what re-applies the configured cookies on every admitted hop), the fastdialer built from
// fastdialerOpts.NetworkPolicy (:61-74, the -deny/-exclude guard), and the proxy resolved
// from -http-proxy/-socks-proxy (:166-181). All three are installed on the primary's
// http.Client and http.Transport ONLY. The two secondary clients are constructed
// separately - one by the dependency, one by the transport2 literal - and receive none of
// them.
//
// SECURITY CONSEQUENCE, and it is the reason these are asserted rather than merely noted.
// On either secondary path:
//
//   - -deny / -exclude private-ips is not enforced. The policy lives inside the fastdialer
//     wired onto the primary transport; a client that dials with anything else reaches a
//     denied address. That is a server-side request forgery guard being bypassed, and the
//     public SupportHTTP2 is enough to trigger it.
//   - -http-proxy / -socks-proxy is not honoured, so traffic a user routed through a proxy
//     for isolation or attribution leaves the host directly instead.
//   - The redirect policy is absent, so -no-follow-redirects, -maxr and -fhr do not apply:
//     net/http's own default follows up to 10 hops, to any host, and setCustomCookies never
//     runs on those hops.
//
// MEASURED against the code as it stands, with three loopback origins and no egress:
//
//	observation                                     primary            secondary
//	------------------------------------------------------------------------------------
//	302 with the default (no-follow) policy         302, 1 origin hit  200, 2 origin hits
//	unusable proxy configured                       error naming it    200 from the origin
//	-deny 127.0.0.1 with the origin on 127.0.0.1    "denied address"   200 from the origin
//	SupportHTTP2 against that denied origin         -                  true
//
// PINNED AS MEASURED AND NOT FIXED. Closing the asymmetry means constructing the secondary
// clients differently - assigning CheckRedirect, routing their dials through httpx.Dialer,
// applying the resolved proxy - which is a production behaviour change to client
// construction, outside the two minimal, separately disclosed fixes this work is permitted
// to make to httpx.go and outside a testing engagement's remit. It also cannot be done
// wholly from this repository: client.HTTPClient2 is built inside retryablehttp-go, and
// http2.Transport exposes no proxy field and no plaintext dial hook at all, so the native
// HTTP/2 client has nowhere to accept either. What CAN be done here, and is, is to pin the
// asymmetry field by field and outcome by outcome, so that a change in either direction -
// a secondary client silently gaining policy, or the primary silently losing it - fails
// this test instead of shipping unnoticed.
//
// Hermetic throughout: every origin binds 127.0.0.1, the proxy that is configured is a
// closed loopback port, and no name outside the loopback interface is ever resolved.

const (
	// secondaryPolicyBody is what the TLS origin in this section serves. It differs from
	// connectionReuseBody and connectionStateBody so a body observed here can never satisfy
	// an assertion belonging to the two tests above.
	secondaryPolicyBody = "secondary-policy-body"

	// secondaryRedirectBody and secondaryFinalBody mark the two hops of the redirecting
	// origin. They differ in content and in length, so the hop a response came from is
	// identifiable from its body alone even if its URL were wrong.
	secondaryRedirectBody = "hop-one-302"
	secondaryFinalBody    = "hop-two-200-final"

	// secondaryDeniedAddress is the address every httptest server binds, and therefore the
	// address the network policy denies. Denying exactly it is what turns "the policy dialer
	// was never consulted" into a protocol-visible outcome: a 200 carrying the origin's body
	// proves a dial to a denied address completed.
	secondaryDeniedAddress = "127.0.0.1"

	// secondaryUnusableProxy points at TCP port 1 on loopback, where nothing listens.
	// Unusable is deliberate: a working proxy would prove only that a proxy can be
	// configured, whereas a closed port makes "honoured the proxy" and "ignored the proxy"
	// opposite and unmistakable - an error naming the proxy address versus a 200 carrying
	// the origin's body.
	secondaryUnusableProxy = "http://127.0.0.1:1"

	// secondaryRedirectPath and secondaryFinalPath are the two hops of the redirect chain.
	secondaryRedirectPath = "/a"
	secondaryFinalPath    = "/b"
)

// newSecondaryPolicyHTTPX builds a REAL client through New, with mut applied to a copy of
// DefaultOptions, and registers the dialer cleanup.
//
// It deliberately replaces no transport. newMockHTTPX installs a scripted round tripper on
// both clients, which is exactly wrong here: the subject is the transports New itself
// built, so a replacement would make every assertion below describe the harness instead of
// production. newLocalHTTPX would do, except that it takes no option mutator and this
// section needs a proxy and a network policy configured; it is left untouched rather than
// widened.
func newSecondaryPolicyHTTPX(t *testing.T, mut func(*Options)) *HTTPX {
	t.Helper()
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 5 * time.Second
	options.RetryMax = 0
	if mut != nil {
		mut(&options)
	}

	ht, err := New(&options)
	require.NoError(t, err, "New must succeed: every assertion below reads the clients it constructs")
	// See registerDialerCleanup in common/httpx/mocktransport_test.go.
	registerDialerCleanup(t, ht)
	return ht
}

// newSecondaryHTTP2Server starts an HTTP/2-capable TLS origin on loopback that answers
// every request with secondaryPolicyBody.
//
// HTTP/2 has to be negotiable for the native HTTP/2 client to be exercised at all - its
// transport speaks h2 and nothing else - so an HTTP/1.1-only origin would fail the
// handshake and make a bypass indistinguishable from a broken fixture. TLS is likewise
// required rather than decorative: with DialTLSContext nil, an http2.Transport reaching a
// cleartext origin still attempts a TLS handshake, so a plain origin could not be reached
// even when no policy denies it.
//
// Returned WITHOUT a registered cleanup, matching newConnectionObserverServer above, so
// every caller pairs it with a visible `defer srv.Close()`.
func newSecondaryHTTP2Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", connectionObserverContentType)
		_, _ = w.Write([]byte(secondaryPolicyBody))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv
}

// newSecondaryRedirectServer starts a plain HTTP/1.1 loopback origin that answers
// secondaryRedirectPath with a 302 to secondaryFinalPath and secondaryFinalPath with a 200,
// recording the connection-level view of every request through rec.
//
// The 302 carries a body of its own so that a client which stops at the redirect is
// distinguishable from one that followed it by body as well as by status and path.
//
// Returned WITHOUT a registered cleanup, matching newConnectionObserverServer above.
func newSecondaryRedirectServer(t *testing.T, rec *connectionRecorder) *httptest.Server {
	t.Helper()
	require.NotNil(t, rec, "newSecondaryRedirectServer: a recorder is required, the hop COUNT is the assertion")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", connectionObserverContentType)
		if r.URL.Path == secondaryRedirectPath {
			w.Header().Set("Location", secondaryFinalPath)
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte(secondaryRedirectBody))
			return
		}
		_, _ = w.Write([]byte(secondaryFinalBody))
	}))
}

// doSecondary issues one GET through client and returns the response together with its
// fully read body.
//
// The body is read and closed before returning, so a caller can assert on it after the
// connection is gone, mirroring what Do leaves its own callers holding.
func doSecondary(t *testing.T, client *http.Client, target string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	require.NoError(t, err, "constructing the probe request for %s must succeed", target)

	resp, err := client.Do(req)
	require.NoError(t, err, "the request to %s must complete: this call is the evidence that the address was reached", target)
	require.NotNil(t, resp, "a completed request must carry a response")

	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	require.NoError(t, readErr, "the response body from %s must be readable in full", target)
	require.NoError(t, closeErr, "the response body from %s must close cleanly", target)
	return resp, string(body)
}

// doSecondaryExpectingError issues one GET that must NOT complete and returns the error.
//
// Any response is released before the error is asserted, so a partially established
// exchange cannot leak a connection out of the test.
func doSecondaryExpectingError(t *testing.T, client *http.Client, target string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	require.NoError(t, err, "constructing the probe request for %s must succeed", target)

	resp, doErr := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, doErr, "the request to %s must fail: a success here would mean the guard under test was never applied", target)
	return doErr
}

// TestSecondaryClientsDoNotCarryThePrimaryRequestPolicy pins, per policy and per client,
// which of New's three clients a configured request policy actually reaches.
//
// Each sub-test states the same thing twice: once as a white-box read of the constructed
// client, which names the field a one-line edit would change, and once as an outcome an
// observer of the exchange could see, which is what proves the field read is not merely
// bookkeeping. Neither form is sufficient alone - a field can be set and unused, and an
// outcome can be right for the wrong reason - and the pairing is what makes the test fail
// in both directions of change.
//
// The full mechanism, the security consequence and the reason the asymmetry is pinned
// rather than repaired are in the section comment above.
func TestSecondaryClientsDoNotCarryThePrimaryRequestPolicy(t *testing.T) {
	t.Run("the fallback client is a distinct client carrying no redirect policy", func(t *testing.T) {
		ht := newSecondaryPolicyHTTPX(t, nil)

		// Preconditions on the option set, so a defaults change cannot quietly turn the
		// comparison below into "both clients followed the redirect".
		require.False(t, ht.Options.FollowRedirects,
			"the default option set must not follow redirects: the contrast asserted below is between a policy that declines to follow and no policy at all")
		require.False(t, ht.Options.FollowHostRedirects,
			"the default option set must not follow same-host redirects either, for the same reason")

		// The primary carries the closure New built; the fallback carries nothing.
		require.NotNil(t, ht.client.HTTPClient.CheckRedirect,
			"the primary client must carry the redirect closure New assembled (httpx.go:92-143, installed at :182-186): without it the primary comparison below would prove nothing")
		require.Nil(t, ht.client.HTTPClient2.CheckRedirect,
			"the fallback client must be observed carrying NO redirect policy: retryablehttp builds it as a library DefaultClient and httpx.go never assigns CheckRedirect on it, so net/http's own default - follow up to 10 hops, to any host, without running setCustomCookies - is what applies on the fallback path")
		require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"on the default protocol path the two must be different clients: they are aliased only when -http11 is forced (httpx.go:188-190), and aliasing here would silently give the fallback the primary's policy and make this whole section vacuous")

		// The one policy that IS symmetric. Asserting it alongside the asymmetric ones is
		// what shows the fallback is a CONFIGURED client missing specific policy, not an
		// unconfigured one - so a reader cannot dismiss the gaps above as "it is just a
		// default client".
		require.Equal(t, ht.Options.Timeout, ht.client.HTTPClient2.Timeout,
			"the fallback client must carry the configured timeout: retryablehttp propagates Options.Timeout to both of its clients, which is precisely why the missing redirect, proxy and policy wiring is an asymmetry rather than a wholesale absence of configuration")

		rec := &connectionRecorder{}
		srv := newSecondaryRedirectServer(t, rec)
		defer srv.Close()

		// The primary declines to follow: one hit, the 302 itself, its own body.
		primaryResp, primaryBody := doSecondary(t, ht.client.HTTPClient, srv.URL+secondaryRedirectPath)
		require.Equal(t, http.StatusFound, primaryResp.StatusCode,
			"the primary must hand the 302 back rather than follow it, because its closure returns http.ErrUseLastResponse when neither follow option is set")
		require.Equal(t, secondaryRedirectPath, primaryResp.Request.URL.Path,
			"the primary's response must belong to the first hop: a %s here would mean it followed", secondaryFinalPath)
		require.Equal(t, secondaryRedirectBody, primaryBody,
			"the primary must deliver the redirect's own body, not the destination's")
		require.Len(t, rec.observations(), 1,
			"the origin must have seen exactly one request from the primary: a second hit would mean the no-follow policy was not applied")

		// The fallback follows: two hits, the destination, the destination's body.
		fallbackRec := &connectionRecorder{}
		fallbackSrv := newSecondaryRedirectServer(t, fallbackRec)
		defer fallbackSrv.Close()

		fallbackResp, fallbackBody := doSecondary(t, ht.client.HTTPClient2, fallbackSrv.URL+secondaryRedirectPath)
		require.Equal(t, http.StatusOK, fallbackResp.StatusCode,
			"the fallback client must have followed the redirect and returned the destination's 200: this is the configured no-follow policy failing to apply on the fallback path")
		require.Equal(t, secondaryFinalPath, fallbackResp.Request.URL.Path,
			"the fallback client's response must belong to the SECOND hop, which is the protocol-visible proof that a hop the configuration forbade was taken")
		require.Equal(t, http.MethodGet, fallbackResp.Request.Method,
			"the followed hop must be a GET, per RFC 9110 section 15.4.3 for a 302 - stated so the followed hop is characterised, not merely counted")
		require.Equal(t, secondaryFinalBody, fallbackBody,
			"the fallback client must deliver the DESTINATION's body: receiving %q instead would mean it had stopped at the redirect after all", secondaryRedirectBody)
		require.Len(t, fallbackRec.observations(), 2,
			"the origin must have seen exactly two requests from the fallback client, one per hop")
	})

	t.Run("the configured proxy reaches only the primary client", func(t *testing.T) {
		ht := newSecondaryPolicyHTTPX(t, func(options *Options) {
			options.HTTPProxy = secondaryUnusableProxy
		})

		require.Equal(t, secondaryUnusableProxy, ht.Options.Proxy,
			"New must have resolved -http-proxy into Options.Proxy (httpx.go:166-181): if it had not, the primary failure below would have some other cause")

		srv := newSecondaryHTTP2Server(t)
		defer srv.Close()

		// White-box: the primary transport resolves the configured proxy for this target.
		primaryTransport, ok := ht.client.HTTPClient.Transport.(*http.Transport)
		require.True(t, ok, "the primary client must still carry the *http.Transport New built (found %T)", ht.client.HTTPClient.Transport)
		require.NotNil(t, primaryTransport.Proxy, "the primary transport must carry a proxy resolver (httpx.go:178)")

		probe, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err, "constructing the proxy-resolution probe must succeed")
		resolved, err := primaryTransport.Proxy(probe)
		require.NoError(t, err, "resolving the proxy for the target must not error")
		require.NotNil(t, resolved, "the primary transport must resolve a proxy for the target")
		require.Equal(t, secondaryUnusableProxy, resolved.String(),
			"the primary transport must route this target through exactly the configured proxy")

		// White-box: the fallback transport resolves no proxy for the same target. Its
		// resolver is http.ProxyFromEnvironment, and that function declines loopback
		// unconditionally (it returns no proxy for localhost or any loopback IP, regardless
		// of HTTP_PROXY), so this assertion does not depend on the ambient environment.
		fallbackTransport, ok := ht.client.HTTPClient2.Transport.(*http.Transport)
		require.True(t, ok, "the fallback client must carry an *http.Transport (found %T)", ht.client.HTTPClient2.Transport)
		require.NotNil(t, fallbackTransport.Proxy, "the fallback transport carries retryablehttp's environment resolver, not the configured one")
		fallbackResolved, err := fallbackTransport.Proxy(probe)
		require.NoError(t, err, "resolving the fallback proxy for the target must not error")
		require.Nil(t, fallbackResolved,
			"the fallback transport must resolve NO proxy for the target: the value configured through -http-proxy was never installed on it, so it dials the origin directly")

		// Outcome: the primary cannot reach the origin, the two secondaries can.
		primaryErr := doSecondaryExpectingError(t, ht.client.HTTPClient, srv.URL)
		require.ErrorContains(t, primaryErr, "proxyconnect",
			"the primary must fail while CONNECTing to the proxy, which is what proves it honoured the configuration rather than failing for some unrelated reason")
		require.ErrorContains(t, primaryErr, secondaryUnusableProxy[len("http://"):],
			"the primary's failure must name the configured proxy address")

		fallbackResp, fallbackBody := doSecondary(t, ht.client.HTTPClient2, srv.URL)
		require.Equal(t, http.StatusOK, fallbackResp.StatusCode,
			"the fallback client must reach the origin despite the configured proxy: the request left the host directly")
		require.Equal(t, secondaryPolicyBody, fallbackBody,
			"the fallback client's reply must be the origin's own body, which is the evidence the origin was contacted directly")

		http2Resp, http2Body := doSecondary(t, ht.client2, srv.URL)
		require.Equal(t, http.StatusOK, http2Resp.StatusCode,
			"the native HTTP/2 client must reach the origin despite the configured proxy: http2.Transport has no proxy field at all, so there is nowhere for the configured value to be applied")
		require.Equal(t, "HTTP/2.0", http2Resp.Proto,
			"the native HTTP/2 client's exchange must be framed as HTTP/2, confirming this outcome belongs to that client and not to a fallback")
		require.Equal(t, secondaryPolicyBody, http2Body,
			"the native HTTP/2 client's reply must be the origin's own body")
	})

	t.Run("the network policy guards only the primary client", func(t *testing.T) {
		policy, err := networkpolicy.New(networkpolicy.Options{DenyList: []string{secondaryDeniedAddress}})
		require.NoError(t, err, "constructing the deny policy must succeed: it is the guard under test")
		require.False(t, policy.ValidateAddress(secondaryDeniedAddress),
			"the policy must reject %s before anything is dialled, otherwise a reachable origin would prove nothing", secondaryDeniedAddress)

		ht := newSecondaryPolicyHTTPX(t, func(options *Options) {
			options.NetworkPolicy = policy
		})
		require.NotNil(t, ht.NetworkPolicy,
			"New must have retained the policy on the client (httpx.go:61-63); it threads the same value into the fastdialer, which is the only place it is enforced")

		srv := newSecondaryHTTP2Server(t)
		defer srv.Close()

		// The primary is guarded: the dial is refused by the policy, not by the origin.
		primaryErr := doSecondaryExpectingError(t, ht.client.HTTPClient, srv.URL)
		require.ErrorContains(t, primaryErr, "denied address found for host",
			"the primary must be stopped by the network policy itself: the exact cause matters, because a timeout or a refused connection would mean the origin decided the outcome rather than the guard")

		// Both secondaries reach the denied address. This is the server-side request
		// forgery bypass in its most direct form: a 200 carrying the origin's body is proof
		// that a dial the configuration forbade completed.
		fallbackResp, fallbackBody := doSecondary(t, ht.client.HTTPClient2, srv.URL)
		require.Equal(t, http.StatusOK, fallbackResp.StatusCode,
			"the fallback client must reach the denied address: it dials through retryablehttp's own package-level dialer, which was never given this policy")
		require.Equal(t, secondaryPolicyBody, fallbackBody,
			"the fallback client must return the denied origin's own body, which is what makes the bypass protocol-visible rather than inferred")

		http2Resp, http2Body := doSecondary(t, ht.client2, srv.URL)
		require.Equal(t, http.StatusOK, http2Resp.StatusCode,
			"the native HTTP/2 client must reach the denied address: with DialTLSContext nil its transport calls tls.Dial directly, so httpx.Dialer - the only holder of the policy - is never consulted")
		require.Equal(t, "HTTP/2.0", http2Resp.Proto,
			"the exchange must be framed as HTTP/2, confirming the bypass belongs to the native HTTP/2 client")
		require.Equal(t, secondaryPolicyBody, http2Body,
			"the native HTTP/2 client must return the denied origin's own body")

		// The bypass is reachable through the PUBLIC API, not only by reaching into the
		// unexported client: SupportHTTP2 is what the -http2 probe calls, and it answers
		// true for an address the configuration denied.
		require.True(t, ht.SupportHTTP2(HTTPS, http.MethodGet, srv.URL),
			"SupportHTTP2 must be observed returning true for a DENIED address: it is an exported method reaching the native HTTP/2 client (common/httpx/http2.go:55), so the bypass above is reachable without touching any unexported field")
	})

	t.Run("the native HTTP/2 client's transport is built without a policy hook", func(t *testing.T) {
		ht := newSecondaryPolicyHTTPX(t, nil)

		require.NotNil(t, ht.client2, "New must build the native HTTP/2 client (httpx.go:202-205)")
		require.Nil(t, ht.client2.CheckRedirect,
			"the native HTTP/2 client must be observed carrying no redirect policy: the literal at httpx.go:202-205 sets only Transport and Timeout")
		require.Nil(t, ht.client2.Jar,
			"the native HTTP/2 client must carry no cookie jar, so nothing restores per-host cookie state that setCustomCookies would have applied on the primary path")
		require.Equal(t, ht.Options.Timeout, ht.client2.Timeout,
			"the native HTTP/2 client must carry the configured timeout - the one policy the literal does propagate")

		transport, ok := ht.client2.Transport.(*http2.Transport)
		require.True(t, ok,
			"the native HTTP/2 client must carry the *http2.Transport the literal at httpx.go:192-200 built (found %T): every field below lives on that concrete type", ht.client2.Transport)

		require.True(t, transport.AllowHTTP,
			"AllowHTTP must stay true (httpx.go:198): it is what lets the h2c probe address a cleartext origin at all")
		require.Nil(t, transport.DialTLSContext,
			"DialTLSContext must stay nil: this is the field that would have to hold httpx.Dialer for the network policy and the resolver cache to apply, and its being unset is exactly why the denied address is reachable above")
		// Reading the DEPRECATED seam is deliberate and the staticcheck exemption is part of
		// the assertion, not an oversight: SA1019 objects to DialTLS precisely because it is
		// superseded, but a superseded seam is still a seam - x/net honours it whenever
		// DialTLSContext is unset - so leaving it unread would let a policy dialer be wired
		// there without this test noticing.
		require.Nil(t, transport.DialTLS, //nolint:staticcheck // SA1019: the deprecated seam is read on purpose, an unwired seam is the assertion
			"the deprecated dial hook must be unset too, so neither of the transport's two dial seams routes through httpx.Dialer")
		require.Nil(t, transport.ConnPool,
			"ConnPool must keep its zero value: the literal sets no pool, so a value here would mean the transport literal had been rewritten")

		// The same TLS posture the primary transport carries, asserted here because it is
		// established by a SECOND literal (httpx.go:192-197) that no other test reads. The
		// posture itself is deliberate - see TestTransportDisablesConnectionReuse - but a
		// change to one literal and not the other would leave the two clients disagreeing
		// about how much of a certificate to trust, and nothing else would notice.
		require.NotNil(t, transport.TLSClientConfig, "the http2 transport literal sets a TLS config (httpx.go:193-196)")
		require.True(t, transport.TLSClientConfig.InsecureSkipVerify,
			"certificate verification must stay disabled on the HTTP/2 client too (httpx.go:194), matching the primary transport: probing hosts that serve expired, self-signed or mismatched certificates is the point of the tool")
		require.Equal(t, uint16(tls.VersionTLS10), transport.TLSClientConfig.MinVersion,
			"the HTTP/2 client's negotiated floor must stay TLS 1.0 (httpx.go:195), matching the primary transport, so legacy endpoints stay reachable on both paths")
		require.Equal(t, "", transport.TLSClientConfig.ServerName,
			"ServerName must stay empty unless -sni is given: only the SniName branch assigns it (httpx.go:199-201), so a value here would mean this client was built on that branch instead of the default one")
	})
}
