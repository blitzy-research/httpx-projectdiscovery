package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Connection policy and the per-request connection lifecycle.
//
// New configures its HTTP/1.1 transport with DisableKeepAlives: true and
// MaxIdleConnsPerHost: -1 (the transport literal at common/httpx/httpx.go:144-153, those
// two fields at :152 and :147). That is a deliberate, scanner-specific choice rather than
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
// process-global GODEBUG variable on its HTTP/1.1 path (httpx.go:157), which is unsafe to
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
// transport literal at common/httpx/httpx.go:144-153:
//
//	DisableKeepAlives   true   (:152)
//	MaxIdleConnsPerHost -1     (:147)
//	MaxIdleConns        0      - never set by the literal, so the zero value
//	ForceAttemptHTTP2   false  - never set by the literal, so the zero value
//	TLSClientConfig     InsecureSkipVerify true (:149), MinVersion TLS 1.0 (:150)
//	TLSNextProto        nil    - only the HTTP/1.1-forced branch at :158 assigns it
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
		"keep-alives must stay disabled (httpx.go:152): with reuse enabled several probes share one connection, so a target can correlate them, per-connection server state leaks from one probe into the next, and per-connection rate limiting sees one connection instead of one per request")
	require.Equal(t, -1, tr.MaxIdleConnsPerHost,
		"MaxIdleConnsPerHost must stay -1 (httpx.go:147): a negative limit stops net/http caching an idle connection at all, which is the second and independent guard against reuse - MEASURED, it is what keeps peer addresses distinct even when DisableKeepAlives is flipped, so this field read is the only assertion in the suite that catches a change to it")

	// Two fields the literal deliberately leaves at their zero value.
	require.Equal(t, 0, tr.MaxIdleConns,
		"MaxIdleConns must keep its zero value: the literal caps idleness per host only, so a global allowance appearing here would mean the transport literal had been rewritten")
	require.False(t, tr.ForceAttemptHTTP2,
		"ForceAttemptHTTP2 must keep its zero value - it never appears in the transport literal: because that literal sets a custom DialTLSContext and TLSClientConfig, net/http will not negotiate HTTP/2 over TLS unless this field is true, so its zero value is what keeps this client on HTTP/1.1 while the separate HTTP/2 client handles h2")

	// The TLS posture the same literal establishes.
	require.NotNil(t, tr.TLSClientConfig, "the transport literal sets a TLS config (httpx.go:148-151)")
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify,
		"certificate verification must stay disabled (httpx.go:149): probing hosts that serve expired, self-signed or mismatched certificates is the point of the tool, and verifying would turn those targets into errors instead of results")
	require.Equal(t, uint16(tls.VersionTLS10), tr.TLSClientConfig.MinVersion,
		"the negotiated floor must stay TLS 1.0 (httpx.go:150) so legacy endpoints remain reachable; raising it would silently drop those targets rather than report them")

	// Proof that this client was built on the default protocol path.
	require.Nil(t, tr.TLSNextProto,
		"TLSNextProto must be nil on the default protocol path: only the HTTP/1.1-forced branch assigns it (httpx.go:158), and that branch also mutates the process-global GODEBUG variable (httpx.go:157) - a non-nil value here would mean this test observed a client built on that branch instead of the default one")
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
// io.Copy(io.Discard, ...) plus Close (common/httpx/httpx.go:281-289), and closes the body
// explicitly at :321, so by the time Do returns the connection has already been drained
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
		"the first response must still hold its complete body after its connection was closed and a second request was served: Do drains and closes the body before returning (httpx.go:281-289, :321), so the bytes the caller keeps cannot depend on the connection still being open")
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
