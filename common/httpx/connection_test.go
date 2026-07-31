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
// MaxIdleConnsPerHost: -1, which is a deliberate scanner-specific choice rather than an
// accident of defaults - net/http reuses connections by default. Every probe therefore gets
// its own connection, so a target cannot correlate probes across one socket, per-connection
// server state cannot leak from one probe into the next, and per-connection rate limiting
// sees one request per connection instead of N.
//
// A loopback server is required here because three of the assertions are socket-level
// observations a scripted http.RoundTripper cannot provide: the peer address each request
// arrives on, the Connection directive and close verdict the origin observes, and the
// protocol version the message was framed in. The origin is an httptest.Server bound to
// 127.0.0.1, so the file stays hermetic - no name resolution, no egress.
//
// No test here opts into parallel execution. No test in the package does - New sets the
// process-global GODEBUG variable on its HTTP/1.1 path, which is unsafe to race - and these
// tests additionally count connections against a shared loopback listener.

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
// It carries no mutex so it can be returned and compared by value without tripping govet's
// copylocks check - connectionRecorder owns the lock. Every field is something an observer on
// the connection could see; nothing is read back out of the client's own state, which is what
// makes these assertions independent evidence.
type connectionObservation struct {
	// RemoteAddr is the peer address the request arrived on. Only its DISTINCTNESS across
	// requests is asserted, never its shape: the host:port spelling and the ephemeral port
	// range are platform details.
	RemoteAddr string
	// Close is net/http's parsed verdict on the request's Connection directive.
	Close bool
	// Connection is the first value of the request's Connection header.
	Connection string
	// ConnectionValues is every value of that header. Header.Get returns only the first, so a
	// duplicated or appended directive would hide behind Connection alone.
	ConnectionValues []string
	// Proto is the protocol version the request was framed in, e.g. "HTTP/1.1".
	Proto string
}

// connectionRecorder collects the origin's view of every request a loopback server received.
//
// The mutex is required because the handler runs on a goroutine owned by the httptest server
// while the assertions run on the test goroutine; pointer receivers keep the lock uncopied.
type connectionRecorder struct {
	mu       sync.Mutex
	observed []connectionObservation
}

// record stores the origin's view of one request.
//
// It performs no assertion of its own on purpose: require's FailNow calls runtime.Goexit,
// which on a server goroutine would abandon the response instead of failing the test, so
// every check is left to the test goroutine.
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
// request that is still being recorded, and it copies the slice so a caller cannot mutate the
// recording.
func (rec *connectionRecorder) observations() []connectionObservation {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]connectionObservation(nil), rec.observed...)
}

// newConnectionObserverServer starts a loopback origin that records the connection-level view
// of every request it receives and answers each one with body.
//
// Returned WITHOUT a registered cleanup, following the package's other server helpers, so
// every caller pairs it with a visible `defer ts.Close()` at the site owning its lifetime.
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
// It is a white-box read of the constructed transport with no I/O, so a failure names the
// field a one-line edit to the transport literal changed rather than a downstream symptom.
// It is possible only because the file is declared `package httpx` - ht.client is
// unexported.
//
// The client comes from newLocalHTTPX, which calls New and installs NOTHING on the
// transport. That is load bearing: newMockHTTPX REPLACES both transports with a scripted
// round tripper, so building the client through it would either fail the type assertion
// below or - far worse - silently assert against the mock and pin nothing about the
// production configuration.
func TestTransportDisablesConnectionReuse(t *testing.T) {
	ht := newLocalHTTPX(t)
	// newLocalHTTPX leaves the disk-backed fastdialer history New allocated; see
	// registerDialerCleanup in common/httpx/mocktransport_test.go.
	registerDialerCleanup(t, ht)

	tr, ok := ht.client.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok,
		"the HTTP/1.1 client must still carry the *http.Transport New built (found %T): every field asserted below lives on that concrete type, and a replacement would make this test describe something other than production configuration",
		ht.client.HTTPClient.Transport)

	// The two fields that decide connection reuse.
	require.True(t, tr.DisableKeepAlives,
		"keep-alives must stay disabled: with reuse enabled several probes share one connection, so a target can correlate them, per-connection server state leaks from one probe into the next, and per-connection rate limiting sees one connection instead of one per request")
	require.Equal(t, -1, tr.MaxIdleConnsPerHost,
		"MaxIdleConnsPerHost must stay -1: a negative limit stops net/http caching an idle connection at all, which is the second and independent guard against reuse, and it is invisible on the wire - this field read is the only assertion in the suite that constrains it")

	// Two fields the literal deliberately leaves at their zero value.
	require.Equal(t, 0, tr.MaxIdleConns,
		"MaxIdleConns must keep its zero value: the literal caps idleness per host only, so a global allowance appearing here would mean the transport literal had been rewritten")
	require.False(t, tr.ForceAttemptHTTP2,
		"ForceAttemptHTTP2 must keep its zero value - it never appears in the transport literal: because that literal sets a custom DialTLSContext and TLSClientConfig, net/http will not negotiate HTTP/2 over TLS unless this field is true, so its zero value is what keeps this client on HTTP/1.1 while the separate HTTP/2 client handles h2")

	// The TLS posture the same literal establishes.
	require.NotNil(t, tr.TLSClientConfig, "the transport literal sets a TLS config")
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify,
		"certificate verification must stay disabled: probing hosts that serve expired, self-signed or mismatched certificates is the point of the tool, and verifying would turn those targets into errors instead of results")
	require.Equal(t, uint16(tls.VersionTLS10), tr.TLSClientConfig.MinVersion,
		"the negotiated floor must stay TLS 1.0 so legacy endpoints remain reachable; raising it would silently drop those targets rather than report them")

	// Proof that this client was built on the default protocol path.
	require.Nil(t, tr.TLSNextProto,
		"TLSNextProto must be nil on the default protocol path: only the Protocol == HTTP11 branch assigns it, and that same branch mutates the process-global GODEBUG variable - a non-nil value here would mean this test observed a client built on that branch instead of the default one")

	// The same per-field reads applied to the two clients New builds BESIDE the primary,
	// where every one of them must come back empty.
	t.Run("the secondary clients carry none of the primary's request policy", assertSecondaryClientsDoNotCarryThePrimaryRequestPolicy)
}

// TestConnectionNotReusedAcrossRequests pins the observable consequence of that
// configuration: three sequential requests to one origin arrive on three different
// connections, each announcing that it will be closed.
//
// A real socket is required because a peer address exists only when a connection does. One
// client issues all three requests SEQUENTIALLY on purpose: reuse is only observable when a
// later request could have taken an earlier connection, and concurrent requests would need
// separate connections even with keep-alives enabled, which would make this test pass under
// the very regression it exists to catch.
//
// Connection: close is what RFC 9110 section 7.6.1 defines for announcing that the sender
// closes the connection once the current message is complete, and it is what net/http emits
// for a transport with keep-alives disabled, so the expectation follows from the
// specification rather than from observed output.
//
// The header assertions are not redundant with the peer-address assertion: enabling
// keep-alives on its own leaves the three peer addresses distinct, because
// MaxIdleConnsPerHost: -1 independently prevents an idle connection from being cached, and
// the only visible change is that Connection: close disappears.
func TestConnectionNotReusedAcrossRequests(t *testing.T) {
	rec := &connectionRecorder{}
	ts := newConnectionObserverServer(t, rec, connectionReuseBody)
	defer ts.Close()

	ht := newLocalHTTPX(t)
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

// TestConnectionStateAfterClose verifies that caller-visible response data remains
// self-contained after the first exchange completes and a later request is served.
// Transport-body Close behaviour is covered separately by the read-cap lifecycle tests in
// common/httpx/response_memory_test.go.
//
// *Response carries bytes, not a stream: Data, Raw and RawHeaders are materialised before Do
// returns, and the type exposes no Close method, so what the caller is left holding cannot
// depend on the connection that produced it. The test states that by fetching a SECOND
// response and only then asserting on the first.
//
// One subtlety the assertions pin: RawHeaders records Connection: close while
// GetHeader("Connection") is empty. net/http consumes the hop-by-hop directive while
// deriving Response.Close and the dump re-emits it from that flag, so Response.Headers holds
// only Content-Type, Date and Content-Length.
func TestConnectionStateAfterClose(t *testing.T) {
	rec := &connectionRecorder{}
	ts := newConnectionObserverServer(t, rec, connectionStateBody)
	defer ts.Close()

	ht := newLocalHTTPX(t)
	registerDialerCleanup(t, ht)

	respA := doLocal(t, ht, ts.URL)
	respB := doLocal(t, ht, ts.URL)

	require.Len(t, rec.observations(), 2,
		"both calls must have reached the origin, otherwise the two responses compared below are not two independent round trips")

	// Everything about respA is asserted AFTER respB was fetched; that ordering is the point.
	require.Equal(t, []byte(connectionStateBody), respA.Data,
		"the first response must still hold its complete body after a second request was served: Do materialises the bytes into Data before returning, so what the caller keeps cannot depend on the connection that delivered it")
	require.Equal(t, len(connectionStateBody), respA.ContentLength,
		"the first response must report the exact number of bytes delivered")
	require.Equal(t, http.StatusOK, respA.StatusCode, "the first exchange completed with 200")

	// The retained wire representation records the close; the parsed header map does not.
	require.Contains(t, respA.RawHeaders, "Connection: close",
		"the retained wire representation must record that the connection was closed for this exchange")
	require.Equal(t, "", respA.GetHeader("Connection"),
		"the parsed header map must NOT expose the hop-by-hop Connection directive: net/http removes it while deriving Response.Close, so a value appearing here would mean a hop-by-hop header had started leaking into caller-visible metadata")
	require.Equal(t, len(respA.RawHeaders)+len(connectionStateBody), len(respA.Raw),
		"Raw must be exactly the response headers followed by the whole body: a short Raw would mean the body was still being read when the exchange ended")

	// The caller-visible type carries no stream and therefore no lifecycle.
	_, isCloser := any(respA).(interface{ Close() error })
	require.False(t, isCloser,
		"*Response must expose no Close method: callers today release nothing, so a Close appearing on the caller-visible type would mean a lifecycle obligation had been handed to callers that none of them discharge")

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
// Everything above describes the primary HTTP/1.1 client, the one every Do goes through. New
// also builds two more, and neither carries the request policy the primary was configured
// with: client.HTTPClient2, which retryablehttp constructs as a library default client and
// falls back to when an HTTP/1.1 round trip reports a malformed HTTP version, and client2, an
// *http.Client over an *http2.Transport that SupportHTTP2 (the -http2 probe) uses.
//
// The primary's policy - the redirect closure, which is also what re-applies the configured
// cookies on every admitted hop; the fastdialer holding the -deny/-exclude network policy;
// and the proxy resolved from -http-proxy/-socks-proxy - is installed on the primary
// http.Client and http.Transport ONLY. The two secondary clients are constructed separately,
// one by the dependency and one by the transport2 literal, and receive none of it.
//
// SECURITY CONSEQUENCE, which is why this is asserted rather than merely noted. On either
// secondary path:
//
//   - -deny / -exclude private-ips is not enforced. The policy lives inside the fastdialer
//     wired onto the primary transport; a client that dials with anything else reaches a
//     denied address. That is a server-side request forgery guard being bypassed, and the
//     exported SupportHTTP2 is enough to trigger it.
//   - -http-proxy / -socks-proxy is not honoured, so traffic a user routed through a proxy
//     for isolation or attribution leaves the host directly instead.
//   - The redirect policy is absent, so -no-follow-redirects, -maxr and -fhr do not apply:
//     net/http's own default follows up to 10 hops, to any host, and setCustomCookies never
//     runs on those hops.
//
// Closing the asymmetry is a change to client construction rather than to these tests:
// assigning CheckRedirect, routing the secondary dials through httpx.Dialer, and applying the
// resolved proxy. Part of it cannot be done from this repository at all, since
// client.HTTPClient2 is built inside retryablehttp-go. For the native HTTP/2 client,
// http2.Transport has no proxy field; its DialTLSContext seam could carry a policy-aware
// dialer, but the current constructor leaves it nil, so equivalent policy there requires
// explicit wiring. Until that wiring exists these tests pin the asymmetry field by field and
// outcome by outcome, so that a change in either direction - a secondary client gaining
// policy, or the primary losing it - fails here instead of shipping unnoticed.
//
// Hermetic throughout: every origin binds 127.0.0.1, the proxy that is configured is a
// closed loopback port, and no name outside the loopback interface is ever resolved.

const (
	// secondaryPolicyBody is what the TLS origin in this section serves. It differs from
	// connectionReuseBody and connectionStateBody so a body observed here can never satisfy an
	// assertion belonging to the two tests above.
	secondaryPolicyBody = "secondary-policy-body"

	// secondaryRedirectBody and secondaryFinalBody mark the two hops of the redirecting origin.
	// They differ in content and in length, so the hop a response came from is identifiable
	// from its body alone even if its URL were wrong.
	secondaryRedirectBody = "hop-one-302"
	secondaryFinalBody    = "hop-two-200-final"

	// secondaryDeniedAddress is the address every httptest server binds, and therefore the one
	// the network policy denies. Denying exactly it turns "the policy dialer was never
	// consulted" into a protocol-visible outcome: a 200 carrying the origin's body proves a
	// dial to a denied address completed.
	secondaryDeniedAddress = "127.0.0.1"

	// secondaryUnusableProxy points at TCP port 1 on loopback, where nothing listens. Unusable
	// is deliberate: a closed port makes "honoured the proxy" and "ignored the proxy" opposite
	// and unmistakable - an error naming the proxy versus a 200 carrying the origin's body.
	secondaryUnusableProxy = "http://127.0.0.1:1"

	// secondaryRedirectPath and secondaryFinalPath are the two hops of the redirect chain.
	secondaryRedirectPath = "/a"
	secondaryFinalPath    = "/b"
)

// newSecondaryPolicyHTTPX builds a REAL client through New, with mut applied to a copy of
// DefaultOptions, and registers the dialer cleanup.
//
// It replaces no transport, and that is the point: the subject is the transports New itself
// built, so installing a scripted round tripper as newMockHTTPX does would make every
// assertion below describe the harness instead of production. newLocalHTTPX takes no option
// mutator, and this section needs a proxy and a network policy configured.
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
	registerDialerCleanup(t, ht)
	return ht
}

// newSecondaryHTTP2Server starts an HTTP/2-capable TLS origin on loopback that answers every
// request with secondaryPolicyBody.
//
// HTTP/2 has to be negotiable for the native HTTP/2 client to be exercised at all - its
// transport speaks h2 and nothing else - so an HTTP/1.1-only origin would fail the handshake
// and make a bypass indistinguishable from a broken fixture. TLS is required for the same
// reason: with DialTLSContext nil, an http2.Transport still attempts a TLS handshake, so a
// cleartext origin could not be reached even when no policy denies it.
//
// Returned WITHOUT a registered cleanup, so every caller pairs it with `defer srv.Close()`.
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
// distinguishable from one that followed it by body as well as by status and path. Returned
// WITHOUT a registered cleanup, like the other server helpers here.
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

// doSecondary issues one GET through client and returns the response together with its fully
// read body, which it reads and closes before returning so a caller can assert on it after the
// connection is gone.
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

// doSecondaryExpectingError issues one GET that must NOT complete and returns the error. Any
// response is released first, so a partially established exchange cannot leak a connection.
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

// assertSecondaryClientsDoNotCarryThePrimaryRequestPolicy pins, per policy and per client,
// which of New's three clients a configured request policy actually reaches. The mechanism and
// the security consequence are in the section comment above.
//
// Each sub-test states the same thing twice: once as a white-box read of the constructed
// client, which names the field a one-line edit would change, and once as an outcome an
// observer of the exchange could see. Neither form suffices alone - a field can be set and
// unused, and an outcome can be right for the wrong reason - and the pairing is what makes the
// test fail in both directions of change.
func assertSecondaryClientsDoNotCarryThePrimaryRequestPolicy(t *testing.T) {
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
			"the primary client must carry the redirect closure New assembled (httpx.go:92-143, installed at :181-185): without it the primary comparison below would prove nothing")
		require.Nil(t, ht.client.HTTPClient2.CheckRedirect,
			"the fallback client must be observed carrying NO redirect policy: retryablehttp builds it as a library DefaultClient and httpx.go never assigns CheckRedirect on it, so net/http's own default - follow up to 10 hops, to any host, without running setCustomCookies - is what applies on the fallback path")
		require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"on the default protocol path the two must be different clients: they are aliased only when -http11 is forced (httpx.go:187-189), and aliasing here would silently give the fallback the primary's policy and make this whole section vacuous")

		// The one policy that IS symmetric, asserted alongside the asymmetric ones to show the
		// fallback is a CONFIGURED client missing specific policy, not an unconfigured one.
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
			"New must have resolved -http-proxy into Options.Proxy (httpx.go:165-179): if it had not, the primary failure below would have some other cause")

		srv := newSecondaryHTTP2Server(t)
		defer srv.Close()

		// White-box: the primary transport resolves the configured proxy for this target.
		primaryTransport, ok := ht.client.HTTPClient.Transport.(*http.Transport)
		require.True(t, ok, "the primary client must still carry the *http.Transport New built (found %T)", ht.client.HTTPClient.Transport)
		require.NotNil(t, primaryTransport.Proxy, "the primary transport must carry the proxy resolver New installed from the configured value")

		probe, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err, "constructing the proxy-resolution probe must succeed")
		resolved, err := primaryTransport.Proxy(probe)
		require.NoError(t, err, "resolving the proxy for the target must not error")
		require.NotNil(t, resolved, "the primary transport must resolve a proxy for the target")
		require.Equal(t, secondaryUnusableProxy, resolved.String(),
			"the primary transport must route this target through exactly the configured proxy")

		// White-box: the fallback transport resolves no proxy for the same target. Its resolver
		// is http.ProxyFromEnvironment, which declines loopback unconditionally regardless of
		// HTTP_PROXY, so this assertion does not depend on the ambient environment.
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
			"New must have retained the policy on the client (httpx.go:60-63); it threads the same value into the fastdialer, which is the only place it is enforced")

		srv := newSecondaryHTTP2Server(t)
		defer srv.Close()

		// The primary is guarded: the dial is refused by the policy, not by the origin.
		primaryErr := doSecondaryExpectingError(t, ht.client.HTTPClient, srv.URL)
		require.ErrorContains(t, primaryErr, "denied address found for host",
			"the primary must be stopped by the network policy itself: the exact cause matters, because a timeout or a refused connection would mean the origin decided the outcome rather than the guard")

		// Both secondaries reach the denied address: a 200 carrying the origin's body is proof
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

		// The bypass is reachable through the EXPORTED API, not only by reaching into the
		// unexported client: SupportHTTP2 is what the -http2 probe calls.
		require.True(t, ht.SupportHTTP2(HTTPS, http.MethodGet, srv.URL),
			"SupportHTTP2 must be observed returning true for a DENIED address: it is an exported method reaching the native HTTP/2 client (common/httpx/http2.go:55), so the bypass above is reachable without touching any unexported field")
	})

	t.Run("the native HTTP/2 client's transport is built without a policy hook", func(t *testing.T) {
		ht := newSecondaryPolicyHTTPX(t, nil)

		require.NotNil(t, ht.client2, "New must build the native HTTP/2 client (httpx.go:201-204)")
		require.Nil(t, ht.client2.CheckRedirect,
			"the native HTTP/2 client must be observed carrying no redirect policy: the literal at httpx.go:201-204 sets only Transport and Timeout")
		require.Nil(t, ht.client2.Jar,
			"the native HTTP/2 client must carry no cookie jar, so nothing restores per-host cookie state that setCustomCookies would have applied on the primary path")
		require.Equal(t, ht.Options.Timeout, ht.client2.Timeout,
			"the native HTTP/2 client must carry the configured timeout - the one policy the literal does propagate")

		transport, ok := ht.client2.Transport.(*http2.Transport)
		require.True(t, ok,
			"the native HTTP/2 client must carry the *http2.Transport the transport2 literal built (found %T): every field below lives on that concrete type", ht.client2.Transport)

		require.True(t, transport.AllowHTTP,
			"AllowHTTP must stay true (httpx.go:196): it is what lets the h2c probe address a cleartext origin at all")
		require.Nil(t, transport.DialTLSContext,
			"DialTLSContext must stay nil: this is the field that would have to hold httpx.Dialer for the network policy and the resolver cache to apply, and its being unset is exactly why the denied address is reachable above")
		// The DEPRECATED seam is read on purpose: x/net honours DialTLS whenever DialTLSContext
		// is unset, so leaving it unread would let a policy dialer be wired there unnoticed.
		require.Nil(t, transport.DialTLS, //nolint:staticcheck // SA1019: the deprecated seam is read on purpose, an unwired seam is the assertion
			"the deprecated dial hook must be unset too, so neither of the transport's two dial seams routes through httpx.Dialer")
		require.Nil(t, transport.ConnPool,
			"ConnPool must keep its zero value: the literal sets no pool, so a value here would mean the transport literal had been rewritten")

		// The same TLS posture the primary transport carries, asserted again here because a
		// SECOND literal establishes it: a change to one literal and not the other would leave
		// the two clients disagreeing about how much of a certificate to trust.
		require.NotNil(t, transport.TLSClientConfig, "the transport2 literal sets a TLS config")
		require.True(t, transport.TLSClientConfig.InsecureSkipVerify,
			"certificate verification must stay disabled on the HTTP/2 client too, matching the primary transport: probing hosts that serve expired, self-signed or mismatched certificates is the point of the tool")
		require.Equal(t, uint16(tls.VersionTLS10), transport.TLSClientConfig.MinVersion,
			"the HTTP/2 client's negotiated floor must stay TLS 1.0, matching the primary transport, so legacy endpoints stay reachable on both paths")
		require.Equal(t, "", transport.TLSClientConfig.ServerName,
			"ServerName must stay empty unless -sni is given: only the SniName branch assigns it, so a value here would mean this client was built on that branch instead of the default one")
	})
}
