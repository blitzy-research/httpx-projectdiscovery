package httpx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
	})
}

func TestSetCustomHeaders(t *testing.T) {
	h := &HTTPX{Options: &Options{}}

	t.Run("duplicate values preserved in order", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one", "two"}})
		require.Equal(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("case-variant duplicates are coalesced", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one"}, "x-test": {"two"}})
		require.ElementsMatch(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("custom header replaces existing value", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("User-Agent", "default-agent")
		h.SetCustomHeaders(req, map[string][]string{"User-Agent": {"custom-agent"}})
		require.Equal(t, []string{"custom-agent"}, req.Header.Values("User-Agent"))
	})

	t.Run("host header sets request host", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Host": {"custom.host"}})
		require.Equal(t, "custom.host", req.Host)
		require.Empty(t, req.Header.Values("Host"))
	})

	t.Run("multiple distinct headers preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-One": {"1"}, "X-Two": {"2"}})
		require.Equal(t, []string{"1"}, req.Header.Values("X-One"))
		require.Equal(t, []string{"2"}, req.Header.Values("X-Two"))
	})

	t.Run("multiple cookie values preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Cookie": {"a=1", "b=2"}})
		require.Equal(t, []string{"a=1", "b=2"}, req.Header.Values("Cookie"))
	})

	t.Run("empty value applied as-is", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Empty": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Empty"))
	})

	t.Run("unsafe raw header line stored verbatim as key", func(t *testing.T) {
		hu := &HTTPX{Options: &Options{Unsafe: true}}
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		// in unsafe mode the runner stores the whole raw header line as the key
		// with an empty value; it must survive canonicalization untouched
		hu.SetCustomHeaders(req, map[string][]string{"X-Test: one": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Test: one"))
	})
}

func TestParseCustomCookies(t *testing.T) {
	options := &Options{CustomHeaders: map[string][]string{"Cookie": {"a=1", "b=2"}}}
	options.parseCustomCookies()
	require.True(t, options.hasCustomCookies())
	require.Len(t, options.customCookies, 2)
}

func TestHTTP11DisablesRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions
	options.Protocol = HTTP11

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

func TestDefaultProtocolKeepsRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

type blockingReadCloser struct{}

func (*blockingReadCloser) Read([]byte) (int, error) {
	select {}
}

func (*blockingReadCloser) Close() error {
	return nil
}

type switchingProtocolsRoundTripper struct{}

func (switchingProtocolsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":    {"websocket"},
			"Connection": {"Upgrade"},
		},
		Body:    &blockingReadCloser{},
		Request: req,
	}, nil
}

func TestDoSwitchingProtocolsDoesNotHang(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.NoError(t, err)

	rt := switchingProtocolsRoundTripper{}
	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		_, _ = ht.Do(req, UnsafeOptions{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("Do hung on 101 Switching Protocols response")
	}
}

// errUnexpected101BodyRead is reported by the body of the fail-fast 101 fixture below the
// moment anything reads it.
//
// Do must never read the body of a protocol switch: after the 101 headers the bytes belong
// to the upgraded protocol, which is why the status is in Do's skip set
// (common/httpx/httpx.go:279, and the guarded read at :316-322). Any read is therefore a
// defect, and naming it with a sentinel turns that defect into an immediate, attributable
// error instead of a symptom to be diagnosed.
var errUnexpected101BodyRead = errors.New("101 Switching Protocols body was read")

// switchingProtocolsFailFastRoundTripper answers with the same 101 response as
// switchingProtocolsRoundTripper (:137) but pairs it with a body that FAILS on first read
// instead of blocking forever.
//
// The difference is what keeps the failure bounded, and it is the reason this fixture exists
// alongside the other rather than replacing it. blockingReadCloser (:127) parks in a Read
// that no client timeout can interrupt - correct for the anti-hang regression test next to
// it, whose whole subject is that Do returns anyway - but wrong for a test that asserts the
// protocol-visible outcome: if a defect dropped 101 from Do's skip set, io.ReadAll on a
// blocking body would stall this test until the go test package timeout (10 minutes by
// default) and report a panic rather than a failed assertion. errReadCloser
// (common/httpx/mocktransport_test.go) returns the sentinel on first read instead, so the
// same defect surfaces as an immediate, named error out of Do and the assertion below fails
// in microseconds.
type switchingProtocolsFailFastRoundTripper struct{}

func (switchingProtocolsFailFastRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":    {"websocket"},
			"Connection": {"Upgrade"},
		},
		Body:    &errReadCloser{err: errUnexpected101BodyRead},
		Request: req,
	}, nil
}

// TestDoSwitchingProtocolsProtocolVisibleOutcome verifies that a 101 response
// preserves its status and upgrade headers while exposing no HTTP response body.
func TestDoSwitchingProtocolsProtocolVisibleOutcome(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.NoError(t, err)
	// Release the disk-backed dialer history this construction allocated; see
	// registerDialerCleanup for why leaving it behind slows every later New down.
	registerDialerCleanup(t, ht)

	// Install the mock on both retryable transports because malformed HTTP/1.x
	// responses may fall back to HTTPClient2. The fail-fast fixture is used deliberately
	// rather than switchingProtocolsRoundTripper: see its doc comment for why a body that
	// blocks would turn the most direct defect in this path into a package-wide hang
	// instead of a failed assertion.
	rt := switchingProtocolsFailFastRoundTripper{}
	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	// Intercepted by the round tripper above, so this host is never resolved or dialled.
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NotErrorIs(t, err, errUnexpected101BodyRead,
		"Do must not read the body of a protocol switch: this failure means 101 was lost from the skip set in Do")
	require.NoError(t, err)

	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
		"the 101 must reach the caller verbatim, not be normalized to 200 or dropped")

	// After the 101 headers, subsequent bytes belong to the upgraded protocol, not an
	// HTTP response body.
	require.Empty(t, resp.Data, "no body may be read for a protocol switch")
	require.Empty(t, resp.RawData, "no undecoded body may be retained for a protocol switch")
	require.Equal(t, 0, resp.ContentLength,
		"with no Content-Length header and no body the recomputation must leave the length at 0")
	require.Equal(t, 0, resp.Words, "word count is derived from the body, which was never read")
	require.Equal(t, 0, resp.Lines, "line count is derived from the body, which was never read")

	require.Equal(t, "websocket", resp.GetHeader("Upgrade"),
		"the negotiated protocol must survive to the caller")
	require.Equal(t, "Upgrade", resp.GetHeader("Connection"),
		"the hop-by-hop upgrade signal must survive to the caller")
	require.Equal(t, "", resp.GetHeader("Content-Length"),
		"a header the origin never sent must read back as the empty string")

	// projectdiscovery/utils v0.11.1 synthesizes 100-103 dumps from resp.Status and a
	// map iteration over headers, using LF separators and Go slice formatting. Header
	// order is nondeterministic, so assert the status line and header set separately;
	// Raw and RawHeaders are identical because the helper returns the same buffer for
	// both.
	require.Equal(t, 67, len(resp.Raw),
		"24-byte status line plus 21-byte Upgrade line plus 22-byte Connection line")
	require.Equal(t, resp.RawHeaders, resp.Raw,
		"the 1xx branch returns a single buffer for both, so Raw carries no body section")

	rawLines := strings.Split(strings.TrimSuffix(resp.Raw, "\n"), "\n")
	require.Len(t, rawLines, 3, "one status line plus exactly the two headers the origin sent")
	require.Equal(t, "101 Switching Protocols", rawLines[0],
		"the first line is the Status field verbatim, without the protocol version prefix")
	require.ElementsMatch(t, []string{"Upgrade: [websocket]", "Connection: [Upgrade]"}, rawLines[1:],
		"each header line is rendered with Go slice syntax around the value")
	require.NotContains(t, resp.Raw, "HTTP/1.1 101",
		"proves the dump is the synthetic 1xx rendering, not a real HTTP status line")
	require.NotContains(t, resp.Raw, "\r\n",
		"the synthetic dump is LF-joined, unlike the CRLF framing of real wire format")

	// The same outcome is pinned once more through switchingProtocolsRoundTripper (:137),
	// whose body blocks forever instead of failing on first read. Driving both fixtures
	// establishes the outcome as a property of Do's 101 handling rather than of either
	// body: a compliant Do reads neither, so both must yield byte-equivalent results.
	//
	// The call runs on its own goroutine behind a deadline because blockingReadCloser
	// (:127) parks in a Read that no client timeout can interrupt. If 101 were ever lost
	// from the skip set, the assertions above would already fail with the named sentinel;
	// this sub-test would otherwise stall until the package timeout, so the deadline
	// converts that stall into a bounded, attributable failure.
	t.Run("the blocking fixture yields the same protocol-visible outcome", func(t *testing.T) {
		blockingOptions := DefaultOptions
		blockingOptions.CdnCheck = "false"
		blockingOptions.Timeout = 2 * time.Second
		blockingOptions.RetryMax = 0

		// A client of its own, so this sub-test cannot inherit transport state from the
		// fail-fast run above.
		htBlocking, err := New(&blockingOptions)
		require.NoError(t, err)
		registerDialerCleanup(t, htBlocking)

		blockingRT := switchingProtocolsRoundTripper{}
		htBlocking.client.HTTPClient.Transport = blockingRT
		htBlocking.client.HTTPClient2.Transport = blockingRT

		blockingReq, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		type doOutcome struct {
			resp *Response
			err  error
		}
		outcome := make(chan doOutcome, 1)
		go func() {
			blockingResp, blockingErr := htBlocking.Do(blockingReq, UnsafeOptions{})
			outcome <- doOutcome{resp: blockingResp, err: blockingErr}
		}()

		var got doOutcome
		select {
		case got = <-outcome:
		case <-time.After(4 * time.Second):
			t.Fatal("Do did not return for a 101 whose body blocks on read: the body of a protocol switch must never be read")
		}

		require.NoError(t, got.err)
		require.Equal(t, http.StatusSwitchingProtocols, got.resp.StatusCode,
			"the 101 must reach the caller verbatim regardless of what the body would do when read")
		require.Empty(t, got.resp.Data, "no body may be read for a protocol switch")
		require.Empty(t, got.resp.RawData, "no undecoded body may be retained for a protocol switch")
		require.Equal(t, 0, got.resp.ContentLength,
			"with no Content-Length header and no body the recomputation must leave the length at 0")
		require.Equal(t, 0, got.resp.Words, "word count is derived from the body, which was never read")
		require.Equal(t, 0, got.resp.Lines, "line count is derived from the body, which was never read")

		require.Equal(t, "websocket", got.resp.GetHeader("Upgrade"),
			"the negotiated protocol must survive to the caller")
		require.Equal(t, "Upgrade", got.resp.GetHeader("Connection"),
			"the hop-by-hop upgrade signal must survive to the caller")

		// Lengths rather than strings: the synthetic 1xx dump renders headers in map
		// iteration order, so only its size is deterministic across runs.
		require.Equal(t, len(resp.Raw), len(got.resp.Raw),
			"both fixtures must produce the identical 67-byte synthetic 1xx dump")
		require.Equal(t, got.resp.RawHeaders, got.resp.Raw,
			"the 1xx branch returns a single buffer for both, so Raw carries no body section")
	})
}

// ---------------------------------------------------------------------------
// Safe / unsafe request-path parity
// ---------------------------------------------------------------------------
//
// Everything from here to the end of the file exercises the third parity axis the client
// exposes: the SAFE path, where Do dispatches through the retryable client
// (common/httpx/httpx.go:443), against the UNSAFE path, where it dispatches through
// doUnsafeWithOptions (:440-442, :447-455) and hands the request to
// rawhttp.DoRawWithOptions instead. Until these tests existed the unsafe branch of
// getResponse, the whole body of doUnsafeWithOptions and the Options.Unsafe branch of
// SetCustomHeaders (:526-528) had never been executed by any test in the repository, so a
// one-line defect in the raw request path - a dropped URIPath override, a dropped body, a
// dropped header, an unplumbed timeout, or chain collection wrongly running - would have
// shipped with the entire suite green. The path is reachable in production through the
// -unsafe flag (runner/options.go:536 -> runner/runner.go:214, :1926).
//
// WHY THESE TESTS CANNOT USE THE SHARED HARNESS. newMockHTTPX intercepts at the
// http.RoundTripper and deliberately refuses Options.Unsafe
// (common/httpx/mocktransport_test.go), because the raw path never consults a
// RoundTripper at all: rawhttp opens its own socket. Interception is therefore impossible
// by construction, and hermeticity has to be established one level lower - by making the
// only reachable authority a loopback socket this test owns. loopbackTargetURL below is
// that guarantee, and it is a hard require() rather than a convention so no later edit can
// turn one of these tests into a live-network test by changing a string. MEASURED:
// rawhttp.DefaultOptions.FastDialer is nil, so rawhttp's plain-HTTP dial falls through to
// net.DialTimeout("tcp", "127.0.0.1:<port>") - no resolver is consulted and no packet
// leaves the loopback interface.
//
// WHY A HAND-ROLLED LISTENER RATHER THAN httptest.NewServer. Three of the observations
// below are invisible to net/http's server implementation, which is what httptest wraps:
//
//	observation                        why httptest cannot report it
//	the byte-exact request line        the server normalizes the target into URL/RequestURI
//	"Host:  <addr>" (two spaces)       header values are trimmed before they are exposed
//	an UNFRAMED request body           with no Content-Length the server reports 0 bytes
//
// The last one is decisive: the raw path writes the body with no framing header at all
// (see TestDoUnsafeSendsRequestBodyWithoutFraming), so an httptest handler would observe
// an empty body and the assertion would pass vacuously against a defect that dropped the
// body entirely. The repository already binds a raw listener for the same reason in
// startTLSServer (common/httpx/tls_impersonate_test.go), so this follows an established
// idiom rather than introducing one. The listener binds 127.0.0.1:0, so these tests remain
// hermetic: no name resolution, no egress.
//
// No test here opts into parallel execution, matching the rest of the package: New sets the
// process-global GODEBUG variable on its HTTP/1.1 path (common/httpx/httpx.go:156-159), and
// the raw client keeps its configuration in the process-global rawhttp.DefaultOptions (see
// pinRawHTTPDefaults), neither of which is safe to race.

const (
	// rawOriginContentType pins the reply's media type so the body is never MIME-sniffed
	// and DecodeData never transcodes it: the assertions below compare exact bytes.
	// Matches connectionObserverContentType in common/httpx/connection_test.go.
	rawOriginContentType = "text/plain"

	// rawOriginConnDeadline is a fail-fast safety budget for one connection. Everything
	// here is in-process over loopback, so a connection that reaches this deadline is
	// misconfigured rather than slow.
	rawOriginConnDeadline = 5 * time.Second

	// rawOriginUnframedBodyWindow is how long the origin waits for body bytes it cannot
	// delimit, i.e. a body sent with neither Content-Length nor Transfer-Encoding. It is
	// only ever used by the test that asserts that framing is absent, and only for the
	// single request that test issues. rawhttp writes the head and the body back to back
	// before it reads anything (rawhttp/client/client.go:93-125), so this window is
	// several orders of magnitude larger than the gap it has to cover.
	rawOriginUnframedBodyWindow = 200 * time.Millisecond

	// rawOriginClientTimeout is the default wall-clock budget newUnsafeCapableHTTPX gives
	// a client. TestDoUnsafeTimeoutErrorIdentity shortens it through the option mutator.
	rawOriginClientTimeout = 5 * time.Second
)

// rawOriginObservation is the origin's byte-level view of one inbound request.
//
// It is a value type carrying no mutex, so it can be returned and compared by value
// without tripping govet's copylocks check - rawOrigin owns the lock. That matches
// capturedRequest in common/httpx/request_body_test.go and connectionObservation in
// common/httpx/connection_test.go. Every field is something an observer on the connection
// could see; nothing is read back out of the client's own state, which is what makes these
// assertions independent evidence rather than a restatement of the client's intent.
type rawOriginObservation struct {
	// Head is the request head verbatim, from the request line up to but excluding the
	// empty line that terminates the header section, CRLFs included.
	Head string
	// Body is the request body bytes the origin collected.
	Body string
	// BodyFramed reports whether a Content-Length header delimited Body. When it is
	// false the origin could only collect the bytes by waiting for them, because the
	// message gave it no way to know where the body ends.
	BodyFramed bool
}

// RequestLine returns the request line with its CRLF stripped, e.g. "GET /a HTTP/1.1".
func (o rawOriginObservation) RequestLine() string {
	lines := o.lines()
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// HeaderLines returns every header line with its CRLF stripped, in wire order.
//
// Whole lines are returned rather than a parsed map on purpose: the raw path emits
// "Host:  <addr>" with two spaces, and any parse that trims the value would silently
// discard exactly the difference these tests exist to observe.
func (o rawOriginObservation) HeaderLines() []string {
	lines := o.lines()
	if len(lines) == 0 {
		return nil
	}
	return lines[1:]
}

// HeaderLinesNamed returns every header line whose field name equals name, compared
// case-insensitively. It returns all of them, not the first, so a duplicated header
// cannot hide behind a single-value lookup.
func (o rawOriginObservation) HeaderLinesNamed(name string) []string {
	var matched []string
	for _, line := range o.HeaderLines() {
		field, _, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(field), name) {
			matched = append(matched, line)
		}
	}
	return matched
}

func (o rawOriginObservation) lines() []string {
	head := strings.TrimSuffix(o.Head, "\r\n")
	if head == "" {
		return nil
	}
	return strings.Split(head, "\r\n")
}

// rawOrigin is a loopback origin that records the exact bytes of every request it receives
// and answers each one with a scripted reply.
//
// The mutex is required because connections are served on goroutines owned by this type
// while the assertions run on the test goroutine. Pointer receivers are used throughout so
// the lock is never copied, following requestBodyRecorder in
// common/httpx/request_body_test.go.
type rawOrigin struct {
	mu       sync.Mutex
	observed []rawOriginObservation

	// replies are served in connection-accept order; the last one repeats, so a single
	// scripted reply serves any number of requests.
	replies []string
	// drainUnframedBody makes the origin wait rawOriginUnframedBodyWindow for body bytes
	// it cannot delimit. It is opt-in because that wait is pure latency for the requests
	// that carry no body at all.
	drainUnframedBody bool
}

// newRawOrigin starts a loopback origin and returns its "host:port" address.
//
// The listener is closed by t.Cleanup, which ends the accept loop, so no goroutine
// outlives the test that started it.
func newRawOrigin(t *testing.T, drainUnframedBody bool, replies ...string) (string, *rawOrigin) {
	t.Helper()
	require.NotEmpty(t, replies, "newRawOrigin: at least one scripted reply is required")

	origin := &rawOrigin{replies: replies, drainUnframedBody: drainUnframedBody}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "newRawOrigin: the origin must bind the loopback interface")
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for accepted := 0; ; accepted++ {
			conn, err := listener.Accept()
			if err != nil {
				// The listener was closed by the cleanup above; nothing left to serve.
				return
			}
			go origin.serve(conn, accepted)
		}
	}()

	return listener.Addr().String(), origin
}

// serve records one request and then answers it.
//
// Recording happens BEFORE the reply is written, and that ordering is the whole
// synchronization contract of this fixture: the client cannot return from Do until it has
// read a reply, so once Do returns every request it made is already recorded and
// requests() needs no polling. It also performs no assertion of its own, because require's
// FailNow calls runtime.Goexit, which on this goroutine would abandon the response and
// hang the client instead of failing the test - the same reason connectionRecorder.record
// keeps its checks on the test goroutine.
func (o *rawOrigin) serve(conn net.Conn, index int) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(rawOriginConnDeadline))

	reader := bufio.NewReader(conn)
	head, ok := readRawOriginHead(reader)
	if !ok {
		return
	}

	body, framed := readRawOriginFramedBody(reader, head)
	if !framed && o.drainUnframedBody {
		// A body with neither Content-Length nor Transfer-Encoding can only be collected
		// by reading until the peer stops sending, so bound the read with a short
		// deadline instead of the connection budget. The deadline has to be reset
		// afterwards: once a deadline has expired, every later operation on the
		// connection - including the Write below - fails with os.ErrDeadlineExceeded
		// until a new one is set.
		_ = conn.SetReadDeadline(time.Now().Add(rawOriginUnframedBodyWindow))
		trailing, _ := io.ReadAll(reader)
		body = string(trailing)
		_ = conn.SetDeadline(time.Now().Add(rawOriginConnDeadline))
	}

	o.record(rawOriginObservation{Head: head, Body: body, BodyFramed: framed})
	_, _ = conn.Write([]byte(o.reply(index)))
}

func (o *rawOrigin) record(observation rawOriginObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observed = append(o.observed, observation)
}

// requests returns the recorded requests in wire order. The slice is a copy, so a caller
// cannot mutate the record it is asserting against.
func (o *rawOrigin) requests() []rawOriginObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]rawOriginObservation(nil), o.observed...)
}

// requestLines projects the recorded requests onto their request lines, which is the
// projection the redirect assertions compare in order.
func (o *rawOrigin) requestLines() []string {
	observed := o.requests()
	lines := make([]string, 0, len(observed))
	for _, observation := range observed {
		lines = append(lines, observation.RequestLine())
	}
	return lines
}

func (o *rawOrigin) reply(index int) string {
	if index < len(o.replies) {
		return o.replies[index]
	}
	return o.replies[len(o.replies)-1]
}

// readRawOriginHead reads the request head up to and including the empty line that
// terminates it, returning the head without that empty line.
func readRawOriginHead(reader *bufio.Reader) (string, bool) {
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		if line == "\r\n" {
			return head.String(), true
		}
		head.WriteString(line)
	}
}

// readRawOriginFramedBody reads exactly as many body bytes as the head declares.
//
// It reports whether the head declared a length at all, which is the difference the
// framing assertions turn on: a message with no Content-Length and no Transfer-Encoding
// leaves the origin unable to delimit the body, no matter how many bytes follow.
func readRawOriginFramedBody(reader *bufio.Reader, head string) (string, bool) {
	for _, line := range strings.Split(head, "\r\n") {
		field, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(field), "Content-Length") {
			continue
		}
		declared, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || declared < 0 {
			return "", false
		}
		if declared == 0 {
			return "", true
		}
		body := make([]byte, declared)
		if _, err := io.ReadFull(reader, body); err != nil {
			return "", true
		}
		return string(body), true
	}
	return "", false
}

// rawOriginReply builds a well-formed HTTP/1.1 reply that delivers exactly the bytes it
// declares.
//
// Declaring a length it does not deliver would make the response dump inside Do fail its
// own length check and return no response at all, which is the same trap mockResponse
// documents for the scripted transport. Connection: close is included because the raw
// client has no connection pool of its own (rawhttp never calls conn.Release), so every
// exchange ends with the socket being torn down anyway.
func rawOriginReply(status string, extraHeaders []string, body string) string {
	head := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: " + rawOriginContentType + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n"
	for _, header := range extraHeaders {
		head += header + "\r\n"
	}
	return head + "\r\n" + body
}

// loopbackTargetURL composes an absolute target for a raw-path test and refuses anything
// that is not loopback.
//
// This is the hermeticity guarantee for every test below. The raw path bypasses the
// http.RoundTripper the rest of the suite installs, so a target is not intercepted by
// anything: whatever authority appears here is genuinely dialled. Asserting the address is
// loopback - rather than merely intending it to be - means a later edit cannot turn one of
// these tests into a live-network test by changing a string.
func loopbackTargetURL(t *testing.T, addr, path string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err, "loopbackTargetURL: %q must be a host:port address", addr)
	require.NotEmpty(t, port, "loopbackTargetURL: %q must carry an explicit port", addr)

	ip := net.ParseIP(host)
	require.NotNil(t, ip, "loopbackTargetURL: %q must be a literal IP, never a name that would need resolving", host)
	require.True(t, ip.IsLoopback(),
		"loopbackTargetURL: the raw request path is not intercepted by any transport, so its target MUST be loopback, got %q", host)

	return "http://" + addr + path
}

// newUnsafeCapableHTTPX builds a client that is allowed to take the raw request path.
//
// It is the raw-path counterpart of newMockHTTPX and deliberately does NOT install a
// transport: the raw path never consults one. The option mutator runs before New for the
// same reason newMockHTTPX runs it there - New freezes option values into the closures and
// clients it builds, so a flag set afterwards is never seen.
//
// RandomAgent is forced off. DefaultOptions enables it (common/httpx/option.go:79), and
// SetCustomHeaders would then inject a randomly chosen User-Agent
// (common/httpx/httpx.go:537-540), which would make the exact wire header set these tests
// assert nondeterministic.
func newUnsafeCapableHTTPX(t *testing.T, mut func(*Options)) *HTTPX {
	t.Helper()

	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = rawOriginClientTimeout
	options.RetryMax = 0
	options.RandomAgent = false
	if mut != nil {
		mut(&options)
	}
	require.Equal(t, "false", options.CdnCheck,
		"newUnsafeCapableHTTPX: CDN checking must stay disabled so no external data source is consulted")
	require.False(t, options.ExcludeCdn,
		"newUnsafeCapableHTTPX: ExcludeCdn forces a cdncheck client even when CdnCheck is disabled")
	require.False(t, options.RandomAgent,
		"newUnsafeCapableHTTPX: a random User-Agent would make the asserted wire header set nondeterministic")

	ht, err := New(&options)
	require.NoError(t, err)
	// Release the disk-backed dialer history this construction allocated; see
	// registerDialerCleanup for why leaving it behind slows every later New down.
	registerDialerCleanup(t, ht)
	return ht
}

// pinRawHTTPDefaults restores rawhttp's process-global options when the test ends.
//
// This is required, not tidiness. doUnsafeWithOptions (common/httpx/httpx.go:452-454) does
// `options := rawhttp.DefaultOptions`, which copies a POINTER, and then assigns
// options.Timeout - so every unsafe request rewrites the shared configuration that
// rawhttp.DefaultClient also holds (MEASURED: Timeout moved from its 30s default to the
// client's own timeout). TestSetCustomHeadersUnsafeHostReachesTheWire additionally calls
// rawhttp.AutomaticHostHeader, which writes to the same struct - exactly as production
// does at runner/runner.go:288-297. Snapshotting the value and restoring it through the
// same pointer keeps one test's configuration from silently becoming another test's
// premise.
//
// The mutation itself is deliberately NOT asserted anywhere: it is upstream-shaped
// behaviour of a pinned dependency, and pinning it would make a future value-copy
// correction fail a test that has nothing to say about correctness. What the tests assert
// instead is the observable consequence - the raw request is abandoned at the configured
// deadline (TestDoUnsafeTimeoutErrorIdentity).
func pinRawHTTPDefaults(t *testing.T) {
	t.Helper()
	require.NotNil(t, rawhttp.DefaultOptions, "pinRawHTTPDefaults: rawhttp must expose its default options")
	saved := *rawhttp.DefaultOptions
	t.Cleanup(func() { *rawhttp.DefaultOptions = saved })
}

// TestDoUnsafeDispatchParity pins what an origin sees, and what the caller gets back, when
// the same request is dispatched down each of the two paths.
//
// Two differences carry most of the assertion power, and both are protocol-visible:
//
//  1. UnsafeOptions.URIPath is the request target on the raw path and is IGNORED on the
//     safe path. Nothing else in the suite observes that, so a defect that stopped
//     honouring the override - or started honouring it on the safe path - would silently
//     redirect every -unsafe probe at a different resource than the one requested.
//  2. The raw path sends ONLY the headers the request carries, while the safe path adds the
//     client's identity headers and net/http's own transport headers. Asserting the exact
//     wire header SET on each path (order-independently, since net/http fixes an order the
//     raw writer does not) fails on any header that is newly added or newly dropped.
//
// The chain assertions are the AAP's stated reason this axis matters: Do skips chain
// collection entirely when Options.Unsafe (common/httpx/httpx.go:419-426), so the caller
// gets an empty chain from the raw path and a one-item chain from the safe path for the
// very same exchange. All five chain accessors, plus the Chain field itself, are asserted
// on both paths, so a defect that started collecting a chain on the raw path (or stopped on
// the safe one) fails here.
//
// MEASURED against the code as it stands; every expected value below was observed on the
// wire, not copied from the client's own state.
func TestDoUnsafeDispatchParity(t *testing.T) {
	const (
		requestPath  = "/original?a=1"
		overridePath = "/override?x=1"
		responseBody = "wire-body"
		etagValue    = `"v1"`
	)

	for _, tc := range []struct {
		name   string
		unsafe bool
		// wantRequestLine is the request line the origin must receive verbatim.
		wantRequestLine string
		// wantHeaderLines is the COMPLETE header set the origin must receive, built from
		// the origin's address because the Host value carries the ephemeral port.
		wantHeaderLines func(addr string) []string
		// wantChainLen and wantChainStatusCodes describe the caller-visible chain. A nil
		// code slice is the exact value the accessor returns for an empty chain, since it
		// appends into a nil slice (common/httpx/response.go:62-68).
		wantChainLen         int
		wantChainStatusCodes []int
	}{
		{
			name:            "unsafe dispatch sends the URIPath override and skips chain collection",
			unsafe:          true,
			wantRequestLine: "GET " + overridePath + " HTTP/1.1",
			wantHeaderLines: func(addr string) []string {
				return []string{
					// Only what the request itself carried. NewRequestWithContext skips
					// the default User-Agent and Accept-Charset when Options.Unsafe
					// (common/httpx/httpx.go:499-505), and no net/http transport is
					// involved to add Accept-Encoding or Connection.
					"X-Probe: one",
					// rawhttp writes its automatic Host value with a leading space
					// (rawhttp/client.go:142-143) and the header writer adds its own
					// separator space, so two spaces reach the wire.
					"Host:  " + addr,
				}
			},
			wantChainLen:         0,
			wantChainStatusCodes: nil,
		},
		{
			name:            "safe dispatch ignores the URIPath override and collects the chain",
			unsafe:          false,
			wantRequestLine: "GET " + requestPath + " HTTP/1.1",
			wantHeaderLines: func(addr string) []string {
				return []string{
					"Host: " + addr,
					"User-Agent: " + defaultUserAgentLiteral,
					"Accept-Charset: utf-8",
					"X-Probe: one",
					// Added by net/http's transport: compression is enabled and
					// DisableKeepAlives is true (common/httpx/httpx.go:145-154), which is
					// what TestTransportDisablesConnectionReuse asserts directly.
					"Accept-Encoding: gzip",
					"Connection: close",
				}
			},
			wantChainLen:         1,
			wantChainStatusCodes: []int{http.StatusOK},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinRawHTTPDefaults(t)

			addr, origin := newRawOrigin(t, false, rawOriginReply("200 OK", []string{"Etag: " + etagValue}, responseBody))
			target := loopbackTargetURL(t, addr, requestPath)

			ht := newUnsafeCapableHTTPX(t, func(options *Options) { options.Unsafe = tc.unsafe })
			req, err := ht.NewRequest(http.MethodGet, target)
			require.NoError(t, err)
			req.Header.Set("X-Probe", "one")

			resp, err := ht.Do(req, UnsafeOptions{URIPath: overridePath})
			require.NoError(t, err)

			observed := origin.requests()
			require.Len(t, observed, 1, "exactly one request must reach the origin on either path")
			require.Equal(t, tc.wantRequestLine, observed[0].RequestLine(),
				"the request line proves which target was actually requested: the raw path substitutes UnsafeOptions.URIPath, the safe path never sees it")
			require.ElementsMatch(t, tc.wantHeaderLines(addr), observed[0].HeaderLines(),
				"the exact header set on the wire, so a newly added or newly dropped header fails here")
			require.Empty(t, observed[0].Body, "a GET carries no body on either path")

			require.Equal(t, http.StatusOK, resp.StatusCode, "the origin's status must reach the caller verbatim")
			require.Equal(t, responseBody, string(resp.Data), "the exact response bytes must reach the caller on either path")
			require.Equal(t, len(responseBody), resp.ContentLength,
				"recomputed from the Content-Length header the origin sent (common/httpx/httpx.go:367-380)")
			require.Equal(t, etagValue, resp.GetHeader("Etag"),
				"a response header must survive to the caller under its canonical spelling on either path")
			require.True(t, strings.HasPrefix(resp.Raw, "HTTP/1.1 200 OK\r\n"),
				"the raw dump starts with a real status line on either path, unlike the synthetic 1xx rendering")
			require.True(t, strings.HasSuffix(resp.Raw, "\r\n\r\n"+responseBody),
				"the raw dump ends with the body, separated from the headers by the empty line")
			require.Equal(t, addr, resp.Input, "Input is the request host (common/httpx/httpx.go:274)")

			require.Len(t, resp.Chain, tc.wantChainLen,
				"chain collection runs only on the safe path: Do skips it entirely when Options.Unsafe (common/httpx/httpx.go:419-426)")
			require.Equal(t, tc.wantChainStatusCodes, resp.GetChainStatusCodes(),
				"the chain status codes are the caller's view of the hops that were recorded")
			require.Len(t, resp.GetChainAsSlice(), tc.wantChainLen, "the projected chain must match the collected chain")
			require.False(t, resp.HasChain(),
				"HasChain requires more than one item, so it is false for a single-hop exchange on either path (common/httpx/response.go:99-101)")
			require.Equal(t, "", resp.GetChainLastURL(),
				"GetChainLastURL is empty without a redirect on either path")
			require.Equal(t, "", resp.GetChain(),
				"the chain dump omits the first request and the last response, so a one-item chain renders as nothing at all")

			if tc.wantChainLen == 1 {
				chain := resp.GetChainAsSlice()
				require.Equal(t, target, chain[0].RequestURL,
					"the recorded hop names the absolute URL that was requested, which is the URL - not the URIPath override")
				require.Equal(t, http.StatusOK, chain[0].StatusCode, "the recorded hop carries the status the origin returned")
				require.Equal(t, "", chain[0].Location, "a non-redirect hop resolves no Location")
			}
		})
	}
}

// TestDoUnsafeSendsRequestBodyWithoutFraming pins how each path frames a request body.
//
// Both paths deliver the same bytes, and that is the assertion that matters most - a defect
// that dropped the body on the raw path would fail it. What differs is whether the origin
// can DELIMIT those bytes:
//
//	path      Content-Length on the wire   how an origin finds the end of the body
//	safe      "Content-Length: 11"         the declared length
//	unsafe    absent                       only by waiting for the sender to stop
//
// MEASURED. The cause is an interaction between two pinned dependencies rather than a
// defect in this repository: rawhttp computes an automatic Content-Length only for a
// *bytes.Buffer or a *strings.Reader (rawhttp/client/client.go:55-68), while
// retryablehttp-go wraps every request body in its own rewindable reader, whose type
// rawhttp cannot measure - so the length is reported as unknown and no framing header is
// written. It is pinned rather than fixed, in the same spirit as the other upstream
// divergences this suite documents. Production compensates: the runner adds
// "Connection: close" to every unsafe request (runner/runner.go:1923-1924), which is what
// lets an origin read such a body to completion.
//
// This is also the only test in the file that needs the origin to wait for bytes it cannot
// delimit, which is why the unframed-body window is opt-in.
func TestDoUnsafeSendsRequestBodyWithoutFraming(t *testing.T) {
	const (
		requestBody  = "hello=world"
		responseBody = "accepted"
	)

	for _, tc := range []struct {
		name       string
		unsafe     bool
		wantFramed bool
	}{
		{
			name:       "the raw path writes the body with no framing header",
			unsafe:     true,
			wantFramed: false,
		},
		{
			name:       "the safe path declares the body length",
			unsafe:     false,
			wantFramed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinRawHTTPDefaults(t)

			addr, origin := newRawOrigin(t, true, rawOriginReply("200 OK", nil, responseBody))
			target := loopbackTargetURL(t, addr, "/submit")

			ht := newUnsafeCapableHTTPX(t, func(options *Options) { options.Unsafe = tc.unsafe })
			req, err := retryablehttp.NewRequest(http.MethodPost, target, strings.NewReader(requestBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			require.Equal(t, int64(len(requestBody)), req.ContentLength,
				"premise: the request object knows the body length on both paths, so a missing wire header is a framing decision and not a lost measurement")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			observed := origin.requests()
			require.Len(t, observed, 1, "exactly one request must reach the origin")
			require.Equal(t, "POST /submit HTTP/1.1", observed[0].RequestLine(),
				"the method and target must survive on both paths: a rewrite to GET would drop the body entirely")
			require.Equal(t, requestBody, observed[0].Body,
				"the exact body bytes must reach the origin on both paths")
			require.Equal(t, tc.wantFramed, observed[0].BodyFramed,
				"whether the origin could delimit the body from the head alone")
			require.Contains(t, observed[0].HeaderLines(), "Content-Type: application/x-www-form-urlencoded",
				"a header the caller set must reach the wire on both paths")

			if tc.wantFramed {
				require.Contains(t, observed[0].HeaderLines(), "Content-Length: "+strconv.Itoa(len(requestBody)),
					"the safe path declares the exact body length")
			} else {
				require.Empty(t, observed[0].HeaderLinesNamed("Content-Length"),
					"the raw path declares no length, which is why an origin can only find the end of the body by waiting")
				require.Empty(t, observed[0].HeaderLinesNamed("Transfer-Encoding"),
					"and it does not fall back to chunked framing either")
			}

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, responseBody, string(resp.Data), "the origin's reply must reach the caller on both paths")
		})
	}
}

// TestDoUnsafeBypassesClientRedirectPolicy pins which component decides whether a redirect
// is followed.
//
// Both rows run with the client's DEFAULT redirect policy, which follows nothing: New
// installs a CheckRedirect that returns http.ErrUseLastResponse
// (common/httpx/httpx.go:93-96) unless FollowRedirects (:98-115) or FollowHostRedirects
// (:117-144) overrides it. The safe path honours it and stops at the 302. The raw path
// never reaches it - CheckRedirect belongs to
// net/http.Client, which rawhttp does not use - and rawhttp follows the redirect itself,
// because its own DefaultOptions.FollowRedirects is true with a budget of 10
// (rawhttp/options.go:27-33, rawhttp/client.go:198-210).
//
// MEASURED: identical options and an identical target produce opposite outcomes - two
// requests on the wire and a 200 on the raw path, one request and a 302 on the safe path -
// and the raw path's extra hop appears in NO caller-visible chain, because chain collection
// is skipped. That combination is the sharpest statement of the parity difference: on the
// unsafe path the caller cannot see, or bound, the redirects that were followed.
func TestDoUnsafeBypassesClientRedirectPolicy(t *testing.T) {
	const (
		redirectBody = "go"
		finalBody    = "final-body"
	)

	for _, tc := range []struct {
		name                 string
		unsafe               bool
		wantRequestLines     []string
		wantStatus           int
		wantData             string
		wantLocation         string
		wantChainLen         int
		wantChainStatusCodes []int
	}{
		{
			name:                 "the raw client follows the redirect the client policy refuses",
			unsafe:               true,
			wantRequestLines:     []string{"GET /start HTTP/1.1", "GET /final HTTP/1.1"},
			wantStatus:           http.StatusOK,
			wantData:             finalBody,
			wantLocation:         "",
			wantChainLen:         0,
			wantChainStatusCodes: nil,
		},
		{
			name:                 "the safe path honours the default no-follow policy",
			unsafe:               false,
			wantRequestLines:     []string{"GET /start HTTP/1.1"},
			wantStatus:           http.StatusFound,
			wantData:             redirectBody,
			wantLocation:         "/final",
			wantChainLen:         1,
			wantChainStatusCodes: []int{http.StatusFound},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinRawHTTPDefaults(t)

			addr, origin := newRawOrigin(t, false,
				rawOriginReply("302 Found", []string{"Location: /final"}, redirectBody),
				rawOriginReply("200 OK", nil, finalBody),
			)
			target := loopbackTargetURL(t, addr, "/start")

			ht := newUnsafeCapableHTTPX(t, func(options *Options) { options.Unsafe = tc.unsafe })
			require.False(t, ht.Options.FollowRedirects,
				"premise: the client is configured to follow nothing, so any hop on the wire was decided elsewhere")
			require.False(t, ht.Options.FollowHostRedirects,
				"premise: host-scoped following is off too")

			req, err := ht.NewRequest(http.MethodGet, target)
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.wantRequestLines, origin.requestLines(),
				"the request stream on the wire names every hop that was taken, in order")
			require.Equal(t, tc.wantStatus, resp.StatusCode, "the status the caller ends up with")
			require.Equal(t, tc.wantData, string(resp.Data), "the body the caller ends up with")
			require.Equal(t, tc.wantLocation, resp.GetHeaderPart("Location", ";"),
				"the safe path surfaces the redirect itself, so its Location is still readable; the raw path returns the followed response, which has none")

			require.Len(t, resp.Chain, tc.wantChainLen,
				"the hop the raw client followed is invisible to the caller, because chain collection is skipped on the unsafe path")
			require.Equal(t, tc.wantChainStatusCodes, resp.GetChainStatusCodes(),
				"so is its status code")
			require.Equal(t, "", resp.GetChainLastURL(),
				"and so is the URL it ended up at, even though the raw client changed target mid-exchange")
		})
	}
}

// TestDoUnsafeTimeoutErrorIdentity pins the raw path's timeout budget and the identity of
// the error it produces.
//
// The budget is protocol-visible: the origin accepts the connection and never answers, so
// the only thing that ends the exchange is the client abandoning it. doUnsafeWithOptions
// passes Options.Timeout to the raw client (common/httpx/httpx.go:453), which applies it as
// a connection deadline (rawhttp/client.go:181-183), so the call returns at the configured
// deadline. Dropping that one assignment leaves rawhttp's own 30s default in force, which
// blows the envelope below by an order of magnitude.
//
// The identity is the parity half, and it is the counterpart of what
// common/httpx/timeout_test.go asserts for the safe path. MEASURED on the raw path:
//
//	axis                              safe path                     raw path
//	retry wrapper                     "giving up after N attempts"  absent
//	errors.Is(err, DeadlineExceeded)  true                          FALSE
//	errors.As to a Timeout() bool     succeeds, reports true        FAILS
//	concrete type                     *fmt.wrapError                *errors.errorString
//
// The raw path never enters the retry layer, and rawhttp flattens the net.Error it received
// into a string (fmt.Errorf with %v, rawhttp/client/client.go:132), so a timeout on this
// path can only be recognized from its message. Callers that classify failures by sentinel
// or by the Timeout() interface therefore cannot classify an unsafe timeout at all - which
// is a real consequence worth pinning, and one no other test in the suite states.
func TestDoUnsafeTimeoutErrorIdentity(t *testing.T) {
	// This is the only test in the file that deliberately waits out a deadline, so its
	// value is the whole of its runtime cost. It is calibrated the same way and for the
	// same reason as timeoutBudget in common/httpx/timeout_test.go: the deadline is a
	// fixture SCALE, never an asserted outcome, and both elapsed bounds below are
	// written relative to it, so halving it halves the cost and changes no assertion.
	//
	// 200ms preserves - in fact widens - the assertion power that matters. The upper
	// bound exists to catch options.Timeout no longer reaching the raw client, which
	// would leave rawhttp's own 30s default in force: at 400ms that was a 75x margin,
	// at 200ms it is 150x. The lower bound only needs the deadline to be reached, and
	// the loopback origin accepts instantly, so the client is provably inside
	// ReadStatusLine long before 200ms - MEASURED at 0.20-0.22s per run over ten
	// consecutive iterations, with the phase prefix asserted below holding every time.
	const timeout = 200 * time.Millisecond

	pinRawHTTPDefaults(t)

	addr := newSilentRawOrigin(t)
	target := loopbackTargetURL(t, addr, "/never-answers")

	ht := newUnsafeCapableHTTPX(t, func(options *Options) {
		options.Unsafe = true
		options.Timeout = timeout
	})
	req, err := ht.NewRequest(http.MethodGet, target)
	require.NoError(t, err)

	start := time.Now()
	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Nil(t, resp, "a timed-out raw request yields no response at all, so the target is dropped from output")
	require.Error(t, err)

	require.True(t, strings.HasPrefix(err.Error(), "ReadStatusLine: "),
		"the raw client names the phase it was in when the deadline fired, got %q", err.Error())
	require.Contains(t, err.Error(), "i/o timeout",
		"the message is the ONLY place a timeout is identifiable on this path, got %q", err.Error())
	require.NotContains(t, err.Error(), "giving up after",
		"the raw path bypasses the retry layer entirely, so its error carries no retry-exhaustion wrapper")

	require.False(t, errors.Is(err, context.DeadlineExceeded),
		"unlike the safe path, the raw path's timeout carries no DeadlineExceeded sentinel")
	require.False(t, errors.Is(err, context.Canceled),
		"and it is not a cancellation either")
	var asTimeout interface{ Timeout() bool }
	require.False(t, errors.As(err, &asTimeout),
		"rawhttp flattens the net.Error into a string, so the Timeout() behaviour of the underlying error is unreachable")

	require.GreaterOrEqual(t, elapsed, timeout,
		"the call must not give up before the configured deadline")
	require.Less(t, elapsed, 3*timeout,
		"and it must not outlive it either: this fails by an order of magnitude if Options.Timeout stops reaching the raw client")
}

// newSilentRawOrigin starts a loopback origin that accepts connections and never answers.
//
// It holds every connection open until the test ends instead of closing it, because a close
// would surface as an EOF rather than as the deadline expiry the timeout test is about.
func newSilentRawOrigin(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "newSilentRawOrigin: the origin must bind the loopback interface")

	held := make(chan struct{})
	t.Cleanup(func() {
		close(held)
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				<-held
				_ = conn.Close()
			}(conn)
		}
	}()

	return listener.Addr().String()
}

// TestSetCustomHeadersUnsafeHostReachesTheWire pins the Options.Unsafe branch of
// SetCustomHeaders (common/httpx/httpx.go:526-528) at both levels: the request it builds,
// and what an origin then receives.
//
// The branch exists because the two paths read a custom Host from different places. On the
// safe path net/http derives the Host header from Request.Host, so setting that field is
// enough. The raw path never looks at it - rawhttp serializes the header map it is handed
// (common/httpx/httpx.go:450 -> rawhttp/util.go:29-46) - so the value has to be written
// into the map as well, which is exactly what the unsafe branch adds.
//
// MEASURED, and the wire rows show that writing it into the map is necessary but not
// sufficient: rawhttp's automatic Host header overwrites the configured value (and mutates
// the caller's own header map doing so) unless it is disabled. Production disables it for
// precisely this case, when a custom header whose name starts with "host" is configured
// (runner/runner.go:288-297), so the second row reproduces the production configuration
// rather than inventing one. pinRawHTTPDefaults restores the global either way.
func TestSetCustomHeadersUnsafeHostReachesTheWire(t *testing.T) {
	const (
		configuredHost = "custom.host"
		responseBody   = "hosted"
	)

	t.Run("unsafe mode writes the configured Host into the header map as well", func(t *testing.T) {
		// No request is issued in this sub-test - SetCustomHeaders performs no I/O - so
		// the authority below is never resolved or dialled.
		unsafeClient := &HTTPX{Options: &Options{Unsafe: true}}
		unsafeReq, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example", nil)
		require.NoError(t, err)
		unsafeClient.SetCustomHeaders(unsafeReq, map[string][]string{"Host": {configuredHost}})
		require.Equal(t, configuredHost, unsafeReq.Host,
			"the request field is set on both paths")
		require.Equal(t, []string{configuredHost}, unsafeReq.Header.Values("Host"),
			"and on the unsafe path the value is additionally placed in the header map, because that map is what the raw writer serializes")

		safeClient := &HTTPX{Options: &Options{}}
		safeReq, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example", nil)
		require.NoError(t, err)
		safeClient.SetCustomHeaders(safeReq, map[string][]string{"Host": {configuredHost}})
		require.Equal(t, configuredHost, safeReq.Host,
			"the safe path sets the same field")
		require.Empty(t, safeReq.Header.Values("Host"),
			"but leaves the header map alone, because net/http writes the Host line from the field")
	})

	for _, tc := range []struct {
		name                string
		automaticHostHeader bool
		// wantHostLine is the single Host line the origin must receive.
		wantHostLine func(addr string) string
		// wantCallerHostValues is the caller's own header map after the call, which the
		// raw client rewrites when its automatic Host header is enabled.
		wantCallerHostValues func(addr string) []string
	}{
		{
			name:                 "the raw client's automatic Host header overrides the configured value",
			automaticHostHeader:  true,
			wantHostLine:         func(addr string) string { return "Host:  " + addr },
			wantCallerHostValues: func(addr string) []string { return []string{" " + addr} },
		},
		{
			name:                 "disabling the automatic Host header lets the configured value reach the wire",
			automaticHostHeader:  false,
			wantHostLine:         func(string) string { return "Host: " + configuredHost },
			wantCallerHostValues: func(string) []string { return []string{configuredHost} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinRawHTTPDefaults(t)

			addr, origin := newRawOrigin(t, false, rawOriginReply("200 OK", nil, responseBody))
			target := loopbackTargetURL(t, addr, "/vhost")

			ht := newUnsafeCapableHTTPX(t, func(options *Options) { options.Unsafe = true })
			req, err := ht.NewRequest(http.MethodGet, target)
			require.NoError(t, err)
			ht.SetCustomHeaders(req, map[string][]string{"Host": {configuredHost}})
			require.Equal(t, []string{configuredHost}, req.Header.Values("Host"),
				"premise: the unsafe branch put the configured Host in the header map")

			// Mirrors runner/runner.go:288-297, which disables the automatic Host header
			// when the user configured one of their own. The global is restored by
			// pinRawHTTPDefaults above.
			rawhttp.AutomaticHostHeader(tc.automaticHostHeader)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			observed := origin.requests()
			require.Len(t, observed, 1, "exactly one request must reach the origin")
			hostLines := observed[0].HeaderLinesNamed("Host")
			// The header lines are named rather than the whole head, following the
			// discipline the shared harness documents: never format a whole request into a
			// diagnostic, because a request line can carry a credential in its path or
			// query. These requests carry none, and the header set is what the assertion
			// is about.
			require.Len(t, hostLines, 1,
				"exactly one Host line may reach the wire: a duplicate would make the request ambiguous, got %q", observed[0].HeaderLines())
			require.Equal(t, tc.wantHostLine(addr), hostLines[0],
				"which authority the origin is actually asked for")
			require.Equal(t, tc.wantCallerHostValues(addr), req.Header.Values("Host"),
				"the raw client writes its automatic Host value into the caller's own header map, so a caller inspecting the request afterwards sees the wire value")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, responseBody, string(resp.Data), "the exchange must still complete on both configurations")
		})
	}
}

// The safe/unsafe request parity axis.
//
// getResponse (common/httpx/httpx.go:439-444) is a two-way switch on one option:
//
//	if h.Options.Unsafe {
//		return h.doUnsafeWithOptions(req, unsafeOptions)
//	}
//	return h.client.Do(req)
//
// The unsafe branch hands the request to rawhttp.DoRawWithOptions (:447-455), which frames
// and writes the message itself instead of going through the configured
// *retryablehttp.Client. Two caller-visible behaviours therefore diverge by design - Do
// skips chain collection entirely for an unsafe request (:420) and NewRequestWithContext
// injects none of the default headers (:499-504) - while everything else about the exchange
// must stay identical, because the same target is being probed either way and the tool
// reports both through the same *Response fields.
//
// Until these tests existed nothing in the repository executed that branch: no test file
// mentioned doUnsafeWithOptions or set Options.Unsafe, so doUnsafeWithOptions sat at 0.0%
// statement coverage and getResponse at 66.7% - its uncovered remainder being precisely the
// dispatch above. A regression in either would have shipped with a fully green suite: an
// inverted condition would send every unsafe probe through the safe client (silently
// re-adding the default User-Agent and the chain, and re-enabling redirect following by the
// client's own policy instead of rawhttp's), and a dropped URIPath argument would silently
// probe the wrong resource.
//
// WHY A REAL SOCKET, AND WHY THE SHARED MOCK CANNOT BE USED HERE. rawhttp dials the target
// itself and never consults http.Client.Transport, so a scripted http.RoundTripper is not
// merely inconvenient for this axis - it is unreachable. newMockHTTPX
// (common/httpx/mocktransport_test.go) states the same conclusion as a precondition,
// require.False(t, options.Unsafe), and that guard is deliberately left exactly as it is:
// these tests build their clients directly rather than relaxing it, so no mock-based test
// can ever drift onto a path the mock cannot observe.
//
// That absence of a transport seam is turned into the sharpest assertion available here. A
// poisonRoundTripper is installed on both of the retryable client's HTTP clients and then
// used as a dispatch oracle: on the unsafe path it must never be called, and on the safe
// path - same code, same request, one option flipped - it must be called exactly once and
// its sentinel must surface to the caller. Either half alone could pass under a defect; the
// pair cannot.
//
// HERMETICITY. The origin is an httptest.Server bound to 127.0.0.1, so no name is resolved
// and nothing leaves the loopback interface. MEASURED with strace over the tests below:
// every connect() is to 127.0.0.1, apart from one connect(AF_INET6, [2001:4860:4860::8888]:53)
// that fails immediately with EADDRNOTAVAIL and transmits nothing. That one is fastdialer's
// resolver probe inside New and is not attributable to the unsafe path at all - it appears
// identically when running TestTransportDisablesConnectionReuse
// (common/httpx/connection_test.go), which issues no request whatsoever.
//
// No test here opts into parallel execution, matching every other test in the package: New
// mutates the process-global GODEBUG variable on its HTTP/1.1 path (httpx.go:158), and these
// tests additionally count requests against a shared loopback listener, which parallel
// execution would make meaningless.

const (
	// unsafeParityBody is the origin's reply body. It carries three spaces and no newline
	// so the derived metrics are non-trivial and exact: Do counts words as
	// bytes.Count(body, ' ')+1 and lines as bytes.Count(TrimSpace(body), '\n')+1
	// (httpx.go:395-403), giving 4 and 1. A single-word body would make the word count
	// indistinguishable from the empty-body case.
	unsafeParityBody = "safe unsafe parity body"

	// unsafeParityContentType pins the reply's media type so the body is never MIME-sniffed
	// and DecodeData never transcodes it. The assertions below compare exact bytes across
	// two responses, and a transcode would silently replace them.
	unsafeParityContentType = "text/plain"

	// unsafeParityProbeHeader and unsafeParityProbeValue are a header the origin sets that
	// neither client would ever add by itself, so reading it back through the accessor
	// proves the response headers really came from the origin on both paths.
	unsafeParityProbeHeader = "X-Parity-Probe"
	unsafeParityProbeValue  = "origin"

	// unsafeParityRequestURI is the request target appended to the server's base URL. It
	// carries a path AND a repeated query key so the parity assertion covers more than "/":
	// a defect that dropped the query, reordered the repeated values or re-encoded the path
	// would change this exact string.
	unsafeParityRequestURI = "/probe?a=1&a=2"

	// unsafeParityOverrideURI is the raw request target used to prove that
	// UnsafeOptions.URIPath reaches the wire on the unsafe path and is ignored on the safe
	// one. It is deliberately distinguishable from unsafeParityRequestURI in both path and
	// query so neither can be mistaken for the other in an assertion failure.
	unsafeParityOverrideURI = "/override?x=1"

	// unsafeParityConnectionCloseLine is the header line the safe path adds to the reply
	// and the unsafe path does not, spelled with its CRLF terminator so it can be measured
	// in bytes. See TestGetResponseSafeUnsafeParity for why the difference exists.
	unsafeParityConnectionCloseLine = "Connection: close\r\n"
)

// unsafeParityObservation is the origin's view of one inbound request, as a value type.
//
// It deliberately carries no mutex so it can be returned and compared by value without
// tripping govet's copylocks check - unsafeParityRecorder owns the lock. That matches
// connectionObservation in common/httpx/connection_test.go and capturedRequest in
// common/httpx/request_body_test.go. Every field is something an observer on the connection
// could see, so nothing asserted from it is read back out of the client's own state.
type unsafeParityObservation struct {
	// Method, RequestURI and Proto are the three components of the request line, which is
	// the most direct protocol-visible evidence that both paths framed the same message.
	Method     string
	RequestURI string
	Proto      string
	// Host is the authority the origin resolved the request to, from the Host header.
	Host string
	// HeaderCount is the number of distinct header keys the origin received. It is the
	// assertion that catches a default header appearing on the unsafe path: checking only
	// User-Agent would miss Accept-Charset, and checking both would still miss a third.
	HeaderCount int
	// UserAgent and AcceptCharset are the two headers NewRequestWithContext injects on the
	// safe path only (httpx.go:501, :503).
	UserAgent     string
	AcceptCharset string
	// Close is net/http's parsed verdict on the request's Connection directive, and the
	// reason the two replies differ by one header line.
	Close bool
}

// unsafeParityRecorder collects the origin's view of every request the loopback server
// received.
//
// The mutex is required because the handler runs on a goroutine owned by the httptest server
// while the assertions run on the test goroutine. Pointer receivers are used throughout so
// the lock is never copied, following connectionRecorder in
// common/httpx/connection_test.go.
type unsafeParityRecorder struct {
	mu       sync.Mutex
	observed []unsafeParityObservation
}

// record stores the origin's view of one request.
//
// It performs no assertion of its own on purpose: require's FailNow calls runtime.Goexit,
// which on a server goroutine would abandon the response instead of failing the test, so
// every check is left to the test goroutine.
func (rec *unsafeParityRecorder) record(r *http.Request) {
	obs := unsafeParityObservation{
		Method:        r.Method,
		RequestURI:    r.RequestURI,
		Proto:         r.Proto,
		Host:          r.Host,
		HeaderCount:   len(r.Header),
		UserAgent:     r.Header.Get("User-Agent"),
		AcceptCharset: r.Header.Get("Accept-Charset"),
		Close:         r.Close,
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
func (rec *unsafeParityRecorder) observations() []unsafeParityObservation {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]unsafeParityObservation(nil), rec.observed...)
}

// newUnsafeParityOriginServer starts a loopback origin that records every request it
// receives and answers each one identically.
//
// Answering identically is what makes the response comparison meaningful: both clients hit
// this one server, so any difference between the two *Response values is attributable to the
// client path rather than to the origin. The reply is deliberately built from
// ResponseWriter defaults plus two explicit headers, so net/http supplies Content-Length and
// Date and the only header that can vary between the two exchanges is the one net/http
// derives from the request's own Connection directive.
//
// The server is returned WITHOUT a registered cleanup, matching newConnectionObserverServer
// in common/httpx/connection_test.go and newRequestBodyEchoServer in
// common/httpx/request_body_test.go, so every caller pairs it with a visible
// `defer ts.Close()` at the site that owns its lifetime.
func newUnsafeParityOriginServer(t *testing.T, rec *unsafeParityRecorder) *httptest.Server {
	t.Helper()
	require.NotNil(t, rec, "newUnsafeParityOriginServer: a recorder is required, there is nothing to observe without one")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", unsafeParityContentType)
		w.Header().Set(unsafeParityProbeHeader, unsafeParityProbeValue)
		_, _ = w.Write([]byte(unsafeParityBody))
	}))
}

// newParityHTTPX builds a client that differs from its sibling in exactly one option.
//
// A single builder is used for both sides of the axis on purpose. Reusing newLocalHTTPX
// (common/httpx/response_memory_test.go) for the safe client and writing a separate
// constructor for the unsafe one would leave a reader unable to tell whether an observed
// difference came from Options.Unsafe or from some other option the two constructors happened
// to set differently - which would make a parity test that proves nothing. Here every option
// is fixed identically and `unsafe` is the only variable, so any difference the assertions
// find is attributable to that flag alone.
//
// The options are a value copy, so nothing here can corrupt the package-level DefaultOptions
// that every other test reads. CdnCheck is disabled so New does not build a cdncheck client
// that would consult an external data source (httpx.go:238), following the existing pattern
// at :157 above. RetryMax is 0 so a failing request reports its cause once rather than
// retrying against a loopback listener.
//
// rt is optional. When non-nil it is installed on BOTH of the retryable client's HTTP
// clients, because retryablehttp falls back to its second client when an attempt reports a
// malformed HTTP version; installing on only one would leave a live path that this test
// could not account for. When nil the client keeps the transport New built, which is what
// the safe half of the parity comparison needs in order to actually reach the origin.
func newParityHTTPX(t *testing.T, unsafe bool, rt http.RoundTripper) *HTTPX {
	t.Helper()

	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 5 * time.Second
	options.RetryMax = 0
	options.Unsafe = unsafe

	ht, err := New(&options)
	require.NoError(t, err)
	// Release the disk-backed dialer history this construction allocated; see
	// registerDialerCleanup in common/httpx/mocktransport_test.go for why leaving it behind
	// makes every later New slower.
	registerDialerCleanup(t, ht)
	require.Equal(t, unsafe, ht.Options.Unsafe,
		"the constructed client must carry the requested Unsafe setting, since every assertion in this file attributes an observed difference to that one option")

	if rt != nil {
		ht.client.HTTPClient.Transport = rt
		ht.client.HTTPClient2.Transport = rt
	}
	return ht
}

// errUnsafeParityPoison is reported by poisonRoundTripper the moment the configured
// transport is used.
//
// Naming it with a sentinel is what makes the dispatch oracle work in both directions: on
// the unsafe path the error must never appear, and on the safe path errors.Is must find it
// underneath retryablehttp's wrapping. A bare error string would force a substring match on
// a message this test does not own.
var errUnsafeParityPoison = errors.New("configured client transport was used")

// poisonRoundTripper fails every round trip and counts how many it was asked to perform.
//
// It is the dispatch oracle for getResponse (common/httpx/httpx.go:439-444). Installed on
// both of the retryable client's HTTP clients, it distinguishes the two branches by whether
// it is reached at all: the unsafe branch hands the request to rawhttp, which dials the
// target itself and never touches an http.Client.Transport, so the count must stay at zero
// and the request must still succeed against the origin; the safe branch goes through
// h.client.Do, so the count must be exactly one and the sentinel must reach the caller.
//
// It refuses rather than answers deliberately. A round tripper that returned a plausible
// response would let a dispatch defect produce a passing safe-path assertion, whereas an
// outright refusal makes the wrong branch impossible to mistake for the right one.
type poisonRoundTripper struct {
	mu    sync.Mutex
	calls int
}

// RoundTrip records the attempt and refuses it.
func (p *poisonRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	return nil, errUnsafeParityPoison
}

// callCount reports how many round trips the transport was asked to perform.
//
// It reads under the same lock RoundTrip writes with, so the count can never be read while
// an attempt is still being recorded. It takes no *testing.T because it raises nothing
// itself, matching mockTransport.callCount() in common/httpx/mocktransport_test.go.
func (p *poisonRoundTripper) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestGetResponseSafeUnsafeParity drives the same request through both branches of
// getResponse against one origin and pins what must match and what must differ.
//
// The two clients come from newParityHTTPX with `unsafe` as the only difference between them,
// and they probe the same loopback server with the same method and the same request target,
// so every assertion below is a statement about the dispatch at
// common/httpx/httpx.go:439-444 and nothing else.
//
// MEASURED against the code as it stands. PARITY - identical on both paths:
//
//	origin's request line   GET /probe?a=1&a=2 HTTP/1.1, Host 127.0.0.1:<port>
//	status                  200
//	Data / RawData          "safe unsafe parity body", 23 bytes
//	ContentLength           23
//	Words / Lines           4 / 1
//	Content-Type            "text/plain"
//	X-Parity-Probe          "origin"
//	Raw                     RawHeaders followed by exactly the 23 body bytes
//	HasChain()              false
//	GetChainLastURL()       ""
//	GetChain()              ""
//
// DIVERGENCE 1 - chain collection. Do builds resp.Chain only when the request is safe
// (httpx.go:419-426, `if !h.Options.Unsafe`), because pdhttputil.GetChain walks the
// response<-request back-references that net/http populates and rawhttp does not. MEASURED:
// len(Chain) is 1 for the safe path and 0 for the unsafe one, and GetChainAsSlice agrees.
// Note that HasChain() is false on BOTH - it reports len(Chain) > 1 (response.go:99) and
// neither exchange redirected - so len(Chain) is the assertion that actually separates the
// two paths here; asserting HasChain alone would pass under a defect that dropped chain
// collection from the safe path as well.
//
// DIVERGENCE 2 - default headers. NewRequestWithContext sets User-Agent and adds
// Accept-Charset only when the request is safe (httpx.go:499-504). MEASURED at the origin:
// the safe request arrives with 4 header keys (Accept-Charset, Accept-Encoding, Connection,
// User-Agent) while the unsafe request arrives with ZERO - rawhttp forwards only what it was
// handed, and it was handed an empty header map. The header COUNT is asserted rather than
// just the two named headers, so a third default appearing on the unsafe path cannot slip
// through.
//
// DIVERGENCE 3 - the reply's Connection header, which follows from divergence 2 rather than
// being independent of it. The safe client's transport sets DisableKeepAlives
// (httpx.go:153), so its request announces Connection: close and net/http's server echoes
// that decision into the reply (RFC 9110 section 7.6.1); the unsafe request announces
// nothing, so the server keeps the connection alive and omits the line. MEASURED: the two
// RawHeaders differ by exactly the 19 bytes of "Connection: close\r\n" and by nothing else -
// asserted as a byte difference rather than as two absolute lengths so the assertion does not
// depend on the Date value, which both replies carry at the same fixed width.
func TestGetResponseSafeUnsafeParity(t *testing.T) {
	rec := &unsafeParityRecorder{}
	ts := newUnsafeParityOriginServer(t, rec)
	defer ts.Close()

	target := ts.URL + unsafeParityRequestURI

	// Request construction is asserted before either request is issued, because the default
	// headers are injected here rather than at dispatch, and because both paths must agree on
	// the URL they derived from the same target string.
	responses := make(map[bool]*Response, 2)
	for _, unsafe := range []bool{false, true} {
		ht := newParityHTTPX(t, unsafe, nil)

		req, err := ht.NewRequest(http.MethodGet, target)
		require.NoErrorf(t, err, "unsafe=%v: constructing the request must succeed for both paths, since Options.Unsafe only changes how the URL is parsed, not whether it can be", unsafe)
		require.Equalf(t, target, req.String(),
			"unsafe=%v: both paths must derive the same absolute URL from the same target, because doUnsafeWithOptions passes req.String() to rawhttp verbatim (httpx.go:450) while the safe path dials req.URL - a difference here would mean the two paths probed different resources", unsafe)

		if unsafe {
			require.Emptyf(t, req.Header,
				"unsafe=%v: an unsafe request must carry NO headers at construction time: NewRequestWithContext skips the default injection when Options.Unsafe (httpx.go:499-504), and rawhttp forwards exactly the map it is handed", unsafe)
		} else {
			require.Lenf(t, req.Header, 2,
				"unsafe=%v: a safe request must carry exactly the two injected defaults, User-Agent and Accept-Charset (httpx.go:501, :503)", unsafe)
			// defaultUserAgentLiteral rather than DefaultOptions.DefaultUserAgent, following
			// the reason recorded at common/httpx/url_semantics_test.go:10-13: deriving the
			// expectation from the option would let a configuration change update both the
			// input and the expectation, leaving the assertion unable to fail.
			require.Equalf(t, defaultUserAgentLiteral, req.Header.Get("User-Agent"),
				"unsafe=%v: the safe path must identify the client with the project's default user agent", unsafe)
			require.Equalf(t, "utf-8", req.Header.Get("Accept-Charset"),
				"unsafe=%v: the safe path must request utf-8 so the response decoder has a declared charset to work from", unsafe)
		}

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoErrorf(t, err, "unsafe=%v: the exchange must succeed on both paths", unsafe)
		responses[unsafe] = resp
	}

	safeResp, unsafeResp := responses[false], responses[true]

	// What the ORIGIN saw. Sequential requests, so arrival order is construction order.
	observed := rec.observations()
	require.Len(t, observed, 2,
		"the origin must have seen exactly two requests, one per path: a silent retry or an extra hop would make the comparison below describe traffic this test never issued")
	safeObs, unsafeObs := observed[0], observed[1]

	// PARITY on the wire: the request line and authority must be byte-identical.
	require.Equal(t, http.MethodGet, unsafeObs.Method,
		"the unsafe path must forward the method verbatim; doUnsafeWithOptions passes req.Method straight through (httpx.go:448)")
	require.Equal(t, safeObs.Method, unsafeObs.Method, "both paths must forward the same method")
	require.Equal(t, unsafeParityRequestURI, unsafeObs.RequestURI,
		"the unsafe path must reproduce the path AND the repeated query key exactly: rawhttp reconstructs the request line from req.String(), so a dropped query, a reordered repeated value or a re-encoded path would change this string")
	require.Equal(t, safeObs.RequestURI, unsafeObs.RequestURI,
		"both paths must request the same resource - this is the assertion that a caller comparing safe and unsafe results is entitled to rely on")
	require.Equal(t, "HTTP/1.1", unsafeObs.Proto,
		"rawhttp frames its messages as HTTP/1.1 (client.HTTP_1_1), matching what the safe client negotiates against a plain origin")
	require.Equal(t, safeObs.Proto, unsafeObs.Proto, "both paths must frame the exchange in the same protocol version")

	// The authority is asserted against the listener's own address rather than only across
	// the two paths, so neither can drift to a different origin together.
	wantAuthority := strings.TrimPrefix(ts.URL, "http://")
	require.Equal(t, wantAuthority, unsafeObs.Host,
		"the unsafe path must address the origin's own authority: rawhttp derives the Host header from the target URL it was handed (AutomaticHostHeader), so a wrong value here would mean a virtual-host-sensitive origin was asked for a different site")
	require.Equal(t, safeObs.Host, unsafeObs.Host,
		"both paths must address the same authority, so a virtual-host-sensitive origin cannot answer them differently")

	// DIVERGENCE 2, as the origin saw it.
	require.Equal(t, 4, safeObs.HeaderCount,
		"the safe request must arrive with exactly four header keys: the two injected defaults plus Accept-Encoding and Connection, which net/http's transport adds")
	require.Equal(t, 0, unsafeObs.HeaderCount,
		"the unsafe request must arrive with NO headers at all: asserting the count rather than only User-Agent and Accept-Charset is what makes this catch a third default leaking onto the raw path")
	require.Equal(t, defaultUserAgentLiteral, safeObs.UserAgent,
		"the safe path must announce the project's default user agent on the wire, not merely hold it on the request object")
	require.Equal(t, "", unsafeObs.UserAgent,
		"the unsafe path must announce no user agent: sending one would defeat the purpose of a raw request, which is to control the bytes exactly")
	require.Equal(t, "utf-8", safeObs.AcceptCharset, "the safe path must send the injected Accept-Charset")
	require.Equal(t, "", unsafeObs.AcceptCharset, "the unsafe path must send no Accept-Charset")

	// DIVERGENCE 3, as the origin parsed it - the cause of the reply difference asserted last.
	require.True(t, safeObs.Close,
		"the safe request must announce that its connection closes after this exchange, because its transport disables keep-alives (httpx.go:153)")
	require.False(t, unsafeObs.Close,
		"the unsafe request must announce nothing about the connection, since rawhttp sends no Connection header - this is what makes the two replies differ by exactly one line")

	// PARITY in the caller-visible response. Asserted as exact values first so a failure
	// names the wrong value, then as cross-path equality so a failure names the divergence.
	for unsafe, resp := range responses {
		require.Equalf(t, http.StatusOK, resp.StatusCode, "unsafe=%v: the origin answered 200, so the caller must see 200", unsafe)
		require.Equalf(t, []byte(unsafeParityBody), resp.Data,
			"unsafe=%v: the caller must receive the origin's body byte for byte on both paths", unsafe)
		require.Equalf(t, []byte(unsafeParityBody), resp.RawData,
			"unsafe=%v: the undecoded body must be retained identically on both paths", unsafe)
		require.Equalf(t, len(unsafeParityBody), resp.ContentLength,
			"unsafe=%v: the reported length must equal the %d bytes actually delivered", unsafe, len(unsafeParityBody))
		require.Equalf(t, 4, resp.Words,
			"unsafe=%v: the word count is derived from the body as bytes.Count(body, ' ')+1 (httpx.go:401), so three spaces give four", unsafe)
		require.Equalf(t, 1, resp.Lines,
			"unsafe=%v: the line count is derived from the body as bytes.Count(TrimSpace(body), '\\n')+1 (httpx.go:402), and the body carries no newline", unsafe)
		require.Equalf(t, unsafeParityContentType, resp.GetHeader("Content-Type"),
			"unsafe=%v: the origin's media type must reach the caller through the accessor on both paths", unsafe)
		require.Equalf(t, unsafeParityProbeValue, resp.GetHeader(unsafeParityProbeHeader),
			"unsafe=%v: a header neither client would add by itself must reach the caller, which proves the response headers really came from the origin", unsafe)
		require.Equalf(t, len(resp.RawHeaders)+len(unsafeParityBody), len(resp.Raw),
			"unsafe=%v: Raw must be exactly the response headers followed by the whole body - a short Raw would mean the body was still being read when the connection closed", unsafe)
		require.Falsef(t, resp.HasChain(),
			"unsafe=%v: neither exchange redirected, so HasChain must be false on both paths - it reports len(Chain) > 1 (response.go:99)", unsafe)
		require.Equalf(t, "", resp.GetChainLastURL(),
			"unsafe=%v: without a chain of more than one item there is no final redirect URL to report (response.go:104-109)", unsafe)
		require.Equalf(t, "", resp.GetChain(),
			"unsafe=%v: the chain dump omits the first request and the last response, so a single-item or empty chain contributes nothing (response.go:71-83)", unsafe)
	}

	// DIVERGENCE 1: chain collection is the one caller-visible field that must differ.
	require.Len(t, safeResp.Chain, 1,
		"the safe path must collect the single-hop chain: Do calls pdhttputil.GetChain whenever the request is safe (httpx.go:419-426)")
	require.Empty(t, unsafeResp.Chain,
		"the unsafe path must collect NO chain: Do skips chain building entirely when Options.Unsafe (httpx.go:419), because rawhttp does not populate the response<-request back-references GetChain walks")
	require.Len(t, safeResp.GetChainAsSlice(), 1,
		"the projection must expose the safe path's one chain item")
	require.Empty(t, unsafeResp.GetChainAsSlice(),
		"the projection must expose nothing for the unsafe path, so a consumer iterating it sees an empty result rather than a partially built item")

	// DIVERGENCE 3 in the reply, and the proof that it is the ONLY difference between the two
	// wire representations.
	require.Contains(t, safeResp.RawHeaders, unsafeParityConnectionCloseLine,
		"the safe reply must record that the connection closes after this exchange, echoing the directive the request announced (RFC 9110 section 7.6.1)")
	require.NotContains(t, unsafeResp.RawHeaders, "Connection:",
		"the unsafe reply must carry no Connection header at all, because its request announced nothing for the server to echo")
	require.Equal(t, len(unsafeResp.RawHeaders)+len(unsafeParityConnectionCloseLine), len(safeResp.RawHeaders),
		"the two replies must differ by exactly the %d bytes of %q and by nothing else: any other difference would mean the origin answered the two paths differently, which would invalidate every parity assertion above", len(unsafeParityConnectionCloseLine), unsafeParityConnectionCloseLine)
}

// TestGetResponseUnsafeDispatchBypassesConfiguredTransport proves WHICH branch of
// getResponse ran, and that UnsafeOptions is honoured on exactly one of them.
//
// The parity test above compares outcomes; this one identifies the mechanism, which is what
// makes the pair mutation-resistant rather than merely descriptive. An inverted dispatch
// condition at common/httpx/httpx.go:440 would keep most of the parity assertions passing on
// the safe path and would only be caught here.
//
// THE ORACLE. poisonRoundTripper is installed on both of the retryable client's HTTP clients
// and refuses every round trip with errUnsafeParityPoison. Because rawhttp dials the target
// itself and never consults http.Client.Transport, the transport it is installed on is
// reached if and only if the safe branch ran. MEASURED, with the same request and the same
// origin, one option apart:
//
//	unsafe=true   request SUCCEEDS against the origin,  poison call count 0
//	unsafe=false  request FAILS with the sentinel,      poison call count 1, resp nil
//
// Both halves are required. The unsafe half alone would pass under a defect that made
// getResponse ignore its transport entirely; the safe half alone would pass under a defect
// that made every request unsafe. Together they pin the dispatch in both directions.
//
// THE URIPath ARGUMENT. doUnsafeWithOptions forwards unsafeOptions.URIPath to rawhttp as the
// raw request target (httpx.go:451, :454) while the safe branch never looks at unsafeOptions
// at all (:443). MEASURED at the origin with the same UnsafeOptions value passed to both: the
// unsafe request line becomes "/override?x=1" and the safe one stays "/probe?a=1&a=2". That
// asymmetry is protocol-visible and load bearing - a dropped argument would silently probe
// the wrong resource, and a leaked one would silently redirect every safe probe.
//
// The three exchanges are issued SEQUENTIALLY against one recorder, so arrival order is the
// order asserted below.
func TestGetResponseUnsafeDispatchBypassesConfiguredTransport(t *testing.T) {
	rec := &unsafeParityRecorder{}
	ts := newUnsafeParityOriginServer(t, rec)
	defer ts.Close()

	target := ts.URL + unsafeParityRequestURI

	// 1. The unsafe branch must never reach the configured transport, yet must still succeed.
	unsafePoison := &poisonRoundTripper{}
	unsafeHT := newParityHTTPX(t, true, unsafePoison)
	unsafeReq, err := unsafeHT.NewRequest(http.MethodGet, target)
	require.NoError(t, err)

	unsafeResp, err := unsafeHT.Do(unsafeReq, UnsafeOptions{})
	require.NoError(t, err,
		"the unsafe exchange must succeed even though the configured transport refuses every round trip, because rawhttp dials the origin itself")
	require.NotErrorIs(t, err, errUnsafeParityPoison,
		"the sentinel must not surface on the unsafe path: if it does, getResponse dispatched to h.client.Do instead of doUnsafeWithOptions (httpx.go:440)")
	require.Equal(t, 0, unsafePoison.callCount(),
		"the configured transport must be asked for ZERO round trips on the unsafe path - this is the positive proof that doUnsafeWithOptions ran, and it is unavailable to any mock-based test because rawhttp never consults http.Client.Transport")
	require.Equal(t, http.StatusOK, unsafeResp.StatusCode,
		"the unsafe exchange reached the origin and must report its 200")
	require.Equal(t, []byte(unsafeParityBody), unsafeResp.Data,
		"the unsafe exchange must deliver the origin's body, proving the request really was written to the socket rather than short-circuited")

	// 2. The safe branch, one option apart, must reach that same transport exactly once.
	safePoison := &poisonRoundTripper{}
	safeHT := newParityHTTPX(t, false, safePoison)
	safeReq, err := safeHT.NewRequest(http.MethodGet, target)
	require.NoError(t, err)

	safeResp, safeErr := safeHT.Do(safeReq, UnsafeOptions{})
	require.Error(t, safeErr,
		"the safe exchange must fail, because the safe branch goes through h.client.Do and the configured transport refuses every round trip")
	require.ErrorIs(t, safeErr, errUnsafeParityPoison,
		"the refusal must reach the caller as the sentinel underneath retryablehttp's wrapping: this is the positive proof that h.client.Do ran, and it is the mirror of the zero call count above")
	require.Nil(t, safeResp,
		"Do must return no response when the transport never produced one (httpx.go:262-264)")
	require.Equal(t, 1, safePoison.callCount(),
		"the configured transport must be asked for exactly one round trip: RetryMax is 0, so more than one would mean the request was retried and fewer would mean it never dispatched")

	// 3. UnsafeOptions.URIPath: honoured on the unsafe path, ignored on the safe one.
	for _, unsafe := range []bool{true, false} {
		ht := newParityHTTPX(t, unsafe, nil)
		req, err := ht.NewRequest(http.MethodGet, target)
		require.NoErrorf(t, err, "unsafe=%v: constructing the request must succeed", unsafe)

		resp, err := ht.Do(req, UnsafeOptions{URIPath: unsafeParityOverrideURI})
		require.NoErrorf(t, err, "unsafe=%v: the exchange must succeed with an override supplied", unsafe)
		require.Equalf(t, http.StatusOK, resp.StatusCode,
			"unsafe=%v: the origin answers 200 for every path it serves, so an override must not change the status", unsafe)
		require.Equalf(t, []byte(unsafeParityBody), resp.Data,
			"unsafe=%v: the override changes which resource is requested, not what the origin returns", unsafe)
	}

	// The origin's record is the evidence: one request per exchange, in order, with the
	// override applied to exactly one of the last two.
	observed := rec.observations()
	require.Len(t, observed, 3,
		"the origin must have seen exactly three requests: the successful unsafe exchange plus the two override exchanges. The safe poisoned exchange never reached it, which is itself part of the proof - a fourth request here would mean the poison transport had been bypassed")

	require.Equal(t, unsafeParityRequestURI, observed[0].RequestURI,
		"the first exchange supplied no override, so the unsafe path must have used the request's own target")
	require.Equal(t, unsafeParityOverrideURI, observed[1].RequestURI,
		"the unsafe path must put UnsafeOptions.URIPath on the wire verbatim, replacing the request's own path AND query: doUnsafeWithOptions forwards it to rawhttp as the raw request target (httpx.go:451, :454)")
	require.Equal(t, unsafeParityRequestURI, observed[2].RequestURI,
		"the safe path must IGNORE UnsafeOptions.URIPath entirely - getResponse hands unsafeOptions only to the unsafe branch (httpx.go:440-443), so a safe probe must reach the resource its request named and nothing else")
	require.NotEqual(t, observed[1].RequestURI, observed[2].RequestURI,
		"the same UnsafeOptions value must produce different request lines on the two paths; equal values here would mean the override had either leaked onto the safe path or been dropped from the unsafe one")

	for i, obs := range observed {
		require.Equalf(t, http.MethodGet, obs.Method, "request %d: the method must survive on both paths", i+1)
		require.Equalf(t, "HTTP/1.1", obs.Proto, "request %d: every exchange must be framed as HTTP/1.1", i+1)
	}
}
