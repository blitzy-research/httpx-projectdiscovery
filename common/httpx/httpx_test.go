package httpx

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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
}
