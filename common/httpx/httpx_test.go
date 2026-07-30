package httpx

import (
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

// TestDoSwitchingProtocolsProtocolVisibleOutcome is the protocol-visible sibling of
// TestDoSwitchingProtocolsDoesNotHang above. That test proves Do returns instead of
// blocking forever on a websocket upgrade, but it discards both return values, so a
// defect that made Do surface the wrong status code, drop the upgrade headers, or
// spuriously populate a body for a 101 would keep it green. This test asserts what an
// observer can actually inspect after the call. It is deliberately added as a separate
// function rather than folded into the existing one so the anti-hang regression test
// stays byte-identical.
//
// Every expected value was measured against the current implementation and is traced
// to the line that produces it:
//   - StatusCode          <- httpx.go:358, assigned from httpresp.StatusCode
//   - empty Data/RawData  <- httpx.go:279 classifies 101 as a body-skip status, so the
//     read at httpx.go:313-319 never runs and respbody stays nil (httpx.go:338, :355)
//   - ContentLength 0     <- httpx.go:341-353 finds neither a Content-Length header nor
//     a body, so the field keeps its zero value
//   - Words/Lines 0       <- httpx.go:365-376 is guarded by len(respbody) > 0
//   - Headers             <- httpx.go:275, httpresp.Header.Clone(). Response.Headers is
//     a plain map[string][]string and GetHeader (response.go:42) is a raw, case-sensitive
//     lookup, so canonical MIME spellings are required
//   - Raw/RawHeaders      <- httpx.go:310-311, from DumpResponseHeadersAndRaw
func TestDoSwitchingProtocolsProtocolVisibleOutcome(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.NoError(t, err)

	// The scripted round tripper is installed on both clients on purpose: New wires a
	// separate HTTP/2 fallback client unless HTTP/1.1 is forced, so leaving either one
	// on its real transport would leave a path that could escape to the network.
	rt := switchingProtocolsRoundTripper{}
	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	// Intercepted by the round tripper above, so this host is never resolved or dialled.
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
		"the 101 must reach the caller verbatim, not be normalized to 200 or dropped")

	// A protocol switch has no HTTP body: the bytes after the header block belong to the
	// upgraded protocol. Absences are asserted as exact values, never as nil checks.
	require.Empty(t, resp.Data, "no body may be read for a protocol switch")
	require.Empty(t, resp.RawData, "no undecoded body may be retained for a protocol switch")
	require.Equal(t, 0, resp.ContentLength,
		"with no Content-Length header and no body the recomputation must leave the length at 0")
	require.Equal(t, 0, resp.Words, "word count is derived from the body, which was never read")
	require.Equal(t, 0, resp.Lines, "line count is derived from the body, which was never read")

	// The upgrade handshake headers are the entire protocol-visible payload of a 101.
	require.Equal(t, "websocket", resp.GetHeader("Upgrade"),
		"the negotiated protocol must survive to the caller")
	require.Equal(t, "Upgrade", resp.GetHeader("Connection"),
		"the hop-by-hop upgrade signal must survive to the caller")
	require.Equal(t, "", resp.GetHeader("Content-Length"),
		"a header the origin never sent must read back as the empty string")

	// Raw is NOT HTTP wire format for a 1xx response, and that is the sharpest
	// protocol-visible fact about this path. DumpResponseHeadersAndRaw
	// (projectdiscovery/utils@v0.11.1, http/httputil.go:34-41) cannot serialize a
	// protocol switch through httputil.DumpResponse, so for any status in
	// [100 Continue, 103 Early Hints] it hand-builds a synthetic string instead: the
	// Status field verbatim with no "HTTP/1.1 " prefix, then one line per header
	// rendered with %s over the []string value - hence the Go slice brackets - joined
	// with bare LF rather than CRLF. It returns that one buffer as both the header dump
	// and the full response, which is why Raw and RawHeaders are identical here.
	//
	// Measured: 67 bytes, "101 Switching Protocols\n" + "Upgrade: [websocket]\n" +
	// "Connection: [Upgrade]\n". The two header lines are asserted as an exact set
	// rather than as one exact string because that upstream loop is a Go map range
	// whose iteration order is randomized; 200 successive calls produced both
	// permutations (172 and 28). Every component is still pinned byte-exactly - only
	// the ordering, which is genuinely nondeterministic upstream, is left free.
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
