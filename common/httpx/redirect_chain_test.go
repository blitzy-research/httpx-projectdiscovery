package httpx

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests cover the five Response chain accessors consumed by runner output.
// Synthetic hosts are handled entirely by the shared RoundTripper, and tests remain
// sequential because New mutates process-wide GODEBUG on the HTTP/1.1 path.

// Fixture targets. origin.example is a synthetic authority that exists only inside the
// scripted transport and is never resolved or dialled.
const (
	chainTargetA      = "http://origin.example/a"
	chainTargetB      = "http://origin.example/b"
	chainTargetC      = "http://origin.example/c"
	chainSingleTarget = "http://origin.example/only"
)

// Per-hop body markers. Each is a distinct literal so a body leaking into a header dump
// is unmistakable, and all three are deliberately the same 12-byte length so every
// scripted hop declares the identical "Content-Length: 12" - which is what lets the dump
// assertions below pin an exact byte count.
const (
	chainBodyMarkerA   = "BODYMARKER-A"
	chainBodyMarkerB   = "BODYMARKER-B"
	chainBodyMarkerC   = "BODYMARKER-C"
	chainSingleHopBody = "single hop body"
)

// chainMaxRedirects exceeds the fixture's two redirects, so the guard at
// common/httpx/httpx.go:104 cannot terminate these chains; redirect-budget behavior is
// covered in redirect_test.go.
const chainMaxRedirects = 10

// Expected header-only dumps for the three-hop fixture. The initial request carries
// HTTP/1.1; redirect-generated requests carry zero protocol fields and dump as HTTP/0.0.
// Response dumps preserve relative Location header bytes, while GetChainAsSlice exposes
// resolved Locations. Each dump ends at the header terminator because the upstream
// builder excludes bodies.
const (
	chainChainRequest0  = "GET /a HTTP/1.1\r\nHost: origin.example\r\n\r\n"
	chainChainResponse0 = "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 12\r\nLocation: /b\r\n\r\n"
	chainChainRequest1  = "GET /b HTTP/0.0\r\nHost: origin.example\r\nReferer: http://origin.example/a\r\n\r\n"
	chainChainResponse1 = "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 12\r\nLocation: /c\r\n\r\n"
	chainChainRequest2  = "GET /c HTTP/0.0\r\nHost: origin.example\r\nReferer: http://origin.example/b\r\n\r\n"
	chainChainResponse2 = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
)

// Expected header-only dumps for the single-hop fixture; its 15-byte body appears only
// as Content-Length.
const (
	chainSingleRequestDump  = "GET /only HTTP/1.1\r\nHost: origin.example\r\n\r\n"
	chainSingleResponseDump = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n"
)

// chainHeaderTerminator is the CRLF pair that closes an HTTP header block. A dump that
// ends here carries no body byte at all, which is the structural property
// TestChainDumpsCarryNoBody asserts.
const chainHeaderTerminator = "\r\n\r\n"

// newChainFixture creates 301 /a -> 301 /b -> 200 /c with relative Locations. Relative
// values let tests distinguish wire header bytes from the absolute Locations resolved by
// the chain builder. Distinct body markers verify dumps exclude bodies.
func newChainFixture(t *testing.T) (*Response, *mockTransport) {
	t.Helper()

	// Routes are keyed host-qualified, which scriptedRedirects matches ahead of a bare
	// path, so the fixture states the authority it expects instead of accepting any.
	mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusMovedPermanently, location: "/b", body: chainBodyMarkerA},
		"origin.example/b": {status: http.StatusMovedPermanently, location: "/c", body: chainBodyMarkerB},
		"origin.example/c": {status: http.StatusOK, body: chainBodyMarkerC},
	}))

	// Set FollowRedirects before New because New selects the CheckRedirect closure
	// during construction; changing the flag afterwards cannot replace the selected
	// closure.
	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = chainMaxRedirects
	}, mt)

	req, err := retryablehttp.NewRequest(http.MethodGet, chainTargetA, nil)
	require.NoError(t, err, "the fixture target must parse, otherwise no hop ever reaches the chain builder")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err,
		"the scripted chain must complete, so a chain assertion below cannot be a failed request in disguise")
	require.Equal(t, 3, mt.callCount(),
		"exactly three round trips must reach the transport - /a, /b and /c - so the chain describes real traffic")
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"both 301s must have been followed through to the terminal 200, otherwise the chain is not the one under test")
	require.Len(t, resp.Chain, 3,
		"precondition for every accessor below: the builder must have reconstructed all three hops")

	return resp, mt
}

// newTwoHopChainFixture creates 302 /a -> 200 /b. A two-item chain is the minimum
// HasChain boundary and reduces GetChain to response0+request1, exercising each write
// branch once.
func newTwoHopChainFixture(t *testing.T) (*Response, *mockTransport) {
	t.Helper()

	mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: chainBodyMarkerA},
		"origin.example/b": {status: http.StatusOK, body: chainBodyMarkerB},
	}))

	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = chainMaxRedirects
	}, mt)

	req, err := retryablehttp.NewRequest(http.MethodGet, chainTargetA, nil)
	require.NoError(t, err, "the boundary fixture target must parse, otherwise no hop reaches the chain builder")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err, "the single 302 must be followed through to its target")
	require.Equal(t, 2, mt.callCount(),
		"exactly two round trips must reach the transport - /a and /b - so the chain has length two on the wire too")
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the 302 must have been followed to the terminal 200, otherwise the chain is not the one under test")
	require.Len(t, resp.Chain, 2,
		"precondition: the boundary case is meaningless unless the chain really has exactly two items")

	return resp, mt
}

// TestChainAccessorsMultiHop verifies status order, resolved Locations, RequestURLs,
// HasChain, and the exact final URL consumed by runner output. Relative fixture Locations
// ensure absolute projected values prove resolution rather than copying.
func TestChainAccessorsMultiHop(t *testing.T) {
	resp, mt := newChainFixture(t)

	require.Len(t, resp.Chain, 3,
		"one chain item per hop: the two 301s and the terminal 200")
	require.Equal(t, []int{http.StatusMovedPermanently, http.StatusMovedPermanently, http.StatusOK},
		resp.GetChainStatusCodes(),
		"GetChainStatusCodes (response.go:62-68) must report every hop's status in progressive order")
	require.True(t, resp.HasChain(),
		"HasChain is len(r.Chain) > 1 (response.go:100), which a three-item chain satisfies")

	require.Equal(t, chainTargetC, resp.GetChainLastURL(),
		"GetChainLastURL must be the absolute URL of the last hop actually requested")

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3,
		"GetChainAsSlice (response.go:85-96) projects every item unconditionally, so it must be as long as the chain")
	require.Equal(t, slice[len(slice)-1].RequestURL, resp.GetChainLastURL(),
		"GetChainLastURL must be exactly the last item's RequestURL (response.go:107), not a recomputed value")

	statusCodes := make([]int, 0, len(slice))
	locations := make([]string, 0, len(slice))
	requestURLs := make([]string, 0, len(slice))
	for _, item := range slice {
		statusCodes = append(statusCodes, item.StatusCode)
		locations = append(locations, item.Location)
		requestURLs = append(requestURLs, item.RequestURL)
	}

	require.Equal(t, resp.GetChainStatusCodes(), statusCodes,
		"the projection must carry the same status codes, in the same order, as the dedicated accessor")

	// The last item's Location is the empty string because a 200 carries no Location
	// header: the builder derives the field from http.Response.Location(), which reports
	// http.ErrNoLocation in that case and leaves the field zero. Asserted as exact
	// empty-string equality, never as a nil check.
	require.Equal(t, []string{chainTargetB, chainTargetC, ""}, locations,
		"each redirect hop must expose its resolved absolute Location, and the terminal hop none at all")

	require.Equal(t, []string{chainTargetA, chainTargetB, chainTargetC}, requestURLs,
		"RequestURL must name the absolute URL each hop was sent to, in progressive order")

	// The fixture sends relative Location headers; comparing the response dump with the
	// absolute projected Location verifies that the builder resolved, rather than copied,
	// the value.
	require.Contains(t, slice[0].Response, "Location: /b"+chainHeaderTerminator,
		"the first hop's response dump must show the relative Location bytes the origin actually sent")
	require.Equal(t, chainTargetB, slice[0].Location,
		"the chain item must expose that relative Location resolved against the hop's own request URL")

	// Cross-check against the wire: the chain's RequestURL sequence must match the
	// requests that genuinely reached the transport, so a fabricated or misordered chain
	// cannot pass.
	hops := mt.requests()
	require.Len(t, hops, 3, "exactly three requests must have gone out, one per chain item")
	require.Equal(t, requestURLs, []string{hops[0].URL, hops[1].URL, hops[2].URL},
		"every RequestURL must correspond, in order, to a request the transport really saw")
	require.Equal(t, []string{http.MethodGet, http.MethodGet, http.MethodGet},
		[]string{hops[0].Method, hops[1].Method, hops[2].Method},
		"a 301 rewrites the follow-up to GET, so every hop of this chain must be a GET")

	// A two-item chain is the minimum value for which HasChain must return true;
	// TestChainSingleItemAccessors covers the false boundary.
	t.Run("a two item chain is the lowest length HasChain accepts", func(t *testing.T) {
		boundary, boundaryTransport := newTwoHopChainFixture(t)

		require.Len(t, boundary.Chain, 2, "one redirect must yield exactly two chain items")
		require.True(t, boundary.HasChain(),
			"two items must satisfy len(r.Chain) > 1, and two is the smallest length that does")
		require.Equal(t, []int{http.StatusFound, http.StatusOK}, boundary.GetChainStatusCodes(),
			"the boundary chain must report the 302 then the 200, in that order")
		require.Equal(t, chainTargetB, boundary.GetChainLastURL(),
			"the final URL must be the redirect target, which is the value the runner emits for this scan")
		require.Equal(t, []byte(chainBodyMarkerB), boundary.Data,
			"the redirect target's body must reach the caller, so the chain describes a completed request")

		boundarySlice := boundary.GetChainAsSlice()
		require.Len(t, boundarySlice, 2, "the projection must carry both items")
		require.Equal(t, []string{chainTargetB, ""},
			[]string{boundarySlice[0].Location, boundarySlice[1].Location},
			"the 302 exposes its resolved absolute Location and the terminal 200 exposes none")
		require.Equal(t, []string{chainTargetA, chainTargetB},
			[]string{boundarySlice[0].RequestURL, boundarySlice[1].RequestURL},
			"both RequestURLs must name the absolute URL their hop was sent to")

		boundaryHops := boundaryTransport.requests()
		require.Equal(t, []string{chainTargetA, chainTargetB},
			[]string{boundaryHops[0].URL, boundaryHops[1].URL},
			"the chain's RequestURL sequence must match the requests the transport really saw")
	})

	// The same accessor surface, driven with a credential-bearing target, where Location
	// resolution decides whether the credential reaches caller-visible output.
	t.Run("a credential in the target URL reaches the accessors when Location is relative", assertChainRetainsURLUserinfoInCallerVisibleOutput)
}

// TestChainGetChainOmitsFirstRequestAndLastResponse verifies GetChain's loop contract:
// index 0 contributes no request and the final index contributes no response. For three
// items the exact composition is response0+request1+response1+request2; GetChainAsSlice
// still retains the omitted fields.
func TestChainGetChainOmitsFirstRequestAndLastResponse(t *testing.T) {
	resp, _ := newChainFixture(t)

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3, "precondition: the projection must expose all three items to compose against")

	dump := resp.GetChain()
	require.NotEmpty(t, dump, "a three-item chain must produce a dump; only a single-item chain yields the empty string")

	// Compose the expected dump from projected items to exercise both loop conditions
	// directly.
	require.Equal(t, slice[0].Response+slice[1].Request+slice[1].Response+slice[2].Request, dump,
		"the dump must be exactly response0+request1+response1+request2, per the two loop conditions at response.go:74 and :77")

	require.Equal(t, chainChainResponse0+chainChainRequest1+chainChainResponse1+chainChainRequest2, dump,
		"the dump must match the measured bytes for this fixture exactly")
	require.Len(t, dump, 286,
		"68+75+68+75 bytes for this fixture, which is stable because every hop declares the same 12-byte length")

	require.Contains(t, dump, "Location: /b"+chainHeaderTerminator,
		"the first response survives, carrying the relative Location bytes the origin sent")
	require.Contains(t, dump, "GET /b HTTP/0.0",
		"the second request survives, because the omission at response.go:74 applies to index 0 only")
	require.Contains(t, dump, "GET /c HTTP/0.0",
		"the third request survives, because it is not index 0 either")

	// Absence: the two omitted pieces. Each is first shown to EXIST in the structured
	// projection, so its absence from the dump is provably GetChain's doing and not
	// missing data.
	require.NotEmpty(t, slice[0].Request,
		"the first request dump must exist in the projection, otherwise its absence below would prove nothing")
	require.NotEmpty(t, slice[2].Response,
		"the last response dump must exist in the projection, otherwise its absence below would prove nothing")
	require.NotContains(t, dump, slice[0].Request,
		"the first request must be absent from the dump: response.go:74 skips Request at index 0")
	require.NotContains(t, dump, slice[2].Response,
		"the last response must be absent from the dump: response.go:77 skips Response at the final index")
	require.NotContains(t, dump, "GET /a",
		"no request line for the caller's own target may appear, which is the visible symptom of the index-0 omission")
	require.NotContains(t, dump, "200 OK",
		"no status line for the terminal response may appear, which is the visible symptom of the final-index omission")

	// The absolute Location form belongs to the projection, not to the wire. Asserting
	// its absence from the dump pins the distinction between the bytes the origin sent
	// and the value the builder resolved; note the plain host-and-path substring does
	// occur inside a Referer header, so the assertion is phrased as the whole field.
	require.NotContains(t, dump, "Location: "+chainTargetB,
		"the dump carries the relative Location the origin sent, so the resolved absolute form must not appear as a field")

	// With two items, GetChain reduces to response0+request1, exercising each write
	// branch once while preserving both omissions.
	t.Run("a two item chain omits the same two pieces", func(t *testing.T) {
		boundary, _ := newTwoHopChainFixture(t)

		boundarySlice := boundary.GetChainAsSlice()
		require.Len(t, boundarySlice, 2, "precondition: both items must be projected to compose against")

		boundaryDump := boundary.GetChain()
		require.NotEmpty(t, boundaryDump, "a two-item chain must still produce a dump")
		require.Equal(t, boundarySlice[0].Response+boundarySlice[1].Request, boundaryDump,
			"with two items the dump must be exactly response0+request1, one write from each branch")

		require.NotEmpty(t, boundarySlice[0].Request,
			"the omitted first request must exist in the projection, otherwise its absence proves nothing")
		require.NotEmpty(t, boundarySlice[1].Response,
			"the omitted last response must exist in the projection, otherwise its absence proves nothing")
		require.NotContains(t, boundaryDump, boundarySlice[0].Request,
			"the first request must still be omitted at this arity: response.go:74 skips index 0")
		require.NotContains(t, boundaryDump, boundarySlice[1].Response,
			"the last response must still be omitted at this arity: response.go:77 skips the final index")
		require.NotContains(t, boundaryDump, "GET /a",
			"no request line for the caller's own target may appear, exactly as in the three-item case")
		require.NotContains(t, boundaryDump, "200 OK",
			"no status line for the terminal response may appear, exactly as in the three-item case")
		require.Contains(t, boundaryDump, "GET /b HTTP/0.0",
			"the surviving piece is the redirect follow-up's request, dumped with the zero-valued protocol version")
		require.Contains(t, boundaryDump, "302 Found",
			"the surviving response is the 302 itself, which is what makes the omission of the 200 visible")
	})
}

// TestChainDumpsCarryNoBody verifies that the upstream builder records headers only: it
// calls DumpRequest and DumpResponse with body=false. Distinct markers confirm no dump
// contains any hop body, while resp.Data still contains the terminal body.
func TestChainDumpsCarryNoBody(t *testing.T) {
	resp, _ := newChainFixture(t)

	// The body did reach the caller: absence from the dumps is a dump property, not a
	// lost response.
	require.Equal(t, []byte(chainBodyMarkerC), resp.Data,
		"the terminal hop's body must reach the caller in full, even though no dump contains it")
	require.Equal(t, len(chainBodyMarkerC), resp.ContentLength,
		"the caller-visible length must be the terminal hop's own 12 bytes")

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3, "precondition: every hop must be projected so every dump can be inspected")

	allMarkers := []string{chainBodyMarkerA, chainBodyMarkerB, chainBodyMarkerC}

	for _, tc := range []struct {
		name         string
		index        int
		wantRequest  string
		wantResponse string
	}{
		{"hop 1 the 301 at slash a", 0, chainChainRequest0, chainChainResponse0},
		{"hop 2 the 301 at slash b", 1, chainChainRequest1, chainChainResponse1},
		{"hop 3 the terminal 200 at slash c", 2, chainChainRequest2, chainChainResponse2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := slice[tc.index]

			// Non-emptiness first: without it every NotContains below could pass
			// vacuously on an empty string.
			require.NotEmpty(t, item.Request, "the request dump must exist, otherwise the body checks below prove nothing")
			require.NotEmpty(t, item.Response, "the response dump must exist, otherwise the body checks below prove nothing")

			require.Equal(t, tc.wantRequest, item.Request, "the request dump must match the measured header-only bytes exactly")
			require.Equal(t, tc.wantResponse, item.Response, "the response dump must match the measured header-only bytes exactly")

			require.Contains(t, item.Response, "Content-Length: 12\r\n",
				"the dump must still DECLARE the 12-byte payload, which is what makes its absence a framing decision")

			require.True(t, strings.HasSuffix(item.Request, chainHeaderTerminator),
				"the request dump must end at the blank line closing its header block, leaving no room for a body")
			require.True(t, strings.HasSuffix(item.Response, chainHeaderTerminator),
				"the response dump must end at the blank line closing its header block, leaving no room for a body")

			for _, marker := range allMarkers {
				require.NotContains(t, item.Request, marker,
					"no body marker may appear in a request dump, including "+marker+" from another hop")
				require.NotContains(t, item.Response, marker,
					"no body marker may appear in a response dump, including "+marker+" from another hop")
			}
		})
	}

	dump := resp.GetChain()
	for _, marker := range allMarkers {
		require.NotContains(t, dump, marker,
			"the concatenated chain dump must stay body-free as well, including "+marker)
	}

	// The dumps carry no body, but they do carry every header verbatim - the other half
	// of what the dump bytes contain.
	t.Run("the dumps retain request and response headers verbatim", assertChainDumpsExposeSensitiveHeaders)
}

// TestChainRedirectHopsDumpProtoZero verifies that the original request dump carries
// HTTP/1.1 while redirect-generated requests dump as HTTP/0.0. NewRequestWithContext
// initializes the original request's protocol fields; net/http's redirect request leaves
// them zero, and upstream DumpRequest surfaces those values. GetChainAsSlice is used for
// index 0 because GetChain omits the first request.
func TestChainRedirectHopsDumpProtoZero(t *testing.T) {
	resp, _ := newChainFixture(t)

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3, "precondition: all three request dumps must be projected")

	require.True(t, strings.HasPrefix(slice[0].Request, "GET /a HTTP/1.1\r\n"),
		"the first item is the caller's own request, which net/http stamped with HTTP/1.1")
	require.Equal(t, chainChainRequest0, slice[0].Request,
		"the first request dump must match the measured bytes exactly")
	require.NotContains(t, slice[0].Request, "HTTP/0.0",
		"the caller's request must not carry the zero-valued protocol of a redirect follow-up")

	for _, tc := range []struct {
		name        string
		index       int
		wantPrefix  string
		wantRequest string
	}{
		{"hop 2 follow up to slash b", 1, "GET /b HTTP/0.0\r\n", chainChainRequest1},
		{"hop 3 follow up to slash c", 2, "GET /c HTTP/0.0\r\n", chainChainRequest2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := slice[tc.index].Request

			require.True(t, strings.HasPrefix(got, tc.wantPrefix),
				"a redirect follow-up dumps its request line with the zero-valued protocol version")
			require.Equal(t, tc.wantRequest, got,
				"the follow-up request dump must match the measured bytes exactly, Referer included")
			require.Contains(t, got, "HTTP/0.0",
				"HTTP/0.0 is the visible trace of net/http leaving ProtoMajor and ProtoMinor unset on a redirect")
			require.NotContains(t, got, "HTTP/1.1",
				"no HTTP/1.1 may appear: a follow-up carrying it would mean the item points at the wrong request object")
		})
	}

	dump := resp.GetChain()
	require.Contains(t, dump, "GET /b HTTP/0.0",
		"the concatenated dump must carry the follow-up's zero-valued protocol version too")
	require.NotContains(t, dump, "GET /b HTTP/1.1",
		"a follow-up request line with a real protocol version must not appear anywhere in the dump")
}

// TestChainSingleItemAccessors verifies the no-redirect boundary. A single item makes
// HasChain false and GetChainLastURL empty. Both GetChain loop conditions omit the sole
// item, so GetChain is empty even though GetChainAsSlice retains the request and response
// dumps; Location remains empty because the 200 has no Location header.
func TestChainSingleItemAccessors(t *testing.T) {
	// A plain 200 with no Location header, so no redirect can occur.
	mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/only": {status: http.StatusOK, body: chainSingleHopBody},
	}))

	// Redirect following is enabled deliberately, matching newChainFixture: the chain
	// must be one item long because the origin never redirected, not because the client
	// was configured to refuse.
	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = chainMaxRedirects
	}, mt)

	req, err := retryablehttp.NewRequest(http.MethodGet, chainSingleTarget, nil)
	require.NoError(t, err, "the fixture target must parse, otherwise the accessors are never reached")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err, "the mocked round trip must succeed, so an empty accessor result cannot be a failed request")
	require.Equal(t, 1, mt.callCount(), "exactly one round trip may reach the transport: nothing redirected")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the accessors must be reading the single 200 under test")
	require.Equal(t, []byte(chainSingleHopBody), resp.Data, "the body must reach the caller on the non-redirect path too")

	require.Len(t, resp.Chain, 1, "a response that never redirected still yields one chain item: itself")
	require.False(t, resp.HasChain(),
		"HasChain is len(r.Chain) > 1 (response.go:100), so a single item reports false")
	require.Equal(t, "", resp.GetChainLastURL(),
		"GetChainLastURL returns the empty string when HasChain is false (response.go:109), not the request URL")
	require.Equal(t, "", resp.GetChain(),
		"PINNED: the dump loop writes nothing for a single item, because index 0 is both the first and the final index")
	require.Equal(t, []int{http.StatusOK}, resp.GetChainStatusCodes(),
		"GetChainStatusCodes still reports the one status, so the chain is populated and only the dump is empty")

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 1, "the projection must carry the single item")
	require.Equal(t, http.StatusOK, slice[0].StatusCode, "the projected status must be the response's own")
	require.Equal(t, "", slice[0].Location,
		"PINNED: a response with no Location header leaves the field empty, because Location() reports ErrNoLocation")
	require.Equal(t, chainSingleTarget, slice[0].RequestURL,
		"RequestURL is the field that does carry the absolute target, which is what distinguishes it from Location")

	// The decisive contrast for the pinned divergence: both dumps exist in the
	// projection, yet GetChain concatenated neither of them.
	require.Equal(t, chainSingleRequestDump, slice[0].Request,
		"the projection carries the full request dump even though GetChain omitted it")
	require.Equal(t, chainSingleResponseDump, slice[0].Response,
		"the projection carries the full response dump even though GetChain omitted it")
	require.NotEmpty(t, slice[0].Request, "the omitted request dump is non-empty, so the empty GetChain is the loop's doing")
	require.NotEmpty(t, slice[0].Response, "the omitted response dump is non-empty, so the empty GetChain is the loop's doing")
}

// Synthetic sentinels represent Authorization, Proxy-Authorization, Cookie, a bespoke
// API-key header, Set-Cookie, and a terminal response header so each carrier is
// distinguishable in the serialized chain.
const (
	chainSecretAuthorization      = "Bearer SENTINEL-TOKEN"
	chainSecretCookie             = "sess=SENTINEL-COOKIE"
	chainSecretProxyAuthorization = "Basic SENTINEL-PROXY"
	chainSecretAPIKeyHeader       = "X-Api-Key"
	chainSecretAPIKey             = "SENTINEL-APIKEY"
	chainSecretSetCookie          = "session=SENTINEL-SETCOOKIE; Path=/"
	chainSecretResponseHeader     = "X-Response-Secret"
	chainSecretResponseValue      = "SENTINEL-RESPHDR"
)

// Expected header-only dumps for the two-hop credential fixture. Headers are set directly
// to avoid RandomAgent changing the byte-exact request dump; net/http writes Host first
// and sorts the remaining fields.
const (
	chainSecretRequest0 = "GET /a HTTP/1.1\r\n" +
		"Host: origin.example\r\n" +
		"Authorization: " + chainSecretAuthorization + "\r\n" +
		"Cookie: " + chainSecretCookie + "\r\n" +
		"Proxy-Authorization: " + chainSecretProxyAuthorization + "\r\n" +
		chainSecretAPIKeyHeader + ": " + chainSecretAPIKey + "\r\n\r\n"
	chainSecretResponse0 = "HTTP/1.1 301 Moved Permanently\r\n" +
		"Content-Length: 12\r\n" +
		"Location: /b\r\n" +
		"Set-Cookie: " + chainSecretSetCookie + "\r\n\r\n"
	chainSecretRequest1 = "GET /b HTTP/0.0\r\n" +
		"Host: origin.example\r\n" +
		"Authorization: " + chainSecretAuthorization + "\r\n" +
		"Cookie: " + chainSecretCookie + "\r\n" +
		"Proxy-Authorization: " + chainSecretProxyAuthorization + "\r\n" +
		"Referer: " + chainTargetA + "\r\n" +
		chainSecretAPIKeyHeader + ": " + chainSecretAPIKey + "\r\n\r\n"
	chainSecretResponse1 = "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 12\r\n" +
		chainSecretResponseHeader + ": " + chainSecretResponseValue + "\r\n\r\n"
)

// assertChainDumpsExposeSensitiveHeaders verifies that same-origin chain dumps retain
// request credentials and response headers verbatim. GetChain is written by StoreChain,
// while GetChainAsSlice populates JSON chain output; neither accessor redacts upstream
// dump bytes. Same-origin routing isolates chain serialization from cross-origin header
// stripping.
//
// It runs as a sub-test of TestChainDumpsCarryNoBody: both examine exactly what the dump
// bytes do and do not contain, one for payload bytes and one for header values.
func assertChainDumpsExposeSensitiveHeaders(t *testing.T) {
	// Two hops on ONE origin. Same-origin is deliberate: it removes net/http's
	// cross-origin stripping from the picture entirely, so what the dumps contain is
	// attributable to the chain builder alone rather than to redirect header policy,
	// which is the separate subject of common/httpx/redirect_test.go.
	mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {
			status:   http.StatusMovedPermanently,
			location: "/b",
			header:   http.Header{"Set-Cookie": []string{chainSecretSetCookie}},
			body:     chainBodyMarkerA,
		},
		"origin.example/b": {
			status: http.StatusOK,
			header: http.Header{chainSecretResponseHeader: []string{chainSecretResponseValue}},
			body:   chainBodyMarkerB,
		},
	}))

	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = chainMaxRedirects
	}, mt)

	req, err := retryablehttp.NewRequest(http.MethodGet, chainTargetA, nil)
	require.NoError(t, err, "the fixture target must parse, otherwise no hop reaches the chain builder")
	// Set directly, NOT via SetCustomHeaders - see the note on the dump constants.
	req.Header.Set("Authorization", chainSecretAuthorization)
	req.Header.Set("Cookie", chainSecretCookie)
	req.Header.Set("Proxy-Authorization", chainSecretProxyAuthorization)
	req.Header.Set(chainSecretAPIKeyHeader, chainSecretAPIKey)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err, "the scripted chain must complete, so an exposure assertion cannot be a failed request in disguise")
	require.Equal(t, 2, mt.callCount(), "exactly two round trips must reach the transport, so the chain describes real traffic")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the 301 must have been followed to the terminal 200")
	require.Len(t, resp.Chain, 2, "precondition: the builder must have reconstructed both hops")

	require.Equal(t, chainSecretRequest0, string(resp.Chain[0].Request),
		"the first hop's request dump carries all four credentials verbatim")
	require.Equal(t, chainSecretResponse0, string(resp.Chain[0].Response),
		"the first hop's response dump carries the origin's Set-Cookie verbatim")
	require.Equal(t, chainSecretRequest1, string(resp.Chain[1].Request),
		"the redirect follow-up repeats every credential, and adds the Referer")
	require.Equal(t, chainSecretResponse1, string(resp.Chain[1].Response),
		"the terminal response dump carries the bespoke response secret")

	require.Len(t, resp.Chain[0].Request, 180)
	require.Len(t, resp.Chain[0].Response, 116)
	require.Len(t, resp.Chain[1].Request, 214)
	require.Len(t, resp.Chain[1].Response, 76)

	chain := resp.GetChain()
	require.Equal(t, chainSecretResponse0+chainSecretRequest1, chain,
		"GetChain is response0 + request1, so the file written under -store-chain is exactly these bytes")
	require.Len(t, chain, 330)

	// The documented omissions give NO confidentiality, and that is the point of the
	// next two groups. GetChain drops request0, yet every credential request0 held is
	// still present - because request1 repeats all of them.
	require.NotContains(t, chain, chainSecretRequest0,
		"the first request dump is omitted as a whole, per the divergence pinned in TestChainGetChainOmitsFirstRequestAndLastResponse")
	for _, secret := range []string{
		chainSecretAuthorization,
		chainSecretCookie,
		chainSecretProxyAuthorization,
		chainSecretAPIKey,
		chainSecretSetCookie,
	} {
		require.Contains(t, chain, secret,
			"omitting the first request does not withhold this credential: the follow-up hop repeats it")
	}

	// The last-response omission, by contrast, DOES withhold the terminal response's
	// bespoke secret from GetChain - and only from GetChain. Asserted as an absence so
	// a change that started including the final response is caught here.
	require.NotContains(t, chain, chainSecretResponseValue,
		"the terminal response is omitted from GetChain, so its bespoke secret does not reach the -store-chain file")

	// The concatenated dump remains body-free; all exposed sentinel data is carried in
	// headers.
	require.NotContains(t, chain, chainBodyMarkerA, "GetChain carries header bytes only")
	require.NotContains(t, chain, chainBodyMarkerB, "GetChain carries header bytes only")

	// GetChainAsSlice retains every request and response dump, including the terminal
	// response omitted by GetChain.
	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 2, "the projection reports one item per hop")

	require.Equal(t, chainSecretRequest0, slice[0].Request,
		"chain[0].request in JSON output is the first request dump in full, credentials included")
	require.Equal(t, chainSecretResponse0, slice[0].Response,
		"chain[0].response in JSON output carries the Set-Cookie")
	require.Equal(t, chainSecretRequest1, slice[1].Request,
		"chain[1].request in JSON output repeats every credential")
	require.Equal(t, chainSecretResponse1, slice[1].Response,
		"chain[1].response in JSON output exposes the terminal response secret that GetChain withheld")

	// The decisive contrast between the two accessors, stated as one pair of assertions:
	// the same secret is absent from one representation and present in the other, so a
	// reader cannot conclude from the -store-chain behaviour that JSON is equally narrow.
	require.NotContains(t, chain, chainSecretResponseValue,
		"absent from GetChain")
	require.Contains(t, slice[1].Response, chainSecretResponseValue,
		"present in GetChainAsSlice - the two accessors expose different amounts, so both must be audited")

	require.Equal(t, []int{http.StatusMovedPermanently, http.StatusOK}, resp.GetChainStatusCodes())
	require.True(t, resp.HasChain())
	require.Equal(t, chainTargetB, resp.GetChainLastURL(),
		"the final URL is the plain target here; the credential-bearing case is TestChainRetainsURLUserinfoInCallerVisibleOutput")
	require.Equal(t, chainTargetB, slice[0].Location, "the resolved Location of the first hop")
	require.Equal(t, "", slice[1].Location, "the terminal hop has no Location")
	require.Equal(t, chainTargetA, slice[0].RequestURL)
	require.Equal(t, chainTargetB, slice[1].RequestURL)
}

// Synthetic URL-userinfo fixtures pair a cleartext password with its exact Basic encoding
// so the test can verify both URL fields and derived Authorization dumps.
const (
	chainUserinfoUser     = "alice"
	chainUserinfoPassword = "s3cr3t-password"
	chainUserinfoBasic    = "Basic YWxpY2U6czNjcjN0LXBhc3N3b3Jk"

	chainUserinfoStart = "http://" + chainUserinfoUser + ":" + chainUserinfoPassword + "@origin.example/start"
	chainUserinfoFinal = "http://" + chainUserinfoUser + ":" + chainUserinfoPassword + "@origin.example/final"
	chainPlainStart    = "http://origin.example/start"
	chainPlainFinal    = "http://origin.example/final"
)

// assertChainRetainsURLUserinfoInCallerVisibleOutput compares relative and absolute
// redirect Locations for a target containing URL userinfo. A relative Location inherits
// the base URL's userinfo, so the resolved Location, follow-up RequestURL, final URL, and
// derived Basic header retain it; an absolute Location without userinfo does not. The
// first chain item still records the original credential-bearing URL and request dump.
// net/http strips userinfo from the synthesized Referer, providing a control.
//
// It runs as a sub-test of TestChainAccessorsMultiHop, which establishes what the
// accessors report for a plain chain; this pins what they report when the target URL
// carries a credential, which is the same accessor surface under a different input.
func assertChainRetainsURLUserinfoInCallerVisibleOutput(t *testing.T) {
	cases := []struct {
		name string
		// scriptedLocation is the ONLY difference between the two rows.
		scriptedLocation string
		wantLastURL      string
		// wantCredentialInLastURL separately records whether the expected final URL
		// contains the password sentinel.
		wantCredentialInLastURL bool
		wantItem0Response       string
		wantItem1Request        string
		wantChainBytes          int
		wantSlice0Location      string
		wantSlice1RequestURL    string
		// wantHop1Authorization is what the SECOND hop actually put on the wire.
		wantHop1Authorization string
	}{
		{
			name:                    "relative Location propagates the URL password into the final URL",
			scriptedLocation:        "/final",
			wantLastURL:             chainUserinfoFinal,
			wantCredentialInLastURL: true,
			wantItem0Response: "HTTP/1.1 302 Found\r\n" +
				"Content-Length: 12\r\n" +
				"Location: /final\r\n\r\n",
			wantItem1Request: "GET /final HTTP/0.0\r\n" +
				"Host: origin.example\r\n" +
				"Authorization: " + chainUserinfoBasic + "\r\n" +
				"Referer: " + chainPlainStart + "\r\n\r\n",
			wantChainBytes:        194,
			wantSlice0Location:    chainUserinfoFinal,
			wantSlice1RequestURL:  chainUserinfoFinal,
			wantHop1Authorization: chainUserinfoBasic,
		},
		{
			name:                    "absolute Location keeps the final URL clean but still leaks the first hop",
			scriptedLocation:        chainPlainFinal,
			wantLastURL:             chainPlainFinal,
			wantCredentialInLastURL: false,
			wantItem0Response: "HTTP/1.1 302 Found\r\n" +
				"Content-Length: 12\r\n" +
				"Location: " + chainPlainFinal + "\r\n\r\n",
			wantItem1Request: "GET /final HTTP/0.0\r\n" +
				"Host: origin.example\r\n" +
				"Referer: " + chainPlainStart + "\r\n\r\n",
			wantChainBytes:        164,
			wantSlice0Location:    chainPlainFinal,
			wantSlice1RequestURL:  chainPlainFinal,
			wantHop1Authorization: "",
		},
	}

	// The first hop's dump is identical on both rows - it is the caller's own request,
	// which the scripted Location cannot influence - so it is stated once here rather
	// than duplicated per row, which is itself the assertion that it is row-invariant.
	const wantItem0Request = "GET /start HTTP/1.1\r\n" +
		"Host: origin.example\r\n" +
		"Authorization: " + chainUserinfoBasic + "\r\n\r\n"
	const wantItem1Response = "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 12\r\n\r\n"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/start": {status: http.StatusFound, location: tc.scriptedLocation, body: chainBodyMarkerA},
				"origin.example/final": {status: http.StatusOK, body: chainBodyMarkerB},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = chainMaxRedirects
			}, mt)

			req, err := retryablehttp.NewRequest(http.MethodGet, chainUserinfoStart, nil)
			require.NoError(t, err, "a userinfo-bearing target must parse, otherwise the scenario never runs")
			// The credential is carried ONLY by the URL. Nothing sets an Authorization
			// header here, so every Authorization byte asserted below was synthesized by
			// net/http from that userinfo.
			require.Empty(t, req.Header.Get("Authorization"),
				"precondition: the caller sets no Authorization, so the header is provably derived from the URL")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err, "the scripted redirect must complete")
			require.Equal(t, 2, mt.callCount(), "exactly two round trips, so the chain describes real traffic")
			require.Equal(t, http.StatusOK, resp.StatusCode, "the 302 must have been followed to the terminal 200")
			require.Len(t, resp.Chain, 2, "precondition: both hops must be in the chain")

			require.Equal(t, tc.wantLastURL, resp.GetChainLastURL(),
				"GetChainLastURL is emitted verbatim as JSON final_url and printed under -location")
			require.Equal(t, tc.wantCredentialInLastURL, strings.Contains(resp.GetChainLastURL(), chainUserinfoPassword),
				"whether the cleartext password reaches Result.FinalURL is decided solely by the Location form")

			slice := resp.GetChainAsSlice()
			require.Len(t, slice, 2)

			require.Equal(t, tc.wantSlice0Location, slice[0].Location,
				"the resolved Location is emitted as chain[0].location")
			require.Equal(t, "", slice[1].Location, "the terminal hop has no Location")
			require.Equal(t, tc.wantSlice1RequestURL, slice[1].RequestURL,
				"chain[1].request-url is the follow-up target, which inherits userinfo only from a relative Location")

			// The row-invariant leak: the FIRST hop's request URL is the caller's own, so
			// it retains the password on BOTH rows. Asserted unconditionally, outside the
			// table, because that is precisely what makes it unavoidable.
			require.Equal(t, chainUserinfoStart, slice[0].RequestURL,
				"chain[0].request-url always retains the caller's userinfo, so an absolute Location narrows the leak but never closes it")
			require.Contains(t, slice[0].RequestURL, chainUserinfoPassword,
				"the cleartext password is present in chain[0].request-url on every row")

			require.Equal(t, wantItem0Request, string(resp.Chain[0].Request),
				"the first request dump is row-invariant and carries the derived Basic credential")
			require.Equal(t, tc.wantItem0Response, string(resp.Chain[0].Response))
			require.Equal(t, tc.wantItem1Request, string(resp.Chain[1].Request),
				"the follow-up dump carries the credential again only when the Location was relative")
			require.Equal(t, wantItem1Response, string(resp.Chain[1].Response))
			require.Equal(t, tc.wantItem0Response+tc.wantItem1Request, resp.GetChain(),
				"GetChain is response0 + request1, so these are the bytes -store-chain writes to disk")
			require.Len(t, resp.GetChain(), tc.wantChainBytes)

			// Decode the Basic value to verify the dump contains the recoverable
			// user/password pair rather than an opaque marker.
			require.Contains(t, string(resp.Chain[0].Request), chainUserinfoBasic,
				"the first request dump carries the Basic value, on every row")
			encoded := strings.TrimPrefix(chainUserinfoBasic, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			require.NoError(t, err, "the dumped Basic value must be well-formed base64, otherwise it is not the credential")
			require.Equal(t, chainUserinfoUser+":"+chainUserinfoPassword, string(decoded),
				"the dumped credential decodes to the exact user and cleartext password, so the artefact discloses both")

			// The synthesized Referer strips userinfo even though the chain's URL and dump
			// fields retain it.
			hops := mt.requests()
			require.Len(t, hops, 2)
			require.Equal(t, chainUserinfoBasic, hops[0].Header.Get("Authorization"),
				"the first hop carries the credential derived from the URL userinfo")
			require.Equal(t, "", hops[0].Header.Get("Referer"), "the first hop has no Referer")
			require.Equal(t, tc.wantHop1Authorization, hops[1].Header.Get("Authorization"),
				"the second hop re-derives the credential only when the resolved URL still carried userinfo")
			require.Equal(t, chainPlainStart, hops[1].Header.Get("Referer"),
				"net/http strips userinfo from the Referer it synthesizes (client.go:160-169) - the same credential, handled correctly one field away")
			require.NotContains(t, hops[1].Header.Get("Referer"), chainUserinfoPassword,
				"stated as an absence so a change that stopped stripping the Referer fails here too")
		})
	}
}
