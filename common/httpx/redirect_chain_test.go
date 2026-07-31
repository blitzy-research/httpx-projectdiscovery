package httpx

import (
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// This file pins the five redirect-chain accessors on Response, every one of which was
// at 0.0% statement coverage before it existed: GetChainStatusCodes
// (common/httpx/response.go:62), GetChain (:71), GetChainAsSlice (:85), HasChain (:99)
// and GetChainLastURL (:104).
//
// They are not incidental helpers. The runner consumes all five on its production
// output paths - runner/runner.go:2339-2343 computes the final URL, :2534-2539 emits the
// chain status codes and the structured chain items, :2657 emits the Location field - so
// a defect in GetChainLastURL corrupts the primary user-facing output of every
// redirect-following scan while leaving the rest of the suite green. Asserting the exact
// final URL after a redirect chain is therefore the single highest-value assertion here.
//
// Every expected value below was measured against the code as it stands and is
// deterministic: the mocked responses carry no Date header (mockResponse sets none and
// http.Response.Write synthesizes none) and the request dumps carry no User-Agent
// (net/http adds one at transport write time, which is after the chain builder has
// already dumped the request), so the byte-exact dump literals are stable. They were
// confirmed byte-identical across repeated runs.
//
// Two divergences from what a reader would reasonably expect are PINNED here rather than
// fixed, because the redirect chain is consumed as-is by the runner's output layer and
// changing it would change every user's output:
//
//  1. GetChain omits the first request and the last response entirely
//     (TestChainGetChainOmitsFirstRequestAndLastResponse).
//  2. GetChain is the empty string for a single-item chain
//     (TestChainSingleItemAccessors).
//
// All interception happens at the http.RoundTripper boundary through the shared harness
// in common/httpx/mocktransport_test.go, so the synthetic authority origin.example is
// never resolved and no test here opens a socket. Nothing in this file runs in parallel,
// and nothing in it may be made to: New sets the process-global GODEBUG variable on the
// HTTP/1.1 path, which is unsafe to race, so every test in package httpx runs
// sequentially - see the same warning on the shared harness.

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

// chainMaxRedirects is well above the fixture's two hops, so the redirect budget guard
// at common/httpx/httpx.go:104 can never be what terminates a chain in this file. The
// budget itself is the subject of common/httpx/redirect_test.go, not of this file.
const chainMaxRedirects = 10

// Measured per-item dumps for the three-hop fixture, exactly as
// pdhttputil.GetChain records them. They are asserted as byte-exact literals because
// that is the strictest possible statement of what the chain contains, and because each
// one encodes a separate protocol-visible fact:
//
//   - chainChainRequest0 carries HTTP/1.1, the protocol version net/http stamped onto
//     the caller's own request.
//   - chainChainRequest1 and chainChainRequest2 carry HTTP/0.0, because net/http builds
//     a redirect follow-up with zero-valued protocol fields, and they carry the per-hop
//     Referer.
//   - chainChainResponse0 and chainChainResponse1 carry the RELATIVE Location bytes the
//     origin actually sent, which is what makes the absolute Location values in
//     GetChainAsSlice provably the product of resolution rather than a copy.
//   - every dump ends at the blank line that terminates the header block, because the
//     builder dumps headers only.
const (
	chainChainRequest0  = "GET /a HTTP/1.1\r\nHost: origin.example\r\n\r\n"
	chainChainResponse0 = "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 12\r\nLocation: /b\r\n\r\n"
	chainChainRequest1  = "GET /b HTTP/0.0\r\nHost: origin.example\r\nReferer: http://origin.example/a\r\n\r\n"
	chainChainResponse1 = "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 12\r\nLocation: /c\r\n\r\n"
	chainChainRequest2  = "GET /c HTTP/0.0\r\nHost: origin.example\r\nReferer: http://origin.example/b\r\n\r\n"
	chainChainResponse2 = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
)

// Measured dumps for the single-hop fixture. The body is 15 bytes, hence the declared
// length, and the response dump still stops at the header terminator.
const (
	chainSingleRequestDump  = "GET /only HTTP/1.1\r\nHost: origin.example\r\n\r\n"
	chainSingleResponseDump = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n"
)

// chainHeaderTerminator is the CRLF pair that closes an HTTP header block. A dump that
// ends here carries no body byte at all, which is the structural property
// TestChainDumpsCarryNoBody asserts.
const chainHeaderTerminator = "\r\n\r\n"

// newChainFixture drives the canonical three-hop chain 301 /a -> 301 /b -> 200 /c on
// origin.example and returns the parsed response together with the recording transport.
//
// The Location headers are scripted RELATIVE ("/b", "/c") on purpose. The chain builder
// derives each item's Location from http.Response.Location(), which resolves a relative
// field against the request URL, so relative scripting is the only form under which the
// absolute Location values asserted in TestChainAccessorsMultiHop prove that resolution
// actually happened. Scripting them absolute would make the resolution a no-op and
// silently drain that assertion of all power.
//
// Every hop returns a distinct body marker so TestChainDumpsCarryNoBody can prove no
// body byte reaches any dump, and the transport is returned so a caller can cross-check
// the chain's own RequestURL sequence against the requests that genuinely went out.
func newChainFixture(t *testing.T) (*Response, *mockTransport) {
	t.Helper()

	// Routes are keyed host-qualified, which scriptedRedirects matches ahead of a bare
	// path, so the fixture states the authority it expects instead of accepting any.
	mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusMovedPermanently, location: "/b", body: chainBodyMarkerA},
		"origin.example/b": {status: http.StatusMovedPermanently, location: "/c", body: chainBodyMarkerB},
		"origin.example/c": {status: http.StatusOK, body: chainBodyMarkerC},
	}))

	// The mutator runs before New, which is mandatory: New freezes the option values
	// into the CheckRedirect closure it builds (common/httpx/httpx.go:92-115), so a
	// redirect flag set afterwards would never be seen and the chain would stay one
	// item long while every assertion below silently changed meaning.
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

// newTwoHopChainFixture drives a single redirect, 302 /a -> 200 /b on origin.example,
// producing a chain of exactly TWO items, and returns the parsed response with the
// recording transport.
//
// Chain length two is not an arbitrary second fixture: it is the ONLY length that
// discriminates HasChain's `len(r.Chain) > 1` (common/httpx/response.go:100) from a
// neighbouring off-by-one. Under a mutated `> 2` the three-item fixture still reports
// true and the one-item fixture still reports false, so the defect would be invisible
// without this case. Chain length two is also a second arity for GetChain's two loop
// conditions, where the dump collapses to response0 + request1 - one write from each
// branch, with each branch's omission still in force.
//
// A 302 is used rather than the 301 of the three-hop fixture so the two fixtures are
// distinguishable in the status-code sequence they produce, and net/http rewrites the
// follow-up to GET for both.
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

// TestChainAccessorsMultiHop pins the caller-visible values every chain accessor reports
// for a three-hop redirect chain.
//
// The final-URL assertion is the reason this file exists: GetChainLastURL
// (common/httpx/response.go:104-110) returns the last item's RequestURL, and the runner
// emits exactly that value as a scan's resolved URL (runner/runner.go:2339-2343). It is
// asserted as one exact absolute URL string, never as a substring or a non-emptiness
// check.
//
// The status-code sequence is compared with require.Equal rather than ElementsMatch
// because chain order is semantically meaningful - [301 301 200] and [200 301 301]
// describe different scans - and an order-insensitive comparison would accept a reversal
// of the builder's final ordering pass.
func TestChainAccessorsMultiHop(t *testing.T) {
	resp, mt := newChainFixture(t)

	require.Len(t, resp.Chain, 3,
		"one chain item per hop: the two 301s and the terminal 200")
	require.Equal(t, []int{http.StatusMovedPermanently, http.StatusMovedPermanently, http.StatusOK},
		resp.GetChainStatusCodes(),
		"GetChainStatusCodes (response.go:62-68) must report every hop's status in progressive order")
	require.True(t, resp.HasChain(),
		"HasChain is len(r.Chain) > 1 (response.go:100), which a three-item chain satisfies")

	// The user-facing final URL after the redirect chain, exact and absolute.
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

	// Resolution proof: the origin sent a RELATIVE Location on the wire, and the chain
	// item exposes the ABSOLUTE form. Both halves are asserted so neither can drift
	// without failing - a builder that stopped resolving, or a mock that started
	// scripting absolute headers, breaks exactly one of the two.
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

	// The HasChain boundary, which the three-item chain above cannot reach. HasChain is
	// len(r.Chain) > 1 (response.go:100), so length TWO is the only length that
	// distinguishes that predicate from an off-by-one: a mutated `> 2` still reports true
	// for three items and false for one, and would slip past every other assertion in
	// this file. Two is the lowest length for which HasChain must be true, and
	// TestChainSingleItemAccessors pins the highest length for which it must be false.
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
}

// TestChainGetChainOmitsFirstRequestAndLastResponse pins the exact composition of the
// concatenated chain dump, which is the most structurally load-bearing behavior in
// response.go.
//
// PINNED DIVERGENCE - asserted as measured, deliberately NOT fixed. GetChain
// (common/httpx/response.go:71-82) writes chainItem.Request for every index EXCEPT 0,
// because of `if counter != 0` at response.go:74, and chainItem.Response for every index
// EXCEPT the last, because of `if counter < len(r.Chain)-1` at response.go:77. The dump
// is therefore response0 + request1 + response1 + request2 and nothing else: the
// caller's own first request and the final response never appear, even though
// GetChainAsSlice does carry both. A reader who expected a complete transcript is not
// wrong to be surprised, but the runner's output layer consumes this string as-is, so
// changing it would change every user's output and it is out of scope to fix.
//
// The assertions come in three strengths on purpose. The byte-exact equalities state
// what the dump IS; the presence checks state which hops survived; the absence checks
// are what make the test mutation-resistant, because dropping either loop condition
// would add bytes that no equality-only test phrased against a prefix could catch.
func TestChainGetChainOmitsFirstRequestAndLastResponse(t *testing.T) {
	resp, _ := newChainFixture(t)

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3, "precondition: the projection must expose all three items to compose against")

	dump := resp.GetChain()
	require.NotEmpty(t, dump, "a three-item chain must produce a dump; only a single-item chain yields the empty string")

	// Composition, expressed in terms of the items themselves: response0 + request1 +
	// response1 + request2. This is the assertion that fails the moment either loop
	// condition at response.go:74 or :77 changes.
	require.Equal(t, slice[0].Response+slice[1].Request+slice[1].Response+slice[2].Request, dump,
		"the dump must be exactly response0+request1+response1+request2, per the two loop conditions at response.go:74 and :77")

	// The same statement again as literal bytes, so a change in what the builder dumps
	// - not just in how GetChain concatenates it - also fails here.
	require.Equal(t, chainChainResponse0+chainChainRequest1+chainChainResponse1+chainChainRequest2, dump,
		"the dump must match the measured bytes for this fixture exactly")
	require.Len(t, dump, 286,
		"68+75+68+75 bytes for this fixture, which is stable because every hop declares the same 12-byte length")

	// Presence: the hops that do survive the omissions.
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

	// The same two omissions at a second arity. With exactly two items the dump collapses
	// to response0 + request1: index 0 contributes only its response and index 1 only its
	// request, so each loop condition fires exactly once and each omission is still in
	// force. Asserting this length as well as three closes the gap a single-arity test
	// leaves - a mutated condition can agree with the correct one at one chain length and
	// disagree at another.
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

// TestChainDumpsCarryNoBody pins that no chain item's dump carries a single body byte,
// while the body itself still reaches the caller.
//
// The cause is structural and upstream: the chain builder calls
// httputil.DumpRequest(req, false) and httputil.DumpResponse(resp, false) - body=false
// on both - so each dump stops at the header terminator. It is a property of
// pdhttputil.GetChain, invoked from common/httpx/httpx.go:397, not of this repository's
// own code, which is why it is pinned rather than changed.
//
// Every hop returns a distinct body marker, and each item is checked against ALL THREE
// markers rather than only its own, so a builder that dumped the wrong hop's body would
// fail too. The dumps are also asserted non-empty and shown to declare a Content-Length:
// a dump that reported a 12-byte payload while carrying none is the exact evidence that
// the omission is deliberate framing rather than an empty response.
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

	// The concatenated dump inherits the property: no marker anywhere in it either.
	dump := resp.GetChain()
	for _, marker := range allMarkers {
		require.NotContains(t, dump, marker,
			"the concatenated chain dump must stay body-free as well, including "+marker)
	}
}

// TestChainRedirectHopsDumpProtoZero pins a distinctive and highly mutation-sensitive
// artifact: only the caller's own request dumps a real protocol version, while every
// redirect follow-up dumps HTTP/0.0.
//
// The caller's request is built by retryablehttp on top of http.NewRequestWithContext,
// which stamps Proto "HTTP/1.1" with ProtoMajor 1 and ProtoMinor 1. net/http builds a
// redirect follow-up itself and leaves those fields at their zero values, so
// httputil.DumpRequest formats the request line as HTTP/0.0. That is surfaced verbatim
// by the chain builder and reaches the runner's chain output.
//
// It is pinned as measured, not fixed: the zero-valued protocol fields originate in the
// standard library's redirect handling, and asserting them makes any change to how the
// chain is reconstructed - or to which request object each item points at - fail loudly.
//
// Index 0 is read from GetChainAsSlice rather than from GetChain, because GetChain omits
// the first request altogether (see
// TestChainGetChainOmitsFirstRequestAndLastResponse), whereas GetChainAsSlice copies
// every field unconditionally at response.go:87-93.
func TestChainRedirectHopsDumpProtoZero(t *testing.T) {
	resp, _ := newChainFixture(t)

	slice := resp.GetChainAsSlice()
	require.Len(t, slice, 3, "precondition: all three request dumps must be projected")

	// The caller's own request: a real protocol version.
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

	// The same contrast inside the concatenated dump, which is what the runner emits.
	dump := resp.GetChain()
	require.Contains(t, dump, "GET /b HTTP/0.0",
		"the concatenated dump must carry the follow-up's zero-valued protocol version too")
	require.NotContains(t, dump, "GET /b HTTP/1.1",
		"a follow-up request line with a real protocol version must not appear anywhere in the dump")
}

// TestChainSingleItemAccessors pins the accessors' behavior when no redirect happened at
// all, which is the common case for a scan and therefore the case a defect would hide in
// longest.
//
// PINNED DIVERGENCE - asserted as measured, deliberately NOT fixed. GetChain
// (common/httpx/response.go:71-82) returns the EMPTY STRING for a single-item chain,
// even though that item holds a complete request dump and a complete response dump. Both
// loop conditions exclude index 0 when it is also the final index: `if counter != 0` at
// response.go:74 skips the request, and `if counter < len(r.Chain)-1` at response.go:77
// skips the response, so the builder writes nothing at all. This is the same pair of
// conditions pinned in TestChainGetChainOmitsFirstRequestAndLastResponse, and it is left
// alone for the same reason: the runner consumes the string as-is.
//
// A second, smaller surprise is pinned alongside it. The item's Location is the empty
// string, not the request URL: the chain builder derives Location from
// http.Response.Location(), which returns http.ErrNoLocation for a response without a
// Location header and leaves the field at its zero value. RequestURL is asserted
// immediately afterwards so the item is provably populated and the two fields are
// visibly distinct.
//
// Both empty results are asserted as exact empty-string equality. Neither is asserted as
// a nil check, which would pass for a value that had merely stopped being computed.
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
