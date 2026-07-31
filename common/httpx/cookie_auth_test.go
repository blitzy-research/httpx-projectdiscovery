package httpx

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/projectdiscovery/httpx/common/authprovider/authx"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests cover credential propagation: which cookies and which authentication
// material the client puts on the wire, on which hop, and what survives a redirect to
// a different origin. That is the highest-consequence behaviour in the package,
// because a defect here does not produce a wrong result - it hands a credential to a
// host the operator never named.
//
// Two mechanisms decide the outcome and they are deliberately kept apart by the tests
// below, because they behave differently and a single "the cookie arrived" assertion
// would conflate them:
//
//   - SetCustomHeaders (common/httpx/httpx.go:486-520) applies the configured headers
//     to the caller's own request, and its "cookie" case falls through to the default
//     branch at :505-509, so each configured value is added with Header.Add - one
//     header LINE per value.
//   - setCustomCookies (common/httpx/httpx.go:522-531) is invoked by both redirect
//     closures on every hop they are handed: :101 in the follow-any-host closure, which
//     is the one these tests select, and :120 in the host-scoped closure, which is
//     redirect_test.go's subject. It deletes the inherited Cookie header and re-adds
//     Options.customCookies with AddCookie, which appends to a SINGLE line.
//
// Configuration therefore has to happen before construction: New parses
// CustomHeaders["Cookie"] into Options.customCookies at httpx.go:78, so a Cookie set
// after New leaves customCookies empty, hasCustomCookies false and setCustomCookies a
// silent no-op - every cookie assertion downstream would then pass vacuously. Every
// test here configures cookies through newMockHTTPX's option mutator, which the shared
// harness runs before New for exactly this reason.
//
// The scripted transport is mandatory rather than idiomatic in this file. A cross-origin
// redirect is the case that decides whether a credential leaks, and it cannot be
// expressed against loopback servers: two httptest servers both bind 127.0.0.1, so
// there is no second origin to redirect to. origin.example and other.example live only
// inside the mock's route map and are never resolved.
//
// Absence is always asserted as an exact empty string through the header accessor, never
// as a nil check: an accessor that returned a wrong-but-present value would satisfy a
// nil check and leave the leak undetected.
//
// No test here opts into parallel execution, matching every other test in this package:
// New sets the process-global GODEBUG variable on the HTTP/1.1 path, which is unsafe to
// race.

// The scripted authorities and payloads. Both hosts exist only inside the route map, so
// no name here is ever resolved.
const (
	// cookieAuthOriginStart is the caller's own target for every redirect scenario.
	cookieAuthOriginStart = "http://origin.example/a"
	// cookieAuthOriginSecond and cookieAuthOriginFinal complete the same-origin chain
	// used by the duplication test, where staying on one origin is what keeps
	// net/http's own credential stripping out of the picture.
	cookieAuthOriginSecond = "http://origin.example/b"
	cookieAuthOriginFinal  = "http://origin.example/c"
	// cookieAuthCrossOriginFinal is a destination on an unrelated registrable domain,
	// which is what makes net/http's shouldCopyHeaderOnRedirect reject the enumerated
	// credential headers.
	cookieAuthCrossOriginFinal = "http://other.example/final"
	// cookieAuthSingleTarget is the single-hop target: no redirect, so the only way a
	// cookie can reach the wire is SetCustomHeaders.
	cookieAuthSingleTarget = "http://origin.example/"

	cookieAuthRedirectBody = "redirect"
	cookieAuthFinalBody    = "final"
	cookieAuthSingleBody   = "ok"

	// cookieAuthMaxRedirects is comfortably above every chain length used here, so no
	// assertion in this file can be perturbed by the redirect budget: the budget
	// boundary itself is redirect_test.go's subject.
	cookieAuthMaxRedirects = 10
)

// The configured cookies, supplied the way the CLI supplies -H "Cookie: ...", plus the
// exact wire forms the two mechanisms produce.
const (
	cookieAuthSessionCookie = "sess=abc"
	cookieAuthIDCookie      = "id=1"
	// cookieAuthJoinedCookies is the single-line form AddCookie builds inside
	// setCustomCookies: "; " between pairs, per RFC 6265 section 5.4.
	cookieAuthJoinedCookies = cookieAuthSessionCookie + "; " + cookieAuthIDCookie
	// cookieAuthDuplicatedSession is the exact prefix the pre-FIX-1 defect produced on
	// every redirect hop. It is asserted as an absence so the regression is named
	// rather than merely implied by the equality above it.
	cookieAuthDuplicatedSession = cookieAuthSessionCookie + "; " + cookieAuthSessionCookie
)

// cookieAuthCrossOriginTransport returns a FRESH recording transport scripting the
// two-hop cross-origin chain: cookieAuthOriginStart answers 302 with a Location on the
// other origin, and that destination answers 200.
//
// A fresh transport per call is required, not tidiness: callCount and the recorded
// snapshots accumulate, so a transport shared between two table rows would report the
// previous row's hops and make the exact per-hop assertions meaningless.
//
// http://origin.example/final is scripted although it must never be requested. Without
// it, a defect that resolved the absolute Location against the original origin would
// fail on scriptedRedirects' unscripted-route error, which says nothing about
// credential propagation; with it, the same defect fails on the exact URL assertion
// that names the origin change.
func cookieAuthCrossOriginTransport(t *testing.T) *mockTransport {
	t.Helper()
	return newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a":     {status: http.StatusFound, location: cookieAuthCrossOriginFinal, body: cookieAuthRedirectBody},
		"other.example/final":  {status: http.StatusOK, body: cookieAuthFinalBody},
		"origin.example/final": {status: http.StatusOK, body: "same origin"},
	}))
}

// TestCustomCookiesReachTheWire asserts that a configured cookie is actually sent, which
// no existing test does: TestParseCustomCookies (common/httpx/httpx_test.go:100-105)
// calls parseCustomCookies directly and then asserts only hasCustomCookies and
// len(Options.customCookies), so it would stay green if the parsed cookies were never
// applied to a request at all. That test is left exactly as it is; this is its
// protocol-visible sibling, added rather than extended.
//
// On a single, non-redirected request the redirect closures never run, so the only path
// that can put the cookie on the wire is SetCustomHeaders - which the runner calls at
// runner/runner.go:1900, and which this test calls in the same position.
//
// MEASURED, and worth stating because it is easy to assume otherwise: that path adds
// one header LINE per configured value (Header.Add in the default branch at
// httpx.go:505-509), so two configured cookies arrive as ["sess=abc", "id=1"] and
// Header.Get - which returns only the first line - yields "sess=abc". The joined
// "sess=abc; id=1" form is produced only by setCustomCookies on a redirect hop, which
// TestCustomCookiesNotDuplicatedAcrossRedirects pins separately. The table therefore
// sweeps one and two configured cookies: with one value both framings agree, so only
// the two-value row can distinguish them.
func TestCustomCookiesReachTheWire(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		// wantLines is the exact Cookie header as it reaches the transport, one entry
		// per header line.
		wantLines []string
		// wantGet is what Header.Get returns for that framing: the first line only.
		wantGet string
	}{
		{
			name:       "one configured cookie arrives as one line",
			configured: []string{cookieAuthSessionCookie},
			wantLines:  []string{cookieAuthSessionCookie},
			wantGet:    cookieAuthSessionCookie,
		},
		{
			name:       "two configured cookies arrive as one line each",
			configured: []string{cookieAuthSessionCookie, cookieAuthIDCookie},
			wantLines:  []string{cookieAuthSessionCookie, cookieAuthIDCookie},
			// Not the joined form: Header.Get reports the first line, so a caller
			// reading Get sees only the first configured cookie.
			wantGet: cookieAuthSessionCookie,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/": {status: http.StatusOK, body: cookieAuthSingleBody},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				// Before New: parseCustomCookies runs inside it (httpx.go:78).
				options.CustomHeaders = map[string][]string{"Cookie": tc.configured}
			}, rt)

			require.True(t, ht.Options.hasCustomCookies(),
				"the cookies must be parsed during construction, otherwise every assertion below is vacuous")
			require.Len(t, ht.Options.customCookies, len(tc.configured),
				"parseCustomCookies must yield one cookie per configured pair (option.go:98-106)")

			req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthSingleTarget, nil)
			require.NoError(t, err)
			require.Equal(t, "", req.Header.Get("Cookie"),
				"precondition: the freshly built request carries no cookie, so whatever arrives on the wire came from SetCustomHeaders")

			// The production build-up order (runner/runner.go:1882-1900): construct,
			// then apply the configured headers.
			ht.SetCustomHeaders(req, ht.CustomHeaders)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 1, rt.callCount(), "a 200 must not produce a second request")
			hops := rt.requests()
			require.Len(t, hops, 1)
			require.Equal(t, cookieAuthSingleTarget, hops[0].URL)

			require.Equal(t, tc.wantLines, hops[0].Header.Values("Cookie"),
				"the configured cookies must reach the transport as exactly these header lines")
			require.Equal(t, tc.wantGet, hops[0].Header.Get("Cookie"),
				"Header.Get returns the first line only, so this is the value a single-line reader observes")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(cookieAuthSingleBody), resp.Data)
			require.Len(t, resp.Chain, 1, "a single request produces a single chain item")
			require.Equal(t, []int{http.StatusOK}, resp.GetChainStatusCodes())
		})
	}
}

// TestCustomCookiesNotDuplicatedAcrossRedirects is the failing case that motivated
// FIX-1 in common/httpx/httpx.go.
//
// BEFORE FIX-1, measured: hops 2 and 3 each carried
// Cookie: "sess=abc; sess=abc; id=1" - the first configured cookie duplicated, and
// duplicated again on every further hop. Root cause: net/http copies the caller's
// multi-line Cookie header onto the redirect request, then setCustomCookies calls
// AddCookie, whose internal get-then-set collapses those lines into one and re-appends
// the first value ahead of them.
//
// FIX-1 is the single line req.Header.Del("Cookie") at common/httpx/httpx.go:526,
// inside the hasCustomCookies guard and ahead of the AddCookie loop at :528. It is
// justified twice over by the repository itself: the comment at httpx.go:506 already
// claimed cookies are "reset during the follow redirect flow" when nothing reset them,
// and CookiesAuthStrategy.ApplyOnRR already used exactly this delete-then-re-add idiom
// at common/authprovider/authx/cookies_auth.go:51.
//
// AFTER FIX-1, measured: hops 2 and 3 each carry exactly "sess=abc; id=1" on one line.
// If this test fails with the duplicated value, FIX-1 is missing from the working tree;
// the assertion must not be relaxed to accommodate that.
//
// The chain stays on one origin deliberately. net/http strips Cookie as part of its
// enumerated sensitive set when the destination changes, so a cross-origin chain would
// mask the duplication behind that strip and prove nothing about the injector.
func TestCustomCookiesNotDuplicatedAcrossRedirects(t *testing.T) {
	rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: cookieAuthRedirectBody},
		"origin.example/b": {status: http.StatusFound, location: "/c", body: cookieAuthRedirectBody},
		"origin.example/c": {status: http.StatusOK, body: cookieAuthFinalBody},
	}))

	ht := newMockHTTPX(t, func(options *Options) {
		options.CustomHeaders = map[string][]string{"Cookie": {cookieAuthSessionCookie, cookieAuthIDCookie}}
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.Len(t, ht.Options.customCookies, 2,
		"both configured cookies must be parsed during construction, otherwise the injector has nothing to duplicate")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	ht.SetCustomHeaders(req, ht.CustomHeaders)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 3, rt.callCount(), "two redirects must be followed, producing three requests")
	hops := rt.requests()
	require.Len(t, hops, 3)
	require.Equal(t, []string{cookieAuthOriginStart, cookieAuthOriginSecond, cookieAuthOriginFinal},
		[]string{hops[0].URL, hops[1].URL, hops[2].URL},
		"the relative Locations must resolve against the previous hop, keeping the whole chain on one origin")

	// Hop 1 was built by SetCustomHeaders, which adds one line per configured value.
	require.Equal(t, []string{cookieAuthSessionCookie, cookieAuthIDCookie}, hops[0].Header.Values("Cookie"),
		"the caller's own request carries one header line per configured cookie")

	// Hops 2 and 3 were built by setCustomCookies, which resets and re-adds, producing
	// one line holding both pairs. Asserting BOTH redirect hops is what catches a
	// defect that duplicates per hop rather than once: the pre-FIX-1 value grew with
	// every hop, so a fix that only cleaned up the first redirect would still fail
	// here. Iteration is over a slice, so the hop numbers in the diagnostics are
	// deterministic.
	redirectHops := []struct {
		number int
		rec    recordedRequest
	}{
		{number: 2, rec: hops[1]},
		{number: 3, rec: hops[2]},
	}
	for _, hop := range redirectHops {
		require.Equalf(t, cookieAuthJoinedCookies, hop.rec.Header.Get("Cookie"),
			"hop %d must carry each configured cookie exactly once, on one line", hop.number)
		require.Lenf(t, hop.rec.Header.Values("Cookie"), 1,
			"hop %d must carry the cookies as a single header line, never one line per cookie", hop.number)
		require.NotContainsf(t, hop.rec.Header.Get("Cookie"), cookieAuthDuplicatedSession,
			"hop %d: FIX-1 (req.Header.Del(\"Cookie\") at httpx.go:526) must stop the inherited Cookie header being re-appended per hop", hop.number)
	}

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 3, "three requests produce three chain items")
	require.Equal(t, []int{http.StatusFound, http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthOriginFinal, resp.GetChainLastURL(),
		"the final URL must name the last hop of the chain")
}

// TestAuthorizationStrippedOnCrossOriginRedirect asserts that an Authorization header
// set on the caller's request is NOT carried to a destination on a different origin.
//
// The credential is set with req.Header.Set rather than through an auth strategy, so
// the assertion isolates net/http's redirect header policy from anything the strategies
// do; TestAuthStrategiesAppliedThroughRedirect covers the strategy-driven paths.
//
// net/http's shouldCopyHeaderOnRedirect withholds an enumerated set - Authorization,
// Www-Authenticate, Cookie and Cookie2 - whenever the destination is not in the same
// trust domain as the initial request, which is the mitigation RFC 9110 section 15.4
// calls for when a redirect target is not necessarily trusted with the original
// request's credentials. MEASURED: hop 1 carries "Bearer tok", hop 2 carries nothing.
//
// Absence is asserted as an exact empty string. A nil check would also be satisfied by
// a defect that forwarded a truncated or stale credential, which is precisely the
// outcome this test exists to catch.
func TestAuthorizationStrippedOnCrossOriginRedirect(t *testing.T) {
	const bearer = "Bearer tok"

	rt := cookieAuthCrossOriginTransport(t)

	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.False(t, ht.Options.hasCustomCookies(),
		"precondition: no cookie is configured here, so nothing re-injects one and the Cookie assertions below observe net/http alone")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", bearer)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
	hops := rt.requests()
	require.Len(t, hops, 2)

	require.Equal(t, cookieAuthOriginStart, hops[0].URL)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, bearer, hops[0].Header.Get("Authorization"),
		"the caller's own origin receives the credential verbatim")
	require.Equal(t, "", hops[0].Header.Get("Referer"),
		"the caller's own request has no predecessor, so it carries no Referer")

	require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
		"the second hop must be the absolute Location, on the other origin - that origin change is what triggers the strip")
	require.Equal(t, http.MethodGet, hops[1].Method,
		"a 302 with a GET leaves the method unchanged, so only the credential differs between the hops")
	require.Equal(t, "", hops[1].Header.Get("Authorization"),
		"Authorization is enumerated as sensitive, so the other origin must receive an empty value - not a truncated or stale one")
	require.Equal(t, "", hops[1].Header.Get("Cookie"),
		"no cookie was set or configured, so the other origin must receive no Cookie header either")
	require.Equal(t, cookieAuthOriginStart, hops[1].Header.Get("Referer"),
		"the destination is still told which URL sent the client to it, which is why the strip is the only thing protecting the credential")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 2, "two requests produce two chain items")
	require.True(t, resp.HasChain())
	require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
		"the final URL must name the origin that answered, so a caller can see the request left the target it asked for")
}

// TestCustomCookieReinjectedAcrossOrigins PINS a divergence: a CONFIGURED cookie is
// re-injected on a redirect hop even when that hop crosses to a different origin.
//
// Cause, by design rather than by accident: both follow closures call
// httpx.setCustomCookies(redirectedRequest) unconditionally on every request net/http
// hands them - common/httpx/httpx.go:101 in the closure these tests select, and :120 in
// the host-scoped one - before any budget or host decision is taken. setCustomCookies
// (:522-531) then deletes whatever Cookie header survived and re-adds
// Options.customCookies. The net effect is that net/http's strip is undone for the
// configured cookies specifically: an INHERITED cookie is gone, while a CONFIGURED one
// reappears on the new origin.
//
// This diverges from RFC 6265 section 5.4, under which a user agent sends a cookie only
// to a host its Domain attribute covers. It is intentional scanner behaviour - an
// operator who passes -H "Cookie: ..." is asserting the cookie applies to the scan, and
// a redirect within a scanned application would otherwise lose the session - so it is
// PINNED AS MEASURED AND NOT FIXED. Changing it would alter results for every user and
// falls well outside a minimal bug fix.
//
// The exact single-line value is what makes the pin meaningful: it distinguishes
// "re-injected once" from "re-injected on top of whatever was inherited".
func TestCustomCookieReinjectedAcrossOrigins(t *testing.T) {
	rt := cookieAuthCrossOriginTransport(t)

	ht := newMockHTTPX(t, func(options *Options) {
		options.CustomHeaders = map[string][]string{"Cookie": {cookieAuthSessionCookie}}
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.Len(t, ht.Options.customCookies, 1,
		"the configured cookie must be parsed during construction, otherwise the re-injection under test cannot happen")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	ht.SetCustomHeaders(req, ht.CustomHeaders)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
	hops := rt.requests()
	require.Len(t, hops, 2)

	require.Equal(t, cookieAuthOriginStart, hops[0].URL)
	require.Equal(t, []string{cookieAuthSessionCookie}, hops[0].Header.Values("Cookie"),
		"the caller's own origin receives the configured cookie from SetCustomHeaders")

	require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
		"the second hop is on a different registrable domain, which is what makes the re-injection notable")
	require.Equal(t, cookieAuthSessionCookie, hops[1].Header.Get("Cookie"),
		"PINNED: the configured cookie is re-injected on the new origin by setCustomCookies (httpx.go:101 -> :522-531), although net/http had stripped the inherited Cookie header")
	require.Len(t, hops[1].Header.Values("Cookie"), 1,
		"PINNED: exactly one header line, so the cookie is re-injected once rather than layered onto an inherited value")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 2)
	require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
		"the final URL names the origin that received the configured cookie")
}

// The credential material for the five authentication strategies. Every value is
// obviously synthetic and cannot match a real provider's token format.
const (
	cookieAuthBasicUser     = "u"
	cookieAuthBasicPassword = "p"
	// cookieAuthBasicExpected is the exact Authorization value SetBasicAuth produces:
	// the "Basic " prefix of RFC 9110 section 11.7 followed by the base64 of
	// "user:password". The literal is asserted rather than recomputed at the assertion
	// site so a defect in the encoding cannot be masked by the same defect appearing on
	// both sides, and a precondition inside the test proves the literal really is that
	// encoding rather than a value transcribed from a passing run.
	cookieAuthBasicExpected = "Basic dTpw"

	cookieAuthBearerToken    = "tok"
	cookieAuthBearerExpected = "Bearer " + cookieAuthBearerToken

	// cookieAuthCustomHeaderKey is deliberately NOT in canonical MIME form.
	// HeadersAuthStrategy writes it into the header map directly, so the casing
	// survives to the wire and http.Header.Get - which canonicalizes its argument -
	// cannot find it. Every assertion on this key therefore reads the raw map.
	cookieAuthCustomHeaderKey   = "barAuthToken"
	cookieAuthCustomHeaderValue = "v1"

	cookieAuthStrategyCookieKey   = "sid"
	cookieAuthStrategyCookieValue = "s1"
	cookieAuthStrategyCookiePair  = cookieAuthStrategyCookieKey + "=" + cookieAuthStrategyCookieValue

	cookieAuthQueryParamKey   = "apikey"
	cookieAuthQueryParamValue = "k1"
	// cookieAuthQueryStart is the caller's target once QueryAuthStrategy has appended
	// its parameter: the credential lives in the request URI, not in a header.
	cookieAuthQueryStart = cookieAuthOriginStart + "?" + cookieAuthQueryParamKey + "=" + cookieAuthQueryParamValue
)

// TestAuthStrategiesAppliedThroughRedirect drives all five authentication strategies
// through a real client request that crosses to a different origin, which no existing
// test does: common/authprovider/authx/strategy_test.go applies each strategy to a bare
// request and asserts the header it wrote, so it cannot observe what happens to that
// header when the client follows a redirect - and that is the only moment at which a
// credential can reach a host the operator never named.
//
// Each row builds a real authx.Secret with the Type string spelled exactly as
// common/authprovider/authx/file.go:19-25 defines it. The literals matter: three of the
// five Go identifiers differ from their string values (BearerTokenAuth is
// "BearerToken", HeadersAuth is "Header", CookiesAuth is "Cookie"), and GetStrategy
// dispatches on the string with strings.EqualFold, so pinning the literal is what
// catches a renamed constant. GetStrategy does not call Validate, so no Domains entry is
// needed to obtain a working strategy. ApplyOnRR is the method under test because the
// client works with *retryablehttp.Request, and it is applied in the production position
// - after SetCustomHeaders, per runner/runner.go:1900-1908.
//
// The table states the FULL observable credential surface on both hops for every row,
// not just the field the row is about. A strategy that wrote into an extra header, or
// that leaked its material into the URL, therefore fails on a row that never mentions
// its own mechanism.
//
// MEASURED outcomes, and one of them is a security finding:
//
//   - Basic, Bearer and Cookie material is withheld from the other origin, because
//     Authorization and Cookie are both in net/http's enumerated sensitive set.
//   - Query material does not propagate, because the redirect target is taken from the
//     Location header verbatim and nothing re-applies the parameter.
//   - The custom header SURVIVES. That is PINNED AS MEASURED AND NOT CHANGED, and it is
//     flagged here as a SECURITY OBSERVATION: HeadersAuthStrategy.ApplyOnRR assigns
//     req.Header[header.Key] = []string{header.Value} at
//     common/authprovider/authx/headers_auth.go:35-39 - a direct map write that bypasses
//     canonicalization, documented as intentional by the NOTE at :32-34 so that
//     case-sensitive APIs keep working - while net/http withholds only Authorization,
//     Www-Authenticate, Cookie and Cookie2. A credential carried in ANY OTHER header is
//     therefore forwarded to whatever origin a redirect names. Neither half of that is
//     this file's to change: the strip list belongs to the standard library and the exact
//     casing is a deliberate, documented feature of the strategy. Pinning it means a
//     future change in either direction is caught and reviewed rather than shipped
//     silently.
func TestAuthStrategiesAppliedThroughRedirect(t *testing.T) {
	require.Equal(t,
		"Basic "+base64.StdEncoding.EncodeToString([]byte(cookieAuthBasicUser+":"+cookieAuthBasicPassword)),
		cookieAuthBasicExpected,
		"precondition: the asserted Basic value must really be the base64 of the credential pair, so the expectation is derived from RFC 9110 section 11.7 rather than transcribed")

	cases := []struct {
		name   string
		secret *authx.Secret
		// The exact credential surface hop 1 - the caller's own origin - receives.
		wantHop1URL           string
		wantHop1Authorization string
		wantHop1Cookie        string
		// wantHop1CustomHeader is a raw-map read, so nil means the key is absent.
		wantHop1CustomHeader []string
		// The same surface after the redirect to the other origin. Every value here is
		// what the OTHER origin gets to see.
		wantHop2Authorization string
		wantHop2Cookie        string
		wantHop2CustomHeader  []string
	}{
		{
			name:                  "basic auth credential withheld from the other origin",
			secret:                &authx.Secret{Type: "BasicAuth", Username: cookieAuthBasicUser, Password: cookieAuthBasicPassword},
			wantHop1URL:           cookieAuthOriginStart,
			wantHop1Authorization: cookieAuthBasicExpected,
			wantHop2Authorization: "",
		},
		{
			name:                  "bearer token withheld from the other origin",
			secret:                &authx.Secret{Type: "BearerToken", Token: cookieAuthBearerToken},
			wantHop1URL:           cookieAuthOriginStart,
			wantHop1Authorization: cookieAuthBearerExpected,
			wantHop2Authorization: "",
		},
		{
			// The security observation in this function's doc comment.
			name:                 "custom auth header survives to the other origin",
			secret:               &authx.Secret{Type: "Header", Headers: []authx.KV{{Key: cookieAuthCustomHeaderKey, Value: cookieAuthCustomHeaderValue}}},
			wantHop1URL:          cookieAuthOriginStart,
			wantHop1CustomHeader: []string{cookieAuthCustomHeaderValue},
			wantHop2CustomHeader: []string{cookieAuthCustomHeaderValue},
		},
		{
			name:           "strategy cookie withheld from the other origin",
			secret:         &authx.Secret{Type: "Cookie", Cookies: []authx.Cookie{{Key: cookieAuthStrategyCookieKey, Value: cookieAuthStrategyCookieValue}}},
			wantHop1URL:    cookieAuthOriginStart,
			wantHop1Cookie: cookieAuthStrategyCookiePair,
			// Withheld by net/http AND not restored: this cookie is applied per target
			// by a strategy, so it is absent from Options.customCookies and
			// setCustomCookies has nothing to re-inject - the contrast with
			// TestCustomCookieReinjectedAcrossOrigins is the point.
			wantHop2Cookie: "",
		},
		{
			name:        "query credential does not propagate to the other origin",
			secret:      &authx.Secret{Type: "Query", Params: []authx.KV{{Key: cookieAuthQueryParamKey, Value: cookieAuthQueryParamValue}}},
			wantHop1URL: cookieAuthQueryStart,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh transport per row: callCount and the recorded snapshots
			// accumulate, so a shared one would let an earlier row's hops satisfy this
			// row's assertions.
			rt := cookieAuthCrossOriginTransport(t)

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = cookieAuthMaxRedirects
			}, rt)
			require.False(t, ht.Options.hasCustomCookies(),
				"precondition: no cookie is configured, so nothing re-injects one and each row observes its own strategy only")

			req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
			require.NoError(t, err)

			strategy := tc.secret.GetStrategy()
			require.NotNil(t, strategy,
				"GetStrategy dispatches on the Type string (authx/file.go:66-80) and returns nil for an unrecognized one, so a nil here means the literal no longer matches")
			strategy.ApplyOnRR(req)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
			hops := rt.requests()
			require.Len(t, hops, 2)

			require.Equal(t, tc.wantHop1URL, hops[0].URL,
				"hop 1's request URI must carry exactly the credential material the strategy put there, and nothing more")
			require.Equal(t, tc.wantHop1Authorization, hops[0].Header.Get("Authorization"),
				"hop 1's Authorization must be exactly what this strategy writes - empty for the strategies that write elsewhere")
			require.Equal(t, tc.wantHop1Cookie, hops[0].Header.Get("Cookie"),
				"hop 1's Cookie must be exactly what this strategy writes - empty for the strategies that write elsewhere")
			// The raw map index is deliberate and the staticcheck exemption is the
			// assertion, not an oversight: SA1008 objects to a non-canonical key
			// precisely because HeadersAuthStrategy writes one directly
			// (authx/headers_auth.go:35-39), and canonicalizing the lookup here would
			// look for "Barauthtoken", find nothing, and silently assert nothing.
			require.Equal(t, tc.wantHop1CustomHeader, hops[0].Header[cookieAuthCustomHeaderKey], //nolint:staticcheck // SA1008: the non-canonical key is the behaviour under test
				"hop 1's non-canonical key is read from the raw map, because Header.Get would canonicalize the lookup and miss the direct map write")

			require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
				"hop 2 must be the absolute Location verbatim: no query parameter is re-applied to it, which is why a query credential cannot propagate")
			require.NotContains(t, hops[1].URL, cookieAuthQueryParamKey,
				"the other origin must not receive the query credential, not even as a bare key")
			require.Equal(t, tc.wantHop2Authorization, hops[1].Header.Get("Authorization"),
				"the other origin's Authorization must be exactly this value - an empty string means withheld, never merely absent from a nil check")
			require.Equal(t, tc.wantHop2Cookie, hops[1].Header.Get("Cookie"),
				"the other origin's Cookie must be exactly this value - an empty string means withheld, never merely absent from a nil check")
			require.Equal(t, tc.wantHop2CustomHeader, hops[1].Header[cookieAuthCustomHeaderKey], //nolint:staticcheck // SA1008: the non-canonical key is the behaviour under test
				"PINNED SECURITY OBSERVATION: net/http withholds only Authorization, Www-Authenticate, Cookie and Cookie2, so a credential in any other header reaches the other origin (authx/headers_auth.go:35-39)")
			require.Equal(t, "", hops[1].Header.Get(cookieAuthCustomHeaderKey),
				"Header.Get canonicalizes its argument, so it cannot observe the directly written key at all - which is exactly why a reviewer auditing with Get would miss the leak above")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
			require.Len(t, resp.Chain, 2, "two requests produce two chain items")
			require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes(),
				"the status sequence is ordered, so the redirect must precede the final response")
			require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
				"the final URL must name the other origin, so a caller can see which host the credential decision applied to")
		})
	}
}
