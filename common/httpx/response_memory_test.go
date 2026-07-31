package httpx

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// newLocalHTTPX builds an HTTPX instance suitable for hitting a local test
// server only (no external network, CDN checks disabled).
func newLocalHTTPX(t *testing.T) *HTTPX {
	t.Helper()
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 5 * time.Second
	options.RetryMax = 0
	// NB: relies on DefaultOptions.MaxResponseBodySizeToRead being non-zero
	// (see TestDefaultOptionsHasNonZeroReadSize) so the body is actually read.

	ht, err := New(&options)
	require.NoError(t, err)
	return ht
}

// doLocal issues a GET against a local httptest server and returns the parsed
// httpx Response.
func doLocal(t *testing.T, ht *HTTPX, url string) *Response {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	return resp
}

// legacyWordsLines reproduces the exact word/line computation that existed
// before the refactor, so we can assert the new byte-based path is equivalent.
func legacyWordsLines(body []byte) (words, lines int) {
	s := string(body)
	if s != "" {
		words = len(strings.Split(s, " "))
		lines = len(strings.Split(strings.TrimSpace(s), "\n"))
	}
	return
}

// TestDefaultOptionsHasNonZeroReadSize guards against the package var-init
// ordering regression where DefaultOptions was initialized before
// DefaultMaxResponseBodySize, leaving MaxResponseBodySizeToRead at 0 (which made
// LimitReader read zero bytes and produced empty bodies for library users).
func TestDefaultOptionsHasNonZeroReadSize(t *testing.T) {
	require.NotZero(t, DefaultMaxResponseBodySize)
	require.Equal(t, DefaultMaxResponseBodySize, DefaultOptions.MaxResponseBodySizeToRead)
}

func TestDoBodyNoDecodePreservesRawAndData(t *testing.T) {
	body := []byte("hello world\nsecond line\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, body, resp.Data, "decoded data must equal body")
	require.Equal(t, body, resp.RawData, "raw data must equal undecoded body")

	wantWords, wantLines := legacyWordsLines(body)
	require.Equal(t, wantWords, resp.Words)
	require.Equal(t, wantLines, resp.Lines)
}

func TestDoBodyEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)
	require.Empty(t, resp.Data)
	require.Empty(t, resp.RawData)
	require.Equal(t, 0, resp.Words)
	require.Equal(t, 0, resp.Lines)
}

// TestDoBodyGBKDecodeKeepsRawUndecoded ensures that when DecodeData actually
// transcodes the body, RawData still holds the original (undecoded) bytes while
// Data holds the decoded UTF-8 bytes.
func TestDoBodyGBKDecodeKeepsRawUndecoded(t *testing.T) {
	utf8Body := "<html><head></head><body>你好世界 测试</body></html>"
	gbkBody, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(utf8Body))
	require.NoError(t, err)
	require.NotEqual(t, []byte(utf8Body), gbkBody, "precondition: gbk bytes differ from utf8")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=gbk")
		_, _ = w.Write(gbkBody)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, gbkBody, resp.RawData, "RawData must hold the original undecoded bytes")
	require.Equal(t, []byte(utf8Body), resp.Data, "Data must hold the decoded UTF-8 bytes")
}

// TestDoBodyNoDecodeSharesBacking documents the memory optimization: on the
// no-decode hot path RawData and Data share the same backing array (no extra
// full-body copy is made).
func TestDoBodyNoDecodeSharesBacking(t *testing.T) {
	body := []byte("shared backing array body")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.NotEmpty(t, resp.Data)
	require.NotEmpty(t, resp.RawData)
	require.Equal(t, resp.Data, resp.RawData)
	require.Same(t, &resp.Data[0], &resp.RawData[0],
		"RawData and Data should share the backing array on the no-decode path")
}

// TestWordsLinesEquivalence is the core guard for the refactor: the byte-based
// counting used on the hot path must be identical to the previous
// strings.Split-based counting for a wide range of inputs and edge cases.
func TestWordsLinesEquivalence(t *testing.T) {
	cases := []string{
		"",
		"a",
		"a b c",
		"   ",                        // only spaces
		"a  b",                       // consecutive spaces
		"line1\nline2\nline3",        // multiple lines
		"\n\n\n",                     // only newlines
		"  leading and trailing  ",   // surrounding whitespace
		"\n  mixed \t whitespace \n", // tabs/newlines around
		"trailing newline\n",
		"word",
		"tab\tseparated values",
		"unicode \u00a0 nbsp space",
		"emoji 😀 and spaces ",
	}

	for _, c := range cases {
		body := []byte(c)
		wantWords, wantLines := legacyWordsLines(body)

		var gotWords, gotLines int
		if len(body) > 0 {
			gotWords = bytes.Count(body, []byte{' '}) + 1
			gotLines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
		}

		require.Equalf(t, wantWords, gotWords, "words mismatch for %q", c)
		require.Equalf(t, wantLines, gotLines, "lines mismatch for %q", c)
	}
}

// TestBodyMetricsCountingDoesNotAllocate locks in the optimization: the
// byte-based word/line counting used on the hot path must not allocate (the
// previous string(respbody) + strings.Split approach allocated O(len(body))).
// If someone reintroduces a full-body string copy or Split-based counting, this
// test fails.
func TestBodyMetricsCountingDoesNotAllocate(t *testing.T) {
	body := bytes.Repeat([]byte("lorem ipsum dolor sit amet\n"), 40000) // ~1MB
	var words, lines int

	allocs := testing.AllocsPerRun(50, func() {
		// identical expressions to the hot path in Do()
		words = bytes.Count(body, []byte{' '}) + 1
		lines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
	})

	require.NotZero(t, words)
	require.NotZero(t, lines)
	require.Zerof(t, allocs, "word/line counting must not allocate, got %v allocs/op", allocs)
}

// TestDoBodyReadCapTruncatesOversizeBody is the motivating failing case for the
// ContentLength guard inside Do's read-cap branch: a response whose origin DECLARES
// more bytes than MaxResponseBodySizeToRead allows must be TRUNCATED, never dropped.
//
// Before that guard existed the body was wrapped in an io.LimitReader while the
// upstream *http.Response kept ContentLength=100, so the full-response
// serialization inside pdhttputil.DumpResponseHeadersAndRaw failed its own length
// check with "http: ContentLength=100 with Body length 10" and Do returned NO
// RESPONSE AT ALL - the target vanished from output entirely. Three independent
// contracts in this repository document the option as a read cap, i.e. truncation
// rather than a hard failure: the -rstr flag help text ("max response size to read
// in bytes"), the DefaultMaxResponseBodySize doc comment in option.go (which speaks
// of what httpx "reads into memory" and points at -rstr/-rsts to read or store
// larger responses), and the specification's description of Do capping the
// in-memory response body read. TestDoBodyReadCapChunkedTruncation is the companion
// proving the guard is inert on the path that already worked.
//
// Every value asserted here was measured against the current code and is stable
// across repeated runs: Date is a fixed-length IMF-fixdate and the handler pins
// Content-Type, so MIME sniffing cannot widen the dump (leaving Content-Type to the
// sniffer yields "text/plain; charset=utf-8", 15 bytes longer, and turns the
// far-over-the-cap dump from 111 bytes into 126).
//
// Note that only the UPSTREAM ContentLength field is invalidated. resp.ContentLength
// is recomputed by Do from the preserved Headers["Content-Length"] entry, so in every
// case below the caller observes the 100 bytes the origin declared even when the cap
// let it keep far fewer - deliberately, not contradictorily.
//
// Raising the cap without touching newLocalHTTPX is safe and is what keeps the
// helper untouched: newLocalHTTPX copies DefaultOptions by VALUE and New retains a
// pointer to that copy, while Do reads MaxResponseBodySizeToRead at request time.
// Assigning through ht.Options therefore reconfigures this client alone and cannot
// corrupt the package-level DefaultOptions every other test reads.
//
// The cap is swept across its whole boundary rather than sampled at one point,
// because an off-by-one in the guard is exactly the plausible defect this test has to
// catch. Below the cap and EXACTLY AT it nothing may change - the declared length is
// still honourable, so the dump must keep framing the body with it - while one byte
// over is where truncation and connection-close framing begin. A guard written with
// >= instead of > would pass every assertion about the bytes and fail only on the
// at-the-cap framing, which is why that case asserts the Content-Length line
// explicitly rather than just the body.
func TestDoBodyReadCapTruncatesOversizeBody(t *testing.T) {
	// 100 bytes whose first 10 are recognizable, so the assertions prove the cap
	// kept the PREFIX rather than merely N bytes from somewhere in the body.
	body := []byte("0123456789" + strings.Repeat("x", 90))
	require.Len(t, body, 100, "precondition: the origin declares and delivers exactly 100 bytes")

	// Raw lengths, all measured. Untruncated:  17 (status line) + 19
	// (Connection: close) + 21 (Content-Length: 100) + 26 (Content-Type: text/plain)
	// + 37 (Date) + 2 (blank line) + N (body). Truncated: the same minus the
	// 21-byte Content-Length line, which the dump can no longer honour.
	for _, tc := range []struct {
		name string
		// readCap rather than cap, which would shadow the builtin.
		readCap       int64
		wantData      []byte
		wantRaw       int
		wantRawHeader int
		// wantDeclaredFraming is true while the dump can still frame the body with
		// the length the origin declared.
		wantDeclaredFraming bool
	}{
		{name: "below the cap", readCap: 200, wantData: body, wantRaw: 222, wantRawHeader: 122, wantDeclaredFraming: true},
		{name: "exactly at the cap", readCap: 100, wantData: body, wantRaw: 222, wantRawHeader: 122, wantDeclaredFraming: true},
		{name: "one byte over the cap", readCap: 99, wantData: body[:99], wantRaw: 200, wantRawHeader: 101},
		{name: "far over the cap", readCap: 10, wantData: body[:10], wantRaw: 111, wantRawHeader: 101},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Content-Length is the field the pre-fix defect keyed on;
				// Content-Type is pinned so the dump length is free of MIME sniffing.
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write(body)
			}))
			defer ts.Close()

			ht := newLocalHTTPX(t)
			ht.Options.MaxResponseBodySizeToRead = tc.readCap

			// doLocal asserts no error, which is itself the regression guard: the
			// truncating cases used to fail outright instead of returning a response.
			resp := doLocal(t, ht, ts.URL)

			require.Equal(t, http.StatusOK, resp.StatusCode, "a truncated body is still a successful response")
			require.Equal(t, tc.wantData, resp.Data,
				"the read cap must retain exactly the first MaxResponseBodySizeToRead body bytes")
			require.Equal(t, resp.Data, resp.RawData, "the undecoded body is the same retained prefix")
			require.Equal(t, 100, resp.ContentLength,
				"ContentLength is recomputed from the origin's own Content-Length header, not from the retained bytes")
			require.Equal(t, "100", resp.GetHeader("Content-Length"),
				"the declared length stays visible to the caller through the response headers")

			require.Len(t, resp.Raw, tc.wantRaw, "the full dump is the headers plus exactly the retained body bytes")
			require.Len(t, resp.RawHeaders, tc.wantRawHeader, "the header-only dump is the full dump minus the retained body")
			require.Equal(t, len(resp.Data), len(resp.Raw)-len(resp.RawHeaders),
				"the body section of the dump must be exactly the bytes the cap retained")
			require.True(t, strings.HasSuffix(resp.Raw, string(tc.wantData)),
				"the dump must end with the retained prefix, got %q", resp.Raw)

			if tc.wantDeclaredFraming {
				require.Contains(t, resp.Raw, "\r\nContent-Length: 100\r\n",
					"an untruncated body must still be framed by the length the origin declared")
			} else {
				// With the declared length invalidated the dump frames the truncated
				// body by connection close instead of by a length it cannot honour. A
				// regression that rewrote the HEADER rather than the field would
				// surface here as a stale or shrunken Content-Length line.
				require.NotContains(t, resp.Raw, "Content-Length",
					"a truncated body must not be framed by a declared length")
			}
			require.Contains(t, resp.Raw, "\r\nConnection: close\r\n",
				"the scanner disables keep-alives, so every response is close-delimited")

			require.Equal(t, 1, resp.Words)
			require.Equal(t, 1, resp.Lines)
		})
	}
}

// TestDoBodyReadCapChunkedTruncation pins the read cap on the path that always
// worked, and is the control for TestDoBodyReadCapTruncatesOversizeBody: every value
// below is byte-identical to the pre-guard baseline, so it proves the ContentLength
// guard in Do is completely inert here.
//
// It is inert by construction rather than by luck. A chunked response carries no
// Content-Length, so net/http hands Do an upstream ContentLength of -1; the guard's
// "declared length exceeds the cap" test is therefore false and its assignment never
// fires. The caller-visible ContentLength of 100 consequently comes from a different
// place than in the declared-length case: Do's header lookup finds no
// Content-Length entry, so it falls back to len(respbody) - which is the TRUNCATED
// length, not the origin's real 40,000 bytes. Asserting the absent header through
// the accessor is what makes that provenance visible instead of implied.
//
// The dump length is independent of how large the payload actually is (measured
// identical for 40,000, 42,000 and 1,080,000-byte bodies), because only the retained
// bytes are ever serialized.
func TestDoBodyReadCapChunkedTruncation(t *testing.T) {
	// Generated at runtime rather than stored as a fixture, following the
	// bytes.Repeat precedent in TestBodyMetricsCountingDoesNotAllocate. 25 bytes per
	// unit means the 100-byte cap lands exactly on a line boundary, which is what
	// makes the word and line counts below exact rather than incidental.
	payload := bytes.Repeat([]byte("chunked response payload\n"), 1600)
	require.Len(t, payload, 40000, "precondition: the origin delivers exactly 40000 bytes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: writing well past the server's buffer without one is
		// what makes net/http chunk the response, which is the whole point here.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	ht := newLocalHTTPX(t)
	ht.Options.MaxResponseBodySizeToRead = 100

	resp := doLocal(t, ht, ts.URL)

	require.Equal(t, payload[:100], resp.Data,
		"the read cap must retain exactly the first 100 bytes of the chunked body")
	require.Equal(t, resp.Data, resp.RawData, "the undecoded body is the same truncated prefix")
	require.Equal(t, 100, resp.ContentLength,
		"with no Content-Length header the length falls back to the number of bytes actually read")
	require.Equal(t, "", resp.GetHeader("Content-Length"),
		"a chunked response declares no length, which is why the fallback is used")

	// 17 (status line) + 19 (Connection: close) + 28 (Transfer-Encoding: chunked)
	// + 26 (Content-Type: text/plain) + 37 (Date) + 2 (blank line)
	// + 111 (chunk framing: "64\r\n" + 100 bytes + "\r\n" + "0\r\n\r\n") = 240.
	require.Len(t, resp.Raw, 240, "the chunked dump length is unchanged from the pre-guard baseline")
	require.Len(t, resp.RawHeaders, 129, "the header-only dump excludes the chunk-framed body")
	require.Contains(t, resp.Raw, "\r\nTransfer-Encoding: chunked\r\n",
		"the truncated body is re-serialized with chunked framing")
	require.Contains(t, resp.Raw, "\r\n\r\n64\r\n",
		"the single chunk declares 0x64 = 100 bytes, the capped length")
	require.True(t, strings.HasSuffix(resp.Raw, "\r\n0\r\n\r\n"),
		"the dump must close with the terminating zero-length chunk, got %q", resp.Raw)

	// 100 retained bytes are exactly four 25-byte units: 4x2 spaces + 1 = 9 words,
	// and TrimSpace drops the trailing newline leaving 3 + 1 = 4 lines.
	require.Equal(t, 9, resp.Words)
	require.Equal(t, 4, resp.Lines)
}

// TestDoBodyNotModifiedSkipsBodyRead pins the body-skip path: Do computes
// shouldSkipBodyRead with generic.EqualsAny over 101 Switching Protocols and 304 Not
// Modified, and for those two statuses it never reads a body at all.
//
// RFC 9110 section 15.4.5 specifies that a 304 carries no message body, and RFC 7232
// section 4.1 is why net/http's server additionally suppresses Content-Type,
// Content-Length and Transfer-Encoding for it - so against a conforming origin the
// response headers are exactly the validator plus Date and the full dump is
// byte-identical to the header-only dump. The word and line counts are zero because
// Do's counting is guarded by len(respbody) > 0, the same reason TestDoBodyEmpty
// asserts 0 and 0.
//
// The validator is asserted through GetHeader with the CANONICAL spelling "Etag".
// Response.Headers is a plain map[string][]string and GetHeader is a raw map read
// with no canonicalization, so the lookup is case-sensitive: net/http stores the
// handler's "ETag" under textproto's canonical "Etag", and "ETag" would silently
// return the empty string.
//
// The two sub-tests are not redundant, and the second is what gives this test its
// teeth. Against a conforming origin the skip is INVISIBLE: a real 304 carries no
// body, so an implementation that dutifully read it would still produce an empty one
// and every assertion would pass anyway. Only a response that carries bytes behind
// the status can tell "Do skipped the read" apart from "there was nothing to read",
// and no loopback server can produce that - net/http's server suppresses a body for
// a 304 by design. Serving it from the mock transport is therefore the only way to
// pin the branch itself.
func TestDoBodyNotModifiedSkipsBodyRead(t *testing.T) {
	const validator = `"abc123"` // a quoted entity-tag, per RFC 9110 section 8.8.3

	t.Run("conforming origin sends no body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", validator)
			w.WriteHeader(http.StatusNotModified)
		}))
		defer ts.Close()

		resp := doLocal(t, newLocalHTTPX(t), ts.URL)

		require.Equal(t, http.StatusNotModified, resp.StatusCode)
		require.Empty(t, resp.Data, "a 304 body is never read")
		require.Empty(t, resp.RawData, "a 304 body is never read, decoded or otherwise")
		require.Equal(t, 0, resp.ContentLength)
		require.Equal(t, 0, resp.Words)
		require.Equal(t, 0, resp.Lines)

		require.Equal(t, resp.RawHeaders, resp.Raw,
			"with no body section the full dump equals the header-only dump")
		require.Len(t, resp.Raw, 101,
			"27 (status line) + 19 (Connection: close) + 37 (Date) + 16 (Etag) + 2 (blank line)")
		require.True(t, strings.HasSuffix(resp.Raw, "\r\n\r\n"),
			"the dump must stop at the header terminator, got %q", resp.Raw)

		require.Equal(t, validator, resp.GetHeader("Etag"),
			"the validator must survive the skipped body read under its canonical key")
		require.Equal(t, "", resp.GetHeader("ETag"),
			"GetHeader is a raw map read: a non-canonical spelling finds nothing")
		require.Equal(t, "", resp.GetHeader("Content-Length"),
			"RFC 7232 section 4.1: a 304 carries no Content-Length")
		require.Equal(t, "", resp.GetHeader("Content-Type"),
			"RFC 7232 section 4.1: a 304 carries no Content-Type")
	})

	t.Run("body smuggled behind the status is not read", func(t *testing.T) {
		// A non-conforming 304 that does carry bytes, contradicting RFC 9110
		// section 15.4.5. Only the mock transport can present one.
		const smuggled = "should-never-be-read"

		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			return mockResponse(r, http.StatusNotModified,
				http.Header{"Etag": {validator}}, smuggled), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/cached", nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)

		// The bytes reached the client - the dump proves it serialized them - and Do
		// still refused to read them into the body. Drop the status from
		// shouldSkipBodyRead and the smuggled payload lands in Data instead.
		require.Contains(t, resp.Raw, smuggled,
			"precondition: the origin really did put bytes behind the 304")
		require.Equal(t, http.StatusNotModified, resp.StatusCode)
		require.Empty(t, resp.Data, "the skipped read must leave the body empty even when bytes are present")
		require.Empty(t, resp.RawData, "the undecoded body must be empty too")
		require.Equal(t, 0, resp.ContentLength, "no bytes read means no length to report")
		require.Equal(t, 0, resp.Words)
		require.Equal(t, 0, resp.Lines)
		require.Equal(t, validator, resp.GetHeader("Etag"))
		require.Equal(t, 1, rt.callCount(), "a skipped body read must not provoke a second request")
	})
}

// TestDoBodyGzipInvalidHeaderRetriesWithIdentity pins Do's one-shot content-encoding
// retry: when a response is LABELLED with a compressed encoding but its body cannot
// be decoded, Do rewrites Accept-Encoding to identity and reissues the request
// exactly once, guarded by an internal flag so a second failure is not retried.
//
// The failure is injected rather than produced, because the transparent
// decompression that raises it in production lives in the http.Transport this test
// replaces. errReadCloser paired with gzip.ErrHeader reproduces it faithfully:
// gzip.ErrHeader is precisely "gzip: invalid header", the substring Do matches on.
//
// Accept-Encoding is set explicitly on the request for the same reason - a custom
// RoundTripper bypasses http.Transport's automatic encoding negotiation, so hop 1
// would otherwise carry no Accept-Encoding at all. Setting it makes the per-hop
// assertion sharper rather than weaker: hop 1 carries exactly what the caller asked
// for, and hop 2 carries identity only because Do overwrote it.
//
// The most telling assertion in the first sub-test is the last one. Do rewrites the
// header on the CALLER'S OWN request object, so the retry is observable from outside
// the call: a caller that inspects its request after Do returns sees identity, not
// the gzip it set. That is a protocol-visible side effect, and a refactor that
// retried on a copy would fail there while leaving every response assertion green.
//
// The second sub-test pins the one-shot guard, which the first cannot reach: once the
// identity attempt succeeds there is no second failure to retry, so an
// implementation that never armed the guard would look identical. Scripting two
// consecutive failures followed by a success separates them by round-trip count
// alone - a correct client stops at two and surfaces the error, while an unguarded
// one retries again and "recovers" on the third.
func TestDoBodyGzipInvalidHeaderRetriesWithIdentity(t *testing.T) {
	const plainBody = "plain-not-gzipped-x" // exactly 19 bytes, never gzip-compressed
	require.Len(t, plainBody, 19, "precondition: the payload is exactly 19 bytes")

	// A response LABELLED gzip whose body yields no byte and fails with the exact
	// error the standard library's gzip reader reports. Shared by both sub-tests as a
	// local closure rather than a package-level helper, since nothing else needs it.
	invalidGzip := func(r *http.Request) *http.Response {
		resp := mockResponse(r, http.StatusOK,
			http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/plain"}}, "")
		resp.Body = &errReadCloser{err: gzip.ErrHeader}
		resp.ContentLength = -1 // a body that yields no byte cannot satisfy a declared length
		return resp
	}

	t.Run("identity retry recovers the body", func(t *testing.T) {
		// Routing on the request's own Accept-Encoding, rather than on a call
		// counter, ties each reply to what the client actually asked for: the origin
		// serves the plain payload only once identity has been negotiated.
		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Accept-Encoding") == "identity" {
				return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, plainBody), nil
			}
			return invalidGzip(r), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/encoding", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)

		// Exactly two round trips: the retry reissues the request once, not in a loop.
		require.Equal(t, 2, rt.callCount(), "the encoding retry must reissue the request exactly once")
		hops := rt.requests()
		require.Len(t, hops, 2)
		require.Equal(t, []string{"gzip", "identity"},
			[]string{hops[0].Header.Get("Accept-Encoding"), hops[1].Header.Get("Accept-Encoding")},
			"hop 1 carries the caller's encoding, hop 2 the identity Do substituted")
		require.Equal(t, hops[0].Method, hops[1].Method, "the retry replays the same method")
		require.Equal(t, hops[0].URL, hops[1].URL, "the retry replays the same target")

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, []byte(plainBody), resp.Data, "the identity reply's bytes are what the caller receives")
		require.Len(t, resp.Data, 19)
		require.Equal(t, 19, resp.ContentLength)
		require.Equal(t, "", resp.GetHeader("Content-Encoding"),
			"the surviving response is the unlabelled one, so no encoding is reported")
		require.True(t, strings.HasSuffix(resp.Raw, "\r\n\r\n"+plainBody),
			"the dump must carry the identity reply's body, got %q", resp.Raw)

		require.Equal(t, "identity", req.Header.Get("Accept-Encoding"),
			"the retry rewrites the caller's own request header, an observable side effect")
	})

	t.Run("the retry is one-shot", func(t *testing.T) {
		// Fail the first two attempts, then succeed. A guarded client never asks a
		// third time, so it never sees this payload; its presence in the response is
		// exactly the symptom of a retry loop.
		const recovered = "third-attempt-body"

		// The handler consults the transport it belongs to, so it is declared before
		// being assigned. callCount is atomic, which keeps the read race-free.
		var rt *mockTransport
		rt = newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			if rt.callCount() > 2 {
				return mockResponse(r, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, recovered), nil
			}
			return invalidGzip(r), nil
		})

		ht := newMockHTTPX(t, nil, rt)
		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/always-invalid", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := ht.Do(req, UnsafeOptions{})

		require.Equal(t, 2, rt.callCount(),
			"the retry must fire once and only once, even when the second attempt fails too")
		require.Error(t, err, "a second undecodable body must surface rather than trigger another retry")
		require.ErrorContains(t, err, "gzip: invalid header",
			"the surfaced error must be the decode failure itself")
		require.Nil(t, resp, "no response is produced when the retried attempt also fails")

		hops := rt.requests()
		require.Len(t, hops, 2)
		require.Equal(t, []string{"gzip", "identity"},
			[]string{hops[0].Header.Get("Accept-Encoding"), hops[1].Header.Get("Accept-Encoding")},
			"the single retry still negotiates identity before giving up")
	})
}
