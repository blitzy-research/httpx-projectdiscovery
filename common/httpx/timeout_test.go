package httpx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests separate the two ways a request can fail on the clock and pin the IDENTITY of
// the error each one produces, so a defect that collapsed the categories - or swapped which
// sentinel came back - cannot pass as "an error occurred". Go has no exception classes, so
// each category is pinned on four axes whose combination carries the assertion power: the
// concrete error type, the errors.Is sentinel relationship in BOTH directions, the
// net.Error-style Timeout() behaviour reached with errors.As, and the presence or absence of
// the retry layer's exhaustion wrapper. The categories differ on every one: a client
// deadline arrives wrapped three deep (*fmt.wrapError -> *url.Error -> net/http's unexported
// timeoutError), reports Timeout() == true, matches context.DeadlineExceeded and carries
// "giving up after N attempts", while a caller cancellation arrives as the bare
// context.Canceled sentinel with no Timeout() method and no retry wrapper.
//
// Interception happens at the http.RoundTripper boundary, above DNS, TCP and TLS, so
// slow.example is never resolved and no socket is opened. Time is deliberately NOT mocked:
// real short deadlines against a handler that never answers exercise the production timer
// paths and keep every case sub-second.
//
// No test here uses t.Parallel(), matching every other test in this package: New sets the
// process-global GODEBUG variable on the HTTP/1.1 path, and these assertions are wall-clock
// sensitive besides.

const (
	// timeoutTarget is a synthetic authority that exists only inside the scripted
	// transport, so nothing here can depend on name resolution or egress.
	timeoutTarget = "http://slow.example/"

	// timeoutBudget is the client wall-clock deadline under test. It has to stay well
	// above the scheduling noise between the deadline firing and the elapsed measurement,
	// and well below timeoutTransportSleep, so every case fails on the deadline rather
	// than on the handler's safety valve. Every elapsed bound is expressed as a multiple
	// of this value, so the envelopes scale with it rather than having to be retuned.
	//
	// CALIBRATION. This value also sets the file's irreducible cost, because six sub-cases
	// each wait out one whole budget before asserting anything - one in
	// TestTimeoutClientTimeoutErrorIdentity, three across the RetryMax sweep and two across
	// the constructor parity rows - so 6*timeoutBudget + timeoutCancelAfter (about 0.66s
	// here) is deliberate sleeping that no amount of host quiet can remove. It is kept this
	// short so the file stays inside its runtime budget, and shortening it costs no
	// assertion power at all, because the deadline is a fixture SCALE and never an asserted
	// outcome: every elapsed bound is written relative to it, and the load-bearing
	// assertions are exact counts (callCount() == 1, len(hops) == 1), the four error
	// identity axes and the anti-per-attempt bound, all of which are scale-free. The floor
	// is the overhead the call cannot avoid - client construction, request building and
	// timer granularity, measured at 10-90ms even under 2-3x CPU oversubscription - which
	// the envelope above still clears comfortably. Do NOT buy margin by raising
	// timeoutEnvelopeFactor instead: that would weaken every upper bound in the file.
	timeoutBudget = 100 * time.Millisecond

	// timeoutCancelAfter is when the caller-driven cancellation fires, two orders of
	// magnitude inside timeoutNoDeadline so a defect that let the client deadline end that
	// call would blow the elapsed envelope rather than pass quietly. It also has to leave
	// the call enough time to reach the transport, which the call-count assertion checks.
	// Calibrated with timeoutBudget and for the same reason: it is the one remaining
	// deliberate wait in the file, and both its lower bound and its envelope are written
	// relative to it, so keeping it short loses nothing.
	timeoutCancelAfter = 60 * time.Millisecond

	// timeoutNoDeadline is the cancellation test's client timeout, deliberately far beyond
	// anything that test tolerates so the client deadline cannot be the cause.
	timeoutNoDeadline = 10 * time.Second

	// timeoutTransportSleep never actually elapses, because the handler's select returns
	// as soon as the request context ends. It is the safety valve that turns "the deadline
	// never fired" into a named failure instead of a hang.
	//
	// It therefore stays at 3s even though the deadlines above are deliberately short: it
	// is free in wall time, and the separation is what makes the diagnostic branch a
	// genuine safety valve rather than a race - 30x timeoutBudget and 50x
	// timeoutCancelAfter. It must not be reduced alongside them.
	timeoutTransportSleep = 3 * time.Second

	// timeoutEnvelopeFactor widens every elapsed assertion to this multiple of the budget.
	// Elapsed is an inequality, never an exact duration: exact would flake under load,
	// while a generous bound still fails a per-attempt deadline, which multiplies the total.
	timeoutEnvelopeFactor = 3
)

// timeoutError is the net.Error-shaped contract through which net/http reports that a
// deadline, rather than a peer, ended a request. It is declared locally and matched with
// errors.As because the implementing type is net/http's unexported timeoutError and cannot
// be named from here; asserting the behaviour also pins what callers depend on.
type timeoutError interface {
	Timeout() bool
}

// timeoutSlowTransport returns a recording transport whose handler never answers: it blocks
// until the request context ends and then reports that context's error, as a real transport
// does when a dial or a header read is cut short.
//
// A FRESH transport per case is mandatory: mockTransport's call counter is cumulative, so
// sharing one would turn every "entered exactly once" assertion into a tautology.
//
// The sleep branch is unreachable in a correctly configured test and names the
// misconfiguration if it becomes reachable. It reports through t.Error rather than require,
// following scriptedRedirects, because a require call from another goroutine would Goexit
// and hang the test. The diagnostic uses redactedRequestLine so a URL userinfo password
// cannot reach a retained log (CWE-532).
func timeoutSlowTransport(t *testing.T) *mockTransport {
	t.Helper()

	return newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			// The production shape of a cut-short request: no response and the context's
			// own error, whose identity is what each test below discriminates.
			return nil, r.Context().Err()
		case <-time.After(timeoutTransportSleep):
			err := fmt.Errorf(
				"timeoutSlowTransport: %s was not cut short within %s (request context error: %v)",
				redactedRequestLine(r), timeoutTransportSleep, r.Context().Err())
			t.Error(err)
			return nil, err
		}
	})
}

// newTimeoutHTTPX builds a client whose transport never answers, with the given wall-clock
// budget and retry ceiling, returning both so a test can assert on the caller-visible error
// and on what reached the wire.
//
// Both values go through the option mutator because newMockHTTPX runs it BEFORE New, and New
// freezes Options.Timeout into HTTPX.New's http.Client Timeout field and into the retry
// layer's overall budget, and Options.RetryMax into the retry options. Assigning either
// after construction would leave the client on the harness default and every elapsed
// envelope would pass for the wrong reason. newMockHTTPX also installs the transport on BOTH
// of the retryable client's HTTP clients and registers the fastdialer cleanup.
func newTimeoutHTTPX(t *testing.T, timeout time.Duration, retryMax int) (*HTTPX, *mockTransport) {
	t.Helper()

	rt := timeoutSlowTransport(t)
	ht := newMockHTTPX(t, func(options *Options) {
		options.Timeout = timeout
		options.RetryMax = retryMax
	}, rt)
	return ht, rt
}

// TestTimeoutClientTimeoutErrorIdentity pins the identity of the error produced when the
// deadline in HTTPX.New's http.Client Timeout field fires, on every axis a caller can
// inspect.
//
// Where the wrap chain comes from: the deadline makes net/http replace the round-trip
// error with its unexported timeoutError, whose Timeout() is true and whose custom Is
// method reports equality with context.DeadlineExceeded - which is why the sentinel
// matches even though nothing literally wraps it. net/http wraps that in *url.Error, and
// retryablehttp wraps THAT with fmt.Errorf("... giving up after %d attempts: %w", ...),
// which is the *fmt.wrapError on the outside. Do surfaces the failure as (nil, err)
// because it returns early whenever the response is nil and the error is not.
func TestTimeoutClientTimeoutErrorIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutBudget, 0)

	req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a transport that never answers must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the deadline fires (httpx.go:261-263)")

	// AXIS 1 - concrete type. *fmt.wrapError is unexported, so %T is the only mechanism
	// available; it still fails the moment the retry layer stops wrapping.
	require.Equal(t, "*fmt.wrapError", fmt.Sprintf("%T", err),
		"the deadline error must reach the caller wrapped by the retry layer's fmt.Errorf")

	// AXIS 2 - sentinel identity, in BOTH directions. Matching DeadlineExceeded alone
	// would still pass under a defect that also made the error match Canceled.
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"a client-deadline failure must match context.DeadlineExceeded")
	require.False(t, errors.Is(err, context.Canceled),
		"a client-deadline failure must NOT match context.Canceled: the two categories have to stay separable")

	// AXIS 3 - Timeout() behaviour: reachable AND true; reaching it and getting false
	// would be a different bug.
	var deadlineErr timeoutError
	require.ErrorAs(t, err, &deadlineErr,
		"a client-deadline failure must expose the net.Error-style Timeout() contract")
	require.True(t, deadlineErr.Timeout(),
		"Timeout() must report true so callers classify this as a timeout rather than a transport fault")

	// AXIS 4 - the retry exhaustion wrapper is PRESENT. The noun stays plural even for a
	// single attempt, so the substring is asserted exactly as the code emits it.
	require.Contains(t, err.Error(), "giving up after 1 attempts:",
		"RetryMax 0 means one attempt, and the retry layer reports that count in the message")

	// Exported structural identity, which the four axes cannot express: the middle of the
	// wrap chain is a *url.Error naming the operation and target that failed and
	// forwarding the deadline nature of the error it carries.
	//
	// The inner error text can vary depending on whether net/http substitutes its
	// client-timeout wrapper before the request context reports DeadlineExceeded, so
	// assertions use causal identity rather than an exact inner string.
	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr,
		"net/http must report the failure as a *url.Error naming the operation and target")
	require.Equal(t, "Get", urlErr.Op)
	require.Equal(t, timeoutTarget, urlErr.URL)
	require.True(t, urlErr.Timeout(), "*url.Error must forward Timeout() from the error it wraps")
	require.ErrorIs(t, urlErr.Err, context.DeadlineExceeded,
		"whichever of net/http's two deadline timers wins, the cause it reports must be the deadline")
	require.Contains(t, urlErr.Err.Error(), "context deadline exceeded",
		"the inner error must name the deadline as the cause, not a cancellation or a transport fault")

	// Protocol-visible: one request reached the wire, with the caller's own target and
	// method. A deadline must not retry onto the network.
	require.Equal(t, 1, rt.callCount(), "the deadline must not send a second request")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed is bounded on both sides and pinned to neither: the lower bound fails if a
	// defect shortens the budget the client waits, the upper bound if it lengthens it.
	require.Less(t, timeoutBudget, elapsed,
		"the call must actually spend its configured budget rather than failing early")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
		"the call must not overrun a generous multiple of its configured budget")
}

// TestTimeoutIsHardDeadlineNotPerAttempt establishes that Options.Timeout is one hard
// wall-clock deadline for the WHOLE call and not a per-attempt budget: across RetryMax 0, 1
// and 2 the transport is entered EXACTLY ONCE and the call returns after roughly one
// budget, yet the error message's attempt count still reads RetryMax+1.
//
// Two budgets govern the call and both are fed from the same Options.Timeout, which is why
// they expire together instead of nesting. One is HTTPX.New's http.Client Timeout field,
// re-applied by the retry client's own constructor from retryablehttpOptions.Timeout, and
// it is what cuts the single in-flight attempt short. The other is the retry layer's
// overall context, created from that same value at the top of its Do. By the time the
// first attempt fails that overall context is ALREADY expired, so the retry loop's backoff
// select takes its "overall deadline done" branch and leaves without dispatching another
// attempt. The count is formatted unconditionally as RetryMax+1 on the way out, so the
// retry counter advances while the wire sees one request.
//
// The attempt count therefore lives only in the error text, and callCount is the exact
// discriminator: mockTransport counts at the very top of RoundTrip, ahead of every early
// return, so a deadline relocated into the transport or made per-attempt would dispatch
// RetryMax+1 requests and fail it. The elapsed bounds confirm the same property in time.
func TestTimeoutIsHardDeadlineNotPerAttempt(t *testing.T) {
	cases := []struct {
		name     string
		retryMax int
		// wantAttemptPhrase is the retry layer's own attempt count: always RetryMax+1,
		// always plural, because the message comes from a fixed template.
		wantAttemptPhrase string
	}{
		{
			name:              "retrymax 0 hits the transport once",
			retryMax:          0,
			wantAttemptPhrase: "giving up after 1 attempts:",
		},
		{
			name:              "retrymax 1 still hits the transport once",
			retryMax:          1,
			wantAttemptPhrase: "giving up after 2 attempts:",
		},
		{
			name:              "retrymax 2 still hits the transport once",
			retryMax:          2,
			wantAttemptPhrase: "giving up after 3 attempts:",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A fresh client AND transport per row: the call counter is cumulative, so a
			// shared transport would make "exactly once" unfalsifiable after row one.
			ht, rt := newTimeoutHTTPX(t, timeoutBudget, c.retryMax)

			req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
			require.NoError(t, err)

			start := time.Now()
			resp, err := ht.Do(req, UnsafeOptions{})
			elapsed := time.Since(start)

			require.Error(t, err, "a transport that never answers must fail the call")
			require.Nil(t, resp, "an exhausted retry loop returns no response")

			require.Equal(t, 1, rt.callCount(),
				"the client deadline is one budget for the whole call: once it fires the retry loop's own overall context is already expired, so no further attempt is dispatched")
			hops := rt.requests()
			require.Len(t, hops, 1, "exactly one request may reach the wire regardless of RetryMax")
			require.Equal(t, http.MethodGet, hops[0].Method)
			require.Equal(t, timeoutTarget, hops[0].URL)

			// The retry counter advances even though the wire did not: the count proves
			// the retry layer ran, callCount that it never re-entered the transport.
			require.Contains(t, err.Error(), c.wantAttemptPhrase,
				"the retry layer reports RetryMax+1 attempts in its message even though only one reached the transport")

			// Sentinel identity per row, both directions, so a defect that swapped the
			// category under retry pressure cannot hide behind the timing assertions.
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"every row must fail with the deadline sentinel, not a cancellation")
			require.False(t, errors.Is(err, context.Canceled),
				"a deadline must never be reported as a caller cancellation")

			// Bounded on both sides: roughly one budget, never RetryMax+1 of them.
			require.Less(t, timeoutBudget, elapsed,
				"the call must actually spend its configured budget rather than failing early")
			require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
				"the call must not overrun a generous multiple of a SINGLE budget")

			// The explicit anti-per-attempt bound: a per-attempt deadline would allow
			// (RetryMax+1) budgets, so elapsed must stay strictly below that product. The
			// no-retry row cannot express the difference - the product is one budget - so
			// it is skipped rather than asserted vacuously.
			if c.retryMax >= 1 {
				perAttemptBudget := time.Duration(c.retryMax+1) * timeoutBudget
				require.Less(t, elapsed, perAttemptBudget,
					"elapsed must not reach (RetryMax+1) budgets: the deadline is per call, not per attempt")
			}
		})
	}
}

// TestTimeoutContextCancellationIdentity pins the identity of the OTHER timeout category:
// a deadline the caller drives through the request context rather than one the client
// enforces. It asserts all four axes in the negative wherever the deadline test asserts
// them in the positive, so neither category can be substituted for the other without
// failing at least one assertion across the two tests.
//
// The client timeout is set two orders of magnitude beyond the cancellation instant, so the
// client deadline cannot be the cause. The retry layer checks the request context before
// classifying the failure and returns that context's error verbatim rather than retrying a
// cancelled request, which bypasses the fmt.Errorf("giving up after ...") wrapper entirely -
// hence the bare, pointer-identical context.Canceled instead of the deadline category's
// three-deep chain. RetryMax is 2 so that "no retry wrapper appeared" is a real finding: a
// retry budget existed and was deliberately not spent.
func TestTimeoutContextCancellationIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutNoDeadline, 2)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel on the way out as well as on the timer, so a failure before the call cannot
	// leak the context or the blocked handler.
	defer cancel()

	req, err := ht.NewRequestWithContext(ctx, http.MethodGet, timeoutTarget)
	require.NoError(t, err)

	// The clock is read BEFORE the timer is armed: arming first would give the
	// cancellation a head start over the measurement and could land elapsed just under
	// timeoutCancelAfter, breaking the lower bound for a reason unrelated to the client.
	// Stopping the timer afterwards keeps no runtime timer past the test's completion.
	start := time.Now()
	cancelTimer := time.AfterFunc(timeoutCancelAfter, cancel)
	defer cancelTimer.Stop()

	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a cancelled request must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the request is cancelled (httpx.go:261-263)")

	// AXIS 1 - concrete type. context.Canceled is an errors.New value, so it arrives
	// unwrapped, in contrast to the deadline category's *fmt.wrapError.
	require.Equal(t, "*errors.errorString", fmt.Sprintf("%T", err),
		"a cancellation must reach the caller unwrapped, unlike the deadline category's *fmt.wrapError")

	// The strongest identity available: not an error that matches the sentinel but the
	// sentinel value itself. require.Same compares pointers, so a distinct error with the
	// same message fails here where require.Equal would not.
	require.Same(t, context.Canceled, err,
		"the caller must receive the context.Canceled sentinel itself, not a copy or a look-alike")
	require.Equal(t, "context canceled", err.Error(),
		"the message must be the sentinel's own, with nothing prefixed or appended")
	require.Nil(t, errors.Unwrap(err),
		"the cancellation error must be a leaf: anything wrapped around it would change how callers classify it")

	// AXIS 2 - sentinel identity, both directions, mirroring the deadline test.
	require.ErrorIs(t, err, context.Canceled,
		"a caller-driven cancellation must match context.Canceled")
	require.False(t, errors.Is(err, context.DeadlineExceeded),
		"a cancellation must NOT match context.DeadlineExceeded: swapping the two would mislead every calling layer")

	// AXIS 3 - Timeout() behaviour: errors.As FAILS outright, because context.Canceled
	// implements no Timeout method and nothing wraps it in a value that does. That is a
	// stronger statement than "Timeout() returned false".
	var cancellationErr timeoutError
	require.False(t, errors.As(err, &cancellationErr),
		"a cancellation must expose no Timeout() contract at all, so callers cannot misread it as a timeout")

	// net/http's *url.Error wrapper is likewise absent - the structural counterpart of the
	// axis above.
	var urlErr *url.Error
	require.False(t, errors.As(err, &urlErr),
		"a cancellation short-circuits before net/http wraps the failure in a *url.Error")

	// AXIS 4 - the retry exhaustion wrapper is ABSENT, asserted as an explicit absence on
	// the message rather than as a nil check, with RetryMax non-zero so it means something.
	require.NotContains(t, err.Error(), "giving up after",
		"context cancellation must not be wrapped by the retry-exhaustion message: the retry layer returns the context error verbatim instead")

	// Protocol-visible: the cancellation reached the wire once and was not retried.
	require.Equal(t, 1, rt.callCount(),
		"a cancelled request must not be retried onto the transport despite RetryMax being 2")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed tracks the CANCELLATION instant, not the client deadline, bounded on both
	// sides by inequalities.
	require.Less(t, timeoutCancelAfter, elapsed,
		"the call must last until the cancellation actually fires")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutCancelAfter,
		"elapsed must track the cancellation instant and stay far below the client deadline, which is the proof that the client deadline is not what ended this call")
}

// TestTimeoutContextVariantParity asserts that the client's two request constructors
// honour the deadline identically.
//
// NewRequest is pure delegation to NewRequestWithContext with context.Background(), so the
// two must be indistinguishable on the wire and in the error they produce, yet a defect
// could plausibly affect one and not the other. Both rows therefore assert the SAME
// expected values, and a projection of each row's observable outcome is compared across
// rows afterwards; divergence in either direction fails that comparison.
func TestTimeoutContextVariantParity(t *testing.T) {
	// timeoutOutcome is the DETERMINISTIC projection of one variant's observable result.
	// The rendered message is excluded because its optional client-timeout suffix varies
	// run to run, so comparing whole messages would flake for a reason unrelated to
	// constructor parity; the deterministic core is pinned per row inside the loop.
	type timeoutOutcome struct {
		ErrType          string
		IsDeadline       bool
		IsCanceled       bool
		ExposesTimeout   bool
		TimeoutValue     bool
		TransportCalls   int
		WireMethod       string
		WireURL          string
		ResponseReturned bool
	}

	cases := []struct {
		name string
		// newRequest exercises one constructor. A single closure shape lets both rows run
		// byte-identical assertions, so a behavioural difference between the constructors
		// cannot hide behind two hand-written test bodies.
		newRequest func(*testing.T, *HTTPX) (*retryablehttp.Request, error)
	}{
		{
			name: "context-free constructor honours the deadline",
			newRequest: func(t *testing.T, ht *HTTPX) (*retryablehttp.Request, error) {
				t.Helper()
				return ht.NewRequest(http.MethodGet, timeoutTarget)
			},
		},
		{
			name: "context-bearing constructor honours the deadline",
			newRequest: func(t *testing.T, ht *HTTPX) (*retryablehttp.Request, error) {
				t.Helper()
				return ht.NewRequestWithContext(context.Background(), http.MethodGet, timeoutTarget)
			},
		},
	}

	// Collected inside the sub-tests and compared afterwards; t.Run without t.Parallel
	// runs synchronously, so the appends are ordered and race-free.
	outcomes := make([]timeoutOutcome, 0, len(cases))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ht, rt := newTimeoutHTTPX(t, timeoutBudget, 0)

			req, err := c.newRequest(t, ht)
			require.NoError(t, err)

			start := time.Now()
			resp, err := ht.Do(req, UnsafeOptions{})
			elapsed := time.Since(start)

			require.Error(t, err, "a transport that never answers must fail the call")
			require.Nil(t, resp, "neither constructor may yield a response once the deadline fires")

			// Identical identity assertions for both variants: deadline sentinel matches,
			// cancellation sentinel does not, Timeout() reachable and true.
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"both constructors must surface the client deadline as context.DeadlineExceeded")
			require.False(t, errors.Is(err, context.Canceled),
				"neither constructor may report the client deadline as a caller cancellation")

			var deadlineErr timeoutError
			require.ErrorAs(t, err, &deadlineErr,
				"both constructors must surface an error exposing the Timeout() contract")
			require.True(t, deadlineErr.Timeout(),
				"both constructors must report Timeout() as true")

			// Identical wire outcome for both variants.
			require.Equal(t, 1, rt.callCount(), "neither constructor may retry onto the transport")
			hops := rt.requests()
			require.Len(t, hops, 1)
			require.Equal(t, http.MethodGet, hops[0].Method)
			require.Equal(t, timeoutTarget, hops[0].URL,
				"both constructors must put the caller's exact target on the wire")

			require.Less(t, timeoutBudget, elapsed,
				"both constructors must spend the configured budget rather than failing early")
			require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
				"neither constructor may overrun a generous multiple of the configured budget")

			// The deterministic core of the rendered message as exact text: attempt count,
			// operation, target and cause. Only the optional trailing marker varies.
			require.Contains(t, err.Error(),
				`giving up after 1 attempts: Get "`+timeoutTarget+`": context deadline exceeded`,
				"both constructors must render the same attempt count, operation, target and cause")

			outcomes = append(outcomes, timeoutOutcome{
				ErrType:          fmt.Sprintf("%T", err),
				IsDeadline:       errors.Is(err, context.DeadlineExceeded),
				IsCanceled:       errors.Is(err, context.Canceled),
				ExposesTimeout:   errors.As(err, &deadlineErr),
				TimeoutValue:     deadlineErr.Timeout(),
				TransportCalls:   rt.callCount(),
				WireMethod:       hops[0].Method,
				WireURL:          hops[0].URL,
				ResponseReturned: resp != nil,
			})
		})
	}

	// The parity assertion proper: both variants use the same URL, method and budget, so
	// any divergence means one constructor takes a different path through the client.
	require.Len(t, outcomes, len(cases),
		"both constructor variants must have produced an outcome to compare")
	require.Equal(t, outcomes[0], outcomes[1],
		"the context-free and context-bearing constructors must produce identical observable outcomes")
}

// Sentinels for the disclosure pin below. They are deliberately NOT credentials: the whole
// point of the pin is to establish WHICH URL components a failure renders into the error a
// caller receives and logs, and establishing that with a real secret would put the secret in
// the very CI log the finding is about (CWE-532). Each component therefore carries a value
// that is unmistakable in a haystack yet worthless if disclosed, and every assertion below is
// written as an occurrence COUNT rather than a substring containment, so a failure prints
// "expected: 2, actual: 0" instead of echoing the URL it was searching.
const (
	// disclosureHost is a synthetic authority that exists only inside the scripted
	// transport. url.URL keeps credentials in User, so Host holds only host[:port] and is
	// safe to render - which is exactly why the harness retains it when redacting.
	disclosureHost = "http://origin.example"

	// disclosurePathSecret stands in for a capability token carried in the PATH, the shape
	// a password-reset or pre-signed-download probe takes. It is entirely alphanumeric and
	// short, which is why no character or length heuristic can classify a path as
	// credential-free.
	disclosurePathSecret = "P4THT0KEN"

	// disclosureQuerySecret stands in for an API key carried in the QUERY, the shape a
	// "?apikey=" or "?access_token=" probe takes.
	disclosureQuerySecret = "QU3RYK3Y"

	// disclosureFragment stands in for a fragment, which is never transmitted on the wire
	// (RFC 9110 7.1) and so is the component a reader would LEAST expect in an error.
	disclosureFragment = "FR4GM3NT"

	// disclosureUserinfoUser and disclosureUserinfoSecret stand in for URL userinfo. The
	// password sentinel is the one value the pin proves is rendered in CLEARTEXT, so it is
	// only ever counted, never printed.
	disclosureUserinfoUser   = "us3r"
	disclosureUserinfoSecret = "P4SSW0RD"
)

// TestDoErrorDisclosesRequestURLComponents pins, component by component, exactly what the
// error returned by Do renders about the target of a failed request - the caller-visible
// surface that a scanner writes to its own log, to stderr and to any aggregator downstream.
//
// Why this is a protocol-visible outcome and not an implementation detail: the returned error
// IS part of the client's contract. A caller cannot choose a narrower rendering, because the
// string is composed before Do returns; whatever it contains has already escaped. The two
// rows below therefore assert the two renderings independently, because they are produced by
// two different layers with two different redaction policies, and the difference is the whole
// finding:
//
//   - The OUTER prefix comes from retryablehttp-go, which formats
//     "METHOD <raw request URL> giving up after N attempts: %w" using the request URL
//     VERBATIM. It performs no redaction whatsoever, so URL userinfo appears with the
//     password in cleartext.
//   - The INNER cause is net/http's *url.Error, whose Error method renders the URL through
//     url.URL.Redacted(), which replaces the password with "***" while leaving the username,
//     path, query and fragment untouched.
//
// The net effect asserted here: path, query and fragment are disclosed TWICE, the username
// TWICE, and the password ONCE in cleartext plus once redacted. Both counts matter. A reader
// who knows only that net/http redacts passwords would conclude the credential is protected;
// the outer prefix is what defeats that, and it can only be seen by counting both renderings
// in the same string.
//
// Row 2 additionally pins the second half of the finding, which is the more alarming half: the
// credential is not stripped BEFORE the round trip either. net/http removes userinfo only when
// it serializes the request target, converting it into a Basic Authorization header at that
// point, so the *url.URL handed to every round tripper - and therefore to any proxy hook or
// transport-level logger a caller installs - still carries the cleartext password. That is
// asserted from the recorded snapshot alongside the serialized-target contrast, and it is the
// reason this package's own harness redacts before rendering anything at all.
//
// Row 1 carries no userinfo, so the harness's invariant-5 tripwire stays quiet by
// construction and the row can drive a genuinely failing round trip. Row 2 needs userinfo on
// a failing request, which is precisely the combination the tripwire reports, so it drives a
// transport built directly rather than through newMockTransport - the test that establishes
// what the tripwire is FOR must not be subject to it - and then asserts the tripwire fired
// and that its retained evidence is credential-free. That makes Row 2 a pin of the leak and a
// pin of the harness guard in one, with nothing sensitive retained either way.
//
// AAP DISPOSITION - the disclosure is pinned here, deliberately NOT fixed. The cleartext
// rendering originates in the pinned dependency github.com/projectdiscovery/retryablehttp-go
// v1.3.18, which builds the prefix from the raw URL; the partial redaction originates in the
// Go standard library's net/url. Neither is this repository's code:
//   - AAP 0.8.2.6 states that upstream and standard-library defects are "ASSERTED, NOT
//     FIXED", and names URL-component handling in the pinned utils module and the standard
//     library's own redirect header-copy policy as the two worked examples of exactly this
//     situation.
//   - AAP 0.8.2.3 forbids adding, upgrading, downgrading or removing any dependency, so the
//     upstream formatter cannot be replaced or patched, and go.sum must stay at 578 lines.
//   - AAP 0.8.2.1 and 0.10.1.1 confine non-test edits to the two documented five-line fixes
//     in httpx.go, so wrapping or re-rendering the error inside Do - the only in-repository
//     remedy - is out of scope. 0.10.1.1 states the required behaviour verbatim: pin the
//     current behavior in a test, document the divergence, and do NOT fix it.
//
// The remediation a future, in-scope change would apply, recorded so it is actionable: have Do
// re-render the error it returns through url.URL.Redacted() applied to a URL whose User is
// cleared outright, rather than surfacing the retryablehttp string unchanged - which would
// close the cleartext-password path and the username path together. Closing the path, query
// and fragment paths additionally requires a size-only rendering of those components, the
// policy this package's own test harness already implements in redactedURL.
func TestDoErrorDisclosesRequestURLComponents(t *testing.T) {
	// The suffix every row shares: a credential-bearing path segment, a credential-bearing
	// query parameter and a fragment. Built once so the two rows differ ONLY in userinfo.
	targetSuffix := "/reset/" + disclosurePathSecret + "?apikey=" + disclosureQuerySecret + "#" + disclosureFragment

	// transportFailure is the cause both rows inject. It is a plain error from the round
	// tripper rather than a timeout, so the rendering under test is the one produced for
	// ANY transport failure - a refused connection, a reset, a handshake failure - and not
	// an artifact of the deadline paths pinned above.
	transportFailure := errors.New("disclosure fixture: the transport refused the connection")

	t.Run("path query and fragment are rendered twice with no userinfo present", func(t *testing.T) {
		rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, transportFailure
		})
		ht := newMockHTTPX(t, nil, rt)

		target := disclosureHost + targetSuffix
		req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, resp, "a transport failure must produce no response, so the error is the caller's only output")
		require.Error(t, err, "the fixture fails the round trip, so an error is required for the rendering to exist")
		rendered := err.Error()

		// The cause is preserved, which is what makes the rendering diagnostic and is the
		// reason the URL is there at all. Asserted first so a fixture that failed for some
		// other reason cannot make the counts below pass vacuously.
		require.Equal(t, 1, strings.Count(rendered, transportFailure.Error()),
			"the injected cause must appear exactly once, so the rendering under test is the one produced for this failure")
		require.Equal(t, 1, strings.Count(rendered, "giving up after 1 attempts"),
			"the retry layer's exhaustion wrapper must be present exactly once, which is what puts the raw URL in front of the cause")

		// The finding proper: each component appears TWICE, once in retryablehttp's raw
		// prefix and once in net/http's redacted *url.Error. Exact counts, so a change that
		// closed one rendering and not the other is a failure here rather than a silent
		// half-fix.
		require.Equal(t, 2, strings.Count(rendered, disclosurePathSecret),
			"a capability token in the PATH is rendered by both layers: retryablehttp's raw prefix and url.Error's redacted form, which redacts only the password")
		require.Equal(t, 2, strings.Count(rendered, "apikey="+disclosureQuerySecret),
			"an API key in the QUERY is rendered by both layers verbatim, key and value together")
		require.Equal(t, 2, strings.Count(rendered, disclosureFragment),
			"the FRAGMENT is rendered by both layers even though RFC 9110 7.1 keeps it off the wire entirely, so it never reached the origin and is disclosed by the client alone")

		// Neither rendering is a truncation or a summary: the whole absolute target is
		// present, twice, exactly as the caller supplied it.
		require.Equal(t, 2, strings.Count(rendered, target),
			"both renderings carry the complete absolute target, so no component was elided by either layer")

		// The request still reached the transport exactly once, which fixes WHERE the
		// rendering came from: the failure is the round trip's, not a construction error.
		require.Equal(t, 1, rt.callCount(), "the fixture must fail at the transport, so exactly one round trip is accounted for")
		hops := rt.requests()
		require.Len(t, hops, 1)
		require.Equal(t, target, hops[0].URL,
			"the snapshot is r.URL.String(), so the URL the round tripper observed is the caller's target in full - fragment included, because net/http drops the fragment only when it SERIALIZES the request target, which TestNewRequestURLEncoding pins separately")
	})

	t.Run("url userinfo is rendered once in cleartext and once redacted", func(t *testing.T) {
		// Built directly rather than through newMockTransport: this row drives exactly the
		// userinfo-plus-transport-error combination that requireNoUserinfoErrorLeaks
		// reports, and the test that establishes what that tripwire is FOR cannot be
		// subject to it. The tripwire is asserted below instead of being registered.
		rt := &mockTransport{handler: func(r *http.Request) (*http.Response, error) {
			return nil, transportFailure
		}}
		ht := newMockHTTPX(t, nil, rt)

		credentialed := "http://" + disclosureUserinfoUser + ":" + disclosureUserinfoSecret + "@origin.example" + targetSuffix
		req, err := retryablehttp.NewRequest(http.MethodGet, credentialed, nil)
		require.NoError(t, err)

		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, resp, "a transport failure must produce no response")
		require.Error(t, err)
		rendered := err.Error()

		// The two renderings, separated. Counted rather than matched as substrings so no
		// assertion message can echo the credential (CWE-532) even when it fails.
		require.Equal(t, 1, strings.Count(rendered, disclosureUserinfoUser+":"+disclosureUserinfoSecret+"@"),
			"retryablehttp-go formats its prefix from the RAW request URL, so the password is rendered in cleartext exactly once and no redaction stands between it and the caller's log")
		require.Equal(t, 1, strings.Count(rendered, disclosureUserinfoUser+":***@"),
			"net/http renders its *url.Error through url.URL.Redacted(), so the inner cause carries the same credential with the password replaced - the redaction that the outer prefix defeats")
		require.Equal(t, 2, strings.Count(rendered, disclosureUserinfoUser+":"),
			"the USERNAME is disclosed by both layers: Redacted() replaces the password only, never the user")

		// The password appears exactly once overall: cleartext in the prefix, redacted in
		// the cause. Stated as a total so a change to either layer alone moves it.
		require.Equal(t, 1, strings.Count(rendered, disclosureUserinfoSecret),
			"the total number of cleartext password renderings in the caller-visible error is one, which is one more than a caller can safely log")

		// The other components behave exactly as in the row above, so userinfo neither
		// widens nor narrows their disclosure.
		require.Equal(t, 2, strings.Count(rendered, disclosurePathSecret),
			"userinfo does not change how the path is rendered")
		require.Equal(t, 2, strings.Count(rendered, "apikey="+disclosureQuerySecret),
			"userinfo does not change how the query is rendered")

		// What the transport actually observed, which is the second half of the finding and
		// the more alarming half. The credential is NOT stripped before the round trip: the
		// snapshot of r.URL.String() still carries it, because net/http removes userinfo
		// only when it serializes the request target - r.URL.RequestURI() yields
		// "/reset/<token>?apikey=<key>" - and converts it into a Basic Authorization header
		// at that point. So any round tripper, proxy hook or transport-level logger
		// installed by a caller sees the cleartext password in the URL it is handed, which
		// is precisely why this package's harness redacts before rendering anything.
		require.Equal(t, 1, rt.callCount())
		hops := rt.requests()
		require.Len(t, hops, 1)
		require.Equal(t, 1, strings.Count(hops[0].URL, disclosureUserinfoSecret),
			"the URL handed to the round tripper still carries the cleartext password: net/http strips userinfo at SERIALIZATION time, not before RoundTrip, so a transport-level observer sees it")
		require.Equal(t, credentialed, hops[0].URL,
			"the round tripper observes the caller's target verbatim, userinfo and fragment included")
		require.Equal(t, "origin.example", hops[0].Host,
			"the authority is the bare host, so the credential travels in the URL object and the Authorization header rather than in the Host")
		require.Equal(t,
			"Basic "+base64.StdEncoding.EncodeToString([]byte(disclosureUserinfoUser+":"+disclosureUserinfoSecret)),
			hops[0].Header.Get("Authorization"),
			"net/http converts URL userinfo into a Basic credential, which is what keeps the SERIALIZED request target clean while the URL object is not")

		// The harness tripwire, asserted rather than registered: it must have detected this
		// exact combination, and its retained evidence must be credential-free. That is what
		// lets every OTHER test in this package keep using newMockTransport safely.
		leaks := rt.userinfoErrorLeaks()
		require.Len(t, leaks, 1,
			"the tripwire must record exactly one userinfo-bearing failed round trip, which is the combination it exists to report")
		require.Equal(t, 0, strings.Count(leaks[0], disclosureUserinfoSecret),
			"the tripwire's own retained evidence must not carry the password, or the guard would reproduce the leak it reports")
		require.Equal(t, 0, strings.Count(leaks[0], disclosurePathSecret),
			"the tripwire redacts the path as well, since a path segment alone is enough to disclose a capability token")
		require.Equal(t, 0, strings.Count(leaks[0], disclosureQuerySecret),
			"the tripwire redacts the query as well")
		require.Equal(t, "GET http://origin.example/<redacted 2 segments, 16 bytes>?<redacted 15 bytes>#<redacted 8 bytes>", leaks[0],
			"the retained evidence is the redacted request line in full: authority kept for attribution, every other component reduced to a size-only marker")
	})
}
