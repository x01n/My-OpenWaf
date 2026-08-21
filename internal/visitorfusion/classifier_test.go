package visitorfusion

import (
	"reflect"
	"strings"
	"testing"

	"My-OpenWaf/internal/core/action"
)

func completeInput() Input {
	return Input{
		HTTPS:          true,
		WAFAction:      action.Result{Matched: true, Type: action.Observe},
		UserAgent:      "Mozilla/5.0 Chrome/123.0 Safari/537.36",
		HasClientHints: true,
		AcceptsHTML:    true,
		AcceptsBrotli:  true,
		TLS: TLSFeatures{
			JA3:          "771,4865,0,29,0",
			JA4:          "t13d1516h2_0123456789ab_0123456789ab",
			TLSVersion:   "TLS13",
			ALPN:         []string{"h2"},
			CipherSuites: 15,
			Extensions:   16,
			Curves:       3,
		},
	}
}

func TestEvaluateRejectsNonHTTPSAndTerminalActions(t *testing.T) {
	httpInput := completeInput()
	httpInput.HTTPS = false
	if result := Evaluate(httpInput); result.IsPersistable() || result.Classification != "" {
		t.Fatalf("HTTP request must not classify or persist: %#v", result)
	}

	terminalTypes := []action.Type{
		action.Drop,
		action.Intercept,
		action.RateLimit,
		action.Challenge,
		action.CaptchaChallenge,
		action.ShieldChallenge,
		action.ChainChallenge,
		action.Redirect,
	}
	for _, actionType := range terminalTypes {
		input := completeInput()
		input.WAFAction = action.Result{Matched: true, Type: actionType}
		if result := Evaluate(input); result.IsPersistable() || result.Classification != "" {
			t.Errorf("terminal action %q must not classify or persist: %#v", actionType, result)
		}
	}
}

func TestEvaluateIncludesObserveAndTagReleasedRequests(t *testing.T) {
	for _, actionType := range []action.Type{action.Observe, action.Tag} {
		input := completeInput()
		input.WAFAction = action.Result{Matched: true, Type: actionType}
		result := Evaluate(input)
		if !result.IsPersistable() {
			t.Errorf("non-terminal action %q must remain in released-request scope: %#v", actionType, result)
		}
		if result.Classification != Human {
			t.Errorf("non-terminal action %q classification = %q, want %q", actionType, result.Classification, Human)
		}
	}
}

func TestEvaluateDetectsChromiumTLSHTTPInconsistencyWithoutCallingItBot(t *testing.T) {
	input := completeInput()
	input.AcceptsBrotli = false
	input.TLS.JA4 = "t13d1516h1_0123456789ab_0123456789ab"

	result := Evaluate(input)
	if result.Consistency != Inconsistent {
		t.Fatalf("consistency = %q, want %q", result.Consistency, Inconsistent)
	}
	if result.Classification == Bot {
		t.Fatalf("TLS/HTTP inconsistency alone must not classify as bot: %#v", result)
	}
	if result.ClientFamily != UnknownFamily {
		t.Fatalf("client family = %q, want %q for contradictory signals", result.ClientFamily, UnknownFamily)
	}
}

func TestEvaluateMissingJA3OrJA4StaysUnknown(t *testing.T) {
	for _, clear := range []func(*Input){
		func(input *Input) { input.TLS.JA3 = "" },
		func(input *Input) { input.TLS.JA4 = "" },
	} {
		input := completeInput()
		clear(&input)
		result := Evaluate(input)
		if result.Classification != Unknown || result.EvidenceSufficient || result.Consistency != InsufficientEvidence {
			t.Errorf("incomplete TLS fingerprints must remain insufficient and unknown: %#v", result)
		}
	}
}

func TestEvaluateReasonsNeverContainRequestValues(t *testing.T) {
	input := completeInput()
	input.UserAgent = "Mozilla/5.0 secret-user-agent"
	input.HeaderOrder = "accept,host,user-agent,x-api-key,x-test"
	result := Evaluate(input)
	for _, reason := range result.Reasons {
		if strings.Contains(reason, "secret-user-agent") || strings.Contains(reason, "x-api-key") ||
			strings.Contains(strings.ToLower(reason), "cookie") {
			t.Fatalf("reason leaks a request value: %q", reason)
		}
	}
}

func TestDisabledExternalModelAdvisorDoesNotAlterLocalResult(t *testing.T) {
	input := completeInput()
	want := Evaluate(input)
	got := EvaluateWithAdvisor(input, DisabledExternalModelAdvisor{})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disabled advisor changed local result: got %#v want %#v", got, want)
	}
}

type countingAdvisor struct {
	calls int
}

func (a *countingAdvisor) Advise(ExternalModelFeatures) ExternalModelAdvice {
	a.calls++
	return ExternalModelAdvice{Available: true}
}

func TestEvaluateWithAdvisorSkipsRequestsOutsideScope(t *testing.T) {
	advisor := &countingAdvisor{}
	httpInput := completeInput()
	httpInput.HTTPS = false
	EvaluateWithAdvisor(httpInput, advisor)

	terminalInput := completeInput()
	terminalInput.WAFAction = action.Result{Matched: true, Type: action.Drop}
	EvaluateWithAdvisor(terminalInput, advisor)

	if advisor.calls != 0 {
		t.Fatalf("advisor called %d times for requests outside fusion scope", advisor.calls)
	}
}
