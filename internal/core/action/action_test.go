package action

import "testing"

// ---- Normalize ----

func TestNormalizeLegacyBlock(t *testing.T) {
	if got := Normalize(Block); got != Intercept {
		t.Fatalf("block → want intercept, got %q", got)
	}
}

func TestNormalizeLegacyLogOnly(t *testing.T) {
	if got := Normalize(LogOnly); got != Observe {
		t.Fatalf("log_only → want observe, got %q", got)
	}
}

func TestNormalizeCanonicalActionsUnchanged(t *testing.T) {
	canonical := []Type{Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag,
		CaptchaChallenge, ShieldChallenge, ChainChallenge}
	for _, a := range canonical {
		if got := Normalize(a); got != a {
			t.Fatalf("canonical %q should be unchanged, got %q", a, got)
		}
	}
}

func TestNormalizeUppercaseInput(t *testing.T) {
	if got := Normalize("INTERCEPT"); got != Intercept {
		t.Fatalf("INTERCEPT → want intercept, got %q", got)
	}
}

func TestNormalizeEmptyString(t *testing.T) {
	if got := Normalize(""); got != "" {
		t.Fatalf("empty → want \"\", got %q", got)
	}
}

// ---- IsValid ----

func TestIsValidCanonicalActionsTrue(t *testing.T) {
	valid := []Type{Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag,
		CaptchaChallenge, ShieldChallenge, ChainChallenge}
	for _, a := range valid {
		if !IsValid(a) {
			t.Fatalf("%q should be valid", a)
		}
	}
}

func TestIsValidLegacyBlockTrue(t *testing.T) {
	if !IsValid(Block) {
		t.Fatal("block (legacy) should be valid")
	}
}

func TestIsValidUnknownActionFalse(t *testing.T) {
	if IsValid("nonexistent_action") {
		t.Fatal("unknown action should be invalid")
	}
}

// ---- TerminalPriority ----

func TestTerminalPriorityOrdering(t *testing.T) {
	cases := []struct {
		action   Type
		wantPrio int
	}{
		{Drop, 90},
		{Intercept, 80},
		{RateLimit, 70},
		{Challenge, 60},
		{CaptchaChallenge, 60},
		{ShieldChallenge, 60},
		{ChainChallenge, 60},
		{Redirect, 50},
		{Observe, 10},
	}
	for _, tc := range cases {
		if got := TerminalPriority(tc.action); got != tc.wantPrio {
			t.Fatalf("%q: want priority %d, got %d", tc.action, tc.wantPrio, got)
		}
	}
}

func TestTerminalPriorityLegacyBlock(t *testing.T) {
	// block 规范化到 intercept → priority 80
	if got := TerminalPriority(Block); got != 80 {
		t.Fatalf("block priority: want 80, got %d", got)
	}
}

func TestTerminalPriorityUnknownIsZero(t *testing.T) {
	if got := TerminalPriority("unknown"); got != 0 {
		t.Fatalf("unknown priority: want 0, got %d", got)
	}
}

// ---- MoreSevere ----

func TestMoreSevereDropBeatsIntercept(t *testing.T) {
	if !MoreSevere(Drop, Intercept) {
		t.Fatal("drop should be more severe than intercept")
	}
	if MoreSevere(Intercept, Drop) {
		t.Fatal("intercept should not be more severe than drop")
	}
}

func TestMoreSevereSameActionFalse(t *testing.T) {
	if MoreSevere(Intercept, Intercept) {
		t.Fatal("same action should not be more severe")
	}
}

// ---- Result.IsTerminal ----

func TestIsTerminalFalseWhenNotMatched(t *testing.T) {
	r := Result{Type: Intercept, Matched: false}
	if r.IsTerminal() {
		t.Fatal("unmatched result should not be terminal")
	}
}

func TestIsTerminalTrueForTerminalActions(t *testing.T) {
	terminal := []Type{Intercept, Drop, Challenge, Redirect, RateLimit, CaptchaChallenge, ShieldChallenge, ChainChallenge}
	for _, a := range terminal {
		r := Result{Type: a, Matched: true}
		if !r.IsTerminal() {
			t.Fatalf("%q matched: want IsTerminal=true", a)
		}
	}
}

func TestIsTerminalFalseForObserve(t *testing.T) {
	r := Result{Type: Observe, Matched: true}
	if r.IsTerminal() {
		t.Fatal("observe should not be terminal")
	}
}

// ---- Result.IsDrop ----

func TestIsDropTrueForDrop(t *testing.T) {
	r := Result{Type: Drop, Matched: true}
	if !r.IsDrop() {
		t.Fatal("drop matched: want IsDrop=true")
	}
}

func TestIsDropFalseForIntercept(t *testing.T) {
	r := Result{Type: Intercept, Matched: true}
	if r.IsDrop() {
		t.Fatal("intercept should not be IsDrop")
	}
}

// ---- Result.IsChallenge ----

func TestIsChallengeCoversAllChallengeTypes(t *testing.T) {
	challenges := []Type{Challenge, CaptchaChallenge, ShieldChallenge, ChainChallenge}
	for _, a := range challenges {
		r := Result{Type: a, Matched: true}
		if !r.IsChallenge() {
			t.Fatalf("%q: want IsChallenge=true", a)
		}
	}
}

func TestIsChallengeSpecificTypes(t *testing.T) {
	cases := []struct {
		t   Type
		cap bool
		sh  bool
		ch  bool
	}{
		{CaptchaChallenge, true, false, false},
		{ShieldChallenge, false, true, false},
		{ChainChallenge, false, false, true},
	}
	for _, tc := range cases {
		r := Result{Type: tc.t, Matched: true}
		if r.IsCaptchaChallenge() != tc.cap {
			t.Fatalf("%q IsCaptchaChallenge: want %v", tc.t, tc.cap)
		}
		if r.IsShieldChallenge() != tc.sh {
			t.Fatalf("%q IsShieldChallenge: want %v", tc.t, tc.sh)
		}
		if r.IsChainChallenge() != tc.ch {
			t.Fatalf("%q IsChainChallenge: want %v", tc.t, tc.ch)
		}
	}
}

// ---- Result.IsRedirect / IsRateLimit ----

func TestIsRedirectAndIsRateLimit(t *testing.T) {
	if r := (Result{Type: Redirect, Matched: true}); !r.IsRedirect() {
		t.Fatal("redirect: want IsRedirect=true")
	}
	if r := (Result{Type: RateLimit, Matched: true}); !r.IsRateLimit() {
		t.Fatal("rate_limit: want IsRateLimit=true")
	}
}

// ---- Result.ShouldLog ----

func TestShouldLogFalseWhenNotMatched(t *testing.T) {
	r := Result{Type: Intercept, Matched: false}
	if r.ShouldLog() {
		t.Fatal("unmatched should not log")
	}
}

func TestShouldLogTrueForLoggableActions(t *testing.T) {
	loggable := []Type{Intercept, Observe, Drop, Challenge, Redirect, RateLimit, CaptchaChallenge, ShieldChallenge, ChainChallenge}
	for _, a := range loggable {
		r := Result{Type: a, Matched: true}
		if !r.ShouldLog() {
			t.Fatalf("%q matched: want ShouldLog=true", a)
		}
	}
}

func TestShouldLogFalseForAllow(t *testing.T) {
	r := Result{Type: Allow, Matched: true}
	if r.ShouldLog() {
		t.Fatal("allow should not be logged")
	}
}

// ---- EffectiveStatusCode / DefaultStatusCode / ResponseStatusCode ----

func TestEffectiveStatusCodeFallsBackToDefault(t *testing.T) {
	r := Result{Type: Intercept, Matched: true}
	if got := r.EffectiveStatusCode(403); got != 403 {
		t.Fatalf("want 403, got %d", got)
	}
}

func TestEffectiveStatusCodeCustomOverridesDefault(t *testing.T) {
	r := Result{Type: Intercept, Matched: true, StatusCode: 418}
	if got := r.EffectiveStatusCode(403); got != 418 {
		t.Fatalf("custom code: want 418, got %d", got)
	}
}

func TestDefaultStatusCodeTable(t *testing.T) {
	cases := []struct {
		t    Type
		want int
	}{
		{RateLimit, 429},
		{Challenge, 403},
		{CaptchaChallenge, 403},
		{ShieldChallenge, 403},
		{ChainChallenge, 403},
		{Redirect, 302},
		{Intercept, 403},
		{Observe, 0},
	}
	for _, tc := range cases {
		r := Result{Type: tc.t, Matched: true}
		if got := r.DefaultStatusCode(); got != tc.want {
			t.Fatalf("%q DefaultStatusCode: want %d, got %d", tc.t, tc.want, got)
		}
	}
}

func TestResponseStatusCodeUsesCustomWhenSet(t *testing.T) {
	r := Result{Type: Intercept, Matched: true, StatusCode: 503}
	if got := r.ResponseStatusCode(); got != 503 {
		t.Fatalf("want 503, got %d", got)
	}
}

// ---- Pass ----

func TestPassReturnsAllowUnmatched(t *testing.T) {
	p := Pass()
	if p.Type != Allow {
		t.Fatalf("Pass type: want allow, got %q", p.Type)
	}
	if p.Matched {
		t.Fatal("Pass should be unmatched")
	}
	if p.IsTerminal() {
		t.Fatal("Pass should not be terminal")
	}
}

// ---- InternalCode / InternalCodeDesc ----

func TestInternalCodeTable(t *testing.T) {
	cases := []struct {
		t    Type
		want int
	}{
		{Drop, InternalCodeDrop},
		{Intercept, InternalCodeIntercept},
		{RateLimit, InternalCodeRateLimit},
		{Challenge, InternalCodeChallenge},
		{CaptchaChallenge, InternalCodeCaptchaChallenge},
		{ShieldChallenge, InternalCodeShieldChallenge},
		{ChainChallenge, InternalCodeChainChallenge},
		{Redirect, InternalCodeRedirect},
		{Observe, InternalCodeObserve},
	}
	for _, tc := range cases {
		if got := InternalCode(tc.t); got != tc.want {
			t.Fatalf("InternalCode(%q): want %d, got %d", tc.t, tc.want, got)
		}
	}
}

func TestInternalCodeLegacyBlock(t *testing.T) {
	// block → intercept → InternalCodeIntercept
	if got := InternalCode(Block); got != InternalCodeIntercept {
		t.Fatalf("block InternalCode: want %d, got %d", InternalCodeIntercept, got)
	}
}

func TestInternalCodeUnknownIsZero(t *testing.T) {
	if got := InternalCode("unknown"); got != 0 {
		t.Fatalf("unknown InternalCode: want 0, got %d", got)
	}
}

func TestInternalCodeDescKnownCodes(t *testing.T) {
	known := []int{
		InternalCodeDrop, InternalCodeIntercept, InternalCodeRateLimit,
		InternalCodeChallenge, InternalCodeCaptchaChallenge, InternalCodeShieldChallenge,
		InternalCodeChainChallenge, InternalCodeRedirect, InternalCodeObserve,
		InternalCodeIPBlock, InternalCodeAntiReplay, InternalCodeBotBlock,
		InternalCodeMaintenance, InternalCodeEscalation, InternalCodeUploadBlock,
		InternalCodeSemanticBlock,
	}
	for _, code := range known {
		if desc := InternalCodeDesc(code); desc == "" {
			t.Fatalf("InternalCodeDesc(%d): want non-empty description", code)
		}
	}
}

func TestInternalCodeDescUnknownReturnsEmpty(t *testing.T) {
	if got := InternalCodeDesc(9999); got != "" {
		t.Fatalf("unknown code desc: want \"\", got %q", got)
	}
}
