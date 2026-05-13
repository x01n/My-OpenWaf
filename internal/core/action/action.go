package action

import "strings"

// Type represents the WAF decision for a matched rule.
type Type string

const (
	Allow     Type = "allow"
	Intercept Type = "intercept"
	Observe   Type = "observe"
	Drop      Type = "drop"       // Highest priority: close TCP immediately, no response
	Challenge Type = "challenge"  // JS challenge or CAPTCHA verification
	Redirect  Type = "redirect"   // HTTP redirect to specified URL
	RateLimit Type = "rate_limit" // Per-rule rate limiting
	Tag       Type = "tag"        // Tag request for downstream processing (non-terminal)

	// Advanced challenge types
	CaptchaChallenge Type = "captcha_challenge" // CAPTCHA image verification (click/slide/rotate/drag)
	ShieldChallenge  Type = "shield_challenge"  // 5-second shield: CAPTCHA + PoW + env fingerprint
	ChainChallenge   Type = "chain_challenge"   // Multi-step chain challenge with state machine

	// Legacy aliases for backward compatibility with existing DB data.
	Block   Type = "block"
	LogOnly Type = "log_only"
)

// Normalize maps legacy action names to their canonical form.
func Normalize(t Type) Type {
	v := Type(strings.ToLower(strings.TrimSpace(string(t))))
	switch v {
	case Block:
		return Intercept
	case LogOnly:
		return Observe
	case Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return v
	default:
		return v
	}
}

// IsValid returns true when the action is supported for runtime decisions.
func IsValid(t Type) bool {
	switch Normalize(t) {
	case Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return true
	default:
		return false
	}
}

// TerminalPriority returns the action severity used when two terminal results
// are produced by concurrent detectors. Higher values are more severe.
func TerminalPriority(t Type) int {
	switch Normalize(t) {
	case Drop:
		return 90
	case Intercept:
		return 80
	case RateLimit:
		return 70
	case CaptchaChallenge, ShieldChallenge, ChainChallenge, Challenge:
		return 60
	case Redirect:
		return 50
	case Observe:
		return 10
	default:
		return 0
	}
}

// MoreSevere reports whether a should win over b when both actions matched.
func MoreSevere(a, b Type) bool {
	return TerminalPriority(a) > TerminalPriority(b)
}

// Result is the outcome of rule evaluation for a single request.
type Result struct {
	Type       Type   `json:"type"`
	RuleID     uint   `json:"rule_id,omitempty"`
	RuleIDStr  string `json:"rule_id_str,omitempty"` // builtin rules like "owasp:sqli:001"
	Phase      string `json:"phase,omitempty"`
	MatchDesc  string `json:"match_desc,omitempty"`
	Matched    bool   `json:"matched"`
	Category   string `json:"category,omitempty"`
	StatusCode int    `json:"status_code,omitempty"` // custom HTTP status code (0 = use default)
	RedirectTo string `json:"redirect_to,omitempty"` // URL for redirect action
}

// IsTerminal returns true when this action must short-circuit
// the pipeline - no upstream, no further phases.
func (r Result) IsTerminal() bool {
	t := Normalize(r.Type)
	return r.Matched && (t == Intercept || t == Drop || t == Challenge || t == Redirect || t == RateLimit ||
		t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge)
}

// IsDrop returns true when this action requires an immediate TCP connection close
// without sending any HTTP response.
func (r Result) IsDrop() bool {
	return r.Matched && Normalize(r.Type) == Drop
}

// IsChallenge returns true when the request should be served a challenge page.
func (r Result) IsChallenge() bool {
	t := Normalize(r.Type)
	return r.Matched && (t == Challenge || t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge)
}

// IsCaptchaChallenge returns true when the request requires a CAPTCHA challenge.
func (r Result) IsCaptchaChallenge() bool {
	return r.Matched && Normalize(r.Type) == CaptchaChallenge
}

// IsShieldChallenge returns true when the request requires a 5-second shield challenge.
func (r Result) IsShieldChallenge() bool {
	return r.Matched && Normalize(r.Type) == ShieldChallenge
}

// IsChainChallenge returns true when the request requires a multi-step chain challenge.
func (r Result) IsChainChallenge() bool {
	return r.Matched && Normalize(r.Type) == ChainChallenge
}

// IsRedirect returns true when the request should be redirected.
func (r Result) IsRedirect() bool {
	return r.Matched && Normalize(r.Type) == Redirect
}

// IsRateLimit returns true when this action should return a rate-limit response.
func (r Result) IsRateLimit() bool {
	return r.Matched && Normalize(r.Type) == RateLimit
}

// ShouldLog returns true when the match warrants a security log entry.
func (r Result) ShouldLog() bool {
	t := Normalize(r.Type)
	return r.Matched && (t == Intercept || t == Observe || t == Drop || t == Challenge || t == Redirect || t == RateLimit ||
		t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge)
}

// EffectiveStatusCode returns the status code to use, falling back to the
// given default when no custom code is set.
func (r Result) EffectiveStatusCode(defaultCode int) int {
	if r.StatusCode > 0 {
		return r.StatusCode
	}
	return defaultCode
}

// DefaultStatusCode returns the canonical HTTP status code for actions that send a response.
func (r Result) DefaultStatusCode() int {
	switch Normalize(r.Type) {
	case RateLimit:
		return 429
	case Challenge, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return 422
	case Redirect:
		return 302
	case Intercept:
		return 403
	default:
		return 0
	}
}

// ResponseStatusCode returns the configured status code or the canonical default.
func (r Result) ResponseStatusCode() int {
	return r.EffectiveStatusCode(r.DefaultStatusCode())
}

// Pass returns an unmatched allow result (default passthrough).
func Pass() Result { return Result{Type: Allow} }
