package action

// Type represents the WAF decision for a matched rule.
type Type string

const (
	Allow     Type = "allow"
	Intercept Type = "intercept"
	Observe   Type = "observe"

	// Legacy aliases for backward compatibility with existing DB data.
	Block   Type = "block"
	LogOnly Type = "log_only"
)

// Normalize maps legacy action names to their canonical form.
func Normalize(t Type) Type {
	switch t {
	case Block:
		return Intercept
	case LogOnly:
		return Observe
	default:
		return t
	}
}

// Result is the outcome of rule evaluation for a single request.
type Result struct {
	Type      Type   `json:"type"`
	RuleID    uint   `json:"rule_id,omitempty"`
	RuleIDStr string `json:"rule_id_str,omitempty"` // builtin rules like "owasp:sqli:001"
	Phase     string `json:"phase,omitempty"`
	MatchDesc string `json:"match_desc,omitempty"`
	Matched   bool   `json:"matched"`
	Category  string `json:"category,omitempty"`
}

// IsTerminal returns true when this action must short-circuit
// the pipeline — no upstream, no further phases.
func (r Result) IsTerminal() bool {
	return r.Matched && Normalize(r.Type) == Intercept
}

// ShouldLog returns true when the match warrants a security log entry.
func (r Result) ShouldLog() bool {
	t := Normalize(r.Type)
	return r.Matched && (t == Intercept || t == Observe)
}

// Pass returns an unmatched allow result (default passthrough).
func Pass() Result { return Result{Type: Allow} }
