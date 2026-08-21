// Package visitorfusion classifies released HTTPS requests with local, explainable signals.
package visitorfusion

import (
	"strings"

	"My-OpenWaf/internal/core/action"
)

// Classification is the local human-machine inference outcome.
type Classification string

const (
	Human   Classification = "human"
	Bot     Classification = "bot"
	Unknown Classification = "unknown"
)

// ClientFamily is a coarse client stack family, never an exact browser identity or version.
type ClientFamily string

const (
	ChromiumLike     ClientFamily = "chromium_like"
	FirefoxLike      ClientFamily = "firefox_like"
	AutomationScript ClientFamily = "automation_or_script"
	UnknownFamily    ClientFamily = "unknown"
)

// UAClaim is the client family claimed by the User-Agent, not an asserted identity.
type UAClaim string

const (
	ChromiumClaim   UAClaim = "chromium"
	FirefoxClaim    UAClaim = "firefox"
	AutomationClaim UAClaim = "automation_or_script"
	UnknownClaim    UAClaim = "unknown"
)

// Consistency describes whether independently available request and TLS signals agree.
type Consistency string

const (
	Consistent           Consistency = "consistent"
	Inconsistent         Consistency = "inconsistent"
	InsufficientEvidence Consistency = "insufficient_evidence"
)

// TLSFeatures contains structural TLS fields already captured by the data plane.
type TLSFeatures struct {
	JA3          string
	JA4          string
	TLSVersion   string
	ALPN         []string
	CipherSuites int
	Extensions   int
	Curves       int
}

// ExistingBotScores copies grouped scores from the existing bot detector without reusing its verdict.
type ExistingBotScores struct {
	Available        bool
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
}

// EnvironmentSignal is reserved for a verified browser-sign or challenge environment result.
// The current released-request path has no such result, so Available remains false.
type EnvironmentSignal struct {
	Available          bool
	AutomationDetected bool
}

// Input holds local request features used for a single fusion evaluation.
type Input struct {
	HTTPS     bool
	WAFAction action.Result

	UserAgent         string
	Method            string
	HasClientHints    bool
	HasFetchMetadata  bool
	AcceptsHTML       bool
	AcceptsBrotli     bool
	HeaderOrder       string
	TLS               TLSFeatures
	ExistingBotScores ExistingBotScores
	Environment       EnvironmentSignal
}

// ScoreBreakdown keeps source weights separate so an aggregate cannot be mistaken for an existing bot score.
type ScoreBreakdown struct {
	IP          int
	Request     int
	Environment int
	Fingerprint int
	Behavior    int
}

// Result is the explainable local fusion outcome. Reasons are stable reason codes only.
type Result struct {
	Eligible           bool
	EvidenceSufficient bool
	Classification     Classification
	Score              int
	ScoreBreakdown     ScoreBreakdown
	ClientFamily       ClientFamily
	UAClaim            UAClaim
	Consistency        Consistency
	Reasons            []string
}

// IsPersistable reports whether this request is inside the HTTPS and released-request scope.
func (r Result) IsPersistable() bool {
	return r.Eligible
}

// ExternalModelFeatures exposes only minimized, structured features to a future model advisor.
// It deliberately excludes raw headers, bodies, cookies, client IPs, JA3, and JA4 values.
type ExternalModelFeatures struct {
	UAClaim              UAClaim
	HasClientHints       bool
	HasFetchMetadata     bool
	AcceptsHTML          bool
	AcceptsBrotli        bool
	TLSVersionPresent    bool
	ALPNPresent          bool
	CipherSuiteCount     int
	ExtensionCount       int
	CurveCount           int
	ScoreBreakdown       ScoreBreakdown
	EnvironmentAvailable bool
}

// ExternalModelAdvice is intentionally observational; local classification never consumes it.
type ExternalModelAdvice struct {
	Available bool
}

// ExternalModelAdvisor reserves a local seam for a later model integration.
// Future network-backed implementations require independent review for timeout, circuit breaker,
// fail-open observation mode, privacy, and data minimization before any request is introduced.
type ExternalModelAdvisor interface {
	Advise(ExternalModelFeatures) ExternalModelAdvice
}

// DisabledExternalModelAdvisor is the production default and never performs network I/O.
type DisabledExternalModelAdvisor struct{}

// Advise keeps the default path disabled and cannot alter local classification.
func (DisabledExternalModelAdvisor) Advise(ExternalModelFeatures) ExternalModelAdvice {
	return ExternalModelAdvice{}
}

// Evaluate evaluates one request with the disabled external-model seam.
func Evaluate(input Input) Result {
	return EvaluateWithAdvisor(input, DisabledExternalModelAdvisor{})
}

// EvaluateWithAdvisor evaluates local rules only; advisor output is observation-only by design.
func EvaluateWithAdvisor(input Input, advisor ExternalModelAdvisor) Result {
	result := evaluateLocal(input)
	if result.Eligible && advisor != nil {
		_ = advisor.Advise(modelFeatures(input, result.ScoreBreakdown))
	}
	return result
}

func evaluateLocal(input Input) Result {
	if !input.HTTPS {
		return Result{Reasons: []string{"https_required"}}
	}
	if input.WAFAction.IsTerminal() {
		return Result{Reasons: []string{"terminal_waf_action"}}
	}

	result := Result{
		Eligible:       true,
		Classification: Unknown,
		ClientFamily:   UnknownFamily,
		UAClaim:        claimUserAgent(input.UserAgent),
		Consistency:    InsufficientEvidence,
	}
	if input.UserAgent == "" && !input.HasClientHints && !input.HasFetchMetadata &&
		!input.AcceptsHTML && !input.AcceptsBrotli && input.HeaderOrder == "" {
		result.Reasons = append(result.Reasons, "request_signal_unavailable")
	}
	if input.TLS.JA3 == "" || input.TLS.JA4 == "" {
		result.Reasons = append(result.Reasons, "insufficient_tls_fingerprint", "environment_unavailable")
		return result
	}

	result.EvidenceSufficient = true
	result.ScoreBreakdown = localScore(input, &result)
	setFamilyAndConsistency(input, &result)
	result.Score = clamp(result.ScoreBreakdown.IP+result.ScoreBreakdown.Request+
		result.ScoreBreakdown.Environment+result.ScoreBreakdown.Fingerprint+
		result.ScoreBreakdown.Behavior, 0, 100)
	if result.ClientFamily == UnknownFamily && result.Consistency != Inconsistent {
		result.Consistency = InsufficientEvidence
	}

	if result.UAClaim == AutomationClaim || input.Environment.AutomationDetected || result.Score >= 70 {
		result.Classification = Bot
		return result
	}
	if (result.ClientFamily == ChromiumLike || result.ClientFamily == FirefoxLike) &&
		result.Consistency == Consistent && result.Score <= 15 {
		result.Classification = Human
	}
	return result
}

func localScore(input Input, result *Result) ScoreBreakdown {
	var scores ScoreBreakdown
	if input.ExistingBotScores.Available {
		ipRisk := input.ExistingBotScores.GeoIPScore + input.ExistingBotScores.IPRepScore
		scores.IP = clamp(ipRisk, 0, 30)
		if scores.IP > 0 {
			result.Reasons = append(result.Reasons, "existing_ip_risk")
		}
		scores.Behavior = clamp(input.ExistingBotScores.BehaviorScore, 0, 20)
		if scores.Behavior > 0 {
			result.Reasons = append(result.Reasons, "existing_behavior_risk")
		}
		scores.Fingerprint = clamp(input.ExistingBotScores.FingerprintScore, 0, 30)
		if scores.Fingerprint > 0 {
			result.Reasons = append(result.Reasons, "existing_fingerprint_risk")
		}
	} else {
		result.Reasons = append(result.Reasons, "existing_behavior_unavailable", "existing_ip_risk_unavailable")
	}

	if result.UAClaim == AutomationClaim {
		scores.Request += 50
		result.Reasons = append(result.Reasons, "automation_user_agent")
	}
	if hasAlphabeticHeaderOrder(input.HeaderOrder) {
		scores.Fingerprint += 8
		result.Reasons = append(result.Reasons, "alphabetic_header_order")
	}
	if hasUABeforeHost(input.HeaderOrder) {
		scores.Fingerprint += 6
		result.Reasons = append(result.Reasons, "ua_before_host")
	}
	if input.Environment.Available {
		if input.Environment.AutomationDetected {
			scores.Environment = 50
			result.Reasons = append(result.Reasons, "verified_environment_automation")
		}
	} else {
		result.Reasons = append(result.Reasons, "environment_unavailable")
	}
	return scores
}

func setFamilyAndConsistency(input Input, result *Result) {
	ja4HasH2 := strings.Contains(strings.ToLower(input.TLS.JA4), "h2")
	switch result.UAClaim {
	case AutomationClaim:
		result.ClientFamily = AutomationScript
		result.Consistency = Consistent
	case ChromiumClaim:
		if !ja4HasH2 && !input.AcceptsBrotli {
			result.Consistency = Inconsistent
			result.ScoreBreakdown.Fingerprint += 15
			result.Reasons = append(result.Reasons, "chromium_tls_http_mismatch")
			return
		}
		if input.HasClientHints && ja4HasH2 {
			result.ClientFamily = ChromiumLike
			result.Consistency = Consistent
			result.Reasons = append(result.Reasons, "chromium_structural_consistency")
		}
	case FirefoxClaim:
		if ja4HasH2 && !input.AcceptsBrotli {
			result.Consistency = Inconsistent
			result.ScoreBreakdown.Fingerprint += 8
			result.Reasons = append(result.Reasons, "firefox_encoding_mismatch")
			return
		}
		if ja4HasH2 && input.AcceptsBrotli {
			result.ClientFamily = FirefoxLike
			result.Consistency = Consistent
			result.Reasons = append(result.Reasons, "firefox_structural_consistency")
		}
	}
}

func modelFeatures(input Input, scores ScoreBreakdown) ExternalModelFeatures {
	return ExternalModelFeatures{
		UAClaim:              claimUserAgent(input.UserAgent),
		HasClientHints:       input.HasClientHints,
		HasFetchMetadata:     input.HasFetchMetadata,
		AcceptsHTML:          input.AcceptsHTML,
		AcceptsBrotli:        input.AcceptsBrotli,
		TLSVersionPresent:    input.TLS.TLSVersion != "",
		ALPNPresent:          len(input.TLS.ALPN) > 0,
		CipherSuiteCount:     input.TLS.CipherSuites,
		ExtensionCount:       input.TLS.Extensions,
		CurveCount:           input.TLS.Curves,
		ScoreBreakdown:       scores,
		EnvironmentAvailable: input.Environment.Available,
	}
}

func claimUserAgent(ua string) UAClaim {
	lower := strings.ToLower(ua)
	if strings.Contains(lower, "python-requests") || strings.Contains(lower, "python-urllib") ||
		strings.Contains(lower, "go-http-client") || strings.HasPrefix(lower, "java/") ||
		strings.HasPrefix(lower, "curl/") || strings.HasPrefix(lower, "wget/") ||
		strings.Contains(lower, "libwww-perl") || strings.Contains(lower, "okhttp") ||
		strings.Contains(lower, "apache-httpclient") || strings.Contains(lower, "node-fetch") || strings.Contains(lower, "axios/") {
		return AutomationClaim
	}
	if strings.Contains(lower, "firefox/") {
		return FirefoxClaim
	}
	if strings.Contains(lower, "chrome/") || strings.Contains(lower, "chromium/") || strings.Contains(lower, "crios/") {
		return ChromiumClaim
	}
	return UnknownClaim
}

func hasAlphabeticHeaderOrder(order string) bool {
	keys := splitHeaderOrder(order)
	if len(keys) < 5 {
		return false
	}
	for i := 1; i < len(keys); i++ {
		if keys[i-1] > keys[i] {
			return false
		}
	}
	return true
}

func hasUABeforeHost(order string) bool {
	keys := splitHeaderOrder(order)
	uaIndex, hostIndex := -1, -1
	for i, key := range keys {
		switch key {
		case "user-agent":
			uaIndex = i
		case "host":
			hostIndex = i
		}
	}
	return uaIndex >= 0 && hostIndex >= 0 && uaIndex < hostIndex
}

func splitHeaderOrder(order string) []string {
	if order == "" {
		return nil
	}
	parts := strings.Split(order, ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return parts
}

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
