// Package visitorfusion 用本地、可解释的信号对已放行的 HTTPS 请求做分类。
package visitorfusion

import (
	"strings"

	"My-OpenWaf/internal/core/action"
)

// Classification 是本地人机推断的结论。
type Classification string

const (
	Human   Classification = "human"
	Bot     Classification = "bot"
	Unknown Classification = "unknown"
)

// ClientFamily 是粗粒度的客户端协议栈族系，绝不是精确的浏览器身份或版本。
type ClientFamily string

const (
	ChromiumLike     ClientFamily = "chromium_like"
	FirefoxLike      ClientFamily = "firefox_like"
	AutomationScript ClientFamily = "automation_or_script"
	UnknownFamily    ClientFamily = "unknown"
)

// UAClaim 是 User-Agent 自称的客户端族系，并非已被证实的身份。
type UAClaim string

const (
	ChromiumClaim   UAClaim = "chromium"
	FirefoxClaim    UAClaim = "firefox"
	AutomationClaim UAClaim = "automation_or_script"
	UnknownClaim    UAClaim = "unknown"
)

// Consistency 描述彼此独立可得的请求信号与 TLS 信号是否一致。
type Consistency string

const (
	Consistent           Consistency = "consistent"
	Inconsistent         Consistency = "inconsistent"
	InsufficientEvidence Consistency = "insufficient_evidence"
)

// TLSFeatures 保存数据面已经采集到的结构化 TLS 字段。
type TLSFeatures struct {
	JA3          string
	JA4          string
	TLSVersion   string
	ALPN         []string
	CipherSuites int
	Extensions   int
	Curves       int
}

// ExistingBotScores 复制既有 bot 检测器的分模块分数，但不复用它的判定结论。
type ExistingBotScores struct {
	Available        bool
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
}

/**
 * EnvironmentSignal 预留给经过验证的 browser-sign 或 challenge 环境结果。
 *
 * 当前已放行请求这条路径没有此类结果，因此 Available 始终为 false。
 */
type EnvironmentSignal struct {
	Available          bool
	AutomationDetected bool
}

// Input 保存单次融合评估所用的本地请求特征。
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

// ScoreBreakdown 把各来源权重分开保存，避免其汇总被误当成既有 bot 分。
type ScoreBreakdown struct {
	IP          int
	Request     int
	Environment int
	Fingerprint int
	Behavior    int
}

// Result 是可解释的本地融合结论。Reasons 只使用稳定的原因码。
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

// IsPersistable 报告该请求是否落在 HTTPS 且已放行的范围内。
func (r Result) IsPersistable() bool {
	return r.Eligible
}

/**
 * ExternalModelFeatures 只向未来的模型顾问暴露最小化、结构化的特征。
 *
 * 有意排除原始头、正文、Cookie、客户端 IP，以及 JA3 与 JA4 取值。
 */
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

// ExternalModelAdvice 有意保持为观测性质；本地分类永不消费它。
type ExternalModelAdvice struct {
	Available bool
}

/**
 * ExternalModelAdvisor 为后续的模型集成预留一个本地接缝。
 *
 * 将来任何走网络的实现，在真正引入请求之前都必须先通过独立评审：超时、
 * 熔断、fail-open 观测模式、隐私与数据最小化。
 */
type ExternalModelAdvisor interface {
	Advise(ExternalModelFeatures) ExternalModelAdvice
}

// DisabledExternalModelAdvisor 是生产默认实现，永不发起网络 I/O。
type DisabledExternalModelAdvisor struct{}

// Advise 保持默认路径为禁用状态，无法改变本地分类结果。
func (DisabledExternalModelAdvisor) Advise(ExternalModelFeatures) ExternalModelAdvice {
	return ExternalModelAdvice{}
}

// Evaluate 用禁用的外部模型接缝评估单个请求。
func Evaluate(input Input) Result {
	return EvaluateWithAdvisor(input, DisabledExternalModelAdvisor{})
}

// EvaluateWithAdvisor 只评估本地规则；顾问的输出按设计仅用于观测。
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
