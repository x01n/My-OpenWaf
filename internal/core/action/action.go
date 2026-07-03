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
	switch t {
	case Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return t
	}
	v := Type(normalizeActionToken(string(t)))
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

func normalizeActionToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	lowerNeeded := false
	for i := 0; i < len(trimmed); i++ {
		if c := trimmed[i]; c >= 'A' && c <= 'Z' {
			lowerNeeded = true
			break
		}
	}
	if !lowerNeeded {
		return trimmed
	}
	buf := make([]byte, len(trimmed))
	copy(buf, trimmed)
	for i := range buf {
		if c := buf[i]; c >= 'A' && c <= 'Z' {
			buf[i] = c + ('a' - 'A')
		}
	}
	return string(buf)
}

// IsValid returns true when the action is supported for runtime decisions.
func IsValid(t Type) bool {
	switch t {
	case Allow, Intercept, Observe, Drop, Challenge, Redirect, RateLimit, Tag, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return true
	}
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
	switch t {
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
	}
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
	if !r.Matched {
		return false
	}
	switch r.Type {
	case Intercept, Drop, Challenge, Redirect, RateLimit, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return true
	}
	t := Normalize(r.Type)
	return r.Matched && (t == Intercept || t == Drop || t == Challenge || t == Redirect || t == RateLimit ||
		t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge)
}

// IsDrop returns true when this action requires an immediate TCP connection close
// without sending any HTTP response.
func (r Result) IsDrop() bool {
	if !r.Matched {
		return false
	}
	if r.Type == Drop {
		return true
	}
	return Normalize(r.Type) == Drop
}

// IsChallenge returns true when the request should be served a challenge page.
func (r Result) IsChallenge() bool {
	if !r.Matched {
		return false
	}
	switch r.Type {
	case Challenge, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return true
	}
	t := Normalize(r.Type)
	return t == Challenge || t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge
}

// IsCaptchaChallenge returns true when the request requires a CAPTCHA challenge.
func (r Result) IsCaptchaChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == CaptchaChallenge {
		return true
	}
	return Normalize(r.Type) == CaptchaChallenge
}

// IsShieldChallenge returns true when the request requires a 5-second shield challenge.
func (r Result) IsShieldChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == ShieldChallenge {
		return true
	}
	return Normalize(r.Type) == ShieldChallenge
}

// IsChainChallenge returns true when the request requires a multi-step chain challenge.
func (r Result) IsChainChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == ChainChallenge {
		return true
	}
	return Normalize(r.Type) == ChainChallenge
}

// IsRedirect returns true when the request should be redirected.
func (r Result) IsRedirect() bool {
	if !r.Matched {
		return false
	}
	if r.Type == Redirect {
		return true
	}
	return Normalize(r.Type) == Redirect
}

// IsRateLimit returns true when this action should return a rate-limit response.
func (r Result) IsRateLimit() bool {
	if !r.Matched {
		return false
	}
	if r.Type == RateLimit {
		return true
	}
	return Normalize(r.Type) == RateLimit
}

// ShouldLog returns true when the match warrants a security log entry.
func (r Result) ShouldLog() bool {
	if !r.Matched {
		return false
	}
	switch r.Type {
	case Intercept, Observe, Drop, Challenge, Redirect, RateLimit, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return true
	}
	t := Normalize(r.Type)
	return t == Intercept || t == Observe || t == Drop || t == Challenge || t == Redirect || t == RateLimit ||
		t == CaptchaChallenge || t == ShieldChallenge || t == ChainChallenge
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
	switch r.Type {
	case RateLimit:
		return 429
	case Challenge, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return 403
	case Redirect:
		return 302
	case Intercept:
		return 403
	}
	switch Normalize(r.Type) {
	case RateLimit:
		return 429
	case Challenge, CaptchaChallenge, ShieldChallenge, ChainChallenge:
		return 403
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

// ---------------------------------------------------------------------------
// 内部状态码系统 (1xxx)
// ---------------------------------------------------------------------------
//
// 内部状态码用于 WAF 内部日志记录和指标追踪，不会发送给客户端。
// 1xxx 范围与标准 HTTP 状态码互不冲突，仅供内部可观测性使用。

const (
	InternalCodeDrop             = 1000 // TCP 立即断开，不发送 HTTP 响应
	InternalCodeIntercept        = 1001 // WAF 拦截/阻断
	InternalCodeRateLimit        = 1002 // 速率限制
	InternalCodeChallenge        = 1003 // JS 验证挑战
	InternalCodeCaptchaChallenge = 1004 // CAPTCHA 图形验证挑战
	InternalCodeShieldChallenge  = 1005 // 5 秒盾验证 (CAPTCHA + PoW + 环境指纹)
	InternalCodeChainChallenge   = 1006 // 多步链式验证挑战
	InternalCodeRedirect         = 1007 // 安全重定向
	InternalCodeObserve          = 1008 // 仅观察/记录，请求放行
	InternalCodeIPBlock          = 1009 // IP 信誉拦截
	InternalCodeAntiReplay       = 1010 // 防重放拦截
	InternalCodeBotBlock         = 1011 // 机器人检测拦截
	InternalCodeMaintenance      = 1012 // 维护模式
	InternalCodeEscalation       = 1013 // 响应升级
	InternalCodeUploadBlock      = 1014 // 文件上传拦截
	InternalCodeSemanticBlock    = 1015 // 语义检测拦截
)

// InternalCode 根据动作类型返回对应的内部状态码。
// 返回值仅用于内部日志与指标，不作为 HTTP 响应码。
func InternalCode(t Type) int {
	switch Normalize(t) {
	case Drop:
		return InternalCodeDrop
	case Intercept:
		return InternalCodeIntercept
	case RateLimit:
		return InternalCodeRateLimit
	case Challenge:
		return InternalCodeChallenge
	case CaptchaChallenge:
		return InternalCodeCaptchaChallenge
	case ShieldChallenge:
		return InternalCodeShieldChallenge
	case ChainChallenge:
		return InternalCodeChainChallenge
	case Redirect:
		return InternalCodeRedirect
	case Observe:
		return InternalCodeObserve
	default:
		return 0
	}
}

// internalCodeDescs 内部状态码与描述的映射表。
var internalCodeDescs = map[int]string{
	InternalCodeDrop:             "TCP drop, no HTTP response",
	InternalCodeIntercept:        "WAF block/intercept",
	InternalCodeRateLimit:        "rate limiting",
	InternalCodeChallenge:        "JS challenge",
	InternalCodeCaptchaChallenge: "CAPTCHA challenge",
	InternalCodeShieldChallenge:  "5s shield challenge",
	InternalCodeChainChallenge:   "chain challenge",
	InternalCodeRedirect:         "security redirect",
	InternalCodeObserve:          "observe/log only, request passes",
	InternalCodeIPBlock:          "IP reputation block",
	InternalCodeAntiReplay:       "anti-replay block",
	InternalCodeBotBlock:         "bot detection block",
	InternalCodeMaintenance:      "maintenance mode",
	InternalCodeEscalation:       "escalation upgrade",
	InternalCodeUploadBlock:      "file upload block",
	InternalCodeSemanticBlock:    "semantic detection block",
}

// InternalCodeDesc 返回内部状态码的描述文本。
// 未知码返回空字符串。
func InternalCodeDesc(code int) string {
	return internalCodeDescs[code]
}
