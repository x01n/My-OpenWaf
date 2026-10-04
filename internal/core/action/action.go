package action

import "strings"

// Type 表示规则命中后 WAF 给出的判定动作。
type Type string

const (
	Allow     Type = "allow"
	Intercept Type = "intercept"
	Observe   Type = "observe"
	Drop      Type = "drop"       // 最高优先级：立即关闭 TCP，不发送响应
	Challenge Type = "challenge"  // JS 挑战或 CAPTCHA 验证
	Redirect  Type = "redirect"   // 重定向到指定 URL
	RateLimit Type = "rate_limit" // 规则级速率限制
	Tag       Type = "tag"        // 为下游处理打标签（非终止）

	// 进阶挑战类型
	CaptchaChallenge Type = "captcha_challenge" // CAPTCHA 图形验证（点击/滑动/旋转/拖拽）
	ShieldChallenge  Type = "shield_challenge"  // 5 秒盾：CAPTCHA + PoW + 环境指纹
	ChainChallenge   Type = "chain_challenge"   // 带状态机的多步链式挑战

	// 遗留别名，用于兼容库中已有的历史数据。
	Block   Type = "block"
	LogOnly Type = "log_only"
)

// Normalize 把遗留动作名映射为规范形式。
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

// IsValid 报告该动作是否可用于运行时判定。
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

// TerminalPriority 返回并发检测器同时给出两个终止结果时的动作严重度。
// 数值越大越严重。
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

// MoreSevere 报告两个动作同时命中时 a 是否应当胜过 b。
func MoreSevere(a, b Type) bool {
	return TerminalPriority(a) > TerminalPriority(b)
}

// Result 是单个请求的规则评估结果。
type Result struct {
	Type      Type   `json:"type"`
	RuleID    uint   `json:"rule_id,omitempty"`
	RuleIDStr string `json:"rule_id_str,omitempty"` // 内置规则形如 "owasp:sqli:001"
	// RuleName 是内置检测规则的名称（如 "SQL UNION 联合查询注入"）。
	// 自定义规则无注册表条目时为空。
	RuleName string `json:"rule_name,omitempty"`
	// RuleDesc 是内置检测规则的说明，比 MatchDesc 更完整；
	// 用于安全事件详情展示可解释的规则信息。
	RuleDesc string `json:"rule_desc,omitempty"`
	// MatchScore 是 OWASP 命中时的累计风险分值；0 表示不适用。
	MatchScore int `json:"match_score,omitempty"`
	// MatchSnippet 是触发命中的内容片段，已按 maxSnippetLen 截断并脱敏。
	MatchSnippet string `json:"match_snippet,omitempty"`
	// MatchPart 是命中部位（url/body/header/cookie/all），CVE 命中时填充。
	MatchPart string `json:"match_part,omitempty"`
	// Severity 是危险度（critical/high/medium/low），CVE 命中时填充。
	Severity string `json:"severity,omitempty"`
	// Source 是规则来源（catalog/nvd/github/manual/auto_generated），CVE 命中时填充。
	Source string `json:"source,omitempty"`
	// CVSSScore / CWEType 是 CVE 规则的危险度明细。
	CVSSScore float64 `json:"cvss_score,omitempty"`
	CWEType   string  `json:"cwe_type,omitempty"`
	// References 是 CVE 参考链接（NVD 采集），换行分隔。
	References string `json:"references,omitempty"`

	Phase       string `json:"phase,omitempty"`
	MatchDesc   string `json:"match_desc,omitempty"`
	Matched     bool   `json:"matched"`
	Category    string `json:"category,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`  // 自定义 HTTP 状态码（0 = 使用默认值）
	RedirectTo  string `json:"redirect_to,omitempty"`  // redirect 动作的跳转 URL
	CaptchaType string `json:"captcha_type,omitempty"` // 规则级 CAPTCHA 类型；空值继承全局配置。
	// CaptchaMinutes 是规则级验证码通过有效期（分钟）；0 表示继承全局 captcha_pass_ttl。
	CaptchaMinutes int                `json:"captcha_minutes,omitempty"`
	SetHeaders     *map[string]string `json:"set_headers,omitempty"`   // Lua 可控的响应头
	ResponseBody   *string            `json:"response_body,omitempty"` // Lua 可控的响应体
	Tags           *[]string          `json:"tags,omitempty"`          // 可观测性标签
}

// IsTerminal 报告该动作是否必须短路管道——既不访问上游，也不再执行后续阶段。
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

// IsDrop 报告该动作是否要求立即关闭 TCP 连接且不发送任何 HTTP 响应。
func (r Result) IsDrop() bool {
	if !r.Matched {
		return false
	}
	if r.Type == Drop {
		return true
	}
	return Normalize(r.Type) == Drop
}

// IsChallenge 报告该请求是否应当返回验证挑战页。
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

// IsCaptchaChallenge 报告该请求是否需要 CAPTCHA 验证。
func (r Result) IsCaptchaChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == CaptchaChallenge {
		return true
	}
	return Normalize(r.Type) == CaptchaChallenge
}

// IsShieldChallenge 报告该请求是否需要 5 秒盾验证。
func (r Result) IsShieldChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == ShieldChallenge {
		return true
	}
	return Normalize(r.Type) == ShieldChallenge
}

// IsChainChallenge 报告该请求是否需要多步链式验证。
func (r Result) IsChainChallenge() bool {
	if !r.Matched {
		return false
	}
	if r.Type == ChainChallenge {
		return true
	}
	return Normalize(r.Type) == ChainChallenge
}

// IsRedirect 报告该请求是否应当重定向。
func (r Result) IsRedirect() bool {
	if !r.Matched {
		return false
	}
	if r.Type == Redirect {
		return true
	}
	return Normalize(r.Type) == Redirect
}

// IsRateLimit 报告该动作是否应返回限流响应。
func (r Result) IsRateLimit() bool {
	if !r.Matched {
		return false
	}
	if r.Type == RateLimit {
		return true
	}
	return Normalize(r.Type) == RateLimit
}

// ShouldLog 报告该命中是否值得写入一条安全日志。
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

// EffectiveStatusCode 返回应当使用的状态码；未设置自定义状态码时回退到
// 传入的默认值。
func (r Result) EffectiveStatusCode(defaultCode int) int {
	if r.StatusCode > 0 {
		return r.StatusCode
	}
	return defaultCode
}

// DefaultStatusCode 返回需要发送响应的动作的规范 HTTP 状态码。
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

// ResponseStatusCode 返回配置的状态码，未配置时返回规范默认值。
func (r Result) ResponseStatusCode() int {
	return r.EffectiveStatusCode(r.DefaultStatusCode())
}

// Pass 返回一个未命中的 allow 结果（默认放行）。
func Pass() Result { return Result{Type: Allow} }

/**
 * 内部状态码系统 (1xxx)。
 *
 * 内部状态码用于 WAF 内部日志记录和指标追踪，不会发送给客户端。
 * 1xxx 范围与标准 HTTP 状态码互不冲突，仅供内部可观测性使用。
 */
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
