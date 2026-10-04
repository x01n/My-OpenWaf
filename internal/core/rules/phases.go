package rules

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/bot/geoip"
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/ratelimit"
)

// MatchCtx 是匹配器所需的请求数据子集。
type MatchCtx struct {
	ClientIP         net.IP
	Method           string
	Path             string
	Query            string
	Headers          map[string]string
	HeadersLowercase bool
	Host             string
	HeaderOrder      string
	TLSALPN          string
	TLSCipherSuites  string
	TLS              *tlsfp.TLSClientFingerprint
	Body             []byte
	// reqCtx 指向共享 RequestCtx，供 bodyJSONPath/queryParam 匹配器挂
	// per-request 懒解析缓存。未填充（纯值构造）时为 nil，匹配器会直接
	// 解析且不缓存，行为与原实现一致。
	reqCtx *pipeline.RequestCtx
}

func fillMatchCtxFromPipeline(ctx *pipeline.RequestCtx, needsDerivedHeaders bool, mc *MatchCtx) {
	mc.reqCtx = ctx
	mc.ClientIP = ctx.ClientIP
	mc.Method = ctx.Method
	mc.Path = ctx.Path
	mc.Query = ctx.RawQuery
	mc.Headers = ctx.Headers
	mc.HeadersLowercase = ctx.HeadersLowercase
	mc.Host = ctx.Host
	mc.TLS = &ctx.TLS
	mc.Body = ctx.Body
	if needsDerivedHeaders {
		// tls_alpn 匹配键沿用「协商结果」语义（与访问日志 TLSALPN 同源）；
		// ClientHello 声明列表在 ctx.TLS.ALPNRaw，由需要它的判定直接读取。
		if len(ctx.TLS.ALPN) > 0 {
			mc.TLSALPN = ctx.DerivedALPN(func() string {
				return strings.Join(ctx.TLS.ALPN, ",")
			})
		}
		if len(ctx.TLS.CipherSuites) > 0 {
			mc.TLSCipherSuites = ctx.DerivedCipherSuites(func() string {
				return formatTLSCipherSuitesHeaderValue(ctx.TLS.CipherSuites)
			})
		}
		if len(ctx.HeaderKeys) > 0 {
			mc.HeaderOrder = ctx.DerivedHeaderOrder(func() string {
				return strings.Join(ctx.HeaderKeys, ",")
			})
		}
	}
}

func ctxFromPipeline(ctx *pipeline.RequestCtx, needsDerivedHeaders bool) MatchCtx {
	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)
	return mc
}

func executeCompiledPhase(ctx *pipeline.RequestCtx, rules []Compiled, allowShortCircuit bool, needsDerivedHeaders bool) (action.Result, bool) {
	if len(rules) == 0 {
		return action.Pass(), false
	}

	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)

	for i := range rules {
		if !rules[i].Match(mc) {
			continue
		}
		r := hit(rules[i])
		return r, r.IsTerminal()
	}

	return action.Pass(), false
}

type aclPhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewACLPhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "acl")
	return &aclPhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewACLPhasePrecompiled 由已分区的规则创建 ACL 阶段（无需再过滤）。
func NewACLPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &aclPhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *aclPhase) Name() string { return "acl" }

func (p *aclPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCompiledPhase(ctx, p.rules, true, p.needsDerivedHeaders)
}

type signaturePhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewSignaturePhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "signature")
	return &signaturePhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewSignaturePhasePrecompiled 由已分区的规则创建 signature 阶段。
func NewSignaturePhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &signaturePhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *signaturePhase) Name() string { return "signature" }

func (p *signaturePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCompiledPhase(ctx, p.rules, false, p.needsDerivedHeaders)
}

type customPhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewCustomPhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "custom")
	return &customPhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewCustomPhasePrecompiled 由已分区的规则创建 custom 阶段。
func NewCustomPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &customPhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *customPhase) Name() string { return "custom" }

func (p *customPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCustomPhase(ctx, p.rules, p.needsDerivedHeaders)
}

func executeCustomPhase(ctx *pipeline.RequestCtx, rules []Compiled, needsDerivedHeaders bool) (action.Result, bool) {
	if len(rules) == 0 {
		return action.Pass(), false
	}

	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)
	var observeHits []action.Result

	for i := range rules {
		if !rules[i].Match(mc) {
			continue
		}
		r := hit(rules[i])
		if r.ShouldLog() && !r.IsTerminal() {
			observeHits = append(observeHits, r)
			continue
		}
		if len(observeHits) > 0 {
			ctx.AppendPhaseObserveHits(observeHits)
		}
		return r, r.IsTerminal()
	}

	if len(observeHits) == 0 {
		return action.Pass(), false
	}
	if len(observeHits) > 1 {
		ctx.AppendPhaseObserveHits(observeHits[1:])
	}
	return observeHits[0], false
}

func compiledRulesNeedDerivedHeaders(rules []Compiled) bool {
	for i := range rules {
		if ruleNeedsDerivedHeaders(rules[i].Kind, rules[i].Arg) {
			return true
		}
	}
	return false
}

func ruleNeedsDerivedHeaders(kind string, arg string) bool {
	switch kind {
	case "tls_alpn",
		"tls_cipher_suite",
		"tls_cipher_suites",
		"header_order_contains",
		"header_order_regex":
		return true
	case "compound":
		return compoundNeedsDerivedHeaders(arg)
	default:
		return false
	}
}

func compoundNeedsDerivedHeaders(raw string) bool {
	var cond compoundCondition
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return false
	}
	return compoundConditionNeedsDerivedHeaders(cond)
}

func compoundConditionNeedsDerivedHeaders(cond compoundCondition) bool {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
	case "and", "or":
		for i := range cond.Children {
			if compoundConditionNeedsDerivedHeaders(cond.Children[i]) {
				return true
			}
		}
		return false
	case "not", "cc_rate":
		if len(cond.Children) == 0 {
			return false
		}
		return compoundConditionNeedsDerivedHeaders(cond.Children[0])
	case "if", "if_else", "ifelse":
		if cond.If != nil && compoundConditionNeedsDerivedHeaders(*cond.If) {
			return true
		}
		if cond.Then != nil && compoundConditionNeedsDerivedHeaders(*cond.Then) {
			return true
		}
		if cond.Else != nil && compoundConditionNeedsDerivedHeaders(*cond.Else) {
			return true
		}
		return false
	default:
		if cond.If != nil && cond.Then != nil {
			if compoundConditionNeedsDerivedHeaders(*cond.If) {
				return true
			}
			if compoundConditionNeedsDerivedHeaders(*cond.Then) {
				return true
			}
			if cond.Else != nil && compoundConditionNeedsDerivedHeaders(*cond.Else) {
				return true
			}
			return false
		}
		if cond.Kind == "" {
			return false
		}
		return ruleNeedsDerivedHeaders(cond.Kind, cond.Arg)
	}
}

type reqRateLimitPhase struct {
	limiter ratelimit.RateLimiterBackend
	act     action.Type
}

func NewReqRateLimitPhase(limiter ratelimit.RateLimiterBackend, act action.Type) pipeline.Phase {
	return &reqRateLimitPhase{limiter: limiter, act: act}
}

func (p *reqRateLimitPhase) Name() string { return "rate_limit" }

func (p *reqRateLimitPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.limiter == nil || !p.limiter.Enabled() {
		return action.Pass(), false
	}
	key := ""
	if ctx.ClientIP != nil {
		key = ctx.ClientIP.String()
	}
	key += "|" + ctx.Host
	if p.limiter.Allow(key) {
		return action.Pass(), false
	}
	act := normalizeConfiguredAction(string(p.act))
	if act == "" {
		act = action.RateLimit
	}
	result := action.Result{
		Type:      act,
		Phase:     "rate_limit",
		RuleIDStr: "request_rate_limit",
		MatchDesc: "request rate limit exceeded",
		Matched:   true,
		Category:  "rate_limit",
	}
	if act == action.RateLimit {
		result.StatusCode = 429
	}
	return result, result.IsTerminal()
}

type ipReputationPhase struct {
	rep           *iprep.IPReputation
	siteWhitelist []iprep.IPListEntry
	siteBlacklist []iprep.IPListEntry
}

func NewIPReputationPhase(rep *iprep.IPReputation, siteWhitelist, siteBlacklist []iprep.IPListEntry) pipeline.Phase {
	return &ipReputationPhase{
		rep:           rep,
		siteWhitelist: siteWhitelist,
		siteBlacklist: siteBlacklist,
	}
}

func (p *ipReputationPhase) Name() string { return "ip_reputation" }

func siteIPEntryMatches(entry iprep.IPListEntry, ip net.IP, now int64) bool {
	if entry.ExpireAt > 0 && now > entry.ExpireAt {
		return false
	}
	if entry.CIDR != nil && entry.CIDR.Contains(ip) {
		return true
	}
	return entry.Single != nil && entry.Single.Equal(ip)
}

func (p *ipReputationPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if ctx.ClientIP == nil {
		return action.Pass(), false
	}

	now := time.Now().Unix()
	for _, entry := range p.siteWhitelist {
		if siteIPEntryMatches(entry, ctx.ClientIP, now) {
			return action.Result{
				Type:      action.Allow,
				Phase:     "ip_reputation",
				RuleIDStr: "ip:site_whitelist",
				MatchDesc: "site whitelist: " + entry.Note,
				Matched:   true,
				Category:  "whitelist",
			}, false
		}
	}
	for _, entry := range p.siteBlacklist {
		if !siteIPEntryMatches(entry, ctx.ClientIP, now) {
			continue
		}
		act := action.Intercept
		if entry.Action == "drop" || entry.Action == "block" {
			act = action.Drop
		}
		return action.Result{
			Type:      act,
			Phase:     "ip_reputation",
			RuleIDStr: "ip:site_blacklist",
			MatchDesc: "site blacklist: " + entry.Note,
			Matched:   true,
			Category:  "site_blacklist",
		}, true
	}

	if p.rep == nil {
		return action.Pass(), false
	}
	d := p.rep.Check(ctx.ClientIP)
	if !d.Matched {
		return action.Pass(), false
	}
	if d.Allowed {
		return action.Result{
			Type:      action.Allow,
			Phase:     "ip_reputation",
			MatchDesc: "whitelist: " + d.Reason,
			Matched:   true,
			Category:  "whitelist",
		}, true
	}

	act := action.Intercept
	if d.Action == "drop" || d.Action == "block" {
		act = action.Drop
	}
	return action.Result{
		Type:      act,
		Phase:     "ip_reputation",
		MatchDesc: d.Category + ": " + d.Reason,
		Matched:   true,
		Category:  d.Category,
		RuleIDStr: "iprep:" + d.Category,
	}, true
}

type botPhase struct {
	rep       *iprep.IPReputation          // 可选，用于记录违规
	geo       *geoip.MaxMindResolver       // 可选，用于 GeoIP 评分
	threshold int                          // 拦截所用的评分阈值
	limiter   ratelimit.RateLimiterBackend // 可选，用于行为（请求速率）评分
	rateMax   int                          // 限流窗口阈值，行为分换算基准
}

// NewBotPhase 创建不带 GeoIP 加权的 bot 检测管道阶段。
// 保留给只需要两模块（UA + 指纹）路径的调用方。
func NewBotPhase(rep *iprep.IPReputation) pipeline.Phase {
	return &botPhase{rep: rep, threshold: 80}
}

// NewBotPhaseWithGeo 创建带 GeoIP 加权的 bot 检测管道阶段，
// 采用 PreScreen → DeepScore 两阶段流程。
func NewBotPhaseWithGeo(rep *iprep.IPReputation, geo *geoip.MaxMindResolver, threshold int) pipeline.Phase {
	return NewBotPhaseWithGeoAndLimiter(rep, geo, threshold, nil, 0)
}

/**
 * NewBotPhaseWithGeoAndLimiter 构造带行为模块的 bot 检测阶段。
 *
 * limiter 用于行为分：阶段内调用 Increment 取得窗口计数，再按
 * bot.BehaviorScoreFromCount 以 rateMax 为基准换算行为模块原始分。
 * limiter 为 nil/未启用，或 rateMax <= 0 时行为分恒为 0。
 *
 * @param rep IP 声誉服务，可为 nil。
 * @param geo GeoIP 解析器，可为 nil。
 * @param threshold 综合评分处置阈值；<=0 时按 80 处理。
 * @param limiter 限流后端，可为 nil。
 * @param rateMax 与 limiter 同窗口的请求阈值（ProtectionConfig.RequestRateLimitMax）。
 * @return bot 检测阶段。
 */
func NewBotPhaseWithGeoAndLimiter(rep *iprep.IPReputation, geo *geoip.MaxMindResolver, threshold int, limiter ratelimit.RateLimiterBackend, rateMax int) pipeline.Phase {
	if threshold <= 0 {
		threshold = 80
	}
	return &botPhase{rep: rep, geo: geo, threshold: threshold, limiter: limiter, rateMax: rateMax}
}

/**
 * challengePassIdentity 在数据面已捕获改写前身份时返回该不可变身份，
 * 同时兼容直接构造 RequestCtx 的调用方。
 */
func challengePassIdentity(ctx *pipeline.RequestCtx) (string, string) {
	if ctx.ChallengeIdentityCaptured {
		return ctx.ChallengeIdentityCookie, ctx.ChallengeIdentityUserAgent
	}
	cookie, _ := lookupHeaderValue(ctx.Headers, "cookie")
	return cookie, ctx.UserAgent
}

func (p *botPhase) Name() string { return "bot_detection" }

/**
 * behaviorScore 用限流后端换算行为模块原始分。
 *
 * key 与 reqRateLimitPhase 同源（clientIP+"|"+host）但带独立后缀：限流阶段
 * 的 Allow 已经给同窗口计数 +1，若行为分复用同一个 key，每个请求会被计两次，
 * 使限流阈值实际减半。使用独立窗口既保持「同一份频率数据」的语义（同窗口
 * 长度、同阈值基准），又不干扰限流的执行计数。
 *
 * @param ctx 请求上下文。
 * @return 行为模块原始分；limiter 缺失/未启用或 rateMax 无效时返回 0。
 */
func (p *botPhase) behaviorScore(ctx *pipeline.RequestCtx) int {
	limiter := p.limiter
	if limiter == nil || !limiter.Enabled() || p.rateMax <= 0 {
		return 0
	}
	key := ""
	if ctx.ClientIP != nil {
		key = ctx.ClientIP.String()
	}
	key += "|" + ctx.Host + botBehaviorKeySuffix
	count := limiter.Increment(key)
	return bot.BehaviorScoreFromCount(int(count), p.rateMax)
}

// botBehaviorKeySuffix 是行为分独立窗口的 key 后缀。
const botBehaviorKeySuffix = "|bot"

func (p *botPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	// 已通过签名验证 cookie 的请求跳过挑战。
	cookie, userAgent := challengePassIdentity(ctx)
	if cookie != "" && challenge.VerifyChallengePassCookieWithClaims(cookie, challenge.ChallengePassClaims{Host: ctx.Host, ClientIP: ctx.ClientIP, UserAgent: userAgent, SiteID: ctx.SiteID, Bind: ctx.Bind}, time.Now()) {
		return action.Pass(), false
	}

	br := bot.NewBotRequest(ctx.Method, ctx.Path, ctx.Headers)
	br.ClientIP = ctx.ClientIP
	br.HeaderKeys = ctx.HeaderKeys
	if len(br.HeaderKeys) > 0 {
		br.HeaderOrder = ctx.DerivedHeaderOrder(func() string { return strings.Join(ctx.HeaderKeys, ",") })
	}
	br.TLS = ctx.TLS

	v, bs := bot.CheckBotTwoPhaseWithBehavior(br, p.rep, p.geo, p.threshold, p.behaviorScore(ctx))
	p.storeBotScore(ctx, v, bs)
	return p.verdictToResult(v, ctx)
}

func (p *botPhase) storeBotScore(ctx *pipeline.RequestCtx, v bot.BotVerdict, bs bot.BotScore) {
	if v.Category == "human" || v.Category == "good" {
		return // 良性流量不写库，省下 DB 写入
	}
	// 档位→动作的唯一映射：与 verdictToResult 共用 BotTier，避免双写。
	actionStr := v.Tier.LogAction()
	var details map[string]string
	if bs.IsHighRisk && len(bs.Details) > 0 {
		details = bs.Details
	}
	ctx.BotScoreResult = &pipeline.BotScoreInfo{
		TotalScore:       bs.Total,
		UAScore:          bs.UAScore,
		GeoIPScore:       bs.GeoIPScore,
		FingerprintScore: bs.FingerprintScore,
		BehaviorScore:    bs.BehaviorScore,
		IPRepScore:       bs.IPRepScore,
		IsHighRisk:       bs.IsHighRisk,
		Action:           actionStr,
		Details:          details,
		Dangerous:        v.Dangerous,
		DangerReasons:    v.DangerReasons,
	}
}

func (p *botPhase) verdictToResult(v bot.BotVerdict, ctx *pipeline.RequestCtx) (action.Result, bool) {
	if v.IsBot && v.Tier >= bot.TierIntercept && p.rep != nil && ctx.ClientIP != nil {
		p.rep.RecordViolation(ctx.ClientIP)
	}
	result := action.Result{
		Phase:     "bot_detection",
		MatchDesc: v.Reason,
		RuleIDStr: v.RuleID,
		Category:  v.Tier.Category(),
	}
	switch v.Tier {
	case bot.TierDrop:
		result.Type = action.Drop
		result.Matched = true
		return result, true
	case bot.TierIntercept:
		result.Type = action.Intercept
		result.Matched = true
		return result, true
	case bot.TierChallenge:
		result.Type = action.Challenge
		result.Matched = true
		return result, true
	case bot.TierObserve:
		result.Type = action.Observe
		result.Matched = true
		return result, false
	default:
		return action.Pass(), false
	}
}

type owaspPhase struct {
	cfg                 *store.ProtectionConfig
	categorySensitivity map[string]string
	overrides           map[string]owasp.OWASPRuleOverride
	thresholds          owasp.CompiledThresholds
	fileUploadEnabled   bool
	protoEnabled        bool
}

func NewOWASPPhase(cfg *store.ProtectionConfig) pipeline.Phase {
	phase := &owaspPhase{cfg: cfg}
	if cfg != nil {
		phase.categorySensitivity = cfg.EffectiveCategorySensitivity()
		phase.overrides = owasp.ParseOWASPRulesConfig(cfg.OWASPRulesConfig)
		phase.thresholds = owasp.CompileThresholds(cfg.OWASPSensitivity, phase.categorySensitivity)
		_, phase.fileUploadEnabled = owasp.CategoryThreshold(cfg.OWASPSensitivity, owasp.CatFileUpload, phase.categorySensitivity)
		_, phase.protoEnabled = owasp.CategoryThreshold(cfg.OWASPSensitivity, owasp.CatProtoViol, phase.categorySensitivity)
	}
	return phase
}

func (p *owaspPhase) Name() string { return "owasp_default" }

func (p *owaspPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.OWASPEnabled {
		return action.Pass(), false
	}

	categorySensitivity := p.categorySensitivity
	overrides := p.overrides
	fileUploadEnabled := p.fileUploadEnabled
	protoEnabled := p.protoEnabled

	if fileUploadEnabled && containsFoldASCII(ctx.ContentType, "multipart/form-data") && len(ctx.Body) > 0 {
		filenames, contentTypes := extractMultipartFilenames(ctx.Body, ctx.ContentType)
		for i, fname := range filenames {
			fct := ""
			if i < len(contentTypes) {
				fct = contentTypes[i]
			}
			if uploadHit, ok := owasp.CheckFileUpload(fname, fct); ok {
				if owasp.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
					continue
				}
				result := owaspHitResult(uploadHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
		// 兜底：扫描原始请求体，找出 Go 的 multipart 解析器可能漏掉的文件名
		// （被 filepath.Base 剥掉的路径穿越、空格扩展名绕过）。
		if uploadHit, ok := owasp.CheckRawMultipartFilenames(ctx.Body); ok {
			if !owasp.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
				result := owaspHitResult(uploadHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
	}

	if !ctx.BodyTargetsDone {
		ctx.BodyTargets = extractBodyTargets(ctx.Body, ctx.ContentType)
		ctx.BodyTargetsDone = true
	}
	bodyTargets := ctx.BodyTargets

	// 在完整 OWASP 扫描之前先检查 HTTP 方法是否异常/危险。
	if protoEnabled {
		if methodHit, ok := owasp.CheckMethodViolation(ctx.Method, ctx.Headers); ok {
			if !owasp.ShouldSkipRule(methodHit.RuleID, ctx.Path, overrides) {
				result := owaspHitResult(methodHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
	}

	hit, ok := owasp.FirstAcceptedOWASPHitWithThresholds(p.thresholds, ctx.Path, ctx.RawQuery, ctx.Headers, bodyTargets, overrides, categorySensitivity)
	if !ok {
		return action.Pass(), false
	}
	result := owaspHitResult(hit, p.cfg, overrides)
	return result, result.IsTerminal()
}

func owaspHitResult(hit owasp.OWASPHit, cfg *store.ProtectionConfig, overrides map[string]owasp.OWASPRuleOverride) action.Result {
	act := normalizeConfiguredAction(cfg.OWASPAction)
	override := owasp.RuleOverride(hit.RuleID, overrides)
	if override.Action != "" {
		act = normalizeConfiguredAction(override.Action)
	}
	// 规则名称/说明取自内置注册表：与规则目录页展示的是同一份元信息，
	// 命中结果因此可以解释「命中了哪条规则」，而不只是类别级文案。
	ruleName, ruleDesc := "", ""
	if rule, ok := owasp.DefaultOWASPRegistry.Get(hit.RuleID); ok && rule != nil {
		ruleName, ruleDesc = rule.Name, rule.Description
	}
	result := action.Result{
		Type:         action.Normalize(act),
		RuleIDStr:    hit.RuleID,
		RuleName:     ruleName,
		RuleDesc:     ruleDesc,
		MatchScore:   hit.Score,
		MatchSnippet: hit.Snippet,
		Phase:        "owasp_default",
		MatchDesc:    hit.Desc,
		Matched:      true,
		Category:     string(hit.Category),
		StatusCode:   override.StatusCode,
		RedirectTo:   override.RedirectTo,
		CaptchaType:  override.CaptchaType,
	}
	if result.Type != action.CaptchaChallenge {
		result.CaptchaType = ""
	}
	return result
}

type cvePhase struct {
	cfg                 *store.ProtectionConfig
	detector            *cve.CVEDetector
	categorySensitivity map[string]string
	ruleOverrides       map[string]cve.CVERuleOverride
	cachedConfig        bool
}

func newCVEPhase(cfg *store.ProtectionConfig, detector *cve.CVEDetector) *cvePhase {
	phase := &cvePhase{cfg: cfg, detector: detector, cachedConfig: true}
	if cfg != nil {
		phase.categorySensitivity = cfg.EffectiveCategorySensitivity()
		phase.ruleOverrides = cve.ParseCVERuleOverrides(cfg.CVERulesConfig)
	}
	return phase
}

// NewCVEPhase 创建运行 CVE 专项检测的管道阶段。
func NewCVEPhase(cfg *store.ProtectionConfig, detector *cve.CVEDetector) pipeline.Phase {
	return newCVEPhase(cfg, detector)
}

func (p *cvePhase) Name() string { return "cve_detection" }

func (p *cvePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.CVEEnabled || p.detector == nil {
		return action.Pass(), false
	}

	categorySensitivity := p.categorySensitivity
	if !p.cachedConfig {
		categorySensitivity = p.cfg.EffectiveCategorySensitivity()
	}

	if !cve.HasRawCVESuspiciousContent(ctx.Path, ctx.RawQuery, ctx.Headers, ctx.Body, ctx.ContentType) {
		return action.Pass(), false
	}

	var req cve.CVERequest
	cve.BuildCVERequestInto(&req, ctx.Path, ctx.RawQuery, ctx.Headers, ctx.Body, ctx.ContentType)
	matches := p.detector.Detect(&req, categorySensitivity)
	if len(matches) == 0 {
		return action.Pass(), false
	}
	var best cve.CVEMatch
	overrides := p.ruleOverrides
	if !p.cachedConfig {
		overrides = cve.ParseCVERuleOverrides(p.cfg.CVERulesConfig)
	}
	found := false
	for _, match := range matches {
		disabled := false
		for _, key := range []string{match.Pattern, "cve:" + match.Pattern, match.CVEID, "cve:" + match.CVEID} {
			if ov, ok := overrides[key]; ok {
				disabled = ov.Enabled != nil && !*ov.Enabled
				break
			}
		}
		if disabled {
			continue
		}
		best = match
		found = true
		break
	}
	if !found {
		return action.Pass(), false
	}

	// 默认顺序：先用配置的 CVE 动作，再用规则级动作，最后才自动 drop。
	cveAction := p.cfg.CVEAction
	if cveAction == "" {
		cveAction = "intercept"
	}
	act := normalizeConfiguredAction(cveAction)
	statusCode := 0
	redirectTo := ""
	captchaType := ""
	explicitAction := false
	if best.Action != "" {
		act = normalizeConfiguredAction(best.Action)
		explicitAction = true
	}
	if best.CaptchaType != "" {
		captchaType = best.CaptchaType
	}
	if len(overrides) > 0 {
		for _, key := range []string{best.Pattern, "cve:" + best.Pattern, best.CVEID, "cve:" + best.CVEID} {
			if ov, ok := overrides[key]; ok {
				if ov.Action != "" {
					act = normalizeConfiguredAction(ov.Action)
					explicitAction = true
				}
				if ov.StatusCode != 0 {
					statusCode = ov.StatusCode
				}
				if ov.RedirectTo != "" {
					redirectTo = ov.RedirectTo
				}
				if ov.CaptchaType != "" {
					captchaType = ov.CaptchaType
				}
				break
			}
		}
	}

	// 严重/高危 CVE 在开关打开且规则未指定动作时，自动升级为 Drop。
	if !explicitAction {
		switch best.Severity {
		case "critical":
			if p.cfg.CVEAutoDropCritical && action.TerminalPriority(action.Drop) > action.TerminalPriority(act) {
				act = action.Drop
			}
		case "high":
			if p.cfg.CVEAutoDropHigh && action.TerminalPriority(action.Drop) > action.TerminalPriority(act) {
				act = action.Drop
			}
		}
	}
	if action.Normalize(act) != action.CaptchaChallenge {
		captchaType = ""
	}

	result := action.Result{
		Type:         action.Normalize(act),
		RuleIDStr:    "cve:" + best.CVEID,
		RuleName:     best.CVEID,
		RuleDesc:     best.Description,
		MatchScore:   0,
		MatchSnippet: best.Snippet,
		MatchPart:    best.MatchedPart,
		Severity:     best.Severity,
		Source:       best.Source,
		CVSSScore:    best.CVSSScore,
		CWEType:      best.CWEType,
		References:   best.References,
		Phase:        "cve_detection",
		MatchDesc:    best.Description + " [" + best.Pattern + "]",
		Matched:      true,
		// 子检测器已产出 cve_ 前缀分类（cve_general/cve_java/...），
		// 直接透传，避免再拼前缀得到 cve_cve_java 这类前端无标签的值。
		Category:    best.Category,
		StatusCode:  statusCode,
		RedirectTo:  redirectTo,
		CaptchaType: captchaType,
	}
	if result.Category == "" {
		result.Category = "cve_general"
	}
	return result, result.IsTerminal()
}

// looksLikeJSON 判断首个非空白字节是否为 { 或 [。
func looksLikeJSON(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// looksLikeFormEncoded 判断请求体是否含 key=value&... 形态。
func looksLikeFormEncoded(body []byte) bool {
	if len(body) == 0 || len(body) > 65536 {
		return false
	}
	hasEq := false
	for _, b := range body {
		if b == '=' {
			hasEq = true
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
	}
	return hasEq
}

func shouldScanOpaqueBodyTarget(body []byte) bool {
	for _, b := range body {
		switch b {
		case '<', '>', '`', ';', '|', '\\', '{', '}', '[', ']':
			return true
		}
	}
	return containsFoldASCIIBytes(body, "%0d") ||
		containsFoldASCIIBytes(body, "%0a") ||
		containsFoldASCIIBytes(body, "%3c") ||
		containsFoldASCIIBytes(body, "%3e") ||
		containsFoldASCIIBytes(body, "%27") ||
		containsFoldASCIIBytes(body, "%22") ||
		containsFoldASCIIBytes(body, "javascript:") ||
		containsFoldASCIIBytes(body, "vbscript:") ||
		containsFoldASCIIBytes(body, "document.") ||
		containsFoldASCIIBytes(body, "onerror") ||
		containsFoldASCIIBytes(body, "onload") ||
		containsFoldASCIIBytes(body, "onmouse") ||
		containsFoldASCIIBytes(body, "onfocus") ||
		containsFoldASCIIBytes(body, "alert(") ||
		containsFoldASCIIBytes(body, " union ") ||
		containsFoldASCIIBytes(body, " select ") ||
		containsFoldASCIIBytes(body, " or ") ||
		containsFoldASCIIBytes(body, " and ") ||
		containsFoldASCIIBytes(body, "sleep(") ||
		containsFoldASCIIBytes(body, "benchmark(") ||
		containsFoldASCIIBytes(body, "../") ||
		containsFoldASCIIBytes(body, "127.0.") ||
		containsFoldASCIIBytes(body, "localhost") ||
		containsFoldASCIIBytes(body, "169.254.169.254") ||
		containsFoldASCIIBytes(body, "metadata.google") ||
		containsFoldASCIIBytes(body, "aced0005") ||
		containsFoldASCIIBytes(body, "ro0ab") ||
		containsFoldASCIIBytes(body, "objectinputstream") ||
		containsFoldASCIIBytes(body, "deserializ")
}

/**
 * extractBodyTargets 依据 Content-Type 解析请求体，返回可逐一扫描攻击载荷的
 * 独立取值。
 *
 * Content-Type 缺失或有误导性时还会对请求体做嗅探，判定其真实格式，
 * 防止通过篡改头部绕过检测。
 */
func extractBodyTargets(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}
	ct := contentType

	var primary []string
	parsedOK := false
	skipRawFallback := false

	switch {
	case containsFoldASCII(ct, "application/x-www-form-urlencoded"):
		primary = extractFormValues(string(body))
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "application/json"):
		primary = extractJSONValues(body)
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "multipart/form-data"):
		primary = extractMultipartFieldValues(body, contentType)
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "text/") || containsFoldASCII(ct, "application/xml") || containsFoldASCII(ct, "application/soap"):
		limit := 8192
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
		parsedOK = true
	default:
		limit := snapshot.WAFBodyScanLimit
		if len(body) < limit {
			limit = len(body)
		}
		if ct == "" {
			primary = []string{string(body[:limit])}
			parsedOK = true
		} else {
			sample := body
			if len(sample) > 512 {
				sample = body[:512]
			}
			printable := 0
			for _, b := range sample {
				if b >= 0x20 && b <= 0x7E || b == '\n' || b == '\r' || b == '\t' {
					printable++
				}
			}
			if float64(printable)/float64(len(sample)) >= 0.9 && shouldScanOpaqueBodyTarget(body[:limit]) {
				primary = []string{string(body[:limit])}
				parsedOK = true
			} else {
				skipRawFallback = true
			}
		}
	}

	// 兜底：声明的 Content-Type 解析器没抽到任何东西时（例如请求体是 base64
	// 包裹但 Content-Type 写着 application/json），始终再扫一遍原始请求体，
	// 让 normalizeWithDecode 有机会剥掉 base64 层。
	if !parsedOK && !skipRawFallback && len(body) > 0 {
		limit := snapshot.WAFBodyScanLimit
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
	}

	// 与 Content-Type 无关的嗅探：同时尝试其他解析器，防止用错误的
	// Content-Type 请求头规避检测。
	if !containsFoldASCII(ct, "application/json") && looksLikeJSON(body) {
		if extra := extractJSONValues(body); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}
	if !containsFoldASCII(ct, "form-urlencoded") && !containsFoldASCII(ct, "multipart/form-data") && ct != "" && looksLikeFormEncoded(body) {
		if extra := extractFormValues(string(body)); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}

	return dedupeBodyTargets(primary)
}

func dedupeBodyTargets(targets []string) []string {
	if len(targets) < 2 {
		return targets
	}

	seen := make(map[string]struct{}, len(targets))
	out := targets[:0]
	for _, target := range targets {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

// extractFormValues 把 form-urlencoded 请求体拆成逐个解码后的值。
// 参数名（键）与值都会被扫描——攻击者可能通过键名注入载荷
// （例如 `1 UNION SELECT--=x`）。
func extractFormValues(body string) []string {
	vals := make([]string, 0, (strings.Count(body, "&")+1)*2)
	// 整串也作为一个目标保留：按 & 拆分会切断 `&&`、`||` 这类命令链
	// （例：cmd=127.0.0.1 && ls /etc 会被切成 "127.0.0.1 "、"cmd"、" ls /etc"），
	// 拆后各段都不再是完整载荷。逐段扫描与整串扫描并存，命中归因不受影响。
	if strings.Contains(body, "&&") || strings.Contains(body, "||") {
		vals = append(vals, body)
	}
	for body != "" {
		pair := body
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, body = pair[:i], pair[i+1:]
		} else {
			body = ""
		}
		if pair == "" {
			continue
		}
		paramKey, value, hasEq := strings.Cut(pair, "=")
		if hasEq {
			dv := value
			if strings.IndexByte(value, '%') >= 0 || strings.IndexByte(value, '+') >= 0 {
				if decoded, err := url.QueryUnescape(value); err == nil {
					dv = decoded
				}
			}
			if dv != "" {
				vals = append(vals, dv)
			}
		}
		// 参数名同样要扫描，攻击者可在其中注入载荷。
		dk := paramKey
		if strings.IndexByte(paramKey, '%') >= 0 || strings.IndexByte(paramKey, '+') >= 0 {
			if decoded, err := url.QueryUnescape(paramKey); err == nil {
				dk = decoded
			}
		}
		if dk != "" {
			vals = append(vals, dk)
		}
	}
	return vals
}

// extractJSONValues 递归收集 JSON 对象中的全部字符串值。
func extractJSONValues(body []byte) []string {
	var raw any
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	var vals []string
	walkJSON(raw, &vals, 0)
	return vals
}

/**
 * walkJSON 递归收集 JSON 中的键与字符串值。
 *
 * 对象键按字典序遍历：Go 的 map 迭代顺序随机，若按 range 顺序产出，
 * BodyTargets 的顺序会随请求变化；而 OWASP 归因取「首个跨阈 target」，
 * 顺序即决定安全事件记录的 RuleID，同一请求会被记成不同规则。
 *
 * 副作用：depth > 10 / len(vals) > 100 的剪枝点由「随机丢弃」变为「确定丢弃」，
 * 即超限时保留排序靠前的键，而非每次不同的子集。
 */
func walkJSON(v any, vals *[]string, depth int) {
	if depth > 10 || len(*vals) > 100 {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*vals = append(*vals, val)
		}
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// 键名同样要扫描：攻击者可通过 JSON 键名注入载荷。
			if k != "" {
				*vals = append(*vals, k)
			}
			walkJSON(val[k], vals, depth+1)
		}
	case []any:
		for _, child := range val {
			walkJSON(child, vals, depth+1)
		}
	}
}

// extractMultipartFilenames 解析 multipart 表单数据，提取文件名。
func extractMultipartFilenames(body []byte, contentType string) (filenames []string, contentTypes []string) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for i := 0; i < 20; i++ {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		if fname := part.FileName(); fname != "" {
			filenames = append(filenames, fname)
			contentTypes = append(contentTypes, part.Header.Get("Content-Type"))
		}
		part.Close()
	}
	return filenames, contentTypes
}

/**
 * extractMultipartFieldValues 解析 multipart 表单数据，返回非文件字段的文本
 * 内容，供 OWASP 载荷扫描。
 *
 * 文件 part 会被跳过，因为其文件名已由文件上传扫描器检查过。
 */
func extractMultipartFieldValues(body []byte, contentType string) []string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var vals []string
	for i := 0; i < 20; i++ {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		// 文件上传 part：扫描内容开头若干字节，查找内嵌代码。
		if part.FileName() != "" {
			buf, _ := io.ReadAll(io.LimitReader(part, 4096))
			part.Close()
			if len(buf) > 0 {
				vals = append(vals, string(buf))
			}
			continue
		}
		// 读取字段值，上限 4096 字节以限定正则扫描耗时。
		buf, _ := io.ReadAll(io.LimitReader(part, 4096))
		part.Close()
		if len(buf) > 0 {
			vals = append(vals, string(buf))
		}
		if fn := part.FormName(); fn != "" {
			vals = append(vals, fn)
		}
		if cd := part.Header.Get("Content-Disposition"); cd != "" {
			vals = append(vals, rawDispositionNameValues(cd)...)
		}
	}
	return vals
}

/**
 * reDispositionRawName 从 Content-Disposition 头部原文中取 name 值。
 *
 * part.FormName() 走 mime 解析并对 quoted-string 做反转义（\\ → \、\" → "），
 * 反转义后的值与攻击者提交的原始字节不同：UNC 前缀 \\host 会被吞成一个
 * 反斜杠，使依赖双反斜杠形态的规则（如 path_traversal:019）失配。头部原文
 * 保留原始字节，因此额外以原文值作为扫描目标。filename 位的同类处理已由
 * CheckRawMultipartFilenames 的原文正则承担。
 */
var reDispositionRawName = regexp.MustCompile(`(?i)\bname="([^"]{0,512})"`)

func rawDispositionNameValues(header string) []string {
	ms := reDispositionRawName.FindAllStringSubmatch(header, 4)
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if v := m[1]; v != "" {
			out = append(out, v)
		}
	}
	return out
}

type antiReplayPhase struct {
	mgr *antireplay.AntiReplayManager
}

func NewAntiReplayPhase(mgr *antireplay.AntiReplayManager) pipeline.Phase {
	return &antiReplayPhase{mgr: mgr}
}

func (p *antiReplayPhase) Name() string { return "anti_replay" }

func (p *antiReplayPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.mgr == nil {
		return action.Pass(), false
	}
	// 从 X-Nonce 请求头提取 nonce。
	nonce, _ := lookupHeaderValue(ctx.Headers, "x-nonce")
	if nonce == "" {
		// 未提供 nonce——跳过重放检查。
		return action.Pass(), false
	}
	if ctx.AntiReplayConsumedNonce != "" && nonce == ctx.AntiReplayConsumedNonce {
		// 处理器已消费过这个确切的 Cookie nonce。值不同的 X-Nonce 仍会走到
		// 下面的 ValidateAndRotate，无法绕过重放校验。
		return action.Pass(), false
	}
	clientIP := ""
	if ctx.ClientIP != nil {
		clientIP = ctx.ClientIP.String()
	}
	ttl := time.Duration(0)
	if ctx.AntiReplayTTL > 0 {
		ttl = time.Duration(ctx.AntiReplayTTL) * time.Second
	}
	valid, isReplay, _ := p.mgr.ValidateAndRotate(nonce, clientIP, ttl)
	if !valid || isReplay {
		result := action.Result{
			Type:      action.Intercept,
			Phase:     "anti_replay",
			MatchDesc: "request replay detected or invalid nonce",
			Matched:   true,
			Category:  "replay",
			RuleIDStr: "antireplay:nonce",
		}
		return result, true
	}
	return action.Pass(), false
}

func filterPhase(rules []Compiled, phase string) []Compiled {
	var out []Compiled
	for _, r := range rules {
		if r.Phase == phase {
			out = append(out, r)
		}
	}
	return out
}

func normalizeConfiguredAction(value string) action.Type {
	act := action.Normalize(action.Type(value))
	if act == action.Type("log") {
		return action.Observe
	}
	if !action.IsValid(act) {
		return action.Intercept
	}
	return act
}

func hit(c Compiled) action.Result {
	act := c.runtimeAction
	if act == "" {
		act = normalizeConfiguredAction(string(c.Action))
	}
	ruleIDStr := c.ruleIDStr
	if ruleIDStr == "" {
		ruleIDStr = "rule:" + c.Phase + ":" + c.Kind
	}
	desc := c.matchDesc
	if desc == "" {
		desc = compiledMatchDesc(c.Kind, c.Arg)
	}
	return action.Result{
		Type:        act,
		RuleID:      c.ID,
		RuleIDStr:   ruleIDStr,
		Phase:       c.Phase,
		MatchDesc:   desc,
		Matched:     true,
		Category:    c.Kind,
		StatusCode:  c.StatusCode,
		RedirectTo:  c.RedirectTo,
		CaptchaType: c.CaptchaType,
		// 规则级验证码有效期；0 表示继承全局，由下发侧归一化。
		CaptchaMinutes: c.CaptchaMinutes,
	}
}

type browserSignPhase struct {
	cfg *store.ProtectionConfig
}

// NewBrowserSignPhase 创建浏览器请求签名校验 phase。
// 仅对 IsLikelyAPIRequest 识别为 API 的请求强制校验请求头签名。
func NewBrowserSignPhase(cfg *store.ProtectionConfig) pipeline.Phase {
	return &browserSignPhase{cfg: cfg}
}

func (p *browserSignPhase) Name() string { return "browser_sign" }

func (p *browserSignPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.cfg == nil || !p.cfg.BrowserSignEnabled {
		return action.Pass(), false
	}
	if !challenge.IsLikelyAPIRequest(ctx.Method, ctx.Path, ctx.Headers) {
		return action.Pass(), false
	}
	// 已通过挑战 cookie 的请求不重复强制签名，避免刷新后误伤。
	cookie, userAgent := challengePassIdentity(ctx)
	if cookie != "" && challenge.VerifyChallengePassCookieWithClaims(cookie, challenge.ChallengePassClaims{
		Host: ctx.Host, ClientIP: ctx.ClientIP, UserAgent: userAgent, SiteID: ctx.SiteID, Bind: ctx.Bind,
	}, time.Now()) {
		return action.Pass(), false
	}

	ok, reason := challenge.VerifyBrowserSignHeaders(ctx.Headers, ctx.Method, ctx.Path, ctx.RawQuery, ctx.SiteID, time.Now())
	if ok {
		return action.Pass(), false
	}

	act := action.Normalize(action.Type(p.cfg.BrowserSignAction))
	switch act {
	case action.Intercept, action.Challenge, action.CaptchaChallenge, action.ShieldChallenge, action.ChainChallenge, action.Observe, action.Drop:
	default:
		act = action.Challenge
	}
	result := action.Result{
		Type:      act,
		Phase:     "browser_sign",
		MatchDesc: reason,
		Matched:   true,
		Category:  "browser_sign",
		RuleIDStr: "browser_sign",
	}
	if act == action.Observe {
		return result, false
	}
	return result, true
}
