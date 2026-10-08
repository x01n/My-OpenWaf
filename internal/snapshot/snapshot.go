package snapshot

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/dynamic"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/jsplugin"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/pageconfig"
)

/**
 * CompiledRule 是轻量级运行时规则（MVP 版 ACL 解析器的产物）。
 *
 * 由 snapshot 构建期从 DSL 文本编译而来，请求期只做匹配，不再解析字符串。
 */
type CompiledRule struct {
	ID          uint
	Phase       store.RulePhase
	Action      store.RuleAction
	Priority    int
	Kind        string
	Arg         string
	StatusCode  int    // 自定义 HTTP 状态码（0 = 用默认值）
	RedirectTo  string // redirect 动作的目标 URL
	CaptchaType string // 规则级验证码类型；留空则继承全局 protection 配置。
	// CaptchaMinutes 是规则级验证码通过有效期（分钟）；0 继承全局 captcha_pass_ttl。
	CaptchaMinutes int
}

/**
 * SiteRuntime 是站点经解析后的运行时视图，供路由与请求处理使用。
 *
 * 快照构建期把 DB 中的站点、规则、上游、证书与各类保护覆盖值一次性解析到本结构；
 * 数据面只读取，不再回查数据库。
 */
type SiteRuntime struct {
	Site         store.Site
	PolicyID     uint
	Rules        []CompiledRule
	UpstreamURLs []string
	Certificate  *store.Certificate

	NetworkDefaults NetworkDefaults
	TLSDefaults     TLSDefaults

	// 监听配置（已内嵌进 Site）
	Bind      string
	TLSConfig *tls.Config

	// bot 与攻击防护
	BotProtection    store.BotProtectionConfig
	AttackProtection store.AttackProtectionConfig

	// 转发设置（已移入 Site 模型）
	XFFMode              string
	TrustedCIDR          string
	ClientIPHeaderOrder  []string
	PreserveOriginalHost bool

	// 站点级维护模式
	MaintenanceEnabled bool
	MaintenanceHTML    string
	MaintenanceStatus  int

	// 站点级挑战策略覆盖（对应站点字段 challenge_action / captcha_type）。
	// 空串 = 站点未覆盖，数据面回退到全局 ProtectionConfig；非空 = 站点覆盖值。
	ChallengeAction      string
	ChallengeCaptchaType string

	// 站点级拦截页
	BlockHTML   string
	BlockStatus int

	// 站点级响应缓存
	CacheEnabled    bool
	CacheDefaultTTL int
	CacheRules      []store.SiteCacheRule

	// 防重放 nonce 防护
	AntiReplayEnabled bool
	AntiReplayAction  string // nonce 校验失败时的动作（默认 "challenge"）
	// AntiReplayCookieMode 合并后的 Cookie 校验模式终值（standard / dual）。
	AntiReplayCookieMode string

	// 站点级保护覆盖（由 Site 字段合并而来）。
	// nil = 使用全局 ProtectionConfig。
	EffectiveProtection *store.ProtectionConfig

	// 站点级应用路由规则（随快照编译）。
	AppRouteRules []appresource.CompiledRule

	// DynamicProtection 是动态防护配置（HTML 混淆、JS 混淆、图片水印）。
	DynamicProtection dynamic.ProtectionConfig

	// AccessControl 是站点访问控制网关配置（nil = 未启用）。
	AccessControl *AccessControlConfig

	ResponseCompressionConfigured     bool
	ResponseCompressionEnabled        bool
	ResponseCompressionGzipEnabled    bool
	ResponseCompressionDeflateEnabled bool
	ResponseCompressionZstdEnabled    bool
	ResponseCompressionMinBytes       int
	BrotliEnabled                     bool

	// 上游 Host 头覆盖（用于显式指定上游 Host 的解析）。
	UpstreamHostHeader string

	// 站点级 IP 黑白名单（仅对该站点生效）。
	SiteIPWhitelist []iprep.IPListEntry
	SiteIPBlacklist []iprep.IPListEntry
}

// AccessControlConfig 站点访问控制运行时配置。
type AccessControlConfig struct {
	Enabled            bool
	SharedPasswordHash string
	SessionTTL         int
	Providers          []AccessControlProvider
	PathRules          []AccessControlPathRule
}

// AccessControlProvider 认证提供方运行时配置。
type AccessControlProvider struct {
	ID       uint
	Type     string
	Name     string
	Priority int
	Config   string // OAuth/OIDC 配置 JSON（密文形式，数据面解密后使用）
}

// AccessControlPathRule 路径访问控制规则。
type AccessControlPathRule struct {
	Path     string
	Action   string
	Priority int
}

// TLSCertificateState 描述某个 SNI 路由是否已有可用的已配置证书。
type TLSCertificateState string

const (
	TLSCertificateStateValid        TLSCertificateState = "valid"
	TLSCertificateStateUnconfigured TLSCertificateState = "unconfigured"
	TLSCertificateStateInvalid      TLSCertificateState = "invalid"
)

// SnapshotConfigDiagnostic 描述当前快照中被跳过的无效配置。
//
// 该结构只保留管理端定位记录所需的稳定标识，不包含原始配置值、备注或解析错误文本。
type SnapshotConfigDiagnostic struct {
	Source           string `json:"source"`
	Field            string `json:"field"`
	Error            string `json:"error"`
	HandlingStrategy string `json:"handling_strategy"`
	Kind             string `json:"kind"`
	Reason           string `json:"reason"`
	PolicyID         uint   `json:"policy_id,omitempty"`
	RuleID           string `json:"rule_id,omitempty"`
	IPListEntryID    uint   `json:"ip_list_entry_id,omitempty"`
	CertificateID    uint   `json:"certificate_id,omitempty"`
	ListenerID       uint   `json:"listener_id,omitempty"`
	Scope            string `json:"scope,omitempty"`
	SiteID           uint   `json:"site_id,omitempty"`
}

const (
	DiagnosticSourcePolicyOWASP  = "policy_owasp_rule_configs"
	DiagnosticSourceIPList       = "ip_list_entries"
	DiagnosticSourceSites        = "sites"
	DiagnosticSourceListeners    = "site_listeners"
	DiagnosticSourceCertificates = "certificates"

	DiagnosticFieldWhitelistJSON   = "whitelist_json"
	DiagnosticFieldValue           = "value"
	DiagnosticFieldCertificateID   = "cert_id"
	DiagnosticFieldCertificatePair = "certificate_key_pair"
	DiagnosticFieldUpstreamMTLS    = "upstream_tls_client_cert"

	DiagnosticHandlingSkipInvalidField         = "skip_invalid_field"
	DiagnosticHandlingSkipInvalidEntry         = "skip_invalid_entry"
	DiagnosticHandlingRejectInvalidCertificate = "reject_invalid_certificate"
)

/**
 * Snapshot 是数据面可见的不可变配置视图（配合原子指针整体替换）。
 *
 * 一次构建、全程只读：请求处理期间不会有任何字段被改写，因此数据面无需加锁，
 * reload 只是把新快照指针换上去。
 */
type Snapshot struct {
	Revision uint64

	Sites map[string]*SiteRuntime

	NetworkDefaults NetworkDefaults
	TLSDefaults     TLSDefaults

	DefaultBlockHTML string
	CaptchaPage      pageconfig.CaptchaPageConfig
	ChallengePage    pageconfig.ChallengePageConfig
	BlockPage        pageconfig.BlockPageConfig

	SiteTLSCertBySNI      map[string]tls.Certificate
	SiteTLSCertStateBySNI map[string]TLSCertificateState

	// 从 SystemSettings 加载的保护配置。
	Protection store.ProtectionConfig

	// LuaPlugins 是已编译的自定义 Lua 策略脚本。
	//
	// 在 snapshot 构建期编译而非请求期：编译有成本，且语法错误应在 reload 时
	// 就被发现。单个脚本编译失败不会使整个 snapshot 构建失败——错误记入
	// LuaPluginErrors 供管理端展示，其余脚本照常生效，避免一处语法错误
	// 导致整次配置重载失败。
	LuaPlugins []*luaplugin.Script
	// LuaPluginErrors 按脚本名记录编译错误。
	LuaPluginErrors map[string]string

	// JSPlugins 是已编译的 JavaScript 边缘脚本。
	JSPlugins []*jsplugin.Script
	// JSPluginErrors 按 JSPluginErrorKey 返回的稳定脚本标识记录编译或元数据错误。
	JSPluginErrors map[string]string

	// ConfigDiagnostics 记录构建期跳过的无效配置，随快照原子发布。
	ConfigDiagnostics []SnapshotConfigDiagnostic

	// HTTP2 配置
	HTTP2Config HTTP2Config

	// HSTS
	HSTSEnabled bool

	// XSS 防护
	XSSProtectionEnabled bool

	// Expect-CT
	ExpectCTEnabled bool
	ExpectCTValue   string

	// HPKP
	HPKPEnabled           bool
	HPKPValue             string
	HPKPReportOnlyEnabled bool
	HPKPReportOnlyValue   string

	// 响应压缩
	ResponseCompressionEnabled        bool
	ResponseCompressionGzipEnabled    bool
	ResponseCompressionDeflateEnabled bool
	ResponseCompressionZstdEnabled    bool
	ResponseCompressionMinBytes       int

	// Brotli
	BrotliEnabled bool

	// ExcludeRecordHeaders 记录的是应跳过资源记录的头部名。
	ExcludeRecordHeaders []string
}

func SiteMapKey(bind string, host string) string {
	return bind + "\x00" + strings.ToLower(strings.TrimSpace(host))
}

// siteMapKeyNorm 组装站点映射键，前提是 host 已经规范化（小写、去首尾空白、去端口）。
func siteMapKeyNorm(bind string, host string) string {
	return bind + "\x00" + host
}

func SNICertKey(bind string, sni string) string {
	return "sni:" + bind + "\x00" + NormalizeMatchHost(sni)
}

/**
 * TLSCertificateStateForSNI 按与站点匹配相同的优先级解析某个 SNI 的证书状态。
 *
 * 优先级依次为精确匹配、通配符（`*.` 父域）、catch-all（`*`），与 MatchSite 保持
 * 一致，避免「站点命中 A、证书却取到 B」这类不一致。
 *
 * @param bind 监听地址。
 * @param sni  ClientHello 中的 SNI 名。
 * @return 证书状态与是否命中；未命中时状态为空串。
 */
func (sn *Snapshot) TLSCertificateStateForSNI(bind string, sni string) (TLSCertificateState, bool) {
	if sn == nil || sn.SiteTLSCertStateBySNI == nil {
		return "", false
	}
	host := NormalizeMatchHost(sni)
	if host == "" {
		return "", false
	}
	lookup := func(candidate string) (TLSCertificateState, bool) {
		state, ok := sn.SiteTLSCertStateBySNI[SNICertKey(bind, candidate)]
		return state, ok
	}
	if state, ok := lookup(host); ok {
		return state, true
	}
	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			if state, ok := lookup("*." + host[idx+1:]); ok {
				return state, true
			}
		}
	}
	return lookup("*")
}

func (sn *Snapshot) MatchSite(bind string, hostHeader string) (SiteRuntime, bool) {
	host := NormalizeMatchHost(hostHeader)
	if host == "" {
		return SiteRuntime{}, false
	}

	key := siteMapKeyNorm(bind, host)
	if rt, ok := sn.Sites[key]; ok {
		return *rt, true
	}

	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			wild := "*." + host[idx+1:]
			if rt, ok := sn.Sites[siteMapKeyNorm(bind, wild)]; ok {
				return *rt, true
			}
		}
	}

	if rt, ok := sn.Sites[siteMapKeyNorm(bind, "*")]; ok {
		return *rt, true
	}

	return SiteRuntime{}, false
}

/**
 * MatchSitePtr 按「监听地址 + Host」查找站点运行时指针。
 *
 * 零拷贝：直接返回 Sites map 中存放的指针，调用方不要在请求期内改写其指向的内容。
 *
 * @param bind 监听地址。
 * @param hostHeader 请求 Host 头原值。
 * @return 站点运行时指针与是否命中。
 */
func (sn *Snapshot) MatchSitePtr(bind string, hostHeader string) (*SiteRuntime, bool) {
	host := NormalizeMatchHost(hostHeader)
	if host == "" {
		return nil, false
	}

	key := siteMapKeyNorm(bind, host)
	if rt, ok := sn.Sites[key]; ok {
		return rt, true
	}

	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			wild := "*." + host[idx+1:]
			if rt, ok := sn.Sites[siteMapKeyNorm(bind, wild)]; ok {
				return rt, true
			}
		}
	}

	if rt, ok := sn.Sites[siteMapKeyNorm(bind, "*")]; ok {
		return rt, true
	}

	return nil, false
}

/**
 * NormalizeMatchHost 对 Host 头做小写化、去首尾空白并剥离端口。
 *
 * 快路径：若 host 已是小写 ASCII 且不含空白与端口，原样返回，不产生分配——
 * 绝大多数规范客户端都走这条路。
 *
 * @param host 请求 Host 头原值。
 * @return 规范化后的 host。
 */
func NormalizeMatchHost(host string) string {
	// 快路径：判断是否已规范化（规范客户端的常见情况）。
	needsWork := false
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'A' && c <= 'Z' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':' {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return host
	}

	host = strings.ToLower(strings.TrimSpace(host))
	// 剥离端口：定位最后一个冒号，并确认其后全部是数字。
	if i := strings.LastIndex(host, ":"); i >= 0 {
		port := host[i+1:]
		allDigits := len(port) > 0
		for _, ch := range port {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			host = host[:i]
		}
	}
	return host
}

// isIPAddress 判断 host 字符串是否为 IP 地址（v4 或 v6）。
func isIPAddress(host string) bool {
	for _, ch := range host {
		if ch == '.' || ch == ':' || (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return net.ParseIP(host) != nil
}

// Holder 以原子方式持有当前快照。
type Holder struct {
	ptr atomic.Pointer[Snapshot]
}

/**
 * Store 无条件发布一个快照。
 *
 * 运行时 reload 请改用 StoreIfNewer，否则可能用旧修订覆盖更新的快照。
 *
 * @param s 待发布的快照。
 */
func (h *Holder) Store(s *Snapshot) { h.ptr.Store(s) }

/**
 * StoreIfNewer 仅在当前已激活的修订更旧时才发布 s。
 *
 * CAS 循环保证并发 reload 之间不会用旧修订覆盖新修订。
 *
 * @param s 待发布的快照。
 * @return 是否发布成功。
 */
func (h *Holder) StoreIfNewer(s *Snapshot) bool {
	if s == nil {
		return false
	}
	for {
		current := h.ptr.Load()
		if current != nil && current.Revision >= s.Revision {
			return false
		}
		if h.ptr.CompareAndSwap(current, s) {
			return true
		}
	}
}

func (h *Holder) Load() *Snapshot { return h.ptr.Load() }

// 共享的运行时上限。
const (
	WAFBodyScanLimit = 48 * 1024 // 48 KB
)

// 时间常量（秒）。
const (
	OneDaySeconds = 86400
)

// 默认安全响应头取值。
const (
	DefaultExpectCTValue       = "max-age=86400, enforce"
	DefaultHPKPValue           = ""
	DefaultHPKPReportOnlyValue = ""
)

// 默认响应压缩设置。
//
// DefaultBrotliEnabled 是 brotli_enabled 与 response_compression_deflate_enabled、
// response_compression_zstd_enabled 共用的缺省值：DB 里没有该设置行时按「开」
// 处理（用户裁定「支持全部都开启」）。显式写入 "false" 仍然关闭。
const (
	DefaultResponseCompressionEnabled     = true
	DefaultResponseCompressionGzipEnabled = true
	DefaultResponseCompressionMinBytes    = 1024
	DefaultBrotliEnabled                  = true
	DefaultResponseCompressionDeflate     = true
	DefaultResponseCompressionZstd        = true
)
