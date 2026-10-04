package challenge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mathrand "math/rand"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"My-OpenWaf/internal/waf/challenge/gm"
)

const envSessionKeySize = 32

// EnvFingerprintProtocolVersion 是环境指纹信封版本标签（"v2"），
// 由标签生成器从 GMEnvelopeVersion 派生产出，无 v1 并存分支。
var EnvFingerprintProtocolVersion = "v" + gm.ProtocolVersionString()

/**
 * EnvFingerprint 表示通过 JavaScript 收集的客户端环境指纹数据。
 * 涵盖浏览器 API、渲染/图形、媒体/音频、存储/API、性能/计时、
 * 权限/安全、自动化检测、环境一致性、DOM/CSS 等多维度检测点。
 */
type EnvFingerprint struct {
	WebDriver            bool           `json:"webdriver"`
	ChromePresent        bool           `json:"chrome_present"`
	PluginsCount         int            `json:"plugins_count"`
	Languages            string         `json:"languages"`
	DevtoolsOpen         bool           `json:"devtools_open"`
	CanvasHash           string         `json:"canvas_hash"`
	WebGLRenderer        string         `json:"webgl_renderer"`
	ScreenWidth          int            `json:"screen_width"`
	ScreenHeight         int            `json:"screen_height"`
	TimezoneOffset       int            `json:"timezone_offset"`
	TouchSupport         bool           `json:"touch_support"`
	HardwareConcur       int            `json:"hardware_concurrency"`
	ColorDepth           int            `json:"color_depth"`
	PixelRatio           float64        `json:"pixel_ratio"`
	AudioHash            string         `json:"audio_hash"`
	FontCount            int            `json:"font_count"`
	SessionStorage       bool           `json:"session_storage"`
	IndexedDB            bool           `json:"indexed_db"`
	PDFViewer            bool           `json:"pdf_viewer"`
	DoNotTrack           string         `json:"do_not_track"`
	MaxTouchPoints       int            `json:"max_touch_points"`
	ConnectionType       string         `json:"connection_type"`
	DevtoolsTiming       float64        `json:"devtools_timing"`
	PlatformStr          string         `json:"platform"`
	CookieEnabled        bool           `json:"cookie_enabled"`
	MemoryGB             float64        `json:"device_memory"`
	UserAgent            string         `json:"user_agent"`
	Vendor               string         `json:"vendor"`
	Product              string         `json:"product"`
	AppVersion           string         `json:"app_version"`
	Language             string         `json:"language"`
	ViewportWidth        int            `json:"viewport_width"`
	ViewportHeight       int            `json:"viewport_height"`
	OuterWidth           int            `json:"outer_width"`
	OuterHeight          int            `json:"outer_height"`
	InnerWidth           int            `json:"inner_width"`
	InnerHeight          int            `json:"inner_height"`
	ScreenX              int            `json:"screen_x"`
	ScreenY              int            `json:"screen_y"`
	NotificationAPI      bool           `json:"notification_api"`
	PushAPI              bool           `json:"push_api"`
	ClipboardAPI         bool           `json:"clipboard_api"`
	GeolocationAPI       bool           `json:"geolocation_api"`
	WebRTCAPI            bool           `json:"webrtc_api"`
	FetchAPI             bool           `json:"fetch_api"`
	WebSocketAPI         bool           `json:"websocket_api"`
	CryptoAPI            bool           `json:"crypto_api"`
	BatteryAPI           bool           `json:"battery_api"`
	GamepadAPI           bool           `json:"gamepad_api"`
	VibrateAPI           bool           `json:"vibrate_api"`
	AutomationSign       string         `json:"automation_sign"`
	Phantom              bool           `json:"phantom"`
	Nightmare            bool           `json:"nightmare"`
	SeleniumSign         bool           `json:"selenium_sign"`
	HeadlessUA           bool           `json:"headless_ua"`
	ChromeCDC            bool           `json:"chrome_cdc"`
	PermNotif            string         `json:"perm_notif"`
	UserAgentData        string         `json:"user_agent_data"`           // navigator.userAgentData JSON 序列化
	BrowserBrand         string         `json:"browser_brand"`             // 从 userAgentData 中提取的主要品牌
	BrowserVersion       string         `json:"browser_version"`           // 从 userAgentData 中提取的版本号
	IsMobile             bool           `json:"is_mobile"`                 // navigator.userAgentData.mobile
	UAMismatch           bool           `json:"ua_mismatch"`               // user-agent 字符串与 userAgentData brands 不匹配
	NavigatorProto       bool           `json:"navigator_proto"`           // navigator 原型链是否标准
	WebGLVendor          string         `json:"webgl_vendor"`              // WEBGL_debug_renderer_info UNMASKED_VENDOR
	CanvasToBlob         bool           `json:"canvas_to_blob"`            // canvas.toBlob 是否可用
	WebGL2Support        bool           `json:"webgl2_support"`            // WebGL2RenderingContext 是否可用
	SVGSupport           bool           `json:"svg_support"`               // SVGElement 是否可用
	MediaDevices         bool           `json:"media_devices"`             // navigator.mediaDevices 是否可用
	SpeechSynthesis      bool           `json:"speech_synthesis"`          // window.speechSynthesis 是否可用
	ServiceWorker        bool           `json:"service_worker"`            // navigator.serviceWorker 是否可用
	CacheAPI             bool           `json:"cache_api"`                 // window.caches 是否可用
	WebAssembly          bool           `json:"web_assembly"`              // WebAssembly 是否可用
	SharedWorker         bool           `json:"shared_worker"`             // SharedWorker 是否可用
	BroadcastChannel     bool           `json:"broadcast_channel"`         // BroadcastChannel 是否可用
	PerformanceObserver  bool           `json:"performance_observer"`      // PerformanceObserver 是否可用
	PerformanceMark      bool           `json:"performance_mark"`          // performance.mark 是否可用
	TimingAPIDepth       int            `json:"timing_api_depth"`          // performance.getEntries 条目数量
	PermissionAPI        bool           `json:"permission_api"`            // navigator.permissions 是否可用
	CredentialAPI        bool           `json:"credential_api"`            // navigator.credentials 是否可用
	CSPViolation         bool           `json:"csp_violation"`             // 指纹采集过程中是否发生 CSP 违规
	WebDriverAdvanced    bool           `json:"webdriver_advanced"`        // 多重 webdriver 指标检测
	CDPRuntime           bool           `json:"cdp_runtime"`               // Chrome DevTools Protocol Runtime.evaluate 痕迹
	PuppeteerSign        bool           `json:"puppeteer_sign"`            // Puppeteer 特有痕迹
	PlaywrightSign       bool           `json:"playwright_sign"`           // Playwright 特有痕迹
	ElectronSign         bool           `json:"electron_sign"`             // 是否运行在 Electron 中
	CypressSign          bool           `json:"cypress_sign"`              // Cypress 测试框架痕迹
	ScreenConsistency    bool           `json:"screen_consistency"`        // screen 属性与 window.screen 一致性
	TimezoneConsistency  bool           `json:"timezone_consistency"`      // Intl 时区与 getTimezoneOffset 一致性
	LanguageConsistency  bool           `json:"language_consistency"`      // navigator.language 与 Intl 区域设置一致性
	MathConsistency      bool           `json:"math_consistency"`          // Math 函数特定值跨次一致性
	CSSSupportsCheck     bool           `json:"css_supports_check"`        // CSS.supports 是否可用
	IntersectionObserver bool           `json:"intersection_observer"`     // IntersectionObserver 是否可用
	MutationObserver     bool           `json:"mutation_observer"`         // MutationObserver 是否可用
	ResizeObserver       bool           `json:"resize_observer"`           // ResizeObserver 是否可用
	HistoryAPI           bool           `json:"history_api"`               // history.pushState 是否可用
	ObjIntegrity         *int64         `json:"obj_integrity,omitempty"`   // window/document 对象自洽与函数原生性（nil=旧信封不参与判分）
	ProtoIntegrity       *int64         `json:"proto_integrity,omitempty"` // navigator.prototype webdriver getter 篡改检测（nil=旧信封不参与判分）
	Behavior             *BehaviorStats `json:"behavior,omitempty"`        // 键鼠行为采样统计（盾页前端统计后随信封提交）
}

/**
 * BehaviorStats 汇总盾挑战页收集的键鼠行为采样原始统计。
 * 前端只发送聚合量（不发送单条事件、轨迹或按键值），
 * 由服务端根据统计量判定其是否接近真实人类的操作节奏。
 * 超人类最大速度、事件间隔熵、重复间隔率、全静止抖动率、
 * 敏感动作键占比都是服务端评分的输入。
 */
type BehaviorStats struct {
	Events    int     `json:"events"`     // 观察到的输入事件数量（pointermove/keydown/keypress）
	Entropy   float64 `json:"entropy"`    // 移动事件间隔的香农熵；无事件或单事件时为 0
	ZeroRatio float64 `json:"zero_ratio"` // 移动间隔中相邻间隔完全重复的比例（0~1）
	Jitter    float64 `json:"jitter"`     // 有位移的移动事件比例（0~1，0 表示全部为零位移合成帧）
	MaxSpeed  float64 `json:"max_speed"`  // 单事件最大位移（像素每事件，含合成事件的位移）
	ActionKey int     `json:"action_key"` // 敏感键（Enter/Tab/Esc 等）触发次数
}

/**
 * EnvCheckResult 保存环境指纹验证的结果。
 */
type EnvCheckResult struct {
	Score   int      `json:"score"`   // 0-100，越高越可疑
	Reasons []string `json:"reasons"` // 每个评分贡献的说明
	Pass    bool     `json:"pass"`    // score <= threshold 时为 true
}

/**
 * ValidateEnvFingerprint 分析环境指纹并返回风险评分。
 * 评分 > 50 表示可疑（机器人/自动化）。
 * 语义等价于（且实现上就是）用全因子 gate 调用 ScoreWithMission：
 * 无过滤时新旧路径的分数与原因序列完全一致。
 */
func ValidateEnvFingerprint(fp *EnvFingerprint) EnvCheckResult {
	return scoreEnvFingerprint(fp, nil)
}

/**
 * scoreEnvFingerprint 是环境评分的唯一公共核心：硬终止检查（webdriver/
 * 自动化痕迹等）不受 gate 影响，任何过滤下都完整执行；累加类评分分支
 * 只有在 gate 为空（无过滤）或 gate 放行该分支依赖的全部因子时才会执行。
 * gate 由此把「本次挑战要求的环境因子集合」翻译成分支级过滤。
 *
 * @param fp   待评分的环境指纹。
 * @param gate 分支因子 gate；nil 表示全部参与（旧路径等价语义）。
 * @return     与 ValidateEnvFingerprint 同构的结果结构。
 */
func scoreEnvFingerprint(fp *EnvFingerprint, gate *envScoreGate) EnvCheckResult {
	if fp == nil {
		return EnvCheckResult{Score: 100, Reasons: []string{"no fingerprint data"}, Pass: false}
	}

	score := 0
	var reasons []string

	if fp.WebDriver {
		return EnvCheckResult{Score: 100, Reasons: []string{"webdriver=true: automated browser detected"}, Pass: false}
	}

	if fp.AutomationSign != "" {
		return EnvCheckResult{Score: 100, Reasons: []string{"client-side automation detected: " + fp.AutomationSign}, Pass: false}
	}

	if fp.Phantom || fp.Nightmare || fp.SeleniumSign || fp.ChromeCDC {
		return EnvCheckResult{Score: 100, Reasons: []string{"automation framework signatures detected"}, Pass: false}
	}

	if fp.HeadlessUA {
		return EnvCheckResult{Score: 100, Reasons: []string{"HeadlessChrome user-agent detected"}, Pass: false}
	}

	if fp.WebDriverAdvanced {
		return EnvCheckResult{Score: 100, Reasons: []string{"advanced webdriver indicators detected"}, Pass: false}
	}

	if fp.PuppeteerSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"puppeteer automation signatures detected"}, Pass: false}
	}

	if fp.PlaywrightSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"playwright automation signatures detected"}, Pass: false}
	}

	if fp.CypressSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"cypress testing framework detected"}, Pass: false}
	}

	if gateAllows(gate, "devtools_open") && fp.DevtoolsOpen {
		score += 30
		reasons = append(reasons, "devtools open (+30)")
	}

	if gateAllows(gate, "devtools_timing") && fp.DevtoolsTiming > 100 {
		score += 20
		reasons = append(reasons, "devtools timing anomaly (+20)")
	}

	if gateAllows(gate, "cdp_runtime") && fp.CDPRuntime {
		score += 25
		reasons = append(reasons, "Chrome DevTools Protocol runtime detected (+25)")
	}

	if gateAllows(gate, "electron_sign") && fp.ElectronSign {
		score += 15
		reasons = append(reasons, "Electron environment detected (+15)")
	}

	if gateAllows(gate, "chrome_present") && !fp.ChromePresent {
		score += 10
		reasons = append(reasons, "chrome object missing (+10)")
	}

	if gateAllows(gate, "plugins_count") {
		if fp.PluginsCount == 0 {
			score += 15
			reasons = append(reasons, "zero plugins (+15)")
		} else if fp.PluginsCount < 2 {
			score += 5
			reasons = append(reasons, "very few plugins (+5)")
		}
	}

	if gateAllows(gate, "languages") && (fp.Languages == "" || fp.Languages == "undefined") {
		score += 10
		reasons = append(reasons, "no language preference (+10)")
	}

	if gateAllows(gate, "canvas_hash") && (fp.CanvasHash == "" || fp.CanvasHash == "0") {
		score += 10
		reasons = append(reasons, "empty canvas hash (+10)")
	}

	if gateAllows(gate, "webgl_renderer") {
		if fp.WebGLRenderer == "" {
			score += 10
			reasons = append(reasons, "no WebGL renderer (+10)")
		} else if isSuspiciousRenderer(fp.WebGLRenderer) {
			score += 15
			reasons = append(reasons, "suspicious WebGL renderer (+15)")
		}
	}

	if gateAllows(gate, "screen_width", "screen_height") && (fp.ScreenWidth == 0 || fp.ScreenHeight == 0) {
		score += 10
		reasons = append(reasons, "zero screen dimensions (+10)")
	}

	if gateAllows(gate, "hardware_concurrency") && fp.HardwareConcur <= 1 {
		score += 5
		reasons = append(reasons, "low hardware concurrency (+5)")
	}

	if gateAllows(gate, "ua_mismatch") && fp.UAMismatch {
		score += 20
		reasons = append(reasons, "user-agent string mismatches userAgentData brands (+20)")
	}

	if gateAllows(gate, "screen_consistency") && !fp.ScreenConsistency {
		score += 15
		reasons = append(reasons, "screen property inconsistency (+15)")
	}

	if gateAllows(gate, "timezone_consistency") && !fp.TimezoneConsistency {
		score += 12
		reasons = append(reasons, "timezone inconsistency between Intl and getTimezoneOffset (+12)")
	}

	if gateAllows(gate, "language_consistency") && !fp.LanguageConsistency {
		score += 10
		reasons = append(reasons, "language inconsistency between navigator and Intl (+10)")
	}

	if gateAllows(gate, "math_consistency") && !fp.MathConsistency {
		score += 20
		reasons = append(reasons, "Math function output tampered (+20)")
	}

	if gateAllows(gate, "obj_integrity") && fp.ObjIntegrity != nil && *fp.ObjIntegrity < 2 {
		score += 20
		reasons = append(reasons, "window/document object integrity check failed (+20)")
	}
	if gateAllows(gate, "proto_integrity") && fp.ProtoIntegrity != nil && *fp.ProtoIntegrity < 2 {
		score += 20
		reasons = append(reasons, "navigator prototype integrity check failed (+20)")
	}

	if gateAllows(gate, "color_depth") && fp.ColorDepth == 0 {
		score += 8
		reasons = append(reasons, "zero color depth (+8)")
	}

	if gateAllows(gate, "pixel_ratio") && fp.PixelRatio == 0 {
		score += 8
		reasons = append(reasons, "zero pixel ratio (+8)")
	}

	if gateAllows(gate, "audio_hash") && fp.AudioHash == "" {
		score += 5
		reasons = append(reasons, "no audio fingerprint (+5)")
	}

	if gateAllows(gate, "session_storage") && !fp.SessionStorage {
		score += 8
		reasons = append(reasons, "sessionStorage unavailable (+8)")
	}

	if gateAllows(gate, "indexed_db") && !fp.IndexedDB {
		score += 8
		reasons = append(reasons, "indexedDB unavailable (+8)")
	}

	if gateAllows(gate, "cookie_enabled") && !fp.CookieEnabled {
		score += 10
		reasons = append(reasons, "cookies disabled (+10)")
	}

	if gateAllows(gate, "touch_support", "max_touch_points") && fp.TouchSupport && fp.MaxTouchPoints == 0 {
		score += 8
		reasons = append(reasons, "touch support inconsistency (+8)")
	}

	if gateAllows(gate, "platform") && fp.PlatformStr == "" {
		score += 5
		reasons = append(reasons, "empty platform string (+5)")
	}

	if gateAllows(gate, "font_count") && fp.FontCount == 0 {
		score += 5
		reasons = append(reasons, "zero detectable fonts (+5)")
	}

	if gateAllows(gate, "web_assembly") && !fp.WebAssembly {
		score += 8
		reasons = append(reasons, "WebAssembly unavailable (+8)")
	}

	if gateAllows(gate, "service_worker") && !fp.ServiceWorker {
		score += 5
		reasons = append(reasons, "ServiceWorker unavailable (+5)")
	}

	if gateAllows(gate, "media_devices") && !fp.MediaDevices {
		score += 5
		reasons = append(reasons, "MediaDevices unavailable (+5)")
	}

	if gateAllows(gate, "intersection_observer", "mutation_observer", "resize_observer") && !fp.IntersectionObserver && !fp.MutationObserver && !fp.ResizeObserver {
		score += 10
		reasons = append(reasons, "all observers missing (Intersection+Mutation+Resize) (+10)")
	}

	if gateAllows(gate, "webgl2_support", "webgl_renderer") && !fp.WebGL2Support && fp.WebGLRenderer == "" {
		score += 12
		reasons = append(reasons, "no WebGL2 support and no WebGL renderer (+12)")
	}

	if gateAllows(gate, "behavior") && fp.Behavior != nil {
		score += validateBehaviorStats(fp.Behavior, &reasons)
	}

	if score > 100 {
		score = 100
	}

	return EnvCheckResult{
		Score:   score,
		Reasons: reasons,
		Pass:    score <= 50,
	}
}

// envMissionFactorCountMin 与 envMissionFactorCountMax 分别是每次环境
// mission 要求因子数量的下界与上界：从全因子清单随机抽取 32..48 个。
const (
	envMissionFactorCountMin = 32
	envMissionFactorCountMax = 48
)

/**
 * EnvMission 描述单次挑战要求检查的环境因子子集。
 * Factor 名与 EnvFingerprint 的 json tag 同字面（见 envMissionAllFactors）。
 * ID 为空表示「无 mission」：接线端必须回退到旧的全因子评分路径。
 */
type EnvMission struct {
	ID      string   `json:"id"`      // 16 字节随机数的 hex 编码（32 字符）
	Factors []string `json:"factors"` // 本次要求参与评分分支的因子名集合（无重复）
}

// NewEnvMission 生成一次全新的环境 mission：ID 为 16 字节 crypto/rand
// 随机数的 hex 编码，Factors 从全因子清单随机抽取 32..48 个（随机顺序）。
// 全因子池实际只有 len(envMissionAllFactors)=37 个，为保证每次要求的
// 因子集恒为真子集（「每次要求不一样」），目标数量上限 clip 为
// len(factors)-1，实际范围 32..36。crypto/rand 失败时返回空 mission
// （ID==""），调用端据此自然回退旧路径。
func NewEnvMission() EnvMission {
	factors := append([]string(nil), envMissionAllFactors...)
	mathrand.Shuffle(len(factors), func(i, j int) {
		factors[i], factors[j] = factors[j], factors[i]
	})
	count := envMissionFactorCountMin + randIntN(envMissionFactorCountMax-envMissionFactorCountMin+1)
	if count >= len(factors) {
		count = len(factors) - 1
	}
	if count < 1 {
		count = 1
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return EnvMission{}
	}
	return EnvMission{ID: hex.EncodeToString(idBytes), Factors: factors[:count]}
}

/**
 * IsEnvMissionFactor 判断给定因子名（与 json tag 同字面）是否在 mission
 * 要求内。空 mission 永远返回 true——即「无 mission 时全部因子参与」，
 * 与旧评分路径语义一致。
 */
func IsEnvMissionFactor(mission EnvMission, factorJSON string) bool {
	if mission.ID == "" {
		return true
	}
	for _, f := range mission.Factors {
		if f == factorJSON {
			return true
		}
	}
	return false
}

/**
 * envScoreGate 把 mission 翻译为分支过滤视图：need(factor...) 返回
 * mission 是否覆盖该评分分支依赖的全部因子；mission 为空时恒真，
 * 等价于旧的全因子评分路径。
 */
type envScoreGate struct {
	mission EnvMission
}

// gateAllows 判定给定因子组合是否被 gate 放行；nil gate 表示不过滤。
func gateAllows(gate *envScoreGate, factors ...string) bool {
	if gate == nil || gate.mission.ID == "" {
		return true
	}
	for _, f := range factors {
		if !IsEnvMissionFactor(gate.mission, f) {
			return false
		}
	}
	return true
}

/**
 * ScoreWithMission 按 mission 要求的因子子集评分：
 * 硬终止分支不受过滤（自动化/伪造迹象任何场景都完整执行），
 * 累加类分支只有在 mission 覆盖其依赖的全部因子时才参与评分。
 * mission.ID 为空时结果与 ValidateEnvFingerprint 完全一致。
 */
func ScoreWithMission(fp *EnvFingerprint, mission EnvMission) EnvCheckResult {
	if mission.ID == "" {
		return scoreEnvFingerprint(fp, nil)
	}
	return scoreEnvFingerprint(fp, &envScoreGate{mission: mission})
}

/**
 * envMissionAllFactors 是参与「可过滤评分分支」的完整因子名清单，
 * 字面值与 EnvFingerprint 的 json tag 一一对应（含指针扩展因子
 * obj_integrity/proto_integrity/behavior）。硬终止检查与 mission 无关，
 * 不在本清单内（webdriver、automation_sign、phantom、nightmare、
 * selenium_sign、chrome_cdc、headless_ua、webdriver_advanced、
 * puppeteer_sign、playwright_sign、cypress_sign）。
 */
var envMissionAllFactors = []string{
	"devtools_open",
	"devtools_timing",
	"cdp_runtime",
	"electron_sign",
	"chrome_present",
	"plugins_count",
	"languages",
	"canvas_hash",
	"webgl_renderer",
	"screen_width",
	"screen_height",
	"hardware_concurrency",
	"ua_mismatch",
	"screen_consistency",
	"timezone_consistency",
	"language_consistency",
	"math_consistency",
	"obj_integrity",
	"proto_integrity",
	"color_depth",
	"pixel_ratio",
	"audio_hash",
	"session_storage",
	"indexed_db",
	"cookie_enabled",
	"touch_support",
	"max_touch_points",
	"platform",
	"font_count",
	"web_assembly",
	"service_worker",
	"media_devices",
	"intersection_observer",
	"mutation_observer",
	"resize_observer",
	"webgl2_support",
	"behavior",
}

/**
 * envFingerprintAADWithAugment 构造与 EnvFingerprintAAD 同构但附带
 * mission 约束的 AAD。mission.ID 空时输出与 EnvFingerprintAAD 逐字节相同，
 * 因此旧会话（无 mission）与旧版本页面互解不受影响；非空时格式为：
 * EnvFingerprintAAD(...) + "#" + mission.ID + "#" + 排序去重后的因子名
 * （以 "," 连接）。扩展后缀仅供测试/将来页面被告知 mission 后使用——
 * 页面在本任务不改动，仍按 EnvFingerprintAAD 的字节加密；服务端解密时
 * 按 session 内存储的 mission 逐字节重建同一 AAD，保证互通。
 */
func envFingerprintAADWithAugment(mission EnvMission, scope, sessionID string, binding ChallengeSessionBinding) string {
	base := EnvFingerprintAAD(scope, sessionID, binding)
	if mission.ID == "" {
		return base
	}
	factors := append([]string(nil), mission.Factors...)
	sort.Strings(factors)
	return base + "#" + mission.ID + "#" + strings.Join(factors, ",")
}

/**
 * DecryptEnvFingerprintForMission 覆盖 R2.2 会话签名链：当会话存储了
 * mission 时，上行信封的 AAD 是带 mission 扩展后缀的版本；旧会话（无
 * mission）继续走 DecryptEnvFingerprintWithAAD 的原样 AAD。
 */
func DecryptEnvFingerprintForMission(encrypted string, sessionKey []byte, mission EnvMission, scope, sessionID string, binding ChallengeSessionBinding) *EnvFingerprint {
	if mission.ID == "" {
		return DecryptEnvFingerprintWithAAD(encrypted, sessionKey, EnvFingerprintAAD(scope, sessionID, binding))
	}
	// 带 mission 的上行信封 AAD 随 mission 变长，直接走通用解密核心；
	// 与 DecryptEnvFingerprintWithAAD 的关键校验完全一致。
	if len(sessionKey) != envSessionKeySize {
		return nil
	}
	raw, err := gm.Decode(encrypted)
	if err != nil {
		return nil
	}
	plaintext, err := gm.Open(sessionKey[:16], raw, []byte(envFingerprintAADWithAugment(mission, scope, sessionID, binding)), gm.DomainEnv, false)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return nil
	}
	return ParseEnvFingerprint(string(plaintext))
}

func validateBehaviorStats(b *BehaviorStats, reasons *[]string) int {
	if b == nil {
		return 0
	}
	added := 0
	c := *b
	if c.Events <= 0 {
		added += 15
		*reasons = append(*reasons, "behavior: empty behavior sample (+15)")
		return added
	}
	if c.Events > shieldEnvMaxEvents ||
		math.IsNaN(c.Entropy) || math.IsInf(c.Entropy, 0) || c.Entropy < 0 ||
		math.IsNaN(c.ZeroRatio) || math.IsInf(c.ZeroRatio, 0) || c.ZeroRatio < 0 ||
		math.IsNaN(c.Jitter) || math.IsInf(c.Jitter, 0) || c.Jitter < 0 {
		added += 65
		*reasons = append(*reasons, "behavior: synthetic event flood (+65)")
		return added
	}
	if math.IsNaN(c.MaxSpeed) || math.IsInf(c.MaxSpeed, 0) || c.MaxSpeed < 0 || c.ActionKey < 0 {
		added += 40
		*reasons = append(*reasons, "behavior: invalid speed or action count (+40)")
		return added
	}
	if c.MaxSpeed > 0 && c.Events < shieldEnvMinEvents {
		added += 40
		*reasons = append(*reasons, "behavior: synthetic click without movement (+40)")
		return added
	}
	if c.Jitter <= 0 {
		added += 35
		*reasons = append(*reasons, "behavior: zero-jitter input frames (+35)")
	}
	if c.ZeroRatio >= 0.5 {
		added += 25
		*reasons = append(*reasons, "behavior: metronomic interval repetition (+25)")
	} else if c.Entropy < 1.5 {
		added += 15
		*reasons = append(*reasons, "behavior: low interval entropy (+15)")
	}
	if c.MaxSpeed > shieldEnvMaxHumanSpeed {
		added += 20
		*reasons = append(*reasons, "behavior: superhuman pointer speed (+20)")
	}
	if c.Events < shieldEnvMinEvents && c.MaxSpeed == 0 {
		added += 15
		*reasons = append(*reasons, "behavior: no interaction before submit (+15)")
	}
	if c.ActionKey > 8 {
		added += 10
		*reasons = append(*reasons, "behavior: action key spam (+10)")
	}

	if added > 100 {
		added = 100
	}
	return added
}

const shieldEnvMaxEvents = 2048
const shieldEnvMinEvents = 5
const shieldEnvMinPixPerEvent = 1.0
const shieldEnvMaxHumanSpeed = 200.0

func ParseEnvFingerprint(data string) *EnvFingerprint {
	if data == "" {
		return nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil
	}
	typeOfFingerprint := reflect.TypeOf(EnvFingerprint{})
	for i := 0; i < typeOfFingerprint.NumField(); i++ {
		field := typeOfFingerprint.Field(i)
		if field.Type.Kind() != reflect.Int {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		raw, ok := values[name]
		if !ok {
			continue
		}
		value, err := parseJSONInteger(raw, field.Type.Bits())
		if err != nil {
			return nil
		}
		values[name] = json.RawMessage(strconv.FormatInt(value, 10))
	}
	var fp EnvFingerprint
	normalized, err := json.Marshal(values)
	if err != nil || json.Unmarshal(normalized, &fp) != nil {
		return nil
	}
	if !validBehaviorRange(&fp) {
		return nil
	}
	return &fp
}

func validBehaviorRange(fp *EnvFingerprint) bool {
	if fp == nil || fp.Behavior == nil {
		return true
	}
	b := fp.Behavior
	return b.Events >= 0 && b.ActionKey >= 0 &&
		b.Entropy >= 0 && b.ZeroRatio >= 0 && b.Jitter >= 0 &&
		b.MaxSpeed >= 0
}

// parseJSONInteger 接受 JSON 整数以及数值上等价的浮点表示，例如 24.0。
// 非整数、字符串、布尔值、null 和超出 int 范围的值都会被拒绝。
func parseJSONInteger(raw []byte, bits int) (int64, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return 0, fmt.Errorf("trailing JSON value")
		}
		return 0, err
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a JSON number")
	}
	if integer, err := strconv.ParseInt(string(number), 10, bits); err == nil {
		return integer, nil
	}
	floatValue, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsNaN(floatValue) || math.IsInf(floatValue, 0) || math.Trunc(floatValue) != floatValue {
		return 0, fmt.Errorf("not an integer")
	}
	if bits == 32 && (floatValue < math.MinInt32 || floatValue > math.MaxInt32) {
		return 0, fmt.Errorf("integer out of range")
	}
	if bits == 64 && (floatValue < -float64(math.MaxInt64) || floatValue >= float64(math.MaxInt64)) {
		return 0, fmt.Errorf("integer out of range")
	}
	return int64(floatValue), nil
}

/**
 * DecryptEnvFingerprint 使用会话绑定密钥解密加密的环境指纹。
 */
/**
 * DecryptEnvFingerprintWithAAD 在解析之前先校验带版本的 WASM 信封。
 * AAD 把密文绑定到服务端签发的挑战作用域。
 */
func DecryptEnvFingerprintWithAAD(encrypted string, sessionKey []byte, aad string) *EnvFingerprint {
	if len(sessionKey) != envSessionKeySize || aad == "" {
		return nil
	}
	raw, err := gm.Decode(encrypted)
	if err != nil {
		return nil
	}
	plaintext, err := gm.Open(sessionKey[:16], raw, []byte(aad), gm.DomainEnv, false)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return nil
	}
	return ParseEnvFingerprint(string(plaintext))
}

/**
 * GenerateEnvSessionKey 创建一个 32 字节的随机会话主密钥，
 * 其前 16 字节作为 SM4-GCM 密钥使用（页面下发为 hex 64 字符）。
 */
func GenerateEnvSessionKey() []byte {
	key := make([]byte, envSessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	return key
}

/**
 * EnvSessionKeyHex 返回十六进制编码的会话密钥，用于嵌入 JS。
 */
func EnvSessionKeyHex(key []byte) string {
	if len(key) != envSessionKeySize {
		return ""
	}
	return hex.EncodeToString(key)
}

// EnvSessionKeyFromChallengeToken 将挑战令牌解码为 32 字节会话密钥材料。
func EnvSessionKeyFromChallengeToken(token string) []byte {
	key, err := hex.DecodeString(token)
	if err != nil || len(key) != envSessionKeySize {
		return nil
	}
	return key
}

// envEncrypt 用会话主密钥前 16 字节（SM4-128）封装明文并返回 raw 信封字节。
func envEncrypt(plaintext, key []byte, aad []byte, domain byte) ([]byte, error) {
	if len(key) != envSessionKeySize {
		return nil, fmt.Errorf("invalid session key length")
	}
	if len(aad) == 0 || len(aad) > 512 {
		return nil, fmt.Errorf("invalid environment AAD")
	}
	return gm.Seal(key[:16], domain, plaintext, aad)
}

// envDecrypt 校验并打开 GM 信封。
func envDecrypt(ciphertext, key, aad []byte, domain byte) ([]byte, error) {
	if len(key) != envSessionKeySize {
		return nil, fmt.Errorf("invalid session key length")
	}
	if len(aad) == 0 || len(aad) > 512 {
		return nil, fmt.Errorf("invalid environment AAD")
	}
	return gm.Open(key[:16], ciphertext, aad, domain, false)
}

func isSuspiciousRenderer(renderer string) bool {
	suspicious := []string{
		"SwiftShader",
		"llvmpipe",
		"softpipe",
		"VirtualBox",
		"VMware",
		"Mesa",
		"Google SwiftShader",
	}
	for _, s := range suspicious {
		if envContainsCI(renderer, s) {
			return true
		}
	}
	return false
}

func envContainsCI(s, substr string) bool {
	sl := len(substr)
	if sl == 0 {
		return true
	}
	if len(s) < sl {
		return false
	}
	for i := 0; i <= len(s)-sl; i++ {
		match := true
		for j := 0; j < sl; j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

/**
 * EnvFingerprintAAD 为指纹信封构造认证数据绑定。
 * session/token 仍是服务端授权根；该绑定用于拒绝跨作用域与跨站的密文重放。
 */
func EnvFingerprintAAD(scope, sessionID string, binding ChallengeSessionBinding) string {
	binding = binding.normalized()
	// 统一拼接模型：label(env, v2) | scope | siteID | host | bind | sessionID。
	label := gm.EnvelopeLabel("env", gm.GMEnvelopeVersion)
	return gm.EnvelopeAAD(label, scope) + fmt.Sprintf("|%d|%s|%s", binding.SiteID, binding.Host, binding.Bind) + "|" + sessionID
}

/**
 * EnvCheckJSEncrypted 返回一个只初始化 WASM 并携带其不透明加密结果的加载器。
 * 指纹采集、规范化 JSON 编码、哈希与 SM4-GCM/SM2 信封封装均在 Rust WASM 中执行。
 */
func EnvCheckJSEncrypted(keyHex, aad string) string {
	return envCheckJSEncryptedWithBehavior(keyHex, aad, false)
}

func EnvCheckJSEncryptedWithBehavior(keyHex, aad string) string {
	return envCheckJSEncryptedWithBehavior(keyHex, aad, true)
}

func envCheckJSEncryptedWithBehavior(keyHex, aad string, withBehavior bool) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize || aad == "" {
		return ""
	}
	template := envCheckJSTemplate
	if withBehavior {
		template = envCheckJSWithBehaviorTemplate
	}
	return fmt.Sprintf(template, strconv.Quote(keyHex), strconv.Quote(aad),
		// 资产 URL 用内容派生版本串（顺序必须与模板一致：先 wasm、后 glue）。
		PowWasmURL(), PowGlueURL())
}

const envCheckJSTemplate = `(function(){
var keyHex=%s,aad=%s,cspNonce=(document.currentScript&&document.currentScript.nonce)||"";
function reportEnvError(err){
  var msg=(err&&err.message)||String(err||"environment WASM initialization failed");
  window.__owaf_env_encrypted="";
  window.__owaf_env_error=msg;
  if(typeof window.__owaf_env_error_callback==="function"){window.__owaf_env_error_callback(msg)}
}
function loadWasm(){
  if(window.__owaf_wasm_ready)return window.__owaf_wasm_ready;
  window.__owaf_wasm_ready=new Promise(function(resolve,reject){
    if(typeof WebAssembly==="undefined"){reject(new Error("WebAssembly is unavailable"));return}
    function initialize(){
      wasm_bindgen({module_or_path:"%s"}).then(resolve).catch(reject)
    }
    if(typeof wasm_bindgen!=="undefined"){initialize();return}
    var script=document.createElement("script");
    script.src="%s";
    if(cspNonce)script.nonce=cspNonce;
    script.async=true;
    script.onload=initialize;
    script.onerror=function(){reject(new Error("WASM glue load failed"))};
    (document.head||document.documentElement).appendChild(script);
  });
  return window.__owaf_wasm_ready;
}
window.__owaf_env_required=true;
window.__owaf_env_ready=loadWasm().then(function(){
  var encrypted=wasm_bindgen.gm_encrypt_fingerprint(keyHex,aad);
  if(!encrypted)throw new Error("WASM fingerprint envelope failed");
  window.__owaf_env_encrypted=encrypted;
  return encrypted;
}).catch(function(err){reportEnvError(err);return ""});
})();`

/**
 * envCheckJSWithBehaviorTemplate 与 envCheckJSTemplate 相同，但加密前把
 * window.__owaf_behavior_sample() 的统计 JSON 并入同一 GM 信封
 * （Rust 侧 gm_encrypt_fingerprint_with_behavior 负责合并与加密）。
 * 强制化语义：采样缺失或返回空直接置错误（fail-closed），不产无行为信封。
 */
const envCheckJSWithBehaviorTemplate = `(function(){
var keyHex=%s,aad=%s,cspNonce=(document.currentScript&&document.currentScript.nonce)||"";
function reportEnvError(err){
  var msg=(err&&err.message)||String(err||"environment WASM initialization failed");
  window.__owaf_env_encrypted="";
  window.__owaf_env_error=msg;
  if(typeof window.__owaf_env_error_callback==="function"){window.__owaf_env_error_callback(msg)}
}
function loadWasm(){
  if(window.__owaf_wasm_ready)return window.__owaf_wasm_ready;
  window.__owaf_wasm_ready=new Promise(function(resolve,reject){
    if(typeof WebAssembly==="undefined"){reject(new Error("WebAssembly is unavailable"));return}
    function initialize(){
      wasm_bindgen({module_or_path:"%s"}).then(resolve).catch(reject)
    }
    if(typeof wasm_bindgen!=="undefined"){initialize();return}
    var script=document.createElement("script");
    script.src="%s";
    if(cspNonce)script.nonce=cspNonce;
    script.async=true;
    script.onload=initialize;
    script.onerror=function(){reject(new Error("WASM glue load failed"))};
    (document.head||document.documentElement).appendChild(script);
  });
  return window.__owaf_wasm_ready;
}
window.__owaf_env_required=true;
window.__owaf_env_ready=loadWasm().then(function(){
  var behavior=null;
  try{
    if(typeof window.__owaf_behavior_sample==="function"){
      var s=window.__owaf_behavior_sample();
      if(s&&typeof s==="object"){behavior=JSON.stringify(s)}
    }
  }catch(e){behavior=null}
  // b0 强制化（B6）：行为采样缺失/异常直接失败，与后端 fail-closed 对齐，
  // 不再产出无行为信封。
  if(!behavior)throw new Error("behavior sample unavailable");
  var encrypted=wasm_bindgen.gm_encrypt_fingerprint_with_behavior(keyHex,aad,behavior);
  if(!encrypted)throw new Error("WASM fingerprint envelope failed");
  window.__owaf_env_encrypted=encrypted;
  return encrypted;
}).catch(function(err){reportEnvError(err);return ""});
})();`
