package rules

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/iprep"
)

// bsaFakeLimiter 是内联的 RateLimiterBackend 替身：按 key 计数，可预置计数。
type bsaFakeLimiter struct {
	enabled bool
	counts  map[string]int64
}

func bsaNewLimiter() *bsaFakeLimiter {
	return &bsaFakeLimiter{enabled: true, counts: map[string]int64{}}
}

func (l *bsaFakeLimiter) Enabled() bool { return l.enabled }
func (l *bsaFakeLimiter) Reconfigure(_, _ int, enabled bool) {
	l.enabled = enabled
}
func (l *bsaFakeLimiter) Allow(key string) bool {
	l.counts[key]++
	return true
}
func (l *bsaFakeLimiter) Increment(key string) int64 {
	l.counts[key]++
	return l.counts[key]
}
func (l *bsaFakeLimiter) IsOverLimit(string) bool { return false }
func (l *bsaFakeLimiter) Close()                  {}

// bsaBrowserHeaders 返回一套完整浏览器头（含 Cookie），把指纹模块压到 0 分。
func bsaBrowserHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Referer":         "https://example.com/",
		"Connection":      "keep-alive",
		"Cookie":          "sid=abc",
	}
}

// bsaHeadersWithUA 全套浏览器头 + 指定 UA。
func bsaHeadersWithUA(ua string) map[string]string {
	h := bsaBrowserHeaders()
	h["User-Agent"] = ua
	return h
}

// bsaHonestHeaders 诚实的最小头集（不伪装浏览器）：真实自动化工具的实际形态。
func bsaHonestHeaders(ua string) map[string]string {
	return map[string]string{
		"User-Agent":      ua,
		"Accept":          "*/*",
		"Accept-Language": "en-US",
		"Accept-Encoding": "gzip",
	}
}

// bsaOnlyUA 只带 UA、其余头全缺——把指纹模块抬到 60 分档的构造手法。
func bsaOnlyUA(ua string) map[string]string {
	return map[string]string{"User-Agent": ua}
}

// bsaHighScoreRequest 返回当前实现下可获得最高加权总分的请求形态（实测 89）：
// 空 UA（UA 模块 100）+ 头全缺（指纹模块 100）+ POST /(scanner path)
// + Connection: close + TLS10 + 已确认黑名单 IP（IP 声誉 60）
// + 行为窗口 3 倍阈值（行为模块 100）。
//
// 注意：该形态**必须**带 IP 声誉命中，否则 PreScreen 不命中、评分链路根本
// 不会执行（空 UA 与缺头本身都不触发预筛）。这是本次实现的一条硬约束，
// 直接决定了「纯靠 UA+指纹 能到多高」的上限。
func bsaHighScoreRequest() (map[string]string, string, string, bool) {
	return map[string]string{"Connection": "close"},
		"POST", "/.env", true
}

const bsaGeoIPFixtureB64 = "" +
	"AAABAAFvAAACAAF4AAADAAFGAAAEAAF4AAAFAAF4AAAGAAF4AAAHAAF4AAAIAAEOAAAJAAF4AAAKAAF4AAALAAF4AAAMAAF4" +
	"AAANAAF4AAAOAAF4AAAPAAF4AAAQAAF4AAARAAF4AAASAAF4AAATAAF4AAAUAAF4AAAVAAF4AAAWAAF4AAAXAAF4AAAYAAF4" +
	"AAAZAAF4AAAaAAF4AAAbAAF4AAAcAAF4AAAdAAF4AAAeAAF4AAAfAAF4AAAgAAF4AAAhAAF4AAAiAAF4AAAjAAF4AAAkAAF4" +
	"AAAlAAF4AAAmAAF4AAAnAAF4AAAoAAF4AAApAAF4AAAqAAF4AAArAAF4AAAsAAF4AAAtAAF4AAAuAAF4AAAvAAF4AAAwAAF4" +
	"AAAxAAF4AAAyAAF4AAAzAAF4AAA0AAF4AAA1AAF4AAA2AAF4AAA3AAF4AAA4AAF4AAA5AAF4AAA6AAF4AAA7AAF4AAA8AAF4" +
	"AAA9AAF4AAA+AAF4AAA/AAF4AABAAAF4AABBAAF4AABCAAF4AABDAAF4AABEAAF4AABFAAF4AABGAAF4AABHAAF4AABIAAF4" +
	"AABJAAF4AABKAAF4AABLAAF4AABMAAF4AABNAAF4AABOAAF4AABPAAF4AABQAAF4AABRAAD/AABSAAF4AABTAAF4AABUAAF4" +
	"AABVAAF4AABWAAF4AABXAAF4AABYAAF4AABZAAF4AABaAAF4AABbAAF4AABcAAF4AABdAAF4AABeAAF4AABfAAF4AABgAAF4" +
	"AABhAACQAABiAACEAABjAAF4AABkAAF4AABlAABoAABmAAF4AABnAAF4AAF4AAF4AABpAAF4AABqAACDAABrAAF4AABsAAF4" +
	"AABtAAF4AABuAAF4AABvAAF4AAF4AABwAABxAAF4AAByAAF4AABzAAF4AAB0AAF4AAB1AAF4AAB2AAF4AAB3AAF4AAF4AAB4" +
	"AAB5AAF4AAB6AAF4AAB7AAF4AAB8AAF4AAB9AAF4AAB+AAF4AAB/AAF4AAF4AACAAACBAAF4AACCAAF4AAGIAAF4AAF4AAF4" +
	"AAF4AACFAACGAACMAACHAAF4AAF4AACIAACJAAF4AACKAAF4AACLAAF4AAF4AAF4AAF4AACNAAF4AACOAAF4AACPAAF4AAF4" +
	"AACRAAClAAF4AACSAACTAAF4AAF4AACUAACVAACfAACWAAF4AAF4AACXAAF4AACYAAF4AACZAAF4AACaAAF4AACbAAF4AACc" +
	"AAF4AACdAAF4AACeAAF4AAF4AACgAAF4AAChAAF4AACiAAF4AACjAAF4AACkAAF4AAF4AAF4AACmAAF4AACnAAF4AACoAADs" +
	"AACpAADWAACqAAF4AACrAAF4AACsAADPAACtAADBAACuAAF4AACvAAF4AACwAAF4AACxAAF4AACyAAF4AACzAAF4AAC0AAF4" +
	"AAC1AAF4AAC2AAF4AAC3AAF4AAC4AAF4AAC5AAF4AAC6AADAAAC7AAF4AAC8AAF4AAC9AAF4AAC+AAF4AAC/AAF4AAF4AAF4" +
	"AAF4AAF4AADCAAF4AAF4AADDAAF4AADEAADFAAF4AADGAAF4AADHAAF4AADIAAF4AAF4AADJAAF4AADKAADLAAF4AADMAAF4" +
	"AADNAAF4AAF4AADOAAF4AAF4AADQAAF4AAF4AADRAADSAAF4AAF4AADTAADUAAF4AADVAAF4AAF4AAF4AAF4AADXAADYAAF4" +
	"AADZAAF4AADaAAF4AADbAADfAAF4AADcAADdAAF4AADeAAF4AAF4AAF4AAF4AADgAADhAAF4AADiAAF4AAF4AADjAAF4AADk" +
	"AADlAAF4AAF4AADmAAF4AADnAADoAAF4AADpAAF4AAF4AADqAADrAAF4AAF4AAF4AADtAAF4AAF4AADuAAF4AADvAADwAAF4" +
	"AADxAAF4AADyAAF4AADzAAF4AAD0AAF4AAD1AAF4AAD2AAF4AAD3AAF4AAD4AAF4AAF4AAD5AAF4AAD6AAF4AAD7AAD8AAF4" +
	"AAD9AAF4AAD+AAF4AAF4AAF4AAF4AAEAAAF4AAEBAAF4AAECAAF4AAEDAAF4AAEEAAF4AAEFAAF4AAEGAAF4AAEHAAF4AAEI" +
	"AAF4AAEJAAF4AAEKAAF4AAELAAF4AAEMAAF4AAENAAF4AABgAAEPAAF4AAEQAAF4AAERAAF4AAESAAF4AAETAAF4AAEUAAF4" +
	"AAEVAAF4AAEWAAF4AAEXAAF4AAEYAAF4AAEZAAF4AAEaAAF4AAEbAAF4AAEcAAF4AAEdAAF4AAEeAAF4AAEfAAF4AAEgAAF4" +
	"AAEhAAF4AAEiAAF4AAEjAAF4AAEkAAF4AAElAAF4AAEmAAF4AAEnAAF4AAEoAAF4AAEpAAF4AAEqAAF4AAErAAF4AAEsAAF4" +
	"AAEtAAF4AAEuAAF4AAEvAAF4AAEwAAF4AAExAAF4AAEyAAF4AAEzAAF4AAE0AAF4AAE1AAF4AAE2AAF4AAE3AAF4AAE4AAF4" +
	"AAE5AAF4AAE6AAF4AAE7AAF4AAE8AAF4AAE9AAF4AAE+AAF4AAE/AAF4AAFAAAF4AAFBAAF4AAFCAAF4AAFDAAF4AAFEAAF4" +
	"AAFFAAF4AAF4AAF4AAFHAAF4AAFIAAF4AAFJAAF4AAFKAAF4AAFLAAF4AAFMAAF4AAFNAAF4AAFOAAF4AAFPAAF4AAFQAAF4" +
	"AAFRAAF4AAFSAAFuAAF4AAFTAAFUAAF4AAFVAAF4AAFWAAF4AAFXAAF4AAFYAAFjAAFZAAF4AAFaAAF4AAFbAAF4AAFcAAF4" +
	"AAFdAAF4AAFeAAF4AAFfAAF4AAFgAAF4AAFhAAF4AAFiAAF4AABgAAF4AAF4AAFkAAFlAAF4AAF4AAFmAAF4AAFnAAFoAAF4" +
	"AAF4AAFpAAF4AAFqAAF4AAFrAAFsAAF4AAFtAAF4AAF4AAF4AABgAAF4AAF4AAFwAAF4AAFxAAF4AAFyAAF4AAFzAAF4AAF0" +
	"AAF4AAF1AAF2AAF4AAF4AAF3AAF4AAF4AAAAAAAAAAAAAAAAAAAAAONYYXV0b25vbW91c19zeXN0ZW1fbnVtYmVywvv0XQFh" +
	"dXRvbm9tb3VzX3N5c3RlbV9vcmdhbml6YXRpb25dAlRlc3QgRGF0YWNlbnRlciBWUE4gSG9zdGluZyBMdGRHY291bnRyeeFI" +
	"aXNvX2NvZGVCQ06rze9NYXhNaW5kLmNvbelbYmluYXJ5X2Zvcm1hdF9tYWpvcl92ZXJzaW9uoQJbYmluYXJ5X2Zvcm1hdF9t" +
	"aW5vcl92ZXJzaW9uoEtidWlsZF9lcG9jaAQCar4TB01kYXRhYmFzZV90eXBlT015LU9wZW5XYWYtVGVzdEtkZXNjcmlwdGlv" +
	"buBKaXBfdmVyc2lvbqEGSWxhbmd1YWdlcwAESm5vZGVfY291bnTCAXhLcmVjb3JkX3NpemWhGA=="

// bsaGeoResolver 从内嵌夹具构造一个 MaxMind 解析器，命中
// 数据中心 ASN + VPN ASN + 高风险国家（ScoreIP 上限 60）。
func bsaGeoResolver(t *testing.T) *bot.MaxMindResolver {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(bsaGeoIPFixtureB64)
	if err != nil {
		t.Fatalf("内嵌 GeoIP 夹具解码失败（base64）: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bsa-fixture.mmdb")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("写入 GeoIP 夹具失败: %v", err)
	}
	geo := bot.NewMaxMindResolver(path, path, core.BotConfig{
		DataCenterASNs:    []uint{64500},
		VPNProxyASNs:      []uint{64500},
		HighRiskCountries: []string{"CN"},
	})
	t.Cleanup(geo.Close)
	if got := geo.ScoreIP(bsaGeoIP); got == 0 {
		t.Fatalf("GeoIP 夹具未生效：ScoreIP(%v) = 0，夹具或解析器配置有误", bsaGeoIP)
	}
	return geo
}

// bsaGeoIP 是夹具命中的地址（唯一被写入数据库的记录）。
var bsaGeoIP = net.ParseIP("8.8.8.8")

// bsaBlacklistIPRep 构造「已确认黑名单 IP」的 IP 声誉实例。
func bsaBlacklistIPRep(t *testing.T, ip string) *iprep.IPReputation {
	t.Helper()
	rep := iprep.NewIPReputation()
	t.Cleanup(rep.Close)
	entry, ok := iprep.ParseIPListEntry(ip, "bsa verify blacklist", "intercept")
	if !ok {
		t.Fatalf("failed to parse blacklist entry for %s", ip)
	}
	rep.SetLists([]iprep.IPListEntry{entry}, nil)
	if dec := rep.Check(net.ParseIP(ip)); !dec.Matched || dec.Allowed {
		t.Fatalf("blacklist entry not effective: %+v", dec)
	}
	return rep
}

// bsaAutoBanIPRep 构造「已自动封禁 IP」的 IP 声誉实例。
func bsaAutoBanIPRep(t *testing.T, ip string) *iprep.IPReputation {
	t.Helper()
	rep := iprep.NewIPReputation()
	t.Cleanup(rep.Close)
	rep.ConfigureAutoBan(true, 1, 60, 3600)
	if !rep.RecordViolation(net.ParseIP(ip)) {
		t.Fatal("failed to arm auto-ban")
	}
	if dec := rep.Check(net.ParseIP(ip)); dec.Category != "auto_ban" {
		t.Fatalf("auto-ban not effective: %+v", dec)
	}
	return rep
}

// bsaCtx 构造一个请求上下文。
func bsaCtx(headers map[string]string) *pipeline.RequestCtx {
	ctx := &pipeline.RequestCtx{
		Method:  "GET",
		Path:    "/",
		Host:    "example.com",
		Bind:    ":443",
		SiteID:  7,
		Headers: headers,
	}
	if ua, ok := headers["User-Agent"]; ok {
		ctx.UserAgent = ua
	}
	return ctx
}

// bsaRun 用公开构造函数装配阶段并执行一次请求。
// threshold 直接传给构造函数（<=0 时实现会回落到默认值）。
func bsaRun(t *testing.T, ctx *pipeline.RequestCtx, rep *iprep.IPReputation, limiter *bsaFakeLimiter, rateMax, threshold int) (action.Result, bool) {
	t.Helper()
	var phase pipeline.Phase
	if limiter == nil || rateMax <= 0 {
		phase = NewBotPhaseWithGeo(rep, nil, threshold)
	} else {
		phase = NewBotPhaseWithGeoAndLimiter(rep, nil, threshold, limiter, rateMax)
	}
	return phase.Execute(ctx)
}

// bsaBehaviorKey 复刻 botPhase 的行为窗口 key（clientIP|host|bot）。
// 这是**接口契约**（跨阶段共享同一份频率数据、且不与限流计数叠加），
// 决定了本文件能否预置计数来构造指定档位。
func bsaBehaviorKey(ctx *pipeline.RequestCtx) string {
	key := ""
	if ctx.ClientIP != nil {
		key = ctx.ClientIP.String()
	}
	return key + "|" + ctx.Host + "|bot"
}

// bsaPrimeBehavior 预置行为窗口计数，使 Execute 内的 +1 之后恰好等于 want。
func bsaPrimeBehavior(limiter *bsaFakeLimiter, ctx *pipeline.RequestCtx, want int64) {
	if want <= 0 {
		return
	}
	limiter.counts[bsaBehaviorKey(ctx)] = want - 1
}

// ─────────────── 期望值推导：独立复算契约，不复制魔数 ───────────────

// bsaExpectedAction 由「加权总分 + 危险标记 + 阈值」独立推导期望 action。
//
// 这是对实现契约的**独立复算**（不是重演实现代码）：
//  1. 档位 = ClassifyScore(总分, 阈值)——档位边界的唯一权威；
//  2. 危险下界：dangerous 且档位低于挑战 → 抬到挑战；
//  3. 档位 → action 的五档映射。
func bsaExpectedAction(total int, dangerous bool, threshold int) (action.Type, bool) {
	tier := bot.ClassifyScore(total, threshold)
	if dangerous && tier < bot.TierChallenge {
		tier = bot.TierChallenge
	}
	switch tier {
	case bot.TierObserve:
		return action.Observe, false
	case bot.TierChallenge:
		return action.Challenge, true
	case bot.TierIntercept:
		return action.Intercept, true
	case bot.TierDrop:
		return action.Drop, true
	default:
		return action.Allow, false
	}
}

func bsaTotalOf(ctx *pipeline.RequestCtx) string {
	if ctx.BotScoreResult == nil {
		return "未写日志"
	}
	return strconv.Itoa(ctx.BotScoreResult.TotalScore)
}

// ══════════════════════════════════════════════════════════════════════════
// 一、裁决第 4 条：五档 → action 的端到端映射
// ══════════════════════════════════════════════════════════════════════════

// TestBSAFiveTierDispositionsReachExpectedActions 用真实 Execute 走完五档。
//
// 样本（数值为实测）与阈值：
//   - pass      : 干净浏览器，总分 0，T=80
//   - observe   : zgrab 工具 UA + 只带 UA 的头集，总分 41，T=80
//   - challenge : 空头集 + 已确认黑名单 IP，总分 64，T=80
//   - intercept : 四模块满分样本（无 GeoIP 命中），总分 89，T=80
//   - drop      : 同一请求改 T=75（75×9/8 = 84 ≤ 89）
//
// 【更正】本节此前断言「默认阈值 80 下 drop 不可达」，该结论有误——漏算了
// GeoIP 模块。ScoreIP 在同一 ASN 同时命中机房与 VPN 时可达 40，再叠加高风险
// 国家 20，上限 60；60×5% = 3 分。因此五模块满分形态为
// 40 + 25 + 15 + 3 + 9 = 92 ≥ 90 → 默认阈值下即落 TierDrop。
// 该形态已由 TestBSADropReachableAtDefaultThreshold 单独覆盖（用内嵌 GeoIP 夹具）。
func TestBSAFiveTierDispositionsReachExpectedActions(t *testing.T) {
	highHeaders, highMethod, highPath, highTLS10 := bsaHighScoreRequest()

	cases := []struct {
		name       string
		headers    map[string]string
		method     string
		path       string
		tls10      bool
		ip         string
		repKind    string // "", "blacklist"
		rateMax    int
		primeTo    int64
		threshold  int
		wantAction action.Type
		wantStop   bool
	}{
		{
			name: "pass/干净浏览器", headers: bsaBrowserHeaders(), method: "GET", path: "/",
			threshold: 80, wantAction: action.Allow, wantStop: false,
		},
		{
			name: "observe/工具UA+只带UA的头集", headers: bsaOnlyUA("zgrab/0.x"), method: "GET", path: "/",
			threshold: 80, wantAction: action.Observe, wantStop: false,
		},
		{
			name: "challenge/空头集+黑名单IP", headers: map[string]string{}, method: "GET", path: "/",
			ip: "203.0.113.30", repKind: "blacklist",
			threshold: 80, wantAction: action.Challenge, wantStop: true,
		},
		{
			name: "intercept/最高分样本", headers: highHeaders, method: highMethod, path: highPath, tls10: highTLS10,
			ip: "203.0.113.31", repKind: "blacklist", rateMax: 10, primeTo: 30,
			threshold: 80, wantAction: action.Intercept, wantStop: true,
		},
		{
			name: "drop/最高分样本+低阈值", headers: highHeaders, method: highMethod, path: highPath, tls10: highTLS10,
			ip: "203.0.113.32", repKind: "blacklist", rateMax: 10, primeTo: 30,
			threshold: 75, wantAction: action.Drop, wantStop: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := bsaCtx(tc.headers)
			ctx.Method, ctx.Path = tc.method, tc.path
			if tc.tls10 {
				ctx.TLS = bot.TLSClientFingerprint{TLSVersion: "TLS10"}
			}
			var rep *iprep.IPReputation
			switch tc.repKind {
			case "blacklist":
				rep = bsaBlacklistIPRep(t, tc.ip)
				ctx.ClientIP = net.ParseIP(tc.ip)
			}
			var limiter *bsaFakeLimiter
			if tc.rateMax > 0 {
				limiter = bsaNewLimiter()
				bsaPrimeBehavior(limiter, ctx, tc.primeTo)
			}

			result, stop := bsaRun(t, ctx, rep, limiter, tc.rateMax, tc.threshold)

			if result.Type != tc.wantAction {
				t.Fatalf("action = %q, want %q（总分=%s）", result.Type, tc.wantAction, bsaTotalOf(ctx))
			}
			if stop != tc.wantStop {
				t.Fatalf("stop = %v, want %v（action=%q 总分=%s）", stop, tc.wantStop, result.Type, bsaTotalOf(ctx))
			}

			if tc.wantAction == action.Allow {
				if result.Matched {
					t.Fatalf("放行档不应带 Matched：%+v", result)
				}
				if ctx.BotScoreResult != nil {
					t.Fatalf("放行档不应写评分日志，实际 %+v", ctx.BotScoreResult)
				}
				return
			}

			if !result.Matched {
				t.Fatalf("处置档必须带 Matched：%+v", result)
			}
			if ctx.BotScoreResult == nil {
				t.Fatalf("非放行档应写入 BotScoreResult，实际为 nil（action=%q）", result.Type)
			}

			// 独立复算：由总分 + 危险标记 + 阈值推导出的 action 必须一致。
			wantAction, wantStop := bsaExpectedAction(ctx.BotScoreResult.TotalScore, ctx.BotScoreResult.Dangerous, tc.threshold)
			if result.Type != wantAction || stop != wantStop {
				t.Fatalf("独立复算不一致：实测 action=%q stop=%v；由 Total=%d dangerous=%v threshold=%d 推导应为 action=%q stop=%v",
					result.Type, stop, ctx.BotScoreResult.TotalScore, ctx.BotScoreResult.Dangerous, tc.threshold, wantAction, wantStop)
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════
// 二、硬指令：只要判断危险就不能放过去
// ══════════════════════════════════════════════════════════════════════════

// TestBSADangerousRequestMustNotPassThrough 危险来源覆盖：
//   - 明确攻击工具 UA（uaToolSeverity ≥ dangerToolSeverityThreshold）
//   - IP 名单命中（黑名单 / 自动封禁）
//
// 断言：必须终止（stop=true），action 至少为 challenge；低分危险请求
// 不应被「一次打死」到 drop。
func TestBSADangerousRequestMustNotPassThrough(t *testing.T) {
	// severity 95 档：注入 / 爆破 / 利用框架 / 主动扫描器。
	toolUAs := []string{
		"sqlmap/1.7", "metasploit/6.4", "THC-Hydra", "commix",
		"nuclei/v3", "nikto/2.5", "masscan/1.3", "ffuf/2.1.0",
		"Nessus Agent", "Burp Suite Professional", "wpscan", "skipfish",
		"Havij",
	}
	for _, ua := range toolUAs {
		t.Run("tool_ua/"+ua, func(t *testing.T) {
			// 诚实头集：加权总分低（38 左右），处置只能来自危险标记。
			ctx := bsaCtx(bsaHonestHeaders(ua))
			result, stop := bsaRun(t, ctx, nil, nil, 0, 80)

			if ctx.BotScoreResult == nil {
				t.Fatal("应写入 BotScoreResult")
			}
			if !ctx.BotScoreResult.Dangerous {
				t.Fatalf("明确攻击工具 UA %q 未被标记为危险（reasons=%v，总分=%d）",
					ua, ctx.BotScoreResult.DangerReasons, ctx.BotScoreResult.TotalScore)
			}
			if !stop {
				t.Fatalf("危险请求必须终止，实际 action=%q stop=false", result.Type)
			}
			if bsaLowerThanChallenge(result.Type) {
				t.Fatalf("危险请求的 action %q 低于 challenge（总分=%d）",
					result.Type, ctx.BotScoreResult.TotalScore)
			}
			if result.Type == action.Drop {
				t.Fatalf("低分危险请求不应直接 drop（总分=%d）", ctx.BotScoreResult.TotalScore)
			}
		})
	}

	t.Run("iprep/blacklist", func(t *testing.T) {
		ctx := bsaCtx(bsaBrowserHeaders())
		ctx.ClientIP = net.ParseIP("203.0.113.50")
		rep := bsaBlacklistIPRep(t, "203.0.113.50")
		result, stop := bsaRun(t, ctx, rep, nil, 0, 80)

		if !ctx.BotScoreResult.Dangerous {
			t.Fatalf("已确认黑名单 IP 未被标记为危险（reasons=%v）", ctx.BotScoreResult.DangerReasons)
		}
		if !stop {
			t.Fatalf("黑名单 IP 必须终止，实际 action=%q stop=false（总分=%d）",
				result.Type, ctx.BotScoreResult.TotalScore)
		}
		if result.Type != action.Challenge {
			t.Fatalf("黑名单 IP + 干净 UA（总分 9）应为危险下界的 challenge，实际 %q", result.Type)
		}
	})

	t.Run("iprep/auto_ban", func(t *testing.T) {
		ctx := bsaCtx(bsaBrowserHeaders())
		ctx.ClientIP = net.ParseIP("203.0.113.51")
		rep := bsaAutoBanIPRep(t, "203.0.113.51")
		result, stop := bsaRun(t, ctx, rep, nil, 0, 80)

		if !ctx.BotScoreResult.Dangerous {
			t.Fatalf("自动封禁 IP 未被标记为危险（reasons=%v）", ctx.BotScoreResult.DangerReasons)
		}
		if !stop || bsaLowerThanChallenge(result.Type) {
			t.Fatalf("自动封禁 IP 必须终止于 challenge 及以上，实际 action=%q stop=%v", result.Type, stop)
		}
	})
}

// TestBSANonDangerousSignalsStayNonDangerous 防过度拦截：只有确定性证据
// （明确攻击工具 UA、IP 名单命中）才置危险标记；采集类工具与所有弱信号
// 一律不置危险。
//
// 采集/侦察/爬虫框架（severity 65：zgrab / crawler4j / Shodan / scrapy 等）
// **不在**危险名单内——这是设计选择，本测试把它固化为回归护栏，防止后续
// 误调 dangerToolSeverityThreshold 把采集类工具一并升级为危险。
func TestBSANonDangerousSignalsStayNonDangerous(t *testing.T) {
	t.Run("采集类工具不置危险", func(t *testing.T) {
		for _, ua := range []string{"zgrab/0.x", "crawler4j", "Shodan", "python selenium"} {
			t.Run(ua, func(t *testing.T) {
				ctx := bsaCtx(bsaHonestHeaders(ua))
				result, stop := bsaRun(t, ctx, nil, nil, 0, 80)
				if ctx.BotScoreResult != nil && ctx.BotScoreResult.Dangerous {
					t.Fatalf("采集类工具 %q 不应置危险：%v", ua, ctx.BotScoreResult.DangerReasons)
				}
				if result.Type == action.Drop || result.Type == action.Intercept {
					t.Fatalf("采集类工具 %q 不应被判死：action=%q", ua, result.Type)
				}
				if stop && result.Type == action.Challenge {
					t.Logf("采集类工具 %q 落 challenge（来自加权总分而非危险标记），符合设计", ua)
				}
			})
		}
	})

	t.Run("弱信号不置危险", func(t *testing.T) {
		samples := []struct {
			name string
			h    map[string]string
		}{
			{"空 UA + 头全缺", map[string]string{}},
			{"短 UA", bsaOnlyUA("shortua")},
			{"伪造 Mozilla", bsaOnlyUA("Mozilla/5.0 NoParentheses")},
			{"curl 全套浏览器头", bsaHeadersWithUA("curl/8.0")},
			{"python-requests 诚实头集", bsaHonestHeaders("python-requests/2.31")},
			{"Postman", bsaHonestHeaders("PostmanRuntime/7.39")},
		}
		for _, s := range samples {
			t.Run(s.name, func(t *testing.T) {
				ctx := bsaCtx(s.h)
				_, _ = bsaRun(t, ctx, nil, nil, 0, 80)
				if ctx.BotScoreResult != nil && ctx.BotScoreResult.Dangerous {
					t.Fatalf("弱信号 %q 被置危险（过度拦截）：%v 总分=%d",
						s.name, ctx.BotScoreResult.DangerReasons, ctx.BotScoreResult.TotalScore)
				}
			})
		}
	})
}

// bsaLowerThanChallenge 判断 action 是否弱于 challenge（放行/记录/仅日志）。
func bsaLowerThanChallenge(a action.Type) bool {
	switch a {
	case action.Drop, action.Intercept, action.Challenge:
		return false
	default:
		return true
	}
}

// ══════════════════════════════════════════════════════════════════════════
// 三、裁决第 3 条：常规自动化工具不得单独判死
// ══════════════════════════════════════════════════════════════════════════

// TestBSAAutomationToolsNeverFatal 双口径覆盖：
//
//	a) 诚实的最小头集（工具的真实形态）
//	b) 全套浏览器头（伪装成浏览器）
//
// 两种形态下都不得落 drop/intercept。(b) 会被判为「伪装」而进入更高档位，
// 这是设计意图（伪装本身是可疑信号），但仍不判死、且不得置危险。
func TestBSAAutomationToolsNeverFatal(t *testing.T) {
	tools := []string{
		"curl/8.0", "curl/8.7.1", "wget/1.21",
		"Go-http-client/1.1", "python-requests/2.31", "python-urllib/3.11",
		"PostmanRuntime/7.39", "okhttp/4.9", "node-fetch/2.6",
	}
	for _, ua := range tools {
		t.Run("honest/"+ua, func(t *testing.T) {
			ctx := bsaCtx(bsaHonestHeaders(ua))
			result, _ := bsaRun(t, ctx, nil, nil, 0, 80)
			if result.Type == action.Drop || result.Type == action.Intercept {
				t.Fatalf("常规自动化工具 %q（诚实头集）被判死：action=%q 总分=%s",
					ua, result.Type, bsaTotalOf(ctx))
			}
		})
		t.Run("browser_headers/"+ua, func(t *testing.T) {
			ctx := bsaCtx(bsaHeadersWithUA(ua))
			result, _ := bsaRun(t, ctx, nil, nil, 0, 80)
			if result.Type == action.Drop || result.Type == action.Intercept {
				t.Fatalf("常规自动化工具 %q（全套浏览器头）被判死：action=%q 总分=%s",
					ua, result.Type, bsaTotalOf(ctx))
			}
			if ctx.BotScoreResult != nil && ctx.BotScoreResult.Dangerous {
				t.Fatalf("常规自动化工具 %q 不应被标记危险：%v", ua, ctx.BotScoreResult.DangerReasons)
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════
// 四、双写分叉风险点：BotScoreInfo.Action 与 action.Result.Type 必须一致
// ══════════════════════════════════════════════════════════════════════════

// TestBSALoggedActionMatchesDisposition 覆盖五档全部边界：
// 同一情形下 storeBotScore 写入日志的 Action 串与 verdictToResult 返回的
// action.Result.Type 在 action.Normalize 归一化后必须相等。
//
// 这是主会话点名的「双写分叉风险点」：两处若各自维护映射表就会漂移。
func TestBSALoggedActionMatchesDisposition(t *testing.T) {
	highHeaders, highMethod, highPath, highTLS10 := bsaHighScoreRequest()

	type sample struct {
		name      string
		headers   map[string]string
		method    string
		path      string
		tls10     bool
		ip        string
		rateMax   int
		primeTo   int64
		threshold int
	}
	samples := []sample{
		{name: "pass", headers: bsaBrowserHeaders(), method: "GET", path: "/", threshold: 80},
		{name: "observe", headers: bsaOnlyUA("zgrab/0.x"), method: "GET", path: "/", threshold: 80},
		{name: "challenge", headers: bsaHonestHeaders("sqlmap/1.7"), method: "GET", path: "/", threshold: 80},
		{name: "intercept", headers: highHeaders, method: highMethod, path: highPath, tls10: highTLS10,
			ip: "203.0.113.60", rateMax: 10, primeTo: 30, threshold: 80},
		{name: "drop", headers: highHeaders, method: highMethod, path: highPath, tls10: highTLS10,
			ip: "203.0.113.61", rateMax: 10, primeTo: 30, threshold: 75},
	}

	seenActions := map[action.Type]bool{}
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			ctx := bsaCtx(s.headers)
			ctx.Method, ctx.Path = s.method, s.path
			if s.tls10 {
				ctx.TLS = bot.TLSClientFingerprint{TLSVersion: "TLS10"}
			}
			var rep *iprep.IPReputation
			if s.ip != "" {
				rep = bsaBlacklistIPRep(t, s.ip)
				ctx.ClientIP = net.ParseIP(s.ip)
			}
			var limiter *bsaFakeLimiter
			if s.rateMax > 0 {
				limiter = bsaNewLimiter()
				bsaPrimeBehavior(limiter, ctx, s.primeTo)
			}

			result, _ := bsaRun(t, ctx, rep, limiter, s.rateMax, s.threshold)
			seenActions[result.Type] = true

			if result.Type == action.Allow {
				if ctx.BotScoreResult != nil {
					t.Fatalf("放行档不应写日志，实际写入 %+v", ctx.BotScoreResult)
				}
				return
			}
			if ctx.BotScoreResult == nil {
				t.Fatalf("非放行档必须写日志（action=%q）", result.Type)
			}

			logged := action.Normalize(action.Type(ctx.BotScoreResult.Action))
			actual := action.Normalize(result.Type)
			if logged != actual {
				t.Fatalf("双写分叉：日志 Action=%q（归一后 %q）≠ 实际处置 %q（归一后 %q）",
					ctx.BotScoreResult.Action, logged, result.Type, actual)
			}
		})
	}

	// 覆盖度自检：本测试必须真的触达五档（否则「一致性」可能是空断言）。
	for _, a := range []action.Type{action.Allow, action.Observe, action.Challenge, action.Intercept, action.Drop} {
		if !seenActions[a] {
			t.Fatalf("本测试未触达 action=%q，档位覆盖不完整（已触达 %v）", a, seenActions)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════
// 五、危险标记的传递与归因
// ══════════════════════════════════════════════════════════════════════════

// TestBSADangerFlagPropagatesToLog 断言落库的危险标记与判定一致，
// 且非危险请求不带危险来源串。
func TestBSADangerFlagPropagatesToLog(t *testing.T) {
	t.Run("dangerous", func(t *testing.T) {
		ctx := bsaCtx(bsaHonestHeaders("sqlmap/1.7"))
		_, _ = bsaRun(t, ctx, nil, nil, 0, 80)
		if ctx.BotScoreResult == nil {
			t.Fatal("应写入 BotScoreResult")
		}
		if !ctx.BotScoreResult.Dangerous {
			t.Fatal("工具 UA 应使日志危险标记为真")
		}
		if len(ctx.BotScoreResult.DangerReasons) == 0 {
			t.Fatal("危险请求应带来源串，供归因")
		}
	})

	t.Run("not_dangerous", func(t *testing.T) {
		ctx := bsaCtx(bsaHeadersWithUA("curl/8.0"))
		_, _ = bsaRun(t, ctx, nil, nil, 0, 80)
		if ctx.BotScoreResult == nil {
			t.Skip("curl 被判放行、未写日志——符合预期（裁决第 3 条）")
		}
		if ctx.BotScoreResult.Dangerous {
			t.Fatalf("curl 不应被标记危险：%v", ctx.BotScoreResult.DangerReasons)
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════
// 六、行为模块接入：botPhase 的行为频率链路
// ══════════════════════════════════════════════════════════════════════════

// TestBSABehaviorWindowIsIsolatedFromRateLimiter 行为分使用独立窗口 key，
// 不与限流阶段的计数叠加（否则限流阈值会被隐形减半）。
func TestBSABehaviorWindowIsIsolatedFromRateLimiter(t *testing.T) {
	ctx := bsaCtx(bsaBrowserHeaders())
	ctx.ClientIP = net.ParseIP("198.51.100.70")
	limiter := bsaNewLimiter()

	// 先让限流阶段用掉同一个 (ip|host) key。
	rateKey := ctx.ClientIP.String() + "|" + ctx.Host
	limiter.Allow(rateKey)
	limiter.Allow(rateKey)

	_, _ = bsaRun(t, ctx, nil, limiter, 10, 80)

	if limiter.counts[rateKey] != 2 {
		t.Fatalf("行为模块污染了限流计数：%s = %d, want 2", rateKey, limiter.counts[rateKey])
	}
	if limiter.counts[bsaBehaviorKey(ctx)] < 1 {
		t.Fatalf("行为模块未使用独立窗口 key：%s = %d",
			bsaBehaviorKey(ctx), limiter.counts[bsaBehaviorKey(ctx)])
	}
}

// TestBSABehaviorCountRaisesTotal 行为窗口计数上升必须抬高总分：
// 同一请求在低计数与 3 倍阈值计数下，总分必须严格上升。
// 为保证评分链路真的执行，样本带已确认黑名单 IP（保证 PreScreen 命中）。
func TestBSABehaviorCountRaisesTotal(t *testing.T) {
	ctx := bsaCtx(bsaBrowserHeaders())
	ctx.ClientIP = net.ParseIP("198.51.100.71")
	rep := bsaBlacklistIPRep(t, "198.51.100.71")
	limiter := bsaNewLimiter()

	_, _ = bsaRun(t, ctx, rep, limiter, 10, 80)
	if ctx.BotScoreResult == nil {
		t.Fatal("应写入 BotScoreResult")
	}
	low := ctx.BotScoreResult.TotalScore
	lowBeh := ctx.BotScoreResult.BehaviorScore

	bsaPrimeBehavior(limiter, ctx, 30) // Execute 内 +1 → 30 = 3 × rateMax
	_, _ = bsaRun(t, ctx, rep, limiter, 10, 80)
	high := ctx.BotScoreResult.TotalScore

	if ctx.BotScoreResult.BehaviorScore <= lowBeh {
		t.Fatalf("行为计数达 3 倍阈值后 BehaviorScore 未上升：%d -> %d",
			lowBeh, ctx.BotScoreResult.BehaviorScore)
	}
	if high <= low {
		t.Fatalf("行为计数上升但总分未上升：%d -> %d", low, high)
	}
}

// TestBSABehaviorScoreAbsentWithoutLimiter limiter 缺失或 rateMax 无效时，
// 行为模块恒为 0，且不影响其它模块的判定。
func TestBSABehaviorScoreAbsentWithoutLimiter(t *testing.T) {
	t.Run("nil_limiter", func(t *testing.T) {
		ctx := bsaCtx(bsaOnlyUA("zgrab/0.x"))
		_, _ = bsaRun(t, ctx, nil, nil, 0, 80)
		if ctx.BotScoreResult != nil && ctx.BotScoreResult.BehaviorScore != 0 {
			t.Fatalf("无 limiter 时行为分应为 0，实际 %d", ctx.BotScoreResult.BehaviorScore)
		}
	})
	t.Run("zero_rate_max", func(t *testing.T) {
		ctx := bsaCtx(bsaOnlyUA("zgrab/0.x"))
		limiter := bsaNewLimiter()
		limiter.counts[bsaBehaviorKey(ctx)] = 1000
		_, _ = bsaRun(t, ctx, nil, limiter, 0, 80)
		if ctx.BotScoreResult != nil && ctx.BotScoreResult.BehaviorScore != 0 {
			t.Fatalf("rateMax=0 时行为分应为 0，实际 %d", ctx.BotScoreResult.BehaviorScore)
		}
	})
	t.Run("clean_browser_stays_pass", func(t *testing.T) {
		ctx := bsaCtx(bsaBrowserHeaders())
		limiter := bsaNewLimiter()
		result, stop := bsaRun(t, ctx, nil, limiter, 10, 80)
		if result.Type != action.Allow || stop {
			t.Fatalf("干净浏览器在低计数下应放行，实际 action=%q stop=%v", result.Type, stop)
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════
// 七、回归护栏：危险下界必须由真实链路带出，且不越界
// ══════════════════════════════════════════════════════════════════════════

// TestBSADangerFloorAppliesWithPlainConstructor 危险下界必须由
// Execute → CheckBotTwoPhaseWithBehavior 这条真实链路带出，
// 而不是依赖某个构造参数（geo=nil 时也必须成立）。
func TestBSADangerFloorAppliesWithPlainConstructor(t *testing.T) {
	ctx := bsaCtx(bsaHonestHeaders("sqlmap/1.7"))
	phase := NewBotPhaseWithGeo(nil, nil, 80)

	result, stop := phase.Execute(ctx)
	if result.Type != action.Challenge || !stop {
		t.Fatalf("低阈值构造（geo=nil）下工具 UA 应为 challenge，实际 action=%q stop=%v（总分=%s）",
			result.Type, stop, bsaTotalOf(ctx))
	}
	if ctx.BotScoreResult == nil || !ctx.BotScoreResult.Dangerous {
		t.Fatalf("危险标记应在 Execute 路径中保留：%+v", ctx.BotScoreResult)
	}
	if ctx.BotScoreResult.TotalScore == 0 {
		t.Fatal("非放行档应带出真实总分")
	}
}

// TestBSADangerFloorNeverExceedsChallengeAtLowScore 危险下界只抬到 challenge：
// 低分危险请求不得被抬到 intercept/drop。这条保证「不确定的危险不一次打死」，
// 与用户硬指令「不能放过去」共同构成完整语义。
func TestBSADangerFloorNeverExceedsChallengeAtLowScore(t *testing.T) {
	for _, ua := range []string{"sqlmap/1.7", "metasploit/6.4", "THC-Hydra", "nuclei/v3"} {
		t.Run(ua, func(t *testing.T) {
			ctx := bsaCtx(bsaHonestHeaders(ua))
			result, stop := bsaRun(t, ctx, nil, nil, 0, 80)
			if !stop || result.Type != action.Challenge {
				t.Fatalf("低分危险请求应为 challenge 且终止，实际 action=%q stop=%v（总分=%s）",
					result.Type, stop, bsaTotalOf(ctx))
			}
		})
	}
}

// TestBSAThresholdGovernsDropBoundary 阈值决定 drop 边界：同一请求（89 分，
// 无 GeoIP 命中），阈值 80 落 intercept，阈值 75 落 drop。这固化了
// 「drop 档下界由 threshold 派生（9T/8）」这一契约。
//
// 注意：该样本不含 GeoIP 命中，89 分只是「无 GeoIP」这一子集的上限，
// **不是**全局上限。含 GeoIP 命中的满分形态为 92 分，默认阈值即落 drop，
// 见 TestBSADropReachableAtDefaultThreshold。
func TestBSAThresholdGovernsDropBoundary(t *testing.T) {
	headers, method, path, tls10 := bsaHighScoreRequest()

	run := func(threshold int) (action.Type, int) {
		ctx := bsaCtx(headers)
		ctx.Method, ctx.Path = method, path
		if tls10 {
			ctx.TLS = bot.TLSClientFingerprint{TLSVersion: "TLS10"}
		}
		ctx.ClientIP = net.ParseIP("203.0.113.70")
		rep := bsaBlacklistIPRep(t, "203.0.113.70")
		limiter := bsaNewLimiter()
		bsaPrimeBehavior(limiter, ctx, 30)
		result, _ := bsaRun(t, ctx, rep, limiter, 10, threshold)
		total := 0
		if ctx.BotScoreResult != nil {
			total = ctx.BotScoreResult.TotalScore
		}
		return result.Type, total
	}

	defaultAction, defaultTotal := run(80)
	if defaultAction != action.Intercept {
		t.Fatalf("默认阈值下最高分样本应为 intercept，实际 %q（总分=%d）", defaultAction, defaultTotal)
	}
	lowAction, lowTotal := run(75)
	if lowAction != action.Drop {
		t.Fatalf("阈值 75 下同一最高分样本应为 drop，实际 %q（总分=%d）", lowAction, lowTotal)
	}
	if defaultTotal != lowTotal {
		t.Fatalf("同一请求在不同阈值下总分应相同：%d vs %d", defaultTotal, lowTotal)
	}
	if defaultTotal < 80 || defaultTotal >= 90 {
		t.Fatalf("该样本（无 GeoIP 命中）总分应落在 [80,90) 的 intercept 区间，实际 %d", defaultTotal)
	}
}

// TestBSADropReachableAtDefaultThreshold 裁决第 4 条：默认阈值 80 下 drop 档可达。
//
// 【更正记录】此前本节断言「默认阈值下 drop 不可达」，该结论**有误**——漏算了
// GeoIP 模块。ScoreIP 在同一 ASN 同时命中机房 ASN 与 VPN ASN 时可达 40 分
// （25+15），再叠加高风险国家 20 分，模块上限 60；60×5% = 3 分。于是五模块
// 满分形态为：UA 100×40%=40 + 指纹 100×25%=25 + 行为 100×15%=15
// + GeoIP 60×5%=3 + 黑名单 IP 60×15%=9 = 92 ≥ 90 → TierDrop。
//
// 本测试用内嵌 GeoIP 夹具构造这一形态，断言默认阈值下的真实 drop 路径。
func TestBSADropReachableAtDefaultThreshold(t *testing.T) {
	const ip = "8.8.8.8" // 夹具内唯一记录，同时命中 dcASN/vpnASN/高风险国家
	geo := bsaGeoResolver(t)

	ctx := bsaCtx(map[string]string{"Connection": "close"})
	ctx.Method, ctx.Path = "POST", "/.env"
	ctx.TLS = bot.TLSClientFingerprint{TLSVersion: "TLS10"}
	ctx.ClientIP = net.ParseIP(ip)

	rep := bsaBlacklistIPRep(t, ip)
	limiter := bsaNewLimiter()
	bsaPrimeBehavior(limiter, ctx, 30)

	phase := NewBotPhaseWithGeoAndLimiter(rep, geo, 80, limiter, 10)
	result, stop := phase.Execute(ctx)

	if ctx.BotScoreResult == nil {
		t.Fatal("满分形态应写入 BotScoreResult")
	}
	if got := ctx.BotScoreResult.TotalScore; got < 90 {
		t.Fatalf("满分形态总分 = %d，未达 drop 档下界 90（模块分 geoip=%d iprep=%d）",
			got, ctx.BotScoreResult.GeoIPScore, ctx.BotScoreResult.IPRepScore)
	}
	if tier := bot.ClassifyScore(ctx.BotScoreResult.TotalScore, 80); tier != bot.TierDrop {
		t.Fatalf("默认阈值 80 下满分形态档位 = %s，want TierDrop", tier.Category())
	}
	if result.Type != action.Drop {
		t.Fatalf("默认阈值 80 下满分形态 action = %q，want drop（总分=%d）",
			result.Type, ctx.BotScoreResult.TotalScore)
	}
	if !stop {
		t.Fatal("drop 必须终止管道")
	}
}
