package bot

import (
	"net"
	"testing"

	"My-OpenWaf/internal/waf/iprep"
)

func defaultThreshold(t *testing.T) int {
	t.Helper()
	for total := 1; total <= 1000; total++ {
		if ClassifyScore(total, 0) == TierIntercept {
			return total
		}
	}
	t.Fatal("ClassifyScore 在 [1,1000] 内未出现 TierIntercept，默认阈值反推失败")
	return 0
}

func bandFloors(t *testing.T) (observe, challenge, intercept, drop int) {
	t.Helper()
	for total := 1; total <= 1000; total++ {
		switch ClassifyScore(total, 0) {
		case TierObserve:
			if observe == 0 {
				observe = total
			}
		case TierChallenge:
			if challenge == 0 {
				challenge = total
			}
		case TierIntercept:
			if intercept == 0 {
				intercept = total
			}
		case TierDrop:
			if drop == 0 {
				drop = total
			}
		}
	}
	if observe == 0 || challenge == 0 || intercept == 0 || drop == 0 {
		t.Fatalf("五档未全部可达：observe=%d challenge=%d intercept=%d drop=%d", observe, challenge, intercept, drop)
	}
	return
}

func TestBotTierBandBoundaries(t *testing.T) {
	observe, challenge, intercept, drop := bandFloors(t)
	threshold := defaultThreshold(t)

	if threshold != intercept {
		t.Fatalf("默认阈值 %d 与 intercept 档下界 %d 不一致（阈值为 0 时应视作默认值）", threshold, intercept)
	}
	if want := threshold / 2; observe != want {
		t.Fatalf("observe 档下界 = %d, want T/2 = %d", observe, want)
	}
	if want := threshold * 3 / 4; challenge != want {
		t.Fatalf("challenge 档下界 = %d, want 3T/4 = %d", challenge, want)
	}
	if want := threshold * 9 / 8; drop != want {
		t.Fatalf("drop 档下界 = %d, want 9T/8 = %d", drop, want)
	}

	// 单调性：分值升高，档位不得回退。
	prev := TierPass
	for total := 0; total <= 1000; total++ {
		cur := ClassifyScore(total, 0)
		if cur < prev {
			t.Fatalf("档位在 total=%d 处回退：%d -> %d", total, prev, cur)
		}
		prev = cur
	}
}

// TestBotTierCategoryAndLogActionAreTotal 裁决第 4 条：每个档位都有稳定的
// 日志分类与动作串，且档位之间互不相同（消费方据此落库与展示）。
func TestBotTierCategoryAndLogActionAreTotal(t *testing.T) {
	tiers := []BotTier{TierPass, TierObserve, TierChallenge, TierIntercept, TierDrop}
	seenCategory := map[string]BotTier{}
	seenAction := map[string]BotTier{}
	for _, tier := range tiers {
		category := tier.Category()
		action := tier.LogAction()
		if category == "" || action == "" {
			t.Fatalf("tier=%d 存在空串：category=%q action=%q", tier, category, action)
		}
		if other, dup := seenCategory[category]; dup {
			t.Fatalf("category %q 被 tier=%d 与 tier=%d 共用", category, other, tier)
		}
		if other, dup := seenAction[action]; dup {
			t.Fatalf("action %q 被 tier=%d 与 tier=%d 共用", action, other, tier)
		}
		seenCategory[category] = tier
		seenAction[action] = tier
	}
	// 允许档位是「放行」语义（不参与处置），其动作串不得是终止类动作。
	if got := TierPass.LogAction(); got == TierDrop.LogAction() || got == TierIntercept.LogAction() || got == TierChallenge.LogAction() {
		t.Fatalf("TierPass 的动作串 %q 与终止档动作串重复", got)
	}
}

// bsCleanBrowserRequest 干净浏览器样本：真实 Chrome UA + 全套浏览器头 +
// Cookie，无 TLS 异常、无 IP 声誉信号（裁决第 4 条的「低分样本」）。
func bsCleanBrowserRequest() BotRequest {
	return NewBotRequest("GET", "/", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Referer":         "https://example.com/",
		"Connection":      "keep-alive",
		"Cookie":          "sid=abc",
	})
}

// bsWithUA 在干净样本上只替换 UA，用于隔离「UA 单独作用」。
func bsWithUA(ua string) BotRequest {
	r := bsCleanBrowserRequest()
	r.UserAgent = ua
	return r
}

// bsWithBlacklistIP 干净样本 + 全局黑名单 IP（iprep 公开 API 构造）。
func bsWithBlacklistIP(t *testing.T) (BotRequest, *iprep.IPReputation) {
	t.Helper()
	rep := iprep.NewIPReputation()
	t.Cleanup(rep.Close)
	entry, ok := iprep.ParseIPListEntry("203.0.113.9", "verify blacklist", "intercept")
	if !ok {
		t.Fatal("failed to parse blacklist entry")
	}
	rep.SetLists([]iprep.IPListEntry{entry}, nil)
	r := bsCleanBrowserRequest()
	r.ClientIP = net.ParseIP("203.0.113.9")
	return r, rep
}

// ────────── 裁决第 1 条：模块化——各模块独立计分，互不串扰 ──────────

func TestBotModulesAreIndependent(t *testing.T) {
	// 裁决第 1 条：UA / 指纹 / IP 声誉 / GeoIP / 行为各自独立成模块。
	// 断言：只改一个模块的输入，其余模块的（加权）分不变。
	baseline := DeepScore(bsCleanBrowserRequest(), nil, nil)

	repReq, rep := bsWithBlacklistIP(t)
	withRep := DeepScore(repReq, rep, nil)

	if withRep.UAScore != baseline.UAScore {
		t.Fatalf("注入 IP 声誉改变了 UA 模块分：%d -> %d（模块未解耦）", baseline.UAScore, withRep.UAScore)
	}
	if withRep.FingerprintScore != baseline.FingerprintScore {
		t.Fatalf("注入 IP 声誉改变了指纹模块分：%d -> %d（模块未解耦）", baseline.FingerprintScore, withRep.FingerprintScore)
	}
	if withRep.GeoIPScore != baseline.GeoIPScore {
		t.Fatalf("注入 IP 声誉改变了 GeoIP 模块分：%d -> %d（模块未解耦）", baseline.GeoIPScore, withRep.GeoIPScore)
	}
	if withRep.IPRepScore <= baseline.IPRepScore {
		t.Fatalf("注入 IP 声誉未改变 IP 声誉模块分：%d -> %d", baseline.IPRepScore, withRep.IPRepScore)
	}

	// UA 模块只受 UA 影响：换 UA 不得改变其余模块分。
	uaChanged := DeepScore(bsWithUA("curl/8.0"), nil, nil)
	if uaChanged.FingerprintScore != baseline.FingerprintScore || uaChanged.GeoIPScore != baseline.GeoIPScore {
		t.Fatalf("更换 UA 影响了非 UA 模块：base=%+v changed=%+v", baseline, uaChanged)
	}
	if uaChanged.UAScore == baseline.UAScore {
		t.Fatalf("更换 UA 未改变 UA 模块分：%d", uaChanged.UAScore)
	}
}

// ────────── 裁决第 2 条：总分 = Σ(模块分 × 权重) ──────────

func TestBotTotalIsWeightedSumOfModules(t *testing.T) {
	// 裁决第 2 条：总分由各模块分加权求和。
	// 断言：五模块分升序变化时总分单调不减；且每个模块单独注入都能抬高总分。
	threshold := defaultThreshold(t)

	base := DeepScore(bsCleanBrowserRequest(), nil, nil).Total

	// UA 模块：curl 的 UA 原始分高于浏览器 UA（后者为 0），总分必须上升。
	uaUp := DeepScore(bsWithUA("curl/8.0"), nil, nil).Total
	if uaUp <= base {
		t.Fatalf("UA 模块分上升但总分未上升：base=%d ua=%d", base, uaUp)
	}

	// IP 声誉模块。
	repReq, rep := bsWithBlacklistIP(t)
	ipUp := DeepScore(repReq, rep, nil).Total
	if ipUp <= base {
		t.Fatalf("IP 声誉模块分上升但总分未上升：base=%d iprep=%d", base, ipUp)
	}

	// 行为模块（裁决第 5 条同一入口）。
	behaviorUp := DeepScoreWithBehavior(bsCleanBrowserRequest(), nil, nil, 100).Total
	if behaviorUp <= base {
		t.Fatalf("行为模块分上升但总分未上升：base=%d behavior=%d", base, behaviorUp)
	}

	// 各模块加权分不得超过总分（权重非负、模块分不被吞掉）。
	probe := DeepScore(repReq, rep, nil)
	for name, module := range map[string]int{
		"ua":          probe.UAScore,
		"fingerprint": probe.FingerprintScore,
		"behavior":    probe.BehaviorScore,
		"geoip":       probe.GeoIPScore,
		"iprep":       probe.IPRepScore,
	} {
		if module < 0 {
			t.Fatalf("模块 %s 出现负分 %d", name, module)
		}
		if module > probe.Total && module > threshold {
			t.Fatalf("模块 %s 的加权分 %d 超过总分 %d", name, module, probe.Total)
		}
	}
}

// ────────── 裁决第 3 条：常规自动化工具 UA 不得单独判死 ──────────

func TestBotAutomationUAMustNotBeFatalAlone(t *testing.T) {
	// 裁决第 3 条：curl/wget/go-http-client/python-requests 等常规自动化工具
	// UA 不得单独判死；只有加权总分决定处置。
	//
	// 断言口径（两条都要满足）：
	//   1) 加权总分不得进入 intercept 档（< T）——不靠分数被处置；
	//   2) 不得被标记为危险（不走上「危险标记」这条终止通道）。
	_, _, interceptFloor, _ := bandFloors(t)
	uas := []string{
		"curl/8.0", "curl/8.7.1", "wget/1.21",
		"Go-http-client/1.1", "python-requests/2.31",
	}
	for _, ua := range uas {
		t.Run(ua, func(t *testing.T) {
			r := bsWithUA(ua)
			bs := DeepScore(r, nil, nil)
			if bs.Total >= interceptFloor {
				t.Fatalf("裁决第3条违背：UA 单独把总分推入 intercept 及以上 (Total=%d >= %d, modules=%+v)",
					bs.Total, interceptFloor, bs.Raw)
			}
			if bs.Dangerous {
				t.Fatalf("裁决第3条违背：常规自动化工具 UA 被标记为危险 %v（来源 %v）", bs.Dangerous, bs.DangerReasons)
			}

			v, _ := CheckBotTwoPhase(r, nil, nil, 0)
			if v.Tier >= TierIntercept {
				t.Fatalf("裁决第3条违背：两阶段判定把常规工具 UA 判入 %s 档：%+v", v.Tier.Category(), v)
			}
			if v.Dangerous {
				t.Fatalf("裁决第3条违背：两阶段判定把常规工具 UA 标记为危险：%+v（来源 %v）", v, v.DangerReasons)
			}
		})
	}
}

// TestBotStrongSignalUAContributesModuleScore 裁决第 3 条：sqlmap/nuclei 等
// 高危 UA「也只贡献模块分」——其加权总分本身不得单独达到 intercept 档，
// 且处置不得为 drop（不判死）。
//
// 【验收观察】当前实现在加权总分之外还有一条独立的「危险标记」通道
// （Dangerous + applyDangerFloor），明确攻击工具 UA 会因此被抬到 challenge
// 档并终止。这与裁决第 3 条「只贡献模块分」的字面表述不一致，本测试
// 只记录实测值（t.Logf）而不对其做硬断言，是否收敛由主会话裁决。
func TestBotStrongSignalUAContributesModuleScore(t *testing.T) {
	_, _, interceptFloor, dropFloor := bandFloors(t)
	for _, ua := range []string{"sqlmap/1.7", "nuclei/v3"} {
		t.Run(ua, func(t *testing.T) {
			r := bsWithUA(ua)
			bs := DeepScore(r, nil, nil)
			v, _ := CheckBotTwoPhase(r, nil, nil, 0)

			t.Logf("UA=%q 加权总分=%d 危险=%v 来源=%v verdict={tier:%d cat:%s action:%s score:%d}",
				ua, bs.Total, bs.Dangerous, bs.DangerReasons, v.Tier, v.Category, v.Tier.LogAction(), v.Score)

			if v.Tier == TierDrop {
				t.Fatalf("裁决第3条违背：强信号 UA 单独被判死（drop）：%+v", v)
			}
			if bs.Total >= interceptFloor && !bs.Dangerous {
				// 若总分本身已到 intercept 档，那属「加权总分决定处置」，与裁决一致。
				t.Logf("注意：%q 的加权总分 %d 自身已达 intercept 档下界 %d", ua, bs.Total, interceptFloor)
			}
			if int(v.Tier) >= dropFloor {
				t.Fatalf("强信号 UA 判决分 %d 达 drop 档下界 %d", v.Score, dropFloor)
			}
		})
	}
}

// ────────── 裁决第 3 条（反向）：强信号仍须被终止，不得因降权而放行 ──────────

func TestBotStrongSignalUANeverPassesThrough(t *testing.T) {
	// 设计约束（重构线引入的「危险标记」通道）：明确攻击工具不得因权重
	// 稀释而被放行。这条与裁决第 3 条不冲突——裁决只要求「不单独判死」，
	// 未要求「必须放行」。断言：注册在 uaToolSeverity 中的工具 UA 必须
	// 能被 PreScreen 识别并进入评分路径，且档位至少 challenge。
	//
	// 样本取自 uaToolSeverity 的键（工具名）而非任意字面：该表是 UA 工具
	// 严重度的权威定义，用它的键构造样本可以避免「随手指定的 UA 字面
	// 本就不在任何工具表里」造成的假阴性。
	toolUAs := []string{
		"sqlmap/1.7",     // sqlmap
		"metasploit/6.4", // metasploit
		"THC-Hydra",      // password_cracker
		"nuclei/v3",      // nuclei
		"nikto/2.5",      // nikto
		"Havij",          // sqli_tool
		"commix",         // exploit_tool
		"wpscan",         // cms_scanner
	}
	for _, ua := range toolUAs {
		t.Run(ua, func(t *testing.T) {
			r := bsWithUA(ua)
			if !PreScreen(r, nil, nil) {
				t.Fatalf("工具 UA %q 未被 PreScreen 识别，评分路径不会执行", ua)
			}
			v, _ := CheckBotTwoPhase(r, nil, nil, 0)
			if v.Tier < TierChallenge {
				t.Fatalf("强信号 UA %q 落 %s 档，未达 challenge：%+v", ua, v.Tier.Category(), v)
			}
		})
	}
}

// ────────── 裁决第 5 条：BehaviorScore 接入请求频率 ──────────

func TestBotBehaviorScoreRespondsToRequestRate(t *testing.T) {
	// 裁决第 5 条：BehaviorScore 接入请求频率（RateLimiter 窗口计数换算）。
	//
	// 覆盖两条公开路径：
	//   1) BehaviorScoreFromCount：窗口计数 → 行为模块原始分，阶梯单调不减；
	//   2) DeepScoreWithBehavior：行为原始分注入后，总分与档位随之上升。
	max := 200
	var prevRaw int
	for _, count := range []int{0, 1, max / 2, max - 1, max, max * 3 / 2, max * 2, max * 3, max * 10} {
		raw := BehaviorScoreFromCount(count, max)
		if raw < prevRaw {
			t.Fatalf("行为分随计数回退：count=%d raw=%d < 前值 %d", count, raw, prevRaw)
		}
		if raw < 0 || raw > 100 {
			t.Fatalf("行为原始分超出 [0,100]：count=%d raw=%d", count, raw)
		}
		prevRaw = raw
	}
	if BehaviorScoreFromCount(max*3, max) <= BehaviorScoreFromCount(max, max) {
		t.Fatal("3 倍阈值计数的行为分未高于 1 倍阈值计数")
	}
	if got := BehaviorScoreFromCount(0, 0); got != 0 {
		t.Fatalf("maxReqs<=0 时行为分应为 0，得 %d", got)
	}

	// 注入行为分 → 总分上升 → 档位不下降。
	clean := bsCleanBrowserRequest()
	before := DeepScore(clean, nil, nil)
	after := DeepScoreWithBehavior(clean, nil, nil, 100)
	if after.BehaviorScore <= before.BehaviorScore {
		t.Fatalf("注入行为原始分后 BehaviorScore 未上升：%d -> %d", before.BehaviorScore, after.BehaviorScore)
	}
	if after.Total <= before.Total {
		t.Fatalf("注入行为原始分后总分未上升：%d -> %d", before.Total, after.Total)
	}
	if ClassifyScore(after.Total, 0) < ClassifyScore(before.Total, 0) {
		t.Fatalf("注入行为分后档位回退：%d -> %d", ClassifyScore(before.Total, 0), ClassifyScore(after.Total, 0))
	}

	// 高频必须能独立把干净流量抬离 0 分（行为模块是可独立生效的模块）。
	// 注意：DeepScore 系列不参与 PreScreen，因此「是否进入处置」由
	// CheckBotTwoPhaseWithBehavior 决定（PreScreen 命中才评分）；
	// 这里只断言模块分与总分确实被抬高，档位断言放在两阶段入口处。
	high := DeepScoreWithBehavior(clean, nil, nil, 100)
	if high.Total <= before.Total {
		t.Fatalf("行为模块满分时总分未上升：%d -> %d", before.Total, high.Total)
	}
	if high.BehaviorScore == 0 {
		t.Fatal("行为模块满分注入后 BehaviorScore 仍为 0")
	}

	// 两阶段入口：干净浏览器不触发 PreScreen，返回空评分且放行——
	// 这是既定的预筛语义，不是行为模块失效。
	v, bs := CheckBotTwoPhaseWithBehavior(clean, nil, nil, 0, 100)
	if v.Tier != TierPass || v.IsBot {
		t.Fatalf("干净样本（PreScreen 未命中）应放行，实际 %+v", v)
	}
	if bs.Total != 0 || bs.BehaviorScore != 0 {
		t.Fatalf("PreScreen 未命中时不应产生评分：%+v", bs)
	}

	// 用一个能被 PreScreen 命中的样本（带工具 UA，此时评分会真正执行）
	// 验证「行为分参与评分 → 档位由加权总分派生」。
	probe := bsWithUA("curl/8.0")
	bv, bbs := CheckBotTwoPhaseWithBehavior(probe, nil, nil, 0, 100)
	if bbs.BehaviorScore == 0 {
		t.Fatalf("两阶段评分中行为分未生效：%+v", bbs)
	}
	if bv.Tier != ClassifyScore(bbs.Total, 0) {
		t.Fatalf("两阶段入口档位 %d 与同分数的 ClassifyScore %d 不一致（Total=%d）", bv.Tier, ClassifyScore(bbs.Total, 0), bbs.Total)
	}
}

// ────────── 裁决第 4 条（分数形态）：干净样本必须落放行档 ──────────

func TestBotCleanBrowserStaysInPassBand(t *testing.T) {
	// 干净浏览器样本（全套头 + Cookie + 真实 Chrome UA）不得产生任何处置。
	clean := bsCleanBrowserRequest()
	bs := DeepScore(clean, nil, nil)
	if bs.Total != 0 {
		t.Fatalf("干净浏览器样本总分非 0：%d（modules=%+v details=%v）", bs.Total, bs.Raw, bs.Details)
	}
	if bs.Dangerous {
		t.Fatalf("干净浏览器样本被标记为危险：%v", bs.DangerReasons)
	}
	if tier := ClassifyScore(bs.Total, 0); tier != TierPass {
		t.Fatalf("干净浏览器样本落 %s 档，want 放行", tier.Category())
	}
	v, _ := CheckBotTwoPhase(clean, nil, nil, 0)
	if v.Tier != TierPass || v.IsBot {
		t.Fatalf("干净浏览器样本两阶段判定 = %+v，want 放行且非 bot", v)
	}
}

// ─────────────────────── 未覆盖面（交主会话裁决） ───────────────────────
//
// 「档位 → WAF action」的映射实现在 internal/core/rules 的 botPhase
// （verdictToResult 把 BotTier 映射为 action.Drop/Intercept/Challenge/Observe），
// bot 包不可见。因此本文件只能断言 Tier 层；要覆盖「Total=75 时 action 应为
// challenge」这类端到端断言，必须新增 internal/core/rules/bot_score_action_levels_test.go。
// B 线已就该文件的许可向主会话请示，未获答复前不创建。
//
// 另：行为分经 botPhase 注入的链路（botPhase.behaviorScore 用 limiter.Increment
// 取窗口计数再换算）同样位于 rules 包，当前无任何测试覆盖。
