package challenge

import (
	"strings"
	"testing"
)

func missionFactorSet(mission EnvMission) map[string]bool {
	set := make(map[string]bool, len(mission.Factors))
	for _, f := range mission.Factors {
		set[f] = true
	}
	return set
}

func factorSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// TestNewEnvMissionVaries / TestR2_2MissionSetsDiffer 锁定「每次要求的环境
// 不一样」：连续 5 个 mission 的因子集合不全等。
func TestR2_2NewEnvMissionFactorSetsNotNullEqual(t *testing.T) {
	missions := make([]EnvMission, 5)
	sets := make([]map[string]bool, 5)
	for i := range missions {
		missions[i] = NewEnvMission()
		if missions[i].ID == "" {
			t.Fatalf("mission %d: crypto/rand failed (empty ID)", i)
		}
		if len(missions[i].ID) != 32 {
			t.Fatalf("mission %d: ID hex length = %d, want 32", i, len(missions[i].ID))
		}
		// 目标范围 32..48 被全因子池大小（37）钳制为真子集盲区 32..36；
		// 见 NewEnvMission 注释（R2.2 自选偏差）。
		if len(missions[i].Factors) < envMissionFactorCountMin || len(missions[i].Factors) > len(envMissionAllFactors)-1 {
			t.Fatalf("mission %d: factor count = %d, want [%d,%d]", i, len(missions[i].Factors), envMissionFactorCountMin, len(envMissionAllFactors)-1)
		}
		seenDuplicate := make(map[string]bool, len(missions[i].Factors))
		for _, f := range missions[i].Factors {
			if !IsEnvMissionFactor(missions[i], f) {
				t.Fatalf("mission %d: factor %q not accepted by IsEnvMissionFactor", i, f)
			}
			if seenDuplicate[f] {
				t.Fatalf("mission %d: duplicate factor %q", i, f)
			}
			seenDuplicate[f] = true
		}
		sets[i] = missionFactorSet(missions[i])
	}
	allEqual := true
	for i := 1; i < len(sets); i++ {
		if !factorSetsEqual(sets[0], sets[i]) {
			allEqual = false
			break
		}
	}
	if allEqual {
		t.Fatal("5 consecutive mission factor sets must not be all equal")
	}
}

// TestR2_2MissionCoversAllFactorsMatchesFullScore 锁定等价性：mission
// 覆盖全部因子时，ScoreWithMission 与 ValidateEnvFingerprint 完全一致。
func TestR2_2MissionCoversAllFactorsMatchesFullScore(t *testing.T) {
	fp := &EnvFingerprint{
		DevtoolsOpen:         true,
		DevtoolsTiming:       150,
		ChromePresent:        false,
		PluginsCount:         0,
		Languages:            "undefined",
		CanvasHash:           "",
		WebGLRenderer:        "",
		ScreenWidth:          0,
		ScreenHeight:         0,
		HardwareConcur:       0,
		ColorDepth:           0,
		PixelRatio:           0,
		AudioHash:            "",
		SessionStorage:       false,
		IndexedDB:            false,
		CookieEnabled:        false,
		PlatformStr:          "",
		FontCount:            0,
		WebAssembly:          false,
		ServiceWorker:        false,
		MediaDevices:         false,
		UAMismatch:           true,
		ScreenConsistency:    false,
		TimezoneConsistency:  false,
		LanguageConsistency:  false,
		MathConsistency:      false,
		TouchSupport:         true,
		MaxTouchPoints:       0,
		WebGL2Support:        false,
		IntersectionObserver: false,
		MutationObserver:     false,
		ResizeObserver:       false,
	}
	full := ValidateEnvFingerprint(fp)

	mission := EnvMission{ID: strings.Repeat("ee", 16), Factors: append([]string(nil), envMissionAllFactors...)}
	// 全因子 mission 覆盖全部累加分支（新字段省略时直接表现不一致，
	// 见 DiffReported 说明）。
	gated := ScoreWithMission(fp, mission)
	if gated.Score != full.Score || gated.Pass != full.Pass {
		t.Fatalf("full mission: score=%d pass=%v, full: score=%d pass=%v", gated.Score, gated.Pass, full.Score, full.Pass)
	}
	if len(gated.Reasons) != len(full.Reasons) {
		t.Fatalf("full mission reasons count: gated=%d full=%d", len(gated.Reasons), len(full.Reasons))
	}
}

// TestR2_2SingleFactorExclusionSkipsOnlyItsBranches 正向锁定「任意单因子
// 被排除时，仅该因子的评分分支被跳过」。devtools_timing 仅被
// devtools_timing 分支使用，排除前后结果差必须是 +20 分支的精确贡献。
func TestR2_2SingleFactorExclusionSkipsOnlyItsBranches(t *testing.T) {
	fp := &EnvFingerprint{
		DevtoolsTiming:       150, // +20
		CanvasHash:           "0", // +10
		ChromePresent:        true,
		PluginsCount:         5,
		Languages:            "zh-CN",
		WebGLRenderer:        "NVIDIA",
		ScreenWidth:          1920,
		ScreenHeight:         1080,
		HardwareConcur:       8,
		ColorDepth:           24,
		PixelRatio:           1,
		AudioHash:            "abc",
		SessionStorage:       true,
		IndexedDB:            true,
		CookieEnabled:        true,
		PlatformStr:          "Linux",
		FontCount:            3,
		WebAssembly:          true,
		ServiceWorker:        true,
		MediaDevices:         true,
		ScreenConsistency:    true,
		TimezoneConsistency:  true,
		LanguageConsistency:  true,
		MathConsistency:      true,
		IntersectionObserver: true,
		MutationObserver:     true,
		ResizeObserver:       true,
		WebGL2Support:        true,
	}
	full := ValidateEnvFingerprint(fp)

	mission := EnvMission{
		ID:      strings.Repeat("aa", 16),
		Factors: append([]string(nil), envMissionAllFactors...),
	}
	// 从全因子 mission 里剔除 devtools_timing：只应少掉该因子的 +20 分支，
	// 其余因子（canvas_hash 的 +10）不受影响（devtools_timing 不落在任何
	// 多因子分支上）。
	excluded := make([]string, 0, len(envMissionAllFactors))
	for _, f := range envMissionAllFactors {
		if f != "devtools_timing" {
			excluded = append(excluded, f)
		}
	}
	mission.Factors = excluded
	gated := ScoreWithMission(fp, mission)
	want := full.Score - 20
	if full.Score != 30 || want != 10 {
		t.Fatalf("priori calibration failed: full=%d want-full=30, want-gated=%d", full.Score, want)
	}
	if gated.Score != want {
		t.Fatalf("mission excluding devtools_timing: score=%d, want %d (full=%d)", gated.Score, want, full.Score)
	}
	if len(gated.Reasons) != len(full.Reasons)-1 {
		t.Fatalf("mission excluding devtools_timing: reasons=%d, full reasons=%d", len(gated.Reasons), len(full.Reasons))
	}
}

// TestR2_2EmptyMissionFallsBackToFullPath 锁定「EnvMission 为空（旧会话/
// 直接构造）时完全走旧逻辑」：空 mission 评分与 ValidateEnvFingerprint 一致。
func TestR2_2EmptyMissionFallsBackToFullPath(t *testing.T) {
	fp := &EnvFingerprint{
		DevtoolsOpen:  true,
		CDPRuntime:    true,
		ChromePresent: false,
		PluginsCount:  0,
		UAMismatch:    true,
	}
	full := ValidateEnvFingerprint(fp)
	emptyMission := ScoreWithMission(fp, EnvMission{})
	if emptyMission.Score != full.Score || emptyMission.Pass != full.Pass {
		t.Fatalf("empty mission: score=%d pass=%v, full: score=%d pass=%v", emptyMission.Score, emptyMission.Pass, full.Score, full.Pass)
	}
	if len(emptyMission.Reasons) != len(full.Reasons) {
		t.Fatalf("empty mission reasons: got %d, want %d", len(emptyMission.Reasons), len(full.Reasons))
	}
}

// TestR2_2HardFailuresNotFilterableByMission 锁定硬终止分支不受 mission
// 影响：webdriver / AutomationSign 在任何过滤下都返回 100 分。
func TestR2_2HardFailuresNotFilterableByMission(t *testing.T) {
	single := EnvMission{ID: strings.Repeat("bb", 16), Factors: []string{"devtools_open"}}
	// 硬停止因子不在可过滤清单里：found 应为 false。
	found := false
	for _, f := range envMissionAllFactors {
		if f == "webdriver" || f == "automation_sign" || f == "phantom" {
			found = true
		}
	}
	if found {
		t.Fatalf("hard-stop factor names leaked into filterable list: %v", envMissionAllFactors)
	}

	for _, fp := range []*EnvFingerprint{
		{WebDriver: true},
		{AutomationSign: "selenium"},
		{Phantom: true},
	} {
		res := ScoreWithMission(fp, single)
		if res.Score != 100 || res.Pass {
			t.Fatalf("mission %v: hard-stop result = %+v, want score=100 pass=false", fp, res)
		}
	}
}
