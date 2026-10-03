package cve

import (
	"math/rand"
	"strings"
	"testing"
)

// buildNodeBenchReqs 构造 bench 样本池:
//   - clean:  不含任何 node 门字面量的白样本(真实线上主体),旧版会全量正则扫空转,
//     新版被门直接关掉;这是本改造的真实收益面。
//   - gatePass: 含门字面量但正则不命中的样本(门通、正则仍空转),新旧两路同价。
//
// 样本经 BuildCVERequest 走真实归一化路径,池大小固定为 300,保证单轮
// 扫描时间可测。返回按 [clean, gatePass] 保序的请求序列。
func buildNodeBenchReqs() []*CVERequest {
	rng := rand.New(rand.NewSource(7))
	ascii := "abcdefghijklmnopqrstuvwxyz0123456789-_./+=:;\"'`|$@#%&<> \t"
	clean := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			switch rng.Intn(6) {
			case 0:
				b.WriteByte(byte(128 + rng.Intn(128)))
			default:
				b.WriteByte(ascii[rng.Intn(len(ascii))])
			}
		}
		return b.String()
	}
	gatePass := func() string {
		return "x " + []string{`__proto__ `, `constructor `, `require `, `"__proto__" `,
			"<% ", "settings ", "| id ", "; ident ", ".. ", "$1a"}[rng.Intn(10)] + clean(rng.Intn(40)+8)
	}

	reqs := make([]*CVERequest, 0, 300)
	for i := 0; i < 240; i++ {
		reqs = append(reqs, BuildCVERequest(
			"/"+clean(rng.Intn(30)+4), clean(rng.Intn(20)), map[string]string{"Host": "x"},
			[]byte(clean(rng.Intn(64)+8)), ""))
	}
	for i := 0; i < 60; i++ {
		reqs = append(reqs, BuildCVERequest(
			"/"+clean(rng.Intn(20)+4), clean(rng.Intn(12)), map[string]string{"Host": "x"},
			[]byte(gatePass()), ""))
	}
	return reqs
}

// legacyNodeDetectFirst 是门改造前的 NodeCVEDetector.DetectFirst 忠实副本:
// AC gate 之后直接对每条 target 跑正则,无必要条件门。
func legacyNodeDetectFirst(d *NodeCVEDetector, req *CVERequest, hits *subDetectorHits) (CVEMatch, bool) {
	for _, rule := range d.rules {
		if !legacyScanNodeRule(req, rule, hits) {
			continue
		}
		for _, t := range resolveTargets(req, rule.target) {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					part := rule.target
					if part == "all" {
						part = guessMatchedPart(req, t)
					}
					return CVEMatch{
						CVEID:       rule.cveID,
						Category:    "node",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					}, true
				}
			}
		}
	}
	return CVEMatch{}, false
}

// benchmarkNodeScan 两路共用扫描循环:唯一差异是 gated 开关决定探测路径。
// hits 在计时外预计算并复用,把 AC 段从对拍中剥离,聚焦"门 vs 纯正则
// 扫描"本身的 CPU 差异。两路样本池与断言完全一致,防池内意外命中漂移。
//
// 布局敏感说明:每轮 300 个样本的 subDetectorHits 共 ~9.9KB AC mask +
// ~300KB AC 自动机逐字节冷读,主导对拍的是 AC 图(尾/中部)而非门本身。
// 两路都吃同一 AC 图,故 CPU 相对差只来自门 vs 正则的探测差异,
// 绝对值本身无意义(与 profile 场上环境不同,不做墙钟推广)。
func benchmarkNodeScan(b *testing.B, gated bool) {
	reqs := buildNodeBenchReqs()
	d := NewNodeCVEDetector()
	hits := make([]subDetectorHits, len(reqs))
	for i, r := range reqs {
		hits[i] = computeSubDetectorHits(r)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, r := range reqs {
			var hit bool
			if gated {
				_, hit = d.DetectFirst(r, &hits[j])
			} else {
				_, hit = legacyNodeDetectFirst(d, r, &hits[j])
			}
			if hit {
				b.Fatalf("bench 样本池意外命中: #%d", j)
			}
		}
	}
}

// BenchmarkNodeDetectFirstLegacy 旧版纯 AC-gate 扫描(回归基线)。
func BenchmarkNodeDetectFirstLegacy(b *testing.B) {
	benchmarkNodeScan(b, false)
}

// BenchmarkNodeDetectFirstGated 新版门 + AC-gate 扫描(目标路径)。
func BenchmarkNodeDetectFirstGated(b *testing.B) {
	benchmarkNodeScan(b, true)
}
