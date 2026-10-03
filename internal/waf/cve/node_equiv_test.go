package cve

import (
	"math/rand"
	"strings"
	"testing"
)

// legacyScanNodeRule 是旧版(门改造前)规则过滤逻辑的忠实副本:
// 只做 subDetectorACGate,无必要条件门。用于与新版 shouldScanNodeRule
// 同输入对拍,锁死"门不改变任何判定"。
func legacyScanNodeRule(req *CVERequest, rule nodeCVERule, hits *subDetectorHits) bool {
	switch rule.cveID {
	case "CVE-2019-10744", "CVE-2020-REACT-SSR", "CVE-2019-NODE-CMD",
		"CVE-2017-14849", "CVE-2022-29078", "CVE-2023-32314",
		"CVE-2024-34351", "CVE-2025-29927", "CVE-2025-55182", "CVE-2025-55184":
		return subDetectorACGate(rule.cveID, rule.target, hits)
	default:
		return true
	}
}

// nodeDetectOutcome 返回检测器在某请求上的全部命中摘要(逐条 CVEID/Pattern)。
func nodeDetectOutcome(d *NodeCVEDetector, req *CVERequest, hits *subDetectorHits) []string {
	out := []string{}
	for _, rule := range d.rules {
		if !legacyScanNodeRule(req, rule, hits) {
			continue
		}
		// 旧版路径:不经过 nodeRuleGate,直接跑正则(与改造前一致)。
		legacyMatched := false
		for _, t := range resolveTargets(req, rule.target) {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					legacyMatched = true
					out = append(out, rule.cveID+"/"+pat.String())
					break
				}
			}
			if legacyMatched {
				break
			}
		}
	}
	return out
}

// TestNodeGateEqualsLegacyOnRandom 对拍核心:随机请求(ASCII/高字节/规则种子
// 混合)上新版(nodyRuleGate 前置)与旧版(纯 AC gate)在每条 node 规则上的
// 正则会话集合一致。会话一致即最终判定一致。
func TestNodeGateEqualsLegacyOnRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	d := NewNodeCVEDetector()

	// 种子池:真实载荷片段拼随机字节,兼顾命中路与白路。
	seeds := []string{
		"__proto__", "constructor", "prototype", "child_process", "require(",
		"dangerouslySetInnerHTML", "__NEXT_DATA__", "${", "`", "..%2f", "..%5c",
		"..\\", "; id", "| cat /", "<%", "settings", "view options",
		"x-middleware-subrequest", "middleware", "$1:A", "/_next/data/",
		".json?", "__nextDataReq", "new Blob", "new Response", ".then(",
		"import(", "\r\n", "%0d%0a", "\x00\x80\xff", "普通中文正文", "{}", "[]",
		"()", "'\"'", "a=b&c=d", "/index.html?q=1",
	}
	var pool []string
	pool = append(pool, seeds...)
	for i := 0; i < 400; i++ {
		n := rng.Intn(48) + 1
		var b strings.Builder
		for j := 0; j < n; j++ {
			switch rng.Intn(5) {
			case 0, 1:
				b.WriteString(seeds[rng.Intn(len(seeds))])
			case 2:
				b.WriteByte(byte(rng.Intn(128)))
			case 3:
				b.WriteByte(byte(128 + rng.Intn(128)))
			default:
				b.WriteString("abcdefghijklmnopqrstuvwxyz0123456789-_./+=:;\"'`|$@#%&<>")
			}
		}
		pool = append(pool, b.String())
	}

	for i, s := range pool {
		for _, view := range []string{"url", "body", "header", "cookie"} {
			req := nodeGatePlace(s, view)
			hits := computeSubDetectorHits(req)
			for _, rule := range d.rules {
				newScan := shouldScanNodeRule(req, rule, &hits)
				legScan := legacyScanNodeRule(req, rule, &hits)
				if newScan == legScan {
					continue
				}
				// 门只能额外关闭,禁止额外开启。
				if newScan && !legScan {
					t.Fatalf("#%d view=%s rules[%s]: 新门放行了旧版会关闭的会话(sample=%q)", i, view, rule.cveID, s)
				}
				// 新门关闭,旧版放行:仅当纯正则扫描没有任何命中时才合法。
				// 有任何命中即说明门阻挡了真实命中,断言必须炸掉。
				targets := resolveTargets(req, rule.target)
				for _, tg := range targets {
					for _, pat := range rule.patterns {
						if pat.MatchString(tg) {
							t.Fatalf("#%d view=%s rules[%s]: 新门关闭了有正则命中的会话(sample=%q, pat=%s)", i, view, rule.cveID, s, pat.String())
						}
					}
				}
				// 旧 open 新 close 且无任何正则会话 = 门省掉纯空转,等价成立。
			}
		}
	}
}
