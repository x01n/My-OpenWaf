package cve

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/ac"
)

/**
 * countScanBytes 统计一次 computeSubDetectorHits 变体在给定请求上实际
 * 走过的自动机状态转移次数(等于逐字节扫描的字节数)。
 *
 * 这是确定性指标:与 CPU 负载、调度、缓存状态无关,可在高竞争机器上
 * 稳定复现,用于证明"空自动机短路"消除的是真实工作量而非测量噪声。
 *
 * @param req 待扫描请求
 * @param skipEmpty 是否启用空自动机短路(true 对应优化后行为)
 * @returns 实际执行的状态转移总次数
 */
func countScanBytes(req *CVERequest, skipEmpty bool) int {
	acSet := &globalSubDetectorAC
	total := 0
	scanSlice := func(m *ac.Matcher, targets []string) {
		if skipEmpty && m.Empty() {
			return
		}
		for _, t := range targets {
			total += len(t)
		}
	}
	scanStr := func(m *ac.Matcher, s string) {
		if skipEmpty && m.Empty() {
			return
		}
		total += len(s)
	}
	scanSlice(acSet.allAC, req.AllTargetsLower)
	scanSlice(acSet.urlAC, req.URLTargetsLower)
	scanSlice(acSet.bodyAC, req.BodyTargetsLower)
	scanSlice(acSet.headerAC, req.HeaderTargetsLower)
	if cookie, ok := cveHeaderValueOK(req.Headers, "Cookie"); ok {
		scanStr(acSet.cookieAC, strings.ToLower(cookie))
	}
	scanSlice(acSet.urlBodyAC, req.URLTargetsLower)
	scanSlice(acSet.urlBodyAC, req.BodyTargetsLower)
	return total
}

/**
 * TestACScanWorkReduction 用确定性字节计数量化空自动机短路消除的工作量。
 *
 * 断言优化后扫描字节数严格少于优化前,并打印精确的削减比例。
 */
func TestACScanWorkReduction(t *testing.T) {
	reqs := loadCorpusRequests(t)
	before, after := 0, 0
	for _, r := range reqs {
		before += countScanBytes(r, false)
		after += countScanBytes(r, true)
	}
	if after >= before {
		t.Fatalf("短路未减少扫描量: before=%d after=%d", before, after)
	}
	saved := before - after
	t.Logf("样本数=%d 扫描字节 优化前=%d 优化后=%d 削减=%d (%.2f%%)",
		len(reqs), before, after, saved, float64(saved)*100/float64(before))

	// 逐视图列出空自动机,说明削减来源。
	acSet := &globalSubDetectorAC
	views := []struct {
		name string
		m    *ac.Matcher
	}{
		{"all", acSet.allAC}, {"url", acSet.urlAC}, {"body", acSet.bodyAC},
		{"header", acSet.headerAC}, {"cookie", acSet.cookieAC}, {"url_body", acSet.urlBodyAC},
	}
	for _, v := range views {
		t.Logf("view=%-9s patterns=%-4d empty=%v", v.name, v.m.NumPatterns(), v.m.Empty())
	}
}
