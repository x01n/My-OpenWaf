package cve

import "testing"

/**
 * TestACStateTableSize 报告各视图自动机的状态数与转移表内存占用。
 *
 * 诊断用:acState 每状态含 [256]int32 转移表(1KB),状态数一旦上千,
 * 转移表就远超 L2/L3 缓存,逐字节随机访问会退化为持续 cache miss。
 */
func TestACStateTableSize(t *testing.T) {
	ac := &globalSubDetectorAC
	report := func(name string, m *acMatcher) {
		n := len(m.states)
		t.Logf("%-10s states=%-6d patterns=%-4d transition_table=%d KB",
			name, n, m.numPatterns, n*256*4/1024)
	}
	// acGateMask 仅 8 个 uint64(512 位),超出 512 的 pattern index 会被
	// set() 静默丢弃,对应 needle 永久失效。此处校验各视图 pattern 数上限。
	counts := map[string]int{}
	for _, e := range subDetectorNeedleEntries {
		v := e.target
		switch v {
		case "all", "url", "body", "header", "cookie", "url_body":
		default:
			v = "all"
		}
		counts[v] += len(e.needles)
	}
	for v, n := range counts {
		t.Logf("view=%-9s patterns=%d over512=%v", v, n, n > 512)
	}
	regN := 0
	for _, ns := range registryNeedleGroups {
		regN += len(ns)
	}
	t.Logf("view=registry  patterns=%d over512=%v", regN, regN > 512)

	report("all", ac.allAC)
	report("url", ac.urlAC)
	report("body", ac.bodyAC)
	report("header", ac.headerAC)
	report("cookie", ac.cookieAC)
	report("url_body", ac.urlBodyAC)
	report("registry", registryACData.ac)
}

/**
 * TestCorpusTargetVolume 报告语料里各视图待扫描字节总量,
 * 用于换算 AC 单遍扫描的理论成本。
 */
func TestCorpusTargetVolume(t *testing.T) {
	reqs := loadCorpusRequests(t)
	var all, url, body, header int
	sum := func(ts []string) int {
		n := 0
		for _, s := range ts {
			n += len(s)
		}
		return n
	}
	for _, r := range reqs {
		all += sum(r.AllTargetsLower)
		url += sum(r.URLTargetsLower)
		body += sum(r.BodyTargetsLower)
		header += sum(r.HeaderTargetsLower)
	}
	t.Logf("samples=%d all=%dB url=%dB body=%dB header=%dB total_scanned=%dB",
		len(reqs), all, url, body, header, all+url+body+header+url+body)
}
