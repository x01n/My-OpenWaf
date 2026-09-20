package cve

import (
	"strings"
	"testing"
)

/**
 * computeSubDetectorHitsNoSkip 复刻空自动机短路优化之前的行为:
 * 无条件扫描全部六个字段视图,包括当前零 needle 的 url_body 视图。
 *
 * 仅用于 A/B 基准对照与等价性验证。与 computeSubDetectorHits 在同一进程内
 * 交替计时,使两者承受相同的 CPU 竞争,在高负载机器上仍可得到可比结论。
 *
 * @param req 待扫描请求
 * @returns 各视图 AC 命中 mask
 */
func computeSubDetectorHitsNoSkip(req *CVERequest) subDetectorHits {
	var h subDetectorHits
	ac := &globalSubDetectorAC
	h.all = matchMaskSliceForced(ac.allAC, req.AllTargetsLower)
	h.url = matchMaskSliceForced(ac.urlAC, req.URLTargetsLower)
	h.body = matchMaskSliceForced(ac.bodyAC, req.BodyTargetsLower)
	h.header = matchMaskSliceForced(ac.headerAC, req.HeaderTargetsLower)
	if cookie, ok := cveHeaderValueOK(req.Headers, "Cookie"); ok {
		h.cookie = matchMaskForced(ac.cookieAC, strings.ToLower(cookie))
	}
	h.urlBody = matchMaskSliceForced(ac.urlBodyAC, req.URLTargetsLower)
	bodyHit := matchMaskSliceForced(ac.urlBodyAC, req.BodyTargetsLower)
	for i := range h.urlBody.words {
		h.urlBody.words[i] |= bodyHit.words[i]
	}
	return h
}

// matchMaskSliceForced 是不带空自动机短路的 matchMaskSlice(优化前实现)。
func matchMaskSliceForced(ac *acMatcher, targets []string) acGateMask {
	var hit acGateMask
	nodes := ac.states
	for _, t := range targets {
		cur := int32(0)
		for i := 0; i < len(t); i++ {
			cur = nodes[cur].next[t[i]]
			for _, idx := range nodes[cur].outputs {
				hit.set(idx)
			}
		}
	}
	return hit
}

// matchMaskForced 是不带空自动机短路的 matchMask(优化前实现)。
func matchMaskForced(ac *acMatcher, target string) acGateMask {
	var hit acGateMask
	cur := int32(0)
	nodes := ac.states
	for i := 0; i < len(target); i++ {
		cur = nodes[cur].next[target[i]]
		for _, idx := range nodes[cur].outputs {
			hit.set(idx)
		}
	}
	return hit
}

/**
 * corpusRequestsCapped 取语料前 n 个样本,固定输入保证 A/B 两侧完全一致。
 */
func corpusRequestsCapped(tb testing.TB, n int) []*CVERequest {
	reqs := loadCorpusRequests(tb)
	if n > len(reqs) {
		n = len(reqs)
	}
	return reqs[:n]
}

// BenchmarkSubDetectorHitsSkip 优化后:跳过零 needle 的自动机。
func BenchmarkSubDetectorHitsSkip(b *testing.B) {
	reqs := corpusRequestsCapped(b, 3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range reqs {
			h := computeSubDetectorHits(r)
			_ = h
		}
	}
}

// BenchmarkSubDetectorHitsNoSkip 优化前:无条件扫描全部视图。
func BenchmarkSubDetectorHitsNoSkip(b *testing.B) {
	reqs := corpusRequestsCapped(b, 3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range reqs {
			h := computeSubDetectorHitsNoSkip(r)
			_ = h
		}
	}
}

/**
 * TestSubDetectorHitsSkipEquivalence 证明空自动机短路不改变任何字段视图的
 * 命中 mask —— 这是该优化的等价性证明(与 golden 语料差分互补)。
 */
func TestSubDetectorHitsSkipEquivalence(t *testing.T) {
	reqs := corpusRequestsCapped(t, 8000)
	for i, r := range reqs {
		got := computeSubDetectorHits(r)
		want := computeSubDetectorHitsNoSkip(r)
		if got != want {
			t.Fatalf("样本 %d 的 subDetectorHits 不一致:\n got=%+v\nwant=%+v", i, got, want)
		}
	}
}
