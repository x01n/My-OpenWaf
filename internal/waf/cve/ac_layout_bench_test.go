package cve

import (
	"strings"
	"testing"
)

/**
 * computeSubDetectorHitsNoSkip 保留对「跳过空自动机短路」语义的等价性基线:
 * 生产路径 computeSubDetectorHits 对零 needle 视图直接短路,NoSkip 版无条件
 * 扫描全部六个字段视图（普通 MatchMask 对空 matcher 同样安全返回零 mask）。
 *
 * 仅用于等价性验证。与 computeSubDetectorHits 在同一进程内交替计时,
 * 使两者承受相同的 CPU 竞争,在高负载机器上仍可得到可比结论。
 *
 * @param req 待扫描请求
 * @returns 各视图 AC 命中 mask
 */
func computeSubDetectorHitsNoSkip(req *CVERequest) subDetectorHits {
	var h subDetectorHits
	acSet := &globalSubDetectorAC
	h.all = acSet.allAC.MatchMaskSlice(req.AllTargetsLower)
	h.url = acSet.urlAC.MatchMaskSlice(req.URLTargetsLower)
	h.body = acSet.bodyAC.MatchMaskSlice(req.BodyTargetsLower)
	h.header = acSet.headerAC.MatchMaskSlice(req.HeaderTargetsLower)
	if cookie, ok := cveHeaderValueOK(req.Headers, "Cookie"); ok {
		h.cookie = acSet.cookieAC.MatchMask(strings.ToLower(cookie))
	}
	h.urlBody = acSet.urlBodyAC.MatchMaskSlice(req.URLTargetsLower)
	h.urlBody.MergeFrom(acSet.urlBodyAC.MatchMaskSlice(req.BodyTargetsLower))
	return h
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
