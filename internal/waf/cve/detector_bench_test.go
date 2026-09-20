package cve

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

/**
 * loadCorpusRequests 加载真实 blazehttp 语料并预解析为 CVERequest 列表。
 *
 * 与 detector_golden_test.go 的 golden 差分共用同一份语料与解析逻辑,
 * 保证 benchmark 测的是真实负载分布而非人造样本。
 * 语料目录缺失时 Skip —— 语料是本地 gitignored 资产。
 *
 * @param tb 测试句柄,用于 Skip/Fatal
 * @returns 预解析完成的 CVERequest 切片(不含解析失败样本)
 */
func loadCorpusRequests(tb testing.TB) []*CVERequest {
	tb.Helper()
	corpus := os.Getenv("CVE_GOLDEN_CORPUS")
	if corpus == "" {
		corpus = filepath.Join("..", "..", "..", "temp", "testcases")
	}
	if _, err := os.Stat(corpus); err != nil {
		tb.Skipf("语料目录不存在,跳过 benchmark: %s", corpus)
	}
	var files []string
	_ = filepath.Walk(corpus, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".white") || strings.HasSuffix(path, ".black") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	reqs := make([]*CVERequest, 0, len(files))
	for _, f := range files {
		if req, ok := parseRawHTTPToCVERequest(f); ok {
			reqs = append(reqs, req)
		}
	}
	if len(reqs) == 0 {
		tb.Skipf("语料目录无可解析样本: %s", corpus)
	}
	return reqs
}

/**
 * BenchmarkCVEDetectFirstCorpus 测量整条 CVE 检测热路径在真实语料上的开销。
 *
 * 这是 pprof 里 CVEDetector.DetectFirst(占 CPU ~29%)的对应基准。
 * 每次迭代遍历全部样本,ns/op 为"扫完整个语料"的耗时。
 */
func BenchmarkCVEDetectFirstCorpus(b *testing.B) {
	reqs := loadCorpusRequests(b)
	detector := NewCVEDetector()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, req := range reqs {
			if m, hit := detector.DetectFirst(req); hit {
				_ = m
			}
		}
	}
}

/**
 * BenchmarkComputeSubDetectorHits 单独测量四子检测器共享的 AC 预扫描开销。
 * 该函数在每请求入口调用一次,覆盖全部六个字段视图。
 */
func BenchmarkComputeSubDetectorHits(b *testing.B) {
	reqs := loadCorpusRequests(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, req := range reqs {
			h := computeSubDetectorHits(req)
			_ = h
		}
	}
}

/**
 * BenchmarkSubDetectorACGate 测量单条规则 gate 判定开销。
 *
 * gate 在每请求里对数十个 CVEID 各调用一次,因此其常数开销会被放大。
 * 用真实存在的 (cveID,target) 组合,覆盖 map 命中路径。
 */
func BenchmarkSubDetectorACGate(b *testing.B) {
	reqs := loadCorpusRequests(b)
	hits := computeSubDetectorHits(reqs[0])
	entries := subDetectorNeedleEntries
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range entries {
			if subDetectorACGate(e.cveID, e.target, &hits) {
				_ = e
			}
		}
	}
}
