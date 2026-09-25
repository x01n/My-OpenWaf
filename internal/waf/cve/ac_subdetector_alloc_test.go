package cve

import (
	"testing"
)

// BenchmarkSubDetectorACGateSynthetic 用固定请求构造 hits,对全部 needle
// 条目逐一调用 subDetectorACGate,独立于 temp/testcases 语料。
//
// 该函数取代语料门控的 BenchmarkSubDetectorACGate(语料缺失时 Skip),
// 直接测量 gate 常数的每调用分配:预取 mask 后应为 0 allocs。
// 注意 ns/op 只作同进程对照(与其他仓建进程共驻的负载经 3 进程取样中位)。
func BenchmarkSubDetectorACGateSynthetic(b *testing.B) {
	var req CVERequest
	BuildCVERequestInto(&req, "/api/login", "page=1&sort=name", map[string]string{
		"Host": "example.com", "Cookie": "session=abc; rememberme=xyz",
	}, []byte(`{"k":"../etc/passwd"}`), "application/json")
	hits := computeSubDetectorHits(&req)
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
