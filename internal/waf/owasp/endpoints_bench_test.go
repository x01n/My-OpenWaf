package owasp

import "testing"

// endpointBenchPaths 覆盖敏感端点热路径的三类输入：
//   - MissNoCandidate：首段不在规则表中，走「首段查找未命中即返回」短路；
//   - MissSecondSegment：首段命中但次段不匹配，需走两级查找后落空；
//   - Hit：命中规则，需要逐段比较。
//
// 另附一条带方法约束的命中，用于量化方法比较的成本。
var endpointBenchPaths = []struct {
	name   string
	path   string
	method string
}{
	{"MissNoCandidate", "/api/v1/users/profile", "GET"},
	{"MissNoCandidateLongSegment", "/some-very-long-first-segment-here/x/y", "GET"},
	{"MissSecondSegment", "/api/someother/endpoint", "GET"},
	{"MissLastSegment", "/cgi-bin/downloadcfg/other.cfg", "GET"},
	{"HitSingleSegment", "/jkstatus", "GET"},
	{"HitMethodMatch", "/global-protect/login.esp", "POST"},
	{"HitMethodMismatch", "/global-protect/login.esp", "GET"},
	{"HitDeepSegments", "/wp-content/plugins/adminimize/adminimize_page.php", "GET"},
}

func BenchmarkSensitiveEndpointPath(b *testing.B) {
	for _, tc := range endpointBenchPaths {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = CheckSensitiveEndpointPath(tc.path, tc.method)
			}
		})
	}
}

// dangerousPathBenchPaths 是 checkDangerousPath（17 条 containsASCIIFold 子串
// 规则）的代表性输入，作为新旧两条路径的成本对照基线。
var dangerousPathBenchPaths = []struct {
	name string
	path string
}{
	{"Miss", "/api/v1/users/profile"},
	{"HitFirstRule", "/mgmt/tm/util/bash"},
	{"HitLastRule", "/service/extdirect"},
}

func BenchmarkDangerousPath(b *testing.B) {
	for _, tc := range dangerousPathBenchPaths {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = checkDangerousPath(tc.path)
			}
		})
	}
}
