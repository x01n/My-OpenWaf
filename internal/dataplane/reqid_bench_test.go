package dataplane

import (
	"testing"
)

// BenchmarkFastRequestID 覆盖完整请求 ID 生成路径：计数器自增、栈缓冲上的
// base64url 编码与 28 字节终串合成。格式等价由 reqid_test.go 锁定。
func BenchmarkFastRequestID(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = fastRequestID()
	}
}
