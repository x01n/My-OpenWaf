package upstream

import (
	"My-OpenWaf/internal/pkg/schemealias"
)

// rpcSchemeAliases 描述 RPC 相关 URL 前缀到传输 scheme 的映射（小写、带 "://"）。
//
// gRPC 本身是 content-type 而非传输 scheme；用户希望通过 URL 前缀直接表达
// gRPC 上游，因此这些别名只做传输层归一，不改变任何业务语义：
//
//   - tls://        -> https（TLS + ALPN 协商，与 https:// 完全同语义）
//   - grpcs://      -> https（TLS 直连 gRPC 服务）
//   - grpc+tls://   -> https（grpcs 的别名）
//   - grpc+https:// -> https（同样归一为 https）
//   - grpc://       -> h2c（h2 prior knowledge 明文）
//
// 别名表与归一逻辑实际收敛在 internal/pkg/schemealias；该包不依赖
// internal/upstream，snapshot 等不能依赖 upstream 的包可直接复用，
// 本文件只保留 upstream 包内部的查看入口（协议偏好等遍历用）。
var rpcSchemeAliases = map[string]string{
	"tls://":        "https",
	"grpcs://":      "https",
	"grpc+tls://":   "https",
	"grpc+https://": "https",
	"grpc://":       "h2c",
}

// normalizeUpstreamScheme 折叠 scheme 大小写并把 RPC 别名展开为传输 scheme：
// tls/grpcs/grpc+tls/grpc+https -> https，grpc -> h2c；其余 scheme 原样小写返回。
// 入参不含 "://" 后缀。
func normalizeUpstreamScheme(scheme string) string {
	return schemealias.Scheme(scheme)
}

// IsRPCUpstreamScheme 报告 scheme 是否为 RPC 别名（比较前折叠大小写）。
// 入参可为 "grpc" 或 "grpc://" 两种形态。
func IsRPCUpstreamScheme(scheme string) bool {
	return schemealias.IsRPCScheme(scheme)
}

// RPCUpstreamAliasForURL 解析 raw 的 scheme 前缀：命中 RPC 别名时返回目标传输
// scheme、"://" 之后的原始剩余内容与 true；未命中时返回零值与 false。
// 该函数是跨包共享的唯一切片/替换逻辑，proxy 与 dataplane 据此改写原 URL 串。
func RPCUpstreamAliasForURL(raw string) (transport string, rest string, ok bool) {
	return schemealias.AliasForURL(raw)
}

// NormalizeUpstreamURLPrefix 展开 raw 开头的 RPC 别名前缀（tls/grpcs 系列
// -> https、grpc -> h2c），保持 "://" 之后的内容不变；其余 scheme 原样返回，
// 旧四前缀行为不变。
func NormalizeUpstreamURLPrefix(raw string) string {
	return schemealias.NormalizeURLPrefix(raw)
}
