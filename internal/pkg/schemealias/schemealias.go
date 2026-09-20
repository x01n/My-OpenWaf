package schemealias

import "strings"

// rpcSchemeAliases 是 RPC 相关 URL 前缀到传输 scheme 的映射。
// 键为小写且带 "://" 后缀；大小写由统一折叠入口处理。
var rpcSchemeAliases = map[string]string{
	"tls://":        "https",
	"grpcs://":      "https",
	"grpc+tls://":   "https",
	"grpc+https://": "https",
	"grpc://":       "h2c",
}

// Scheme 折叠 scheme 大小写并把 RPC 别名展开为传输 scheme：
// tls/grpcs/grpc+tls/grpc+https -> https，grpc -> h2c；其余 scheme 原样小写返回。
// 入参不含 "://" 后缀。
func Scheme(scheme string) string {
	scheme = strings.ToLower(scheme)
	if alias, ok := rpcSchemeAliases[scheme+"://"]; ok {
		return alias
	}
	return scheme
}

// IsRPCScheme 报告 scheme 是否为 RPC 别名（比较前折叠大小写）。
// 入参可为 "grpc" 或 "grpc://" 两种形态。
func IsRPCScheme(scheme string) bool {
	scheme = strings.ToLower(strings.TrimSuffix(scheme, "://"))
	_, ok := rpcSchemeAliases[scheme+"://"]
	return ok
}

// AliasForURL 解析 raw 的 scheme 前缀：命中 RPC 别名时返回目标传输 scheme、
// "://" 之后的原始剩余内容与 true；未命中时返回零值与 false。
// 该函数是跨包共享的唯一切片/替换逻辑，proxy 与 dataplane 据此改写原 URL 串。
func AliasForURL(raw string) (transport string, rest string, ok bool) {
	lower := strings.ToLower(raw)
	for alias, target := range rpcSchemeAliases {
		// 前缀比较按「完整别名 + ://」进行，避免 grpcs 与 grpc 的歧义。
		if strings.HasPrefix(lower, alias) {
			return target, raw[len(alias):], true
		}
	}
	return "", "", false
}

// NormalizeURLPrefix 展开 raw 开头的 RPC 别名前缀（tls/grpcs 系列 -> https、
// grpc -> h2c），保持 "://" 之后的内容不变；其余 scheme 原样返回，
// 旧四前缀行为不变。
func NormalizeURLPrefix(raw string) string {
	if transport, rest, ok := AliasForURL(raw); ok {
		return transport + "://" + rest
	}
	return raw
}
