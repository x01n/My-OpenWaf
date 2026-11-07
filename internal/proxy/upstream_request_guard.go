package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/net/http/httpguts"
)

var (
	upstreamHeaderNameDroppedCounter     atomic.Uint64
	upstreamHeaderValueDroppedCounter    atomic.Uint64
	upstreamPathSanitizedCounter         atomic.Uint64
	upstreamSecurityHeaderDroppedCounter atomic.Uint64
)

const maxLoggedDroppedHeaderNames = 4

// maxLoggedDroppedHeaderNameBytes 限制单个头名在日志里的保留长度。
const maxLoggedDroppedHeaderNameBytes = 64

// UpstreamRequestGuardStats 是上游请求净化器的累计计数快照。
type UpstreamRequestGuardStats struct {
	// DroppedHeaderNames 是被丢弃的非法头名个数（按头字段计，非按值计）。
	DroppedHeaderNames uint64
	// DroppedHeaderValues 是被丢弃的非法头值个数。
	DroppedHeaderValues uint64
	// SanitizedPaths 是被转义过裸 '%' 的请求个数。
	SanitizedPaths uint64
	// DroppedSecurityHeaderNames 是被整体丢弃的安全相关头个数
	// （Authorization / Cookie / X-Forwarded-* 等，见 isSecurityRelevantOutboundHeader）。
	// 单列一格是因为它改变了上游看到的身份与来源，与普通畸形头不是一回事。
	DroppedSecurityHeaderNames uint64
}

/**
 * UpstreamRequestGuardSnapshot 返回净化器的累计计数。
 *
 * @return 计数快照。
 */
func UpstreamRequestGuardSnapshot() UpstreamRequestGuardStats {
	return UpstreamRequestGuardStats{
		DroppedHeaderNames:         upstreamHeaderNameDroppedCounter.Load(),
		DroppedHeaderValues:        upstreamHeaderValueDroppedCounter.Load(),
		SanitizedPaths:             upstreamPathSanitizedCounter.Load(),
		DroppedSecurityHeaderNames: upstreamSecurityHeaderDroppedCounter.Load(),
	}
}

/**
 * sanitizeUpstreamHeaders 就地删除无法通过 net/http 出站校验的请求头。
 *
 * @param header 待净化的出站请求头；就地修改。
 */
func sanitizeUpstreamHeaders(header http.Header) {
	if len(header) == 0 {
		return
	}
	droppedNames := 0
	droppedValues := 0
	droppedSecurityNames := 0
	var sample []string
	for name, values := range header {
		if !httpguts.ValidHeaderFieldName(name) {
			delete(header, name)
			droppedNames++
			if len(sample) < maxLoggedDroppedHeaderNames {
				sample = append(sample, truncateHeaderNameForLog(name))
			}
			continue
		}
		if len(values) == 0 {
			continue
		}
		kept := values[:0]
		for _, value := range values {
			if httpguts.ValidHeaderFieldValue(value) {
				kept = append(kept, value)
				continue
			}
			droppedValues++
		}
		switch {
		case len(kept) == 0:
			delete(header, name)
			if isSecurityRelevantOutboundHeader(name) {
				droppedSecurityNames++
			}
		case len(kept) != len(values):
			header[name] = kept
		}
	}
	if droppedNames == 0 && droppedValues == 0 {
		return
	}
	upstreamHeaderNameDroppedCounter.Add(uint64(droppedNames))
	upstreamHeaderValueDroppedCounter.Add(uint64(droppedValues))
	securityTotal := uint64(0)
	if droppedSecurityNames > 0 {
		securityTotal = upstreamSecurityHeaderDroppedCounter.Add(uint64(droppedSecurityNames))
	}
	// 头名由客户端控制，只记截断后的样本，完整取值一律不落日志。
	logger := slog.Default()
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		logger.Debug("upstream request headers dropped before dispatch",
			slog.Int("dropped_names", droppedNames),
			slog.Int("dropped_values", droppedValues),
			slog.Int("dropped_security_names", droppedSecurityNames),
			slog.Any("sample_names", sample))
	}
	// 安全相关头被整体丢弃时升到 WARN：这条路径不改变请求的成败，客户端与
	// 上游都看不到异常，只有本日志能证明它发生过。沿用上游错误日志的抽样
	// 规则（首见 + 每 1024 条一条），避免刷屏。
	if droppedSecurityNames > 0 && shouldLogUpstreamErrorCount(securityTotal) {
		logger.Warn("upstream security-relevant request headers dropped before dispatch",
			slog.Any("sample_names", sample),
			slog.Uint64("dropped_security_names_total", securityTotal))
	}
}

/**
 * isSecurityRelevantOutboundHeader 判断头名是否属于「被丢掉会改变上游安全语义」的一类。
 *
 * @param name 出站头名（net/http 的 Header map 键，可能是任意大小写）。
 * @return 属于安全相关头时为 true。
 */
func isSecurityRelevantOutboundHeader(name string) bool {
	switch {
	case strings.EqualFold(name, "Authorization"),
		strings.EqualFold(name, "Cookie"),
		strings.EqualFold(name, "Proxy-Authorization"),
		strings.EqualFold(name, "X-Forwarded-For"),
		strings.EqualFold(name, "X-Forwarded-Host"),
		strings.EqualFold(name, "X-Forwarded-Proto"),
		strings.EqualFold(name, "X-Real-Ip"),
		strings.EqualFold(name, "Client-Ip"),
		strings.EqualFold(name, "Forwarded"):
		return true
	}
	return false
}

// truncateHeaderNameForLog 截断头名，避免把超长或含非打印字节的取值写进日志。
//
// @param name 原始头名。
// @return 不超过 maxLoggedDroppedHeaderNameBytes 字节的头名。
func truncateHeaderNameForLog(name string) string {
	if len(name) <= maxLoggedDroppedHeaderNameBytes {
		return name
	}
	return name[:maxLoggedDroppedHeaderNameBytes] + "..."
}

func sanitizeRawPercentEscapes(path []byte) []byte {
	first := firstRawPercentEscape(path)
	if first < 0 {
		return nil
	}
	upstreamPathSanitizedCounter.Add(1)
	out := make([]byte, 0, len(path)+8)
	out = append(out, path[:first]...)
	for i := first; i < len(path); i++ {
		if path[i] == '%' && !hasHexPairAt(path, i+1) {
			out = append(out, '%', '2', '5')
			continue
		}
		out = append(out, path[i])
	}
	return out
}

// firstRawPercentEscape 返回第一个裸 '%' 的下标；全部合法时返回 -1。
//
// @param path 原始 path 字节。
// @return 下标或 -1。
func firstRawPercentEscape(path []byte) int {
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		if hasHexPairAt(path, i+1) {
			i += 2
			continue
		}
		return i
	}
	return -1
}

// hasHexPairAt 报告 path[i] 与 path[i+1] 是否都是十六进制位。
//
// @param path 原始 path 字节。
// @param i 待检查的起始下标。
// @return 两个字符都在界内且都是十六进制位时为 true。
func hasHexPairAt(path []byte, i int) bool {
	return i+1 < len(path) && isHexDigit(path[i]) && isHexDigit(path[i+1])
}

// isHexDigit 报告 b 是否 ASCII 十六进制位。
//
// @param b 待检查字节。
// @return 是十六进制位时为 true。
func isHexDigit(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}
