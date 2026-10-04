package app

import (
	"os"

	snapshotpkg "My-OpenWaf/internal/snapshot"
)

/**
 * needsTLSClientHelloFingerprint 决定是否为某个 TLS 监听启用 ClientHello 解析。
 *
 * 默认对所有 TLS 监听都开启，这样即使没有配置任何指纹检测器，普通访问日志与
 * 访客融合分析里仍保留真实的客户端指纹。
 *
 * MY_OPENWAF_H2WS_PEEKER_OFF=1 是只给子进程 h2 WebSocket E2E 用的逃生门：原始 h2
 * 测试客户端在 TLS 握手后立刻写出前言，而带前缀窥探的连接会把这几个字节吃掉。
 * 该环境变量置位时改用普通 FixURIConn 包装监听——它的 h2 零窥探快路径保持扩展
 * CONNECT 语义完好，且 onConnect 里无条件的 setTLSHandshakeInfo 兜底仍会填上
 * tls_version/SNI/ALPN；此时 JA3/JA4 为空属于预期。生产二进制与既有测试都不会
 * 设置该环境变量，因此默认行为逐字节不变。
 *
 * 参数为匿名的站点运行时，保留以匹配监听创建处的调用签名。
 *
 * @return 是否启用 ClientHello 解析。
 */
func needsTLSClientHelloFingerprint(snapshotpkg.SiteRuntime) bool {
	if os.Getenv("MY_OPENWAF_H2WS_PEEKER_OFF") == "1" {
		return false
	}
	return true
}
