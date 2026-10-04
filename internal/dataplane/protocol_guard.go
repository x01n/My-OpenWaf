package dataplane

import (
	"net"
	"reflect"

	dpstream "My-OpenWaf/internal/dataplane/stream"
	"My-OpenWaf/internal/waf/drop"

	"github.com/cloudwego/hertz/pkg/app"
)

type InboundProtocolGuard struct {
	protocol string // "http/1.1" / "http/1.0" / "http/2.0" / "h2" / "h3" / ""(未知)
	conn     any    // 请求处理开始时捕获的连接(h1 为 *fixURIHertzConn/TlsConn)
}

/**
 * NewInboundProtocolGuard 在 handler 入口捕获协议与连接。构造零反射:
 * 6 层包裹解包(rawTCPConnForRST)由 CloseForDrop 在执行 RST 的瞬间按需做
 * 一次——绝大多数请求不会触发 drop,热路径不再为每个安全判定付反射成本
 * (r7.45 性能修正,此前的 hasRaw 构造期缓存已被移除)。
 */
func NewInboundProtocolGuard(c *app.RequestContext) *InboundProtocolGuard {
	if c == nil {
		return &InboundProtocolGuard{}
	}
	var conn any
	if c.GetConn() != nil {
		conn = c.GetConn()
	}
	return &InboundProtocolGuard{
		protocol: normalizeHTTPProtocol(c.Request.Header.GetProtocol()),
		conn:     conn,
	}
}

/**
 * ProtocolName 返回 handler 入口处捕获并归一化后的入站协议；
 * 返回空串表示协议未知或上下文为 nil。
 */
func (g *InboundProtocolGuard) ProtocolName() string {
	if g == nil {
		return ""
	}
	return g.protocol
}

func (g *InboundProtocolGuard) IsStreamMultiplexed() bool {
	if g == nil {
		return true
	}
	return g.protocol != "http/1.1" && g.protocol != "http/1.0"
}

func (g *InboundProtocolGuard) tcpDropTarget() net.Conn {
	if g == nil || g.conn == nil {
		return nil
	}
	if g.IsStreamMultiplexed() {
		return nil
	}
	return rawTCPConnForRST(g.conn)
}

func (g *InboundProtocolGuard) CloseForDrop() bool {
	target := g.tcpDropTarget()
	if target == nil {
		return false
	}
	if cur := rawTCPConnForRST(g.conn); !sameNetAddr(cur, target) {
		return false
	}
	_ = target.Close()
	return true
}

/**
 * Execute 执行带统计的 TCP drop：
 *   - guard 为惰性构建：通用 drop 判定（bot/IP 声誉等非检测相位）不构建 guard
 *     （nil），此时直接走 executor 的 nil-conn 路径，等价于旧版无条件
 *     conn.Close 分支的空操作——语义无损且省去 6 层反射；
 *   - guard 非 nil（OWASP/CVE 检测相位）时执行真实 CloseForDrop 并判定
 *     是否成功（含多路复用/未知协议回落）。
 */
func (g *InboundProtocolGuard) Execute(executor *drop.DropExecutor, reason drop.DropReason) bool {
	if g == nil {
		if executor != nil {
			_ = executor.Execute(nil, reason)
		}
		return true
	}
	if g.CloseForDrop() {
		if executor != nil {
			_ = executor.Execute(rawTCPConnForRST(g.conn), reason)
		}
		return true
	}
	// 多路复用/未知协议：连接不可触碰，由调用方以 HTTP 级响应（502）收尾。
	return false
}

func RawTCPConnForRST(conn any) net.Conn {
	return rawTCPConnForRST(conn)
}

/**
 * RawTCPConn 返回解包后的 TCP 基础连接，没有则返回 nil。
 * 测试用它来对回环监听器的连接做同一性断言。
 */
func (g *InboundProtocolGuard) RawTCPConn() net.Conn {
	if g == nil {
		return nil
	}
	return rawTCPConnForRST(g.conn)
}

func rawTCPConnForRST(conn any) net.Conn {
	cur := conn
	seen := map[any]struct{}{}
	for i := 0; i < 6 && cur != nil; i++ {
		if _, dup := seen[cur]; dup {
			return nil
		}
		seen[cur] = struct{}{}
		if tc, ok := cur.(*net.TCPConn); ok {
			return tc
		}
		cur = nextConnLink(cur)
	}
	return nil
}

func nextConnLink(conn any) net.Conn {
	switch c := conn.(type) {
	case net.Conn:
		return connLinkOrNil(c)
	default:
		return nil
	}
}

func connLinkOrNil(conn net.Conn) net.Conn {
	v := reflect.ValueOf(conn)
	if !v.IsValid() {
		return nil
	}
	v = dpstream.AccessibleValue(v)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil
	}
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return nil
	}
	return firstConnField(elem)
}

func firstConnField(elem reflect.Value) net.Conn {
	for i := 0; i < elem.NumField(); i++ {
		field := dpstream.AccessibleValue(elem.Field(i))
		if !field.IsValid() {
			continue
		}
		if field.Kind() == reflect.Pointer && field.IsNil() {
			continue
		}
		if c, ok := field.Interface().(net.Conn); ok && c != nil {
			return c
		}
	}
	return nil
}

func sameNetAddr(a, b net.Conn) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	la, ra := a.LocalAddr(), a.RemoteAddr()
	lb, rb := b.LocalAddr(), b.RemoteAddr()
	if la == nil || ra == nil || lb == nil || rb == nil {
		return false
	}
	return la.String() == lb.String() && ra.String() == rb.String()
}
