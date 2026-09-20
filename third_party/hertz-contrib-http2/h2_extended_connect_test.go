/*
 *	Copyright 2022 CloudWeGo Authors
 *
 * 本文件覆盖 My-OpenWaf 对 RFC 8441 扩展 CONNECT 的 fork 侧补丁：
 *  1) 服务端识别扩展 CONNECT 并把 ":protocol" 伪头植入请求头；
 *  2) 缺 ":path" / ":scheme" / ":authority" 或非法 ":protocol" 值
 *     被 PROTOCOL_ERROR 拒绝。
 *
 * 注意：禁与自定义服务器状态断言（testHookGetServerConn/STA）混跑；
 * 全部用例只通过 testServerRequest/testServerRejectsStream 驱动，
 * 与既有 TestServer_Request_Connect* 同构。
 */

package http2

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

// TestServerRequestExtendedConnectProtoHeader 验证带 ":protocol" 的扩展
// CONNECT 到达业务层时伪头以请求头形式可见且 authority/path 保持。
func TestServerRequestExtendedConnectProtoHeader(t *testing.T) {
	var gotProtocol, gotHost, gotPath string
	var gotMethod string
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":protocol", "websocket",
				":scheme", "https",
				":authority", "ws.example.com",
				":path", "/socket",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	}, func(ctx *app.RequestContext) {
		gotMethod = string(ctx.Method())
		gotProtocol = string(ctx.GetHeader(":protocol"))
		gotHost = string(ctx.Host())
		gotPath = string(ctx.Path())
		ctx.Response.SetStatusCode(200)
	})

	if gotMethod != "CONNECT" {
		t.Errorf("Method = %q; want CONNECT", gotMethod)
	}
	if gotProtocol != "websocket" {
		t.Errorf("handler :protocol = %q; want websocket", gotProtocol)
	}
	if gotHost != "ws.example.com" {
		t.Errorf("handler host = %q; want ws.example.com", gotHost)
	}
	if gotPath != "/socket" {
		t.Errorf("handler path = %q; want /socket", gotPath)
	}
}

// TestServerRejectsExtendedConnectWithoutPath 覆盖 RFC 8441 校验：
// 带 ":protocol" 却缺 ":path" 必须按 PROTOCOL_ERROR 拒绝。
func TestServerRejectsExtendedConnectWithoutPath(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":protocol", "websocket",
				":scheme", "https",
				":authority", "ws.example.com",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	})
}

// TestServerRejectsExtendedConnectWithoutScheme 覆盖 RFC 8441 校验：
// 带 ":protocol" 却缺 ":scheme" 必须按 PROTOCOL_ERROR 拒绝。
func TestServerRejectsExtendedConnectWithoutScheme(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":protocol", "websocket",
				":authority", "ws.example.com",
				":path", "/socket",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	})
}

// TestServerRejectsExtendedConnectWithBadProtocolValue 覆盖自定义校验：
// ":protocol" 必须是 RFC 6455 token 形态（无空白/控制字符）。
func TestServerRejectsExtendedConnectWithBadProtocolValue(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":protocol", "bad proto",
				":scheme", "https",
				":authority", "ws.example.com",
				":path", "/socket",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	})
}
