package luaplugin

import (
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// newDecisionTable 用给定的 Lua 源码片段构造返回值表，复用真实的
// decisionFromTable 路径——测试要覆盖的是用户实际写出的脚本形态。
func decisionFromSource(t *testing.T, source string) Decision {
	t.Helper()
	L := lua.NewState()
	defer L.Close()
	if err := L.DoString("result = " + source); err != nil {
		t.Fatalf("lua source %q failed: %v", source, err)
	}
	dec, err := decisionFromLua(L.GetGlobal("result"))
	if err != nil {
		t.Fatalf("decisionFromLua(%q) error = %v", source, err)
	}
	return dec
}

// TestDecisionParsesRequestMutation 锁定 pre 阶段请求改写契约：方法、路径、
// 查询、请求体、请求头增删全部可从脚本读出。
func TestDecisionParsesRequestMutation(t *testing.T) {
	dec := decisionFromSource(t, `{
		request = {
			method = "POST",
			path = "/internal/api",
			query = "debug=1",
			body = "rewritten",
			headers = { ["X-Internal"] = "1" },
			delete_headers = { "X-Remove" }
		}
	}`)
	mutation := dec.RequestMutation
	if mutation == nil {
		t.Fatal("RequestMutation = nil, want parsed mutation")
	}
	if mutation.Method == nil || *mutation.Method != "POST" {
		t.Fatalf("method = %v, want POST", mutation.Method)
	}
	if mutation.Path == nil || *mutation.Path != "/internal/api" {
		t.Fatalf("path = %v, want /internal/api", mutation.Path)
	}
	if mutation.RawQuery == nil || *mutation.RawQuery != "debug=1" {
		t.Fatalf("raw query = %v, want debug=1", mutation.RawQuery)
	}
	if mutation.Body == nil || *mutation.Body != "rewritten" {
		t.Fatalf("body = %v, want rewritten", mutation.Body)
	}
	if mutation.SetHeaders["X-Internal"] != "1" {
		t.Fatalf("set headers = %#v", mutation.SetHeaders)
	}
	if len(mutation.DeleteHeaders) != 1 || mutation.DeleteHeaders[0] != "X-Remove" {
		t.Fatalf("delete headers = %#v, want [X-Remove]", mutation.DeleteHeaders)
	}
}

// TestDecisionParsesRequestMutationAliases 锁定别名与对象形态的删除表：
// raw_query 与 query 等价、set_headers 与 headers 等价、delete_headers 数组
// 与对象都接受。
func TestDecisionParsesRequestMutationAliases(t *testing.T) {
	dec := decisionFromSource(t, `{
		request = {
			raw_query = "a=1",
			set_headers = { ["X-A"] = "b" },
			delete_headers = { ["X-B"] = true, ["X-Keep"] = false }
		}
	}`)
	mutation := dec.RequestMutation
	if mutation == nil {
		t.Fatal("RequestMutation = nil")
	}
	if mutation.RawQuery == nil || *mutation.RawQuery != "a=1" {
		t.Fatalf("raw query = %v, want a=1", mutation.RawQuery)
	}
	if mutation.SetHeaders["X-A"] != "b" {
		t.Fatalf("set headers = %#v", mutation.SetHeaders)
	}
	if len(mutation.DeleteHeaders) != 1 || mutation.DeleteHeaders[0] != "X-B" {
		t.Fatalf("delete headers = %#v, want [X-B]", mutation.DeleteHeaders)
	}
}

// TestDecisionRejectsUnsafeRequestMutation 锁定安全边界：绝对 URL、协议相对
// 路径、禁用头、CR/LF 值一律不接受；非法项被丢弃而不是让整份判定失败。
func TestDecisionRejectsUnsafeRequestMutation(t *testing.T) {
	dec := decisionFromSource(t, `{
		request = {
			method = "GET /admin",
			path = "//evil.example/x",
			query = "a=1#fragment",
			headers = { ["Host"] = "evil.example", ["X-Ok"] = "v" },
			delete_headers = { "Content-Length" }
		}
	}`)
	mutation := dec.RequestMutation
	if mutation == nil {
		t.Fatal("RequestMutation = nil")
	}
	if mutation.Method != nil {
		t.Fatalf("method = %v, want rejected", *mutation.Method)
	}
	if mutation.Path != nil {
		t.Fatalf("path = %v, want rejected", *mutation.Path)
	}
	if mutation.RawQuery != nil {
		t.Fatalf("raw query = %v, want rejected", *mutation.RawQuery)
	}
	if _, exists := mutation.SetHeaders["Host"]; exists {
		t.Fatalf("Host header accepted: %#v", mutation.SetHeaders)
	}
	if mutation.SetHeaders["X-Ok"] != "v" {
		t.Fatalf("valid header dropped: %#v", mutation.SetHeaders)
	}
	if mutation.DeleteHeaders != nil {
		t.Fatalf("delete headers = %#v, want nil (Content-Length rejected)", mutation.DeleteHeaders)
	}
}

// TestDecisionParsesResponseMutation 锁定 post 阶段响应改写契约。
func TestDecisionParsesResponseMutation(t *testing.T) {
	dec := decisionFromSource(t, `{
		response = {
			status_code = 503,
			body = "maintenance",
			headers = { ["X-Served-By"] = "waf" },
			delete_headers = { "X-Upstream" }
		}
	}`)
	mutation := dec.ResponseMutation
	if mutation == nil {
		t.Fatal("ResponseMutation = nil")
	}
	if mutation.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", mutation.StatusCode)
	}
	if mutation.Body == nil || *mutation.Body != "maintenance" {
		t.Fatalf("body = %v", mutation.Body)
	}
	if mutation.SetHeaders["X-Served-By"] != "waf" {
		t.Fatalf("set headers = %#v", mutation.SetHeaders)
	}
	if len(mutation.DeleteHeaders) != 1 || mutation.DeleteHeaders[0] != "X-Upstream" {
		t.Fatalf("delete headers = %#v", mutation.DeleteHeaders)
	}
}

// TestDecisionRejectsUnsafeResponseMutation 锁定响应侧边界：状态码越界被拒、
// 认证头不可写、带认证秘密的响应体不反射。全部条目都被拒时整条改写通道为
// nil——「没有任何合法改写生效」与「没有改写」对宿主是同一件事。
func TestDecisionRejectsUnsafeResponseMutation(t *testing.T) {
	dec := decisionFromSource(t, `{
		response = {
			status_code = 42,
			headers = { ["Set-Cookie"] = "a=b" },
			body = "Authorization: bearer secret"
		}
	}`)
	if dec.ResponseMutation != nil {
		t.Fatalf("ResponseMutation = %#v, want nil (every entry rejected)", dec.ResponseMutation)
	}
}

// TestDecisionKeepsValidEntriesWhenOthersRejected 确认非法条目只丢自己：
// 同一次改写里的合法部分照常生效。
func TestDecisionKeepsValidEntriesWhenOthersRejected(t *testing.T) {
	dec := decisionFromSource(t, `{
		response = {
			status_code = 42,
			headers = { ["Set-Cookie"] = "a=b", ["X-Ok"] = "v" },
			body = "plain"
		}
	}`)
	mutation := dec.ResponseMutation
	if mutation == nil {
		t.Fatal("ResponseMutation = nil, want the valid entries")
	}
	if mutation.StatusCode != 0 {
		t.Fatalf("status = %d, want rejected", mutation.StatusCode)
	}
	if mutation.SetHeaders["X-Ok"] != "v" || len(mutation.SetHeaders) != 1 {
		t.Fatalf("set headers = %#v, want only X-Ok", mutation.SetHeaders)
	}
	if mutation.Body == nil || *mutation.Body != "plain" {
		t.Fatalf("body = %v, want plain", mutation.Body)
	}
}

// TestDecisionWithoutMutationsKeepsVerdictSemantics 确认没有 request/response
// 子表时两条改写通道都是 nil，既有判定语义不受影响。
func TestDecisionWithoutMutationsKeepsVerdictSemantics(t *testing.T) {
	dec := decisionFromSource(t, `{action = "intercept", response_body = "blocked"}`)
	if dec.RequestMutation != nil || dec.ResponseMutation != nil {
		t.Fatalf("mutations = %#v / %#v, want nil", dec.RequestMutation, dec.ResponseMutation)
	}
	if dec.Action != "intercept" || dec.ResponseBody != "blocked" {
		t.Fatalf("verdict changed: %#v", dec)
	}
}

// TestDecisionRequestMutationBodyTruncated 确认超长请求体被截断到上限而不是
// 原样带出（沙箱出口必须有界）。
func TestDecisionRequestMutationBodyTruncated(t *testing.T) {
	payload := strings.Repeat("x", maxMutationBodyBytes+512)
	dec := decisionFromSource(t, `{request = {body = "`+payload+`"}}`)
	if dec.RequestMutation == nil || dec.RequestMutation.Body == nil {
		t.Fatal("RequestMutation body = nil")
	}
	if len(*dec.RequestMutation.Body) != maxMutationBodyBytes {
		t.Fatalf("body length = %d, want %d", len(*dec.RequestMutation.Body), maxMutationBodyBytes)
	}
}
