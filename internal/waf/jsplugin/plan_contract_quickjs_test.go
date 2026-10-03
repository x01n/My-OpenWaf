//go:build cgo && quickjs

package jsplugin

import (
	"context"
	"testing"
)

// TestQuickJSEngineAcceptsUserReportedResponseScript 用真实 QuickJS 执行用户
// 实测失败的脚本形态：response 阶段写 status_code（Lua 写法）+ delete_headers
// 对象形态。修复前该脚本在形状检查处即失败、计划被静默丢弃。
func TestQuickJSEngineAcceptsUserReportedResponseScript(t *testing.T) {
	script, err := Compile("user-reported-response",
		`export default {
			fetch(response) {
				if (((response.request_headers["x-internal-custom-html"] || "") !== "1")) {
					return null;
				}
				return {
					status_code: 403,
					response_body: "<html><body>forbidden</body></html>",
					delete_headers: {"x-upstream": true},
					headers: {"X-Custom-Page": "1"}
				};
			}
		}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	plan, err := engine.EvaluateResponse(context.Background(), script, ResponseSnapshot{
		SiteID:         1,
		Status:         200,
		Path:           "/",
		RequestHeaders: map[string]string{"x-internal-custom-html": "1"},
	})
	if err != nil {
		t.Fatalf("EvaluateResponse error = %v", err)
	}
	if plan.Status == nil || *plan.Status != 403 {
		t.Fatalf("status = %v, want 403", plan.Status)
	}
	if plan.Body == nil || *plan.Body != "<html><body>forbidden</body></html>" {
		t.Fatalf("body = %v", plan.Body)
	}
	if plan.SetHeaders["X-Custom-Page"] != "1" {
		t.Fatalf("set headers = %#v", plan.SetHeaders)
	}
	if len(plan.DeleteHeaders) != 1 || plan.DeleteHeaders[0] != "x-upstream" {
		t.Fatalf("delete headers = %#v, want [x-upstream]", plan.DeleteHeaders)
	}
	if err := ValidateResponseMutationPlan(plan); err != nil {
		t.Fatalf("ValidateResponseMutationPlan error = %v", err)
	}
}
