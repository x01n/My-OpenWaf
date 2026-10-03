package jsplugin

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCanonicalizeMutationPlanAcceptsLuaAliases 锁定「JS 也接受 Lua 写法」这一
// 契约：status_code / response_body / headers 三个键在对应阶段等价于规范键。
func TestCanonicalizeMutationPlanAcceptsLuaAliases(t *testing.T) {
	encoded, err := canonicalizeMutationPlan(`{"status_code":403,"response_body":"denied","headers":{"X-Test":"1"}}`, true)
	if err != nil {
		t.Fatalf("canonicalize response plan error = %v", err)
	}
	var plan ResponseMutationPlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		t.Fatalf("unmarshal canonical plan error = %v", err)
	}
	if plan.Status == nil || *plan.Status != 403 {
		t.Fatalf("status = %v, want 403", plan.Status)
	}
	if plan.Body == nil || *plan.Body != "denied" {
		t.Fatalf("body = %v, want denied", plan.Body)
	}
	if plan.SetHeaders["X-Test"] != "1" {
		t.Fatalf("set headers = %#v, want X-Test=1", plan.SetHeaders)
	}

	encoded, err = canonicalizeMutationPlan(`{"headers":{"X-Test":"1"}}`, false)
	if err != nil {
		t.Fatalf("canonicalize request plan error = %v", err)
	}
	var requestPlan MutationPlan
	if err := json.Unmarshal(encoded, &requestPlan); err != nil {
		t.Fatalf("unmarshal canonical request plan error = %v", err)
	}
	if requestPlan.SetHeaders["X-Test"] != "1" {
		t.Fatalf("request set headers = %#v, want X-Test=1", requestPlan.SetHeaders)
	}
}

// TestCanonicalizeMutationPlanRejectsAliasAndCanonicalTogether 锁定「不静默取舍」：
// 同一语义同时给规范键与别名时报错，用户才能在脚本日志里看到冲突。
func TestCanonicalizeMutationPlanRejectsAliasAndCanonicalTogether(t *testing.T) {
	_, err := canonicalizeMutationPlan(`{"status":200,"status_code":403}`, true)
	if err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("conflicting canonical/alias keys error = %v, want alias conflict", err)
	}
	_, err = canonicalizeMutationPlan(`{"set_headers":{"A":"1"},"headers":{"B":"2"}}`, false)
	if err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("conflicting request alias keys error = %v, want alias conflict", err)
	}
}

// TestCanonicalizeMutationPlanAcceptsDeleteHeadersObject 锁定用户实测的
// delete_headers: {"x": true} 写法。
func TestCanonicalizeMutationPlanAcceptsDeleteHeadersObject(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		deleted []string
	}{
		{name: "true marker", raw: `{"delete_headers":{"X-Drop":true,"X-Keep":false}}`, deleted: []string{"X-Drop"}},
		{name: "numeric marker", raw: `{"delete_headers":{"X-Drop":1,"X-Keep":0}}`, deleted: []string{"X-Drop"}},
		{name: "string marker", raw: `{"delete_headers":{"X-Drop":"yes","X-Keep":""}}`, deleted: []string{"X-Drop"}},
		{name: "null marker", raw: `{"delete_headers":{"X-Keep":null}}`, deleted: nil},
		{name: "deterministic order", raw: `{"delete_headers":{"b":true,"a":true,"c":true}}`, deleted: []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := canonicalizeMutationPlan(tc.raw, false)
			if err != nil {
				t.Fatalf("canonicalize error = %v", err)
			}
			var plan MutationPlan
			if err := json.Unmarshal(encoded, &plan); err != nil {
				t.Fatalf("unmarshal error = %v", err)
			}
			if len(plan.DeleteHeaders) != len(tc.deleted) {
				t.Fatalf("delete headers = %#v, want %#v", plan.DeleteHeaders, tc.deleted)
			}
			for i, name := range tc.deleted {
				if plan.DeleteHeaders[i] != name {
					t.Fatalf("delete headers = %#v, want %#v", plan.DeleteHeaders, tc.deleted)
				}
			}
		})
	}
}

// TestCanonicalizeMutationPlanKeepsDeleteHeadersArray 确认既有的数组写法零改动。
func TestCanonicalizeMutationPlanKeepsDeleteHeadersArray(t *testing.T) {
	encoded, err := canonicalizeMutationPlan(`{"delete_headers":["X-One","X-Two"]}`, true)
	if err != nil {
		t.Fatalf("canonicalize error = %v", err)
	}
	var plan ResponseMutationPlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}
	if len(plan.DeleteHeaders) != 2 || plan.DeleteHeaders[0] != "X-One" || plan.DeleteHeaders[1] != "X-Two" {
		t.Fatalf("delete headers = %#v, want [X-One X-Two]", plan.DeleteHeaders)
	}
}

// TestCanonicalizeMutationPlanRejectsUnusableShapes 锁定失败可见性：这些输入
// 必须报错而不是静默丢弃字段。
func TestCanonicalizeMutationPlanRejectsUnusableShapes(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		isResponse bool
	}{
		{name: "delete headers scalar", raw: `{"delete_headers":"X-Drop"}`},
		{name: "delete headers nested object", raw: `{"delete_headers":{"X-Drop":{"nested":true}}}`},
		{name: "delete headers nested array", raw: `{"delete_headers":{"X-Drop":["a"]}}`},
		{name: "plan is not object", raw: `["X-Drop"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := canonicalizeMutationPlan(tc.raw, tc.isResponse); err == nil {
				t.Fatalf("canonicalize(%s) error = nil, want error", tc.raw)
			}
		})
	}
}

// TestCanonicalizeMutationPlanLeavesTypeErrorsToUnmarshal 锁定分层：折叠只负责
// 键名与形状，别名值类型不对由随后的结构反序列化报出，错误同样可见。
func TestCanonicalizeMutationPlanLeavesTypeErrorsToUnmarshal(t *testing.T) {
	encoded, err := canonicalizeMutationPlan(`{"status_code":"403"}`, true)
	if err != nil {
		t.Fatalf("canonicalize error = %v", err)
	}
	var plan ResponseMutationPlan
	if err := json.Unmarshal(encoded, &plan); err == nil {
		t.Fatalf("string status_code unmarshalled into %#v, want type error", plan)
	}
}

// TestCanonicalizeMutationPlanPreservesOversizedValues 确认折叠不会替校验层
// 吞掉超长值：体积上限仍由 validateMutationPlan / ValidateResponseMutationPlan 报出。
func TestCanonicalizeMutationPlanPreservesOversizedValues(t *testing.T) {
	body := strings.Repeat("x", MaxMutationStringBytes+1)
	encoded, err := canonicalizeMutationPlan(`{"response_body":"`+body+`"}`, true)
	if err != nil {
		t.Fatalf("canonicalize error = %v", err)
	}
	var plan ResponseMutationPlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}
	if err := ValidateResponseMutationPlan(plan); err == nil {
		t.Fatal("oversized alias body was accepted by response validation")
	}
}

// TestAllowedMutationPlanFieldAcceptsAliases 锁定形状白名单与折叠表同源：
// 别名键必须通过形状检查，否则折叠逻辑永远走不到。
func TestAllowedMutationPlanFieldAcceptsAliases(t *testing.T) {
	for name := range mutationPlanAliases(true) {
		if !allowedMutationPlanField(name, true) {
			t.Fatalf("response alias %q rejected by shape check", name)
		}
	}
	for name := range mutationPlanAliases(false) {
		if !allowedMutationPlanField(name, false) {
			t.Fatalf("request alias %q rejected by shape check", name)
		}
	}
	// 请求阶段的裁决字段必须全部被形状检查接受，否则脚本给出的裁决会被
	// 「unknown field」挡在门外——这是本次新增能力最容易踩的死路。
	for _, name := range []string{"action", "status_code", "response_body", "redirect_to", "message", "tags"} {
		if !allowedMutationPlanField(name, false) {
			t.Fatalf("request verdict field %q rejected by shape check", name)
		}
	}
	if allowedMutationPlanField("unknown_field", true) || allowedMutationPlanField("unknown_field", false) {
		t.Fatal("unknown field accepted by shape check")
	}
}

// TestValidateMutationVerdict 锁定动作词汇与内置 action 包同源：合法动作
// 通过，未知动作被拒绝而不是静默放行。
func TestValidateMutationVerdict(t *testing.T) {
	actionValue := func(value string) *string { return &value }
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("block")}); err != nil {
		t.Fatalf("legacy action block rejected: %v", err)
	}
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("captcha_challenge")}); err != nil {
		t.Fatalf("captcha_challenge rejected: %v", err)
	}
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("blcok")}); err == nil {
		t.Fatal("unknown action accepted")
	}
	target := "https://example.test/x"
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("redirect"), RedirectTo: &target}); err != nil {
		t.Fatalf("valid redirect target rejected: %v", err)
	}
	for _, bad := range []string{"//evil.example", "javascript:alert(1)", "evil.example/x", ""} {
		value := bad
		if err := ValidateMutationPlan(MutationPlan{Action: actionValue("redirect"), RedirectTo: &value}); err == nil {
			t.Fatalf("redirect target %q accepted", bad)
		}
	}
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("intercept"), StatusCode: intValue(0)}); err != nil {
		t.Fatalf("status_code with 0 rejected: %v", err)
	}
	if err := ValidateMutationPlan(MutationPlan{Action: actionValue("intercept"), StatusCode: intValue(1000)}); err == nil {
		t.Fatal("status_code 1000 accepted")
	}
}

func intValue(value int) *int { return &value }
