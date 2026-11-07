package site

import (
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

// ccRulesTrigger 模拟 UpdateSite 绑定后的站点快照，用于在不触库的前提下
// 直接调用 ccRulesValidationRequired 判定「本次请求是否必须校验 cc_rules」。
func ccRulesTrigger(t *testing.T, body string, item *store.Site) bool {
	t.Helper()
	if err := shared.BindSiteFromRequestBody([]byte(body), item); err != nil {
		t.Fatalf("bind site body: %v", err)
	}
	return ccRulesValidationRequired([]byte(body), item)
}

/**
 * TestCCRulesValidationTriggerPredicate 锁定「何时必须校验站点级 CC 规则」的判定。
 *
 * 判定必须覆盖三种触发前置条件：
 *   - 请求体显式携带 `cc_rules`（错误提示要指向本次提交的非法内容）；
 *   - 请求体显式携带 `cc_use_custom`（开启站点覆盖必须带合法规则）；
 *   - 站点在本次绑定后已处于「使用自定义 CC 规则」状态（存量脏数据不能继续外流）。
 */
func TestCCRulesValidationTriggerPredicate(t *testing.T) {
	useCustom := true
	notCustom := false

	cases := []struct {
		name string
		body string
		seed *store.Site
		want bool
	}{
		{
			name: "body carries invalid cc_rules",
			body: `{"cc_rules":"[{\"action\":\"unknown\"}]"}`,
			seed: &store.Site{},
			want: true,
		},
		{
			name: "empty cc_rules in body still triggers",
			body: `{"cc_rules":""}`,
			seed: &store.Site{CCUseCustom: &useCustom},
			want: true,
		},
		{
			name: "body turns cc_use_custom on",
			body: `{"cc_use_custom":true}`,
			seed: &store.Site{},
			want: true,
		},
		{
			name: "body does not carry cc fields and site is not custom",
			body: `{"name":"untouched"}`,
			seed: &store.Site{CCUseCustom: &notCustom},
			want: false,
		},
		{
			name: "site already uses custom rules",
			body: `{"name":"untouched"}`,
			seed: &store.Site{CCUseCustom: &useCustom},
			want: true,
		},
		{
			name: "body turns cc_use_custom off with stale rules",
			body: `{"cc_use_custom":false}`,
			seed: &store.Site{CCUseCustom: &useCustom, CCRules: `[{"action":"unknown"}]`},
			want: false, // 切回继承全局时不得被库里遗留的规则挡住
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := *tc.seed
			if got := ccRulesTrigger(t, tc.body, &item); got != tc.want {
				t.Fatalf("ccRulesValidationRequired = %v, want %v", got, tc.want)
			}
		})
	}
}
