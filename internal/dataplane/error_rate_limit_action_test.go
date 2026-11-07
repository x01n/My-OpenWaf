package dataplane

import (
	"testing"

	"My-OpenWaf/internal/core/action"
)

/**
 * TestErrorRateLimitActionFallsBackToInterceptForInvalidAction 锁定错误限流的动作兜底语义。
 *
 * 数据库被直接改写、或历史版本写入未注册动作名时，action.Normalize 会把未知串
 * 原样返回。若不校验 action.IsValid，Result 会带着非终止动作放行到上游，且
 * ShouldLog 为 false，错误限流静默失效。这里逐条锁定归一化结果与状态码。
 */
func TestErrorRateLimitActionFallsBackToInterceptForInvalidAction(t *testing.T) {
	cases := []struct {
		name         string
		configured   string
		wantType     action.Type
		wantStatus   int
		wantTerminal bool
	}{
		{name: "invalid captcha alias", configured: "captcha", wantType: action.Intercept, wantStatus: 0, wantTerminal: true},
		{name: "invalid uppercase captcha alias", configured: "CAPTCHA", wantType: action.Intercept, wantStatus: 0, wantTerminal: true},
		{name: "unknown action name", configured: "unknown_action", wantType: action.Intercept, wantStatus: 0, wantTerminal: true},
		{name: "legacy block normalizes to intercept", configured: "block", wantType: action.Intercept, wantStatus: 0, wantTerminal: true},
		{name: "legacy log_only normalizes to observe", configured: "log_only", wantType: action.Observe, wantStatus: 0, wantTerminal: false},
		{name: "explicit rate_limit keeps 429", configured: "rate_limit", wantType: action.RateLimit, wantStatus: 429, wantTerminal: true},
		{name: "empty defaults to rate_limit", configured: "", wantType: action.RateLimit, wantStatus: 429, wantTerminal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := errorRateLimitAction(tc.configured)
			if got.Type != tc.wantType {
				t.Fatalf("errorRateLimitAction(%q).Type = %q, want %q", tc.configured, got.Type, tc.wantType)
			}
			if got.StatusCode != tc.wantStatus {
				t.Fatalf("errorRateLimitAction(%q).StatusCode = %d, want %d", tc.configured, got.StatusCode, tc.wantStatus)
			}
			if got.IsTerminal() != tc.wantTerminal {
				t.Fatalf("errorRateLimitAction(%q).IsTerminal() = %v, want %v", tc.configured, got.IsTerminal(), tc.wantTerminal)
			}
			if !got.ShouldLog() {
				t.Fatalf("errorRateLimitAction(%q).ShouldLog() = false, want true", tc.configured)
			}
			if !got.Matched || got.Phase != "error_rate_limit" || got.RuleIDStr != "error_rate_limit" {
				t.Fatalf("errorRateLimitAction(%q) identity = %#v", tc.configured, got)
			}
			if !action.IsValid(got.Type) {
				t.Fatalf("errorRateLimitAction(%q).Type = %q is not a valid runtime action", tc.configured, got.Type)
			}
		})
	}
}

/**
 * TestErrorRateLimitActionInvalidCaptchaIsTerminalAndLogged 锁定兜底后的可观测性。
 *
 * "captcha" 不是注册动作（注册的是 captcha_challenge），兜底为 intercept 后必须
 * 同时满足 IsTerminal（短路管道，不访问上游）与 ShouldLog（写入安全事件）。
 */
func TestErrorRateLimitActionInvalidCaptchaIsTerminalAndLogged(t *testing.T) {
	got := errorRateLimitAction("captcha")
	if !got.IsTerminal() {
		t.Fatalf("errorRateLimitAction(captcha).IsTerminal() = false, want true (Type = %q)", got.Type)
	}
	if !got.ShouldLog() {
		t.Fatalf("errorRateLimitAction(captcha).ShouldLog() = false, want true (Type = %q)", got.Type)
	}
}
