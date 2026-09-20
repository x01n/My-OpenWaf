package snapshot

import (
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * TestMergeProtectionRateLimitPartialOverrides 覆盖 mergeProtection 对
 * rate_limit 组件的「部分覆盖」语义：
 *   - enabled 非 nil 时：window/max 仅在 >0 时覆盖、action 仅在非空时覆盖，
 *     其余保持全局值；
 *   - enabled 为 nil 时：window/max/action 即便被赋值也全部忽略（继承全局）。
 */
func TestMergeProtectionRateLimitPartialOverrides(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.RequestRateLimitEnabled = true
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300
	global.RequestRateLimitAction = "rate_limit"

	enabled := true
	partial := mergeProtection(global, store.Site{
		RateLimitEnabled: &enabled,
		RateLimitMax:     10,
	})
	if !partial.RequestRateLimitEnabled {
		t.Fatal("enabled override should apply")
	}
	if partial.RequestRateLimitWindow != 60 {
		t.Fatalf("window = %d, want global 60 (window > 0 required for override)", partial.RequestRateLimitWindow)
	}
	if partial.RequestRateLimitMax != 10 {
		t.Fatalf("max = %d, want site 10", partial.RequestRateLimitMax)
	}
	if partial.RequestRateLimitAction != "rate_limit" {
		t.Fatalf("action = %q, want global %q (empty action inherits)", partial.RequestRateLimitAction, "rate_limit")
	}

	actionOnly := mergeProtection(global, store.Site{
		RateLimitEnabled: &enabled,
		RateLimitAction:  "drop",
	})
	if !actionOnly.RequestRateLimitEnabled {
		t.Fatal("enabled override should apply")
	}
	if actionOnly.RequestRateLimitWindow != 60 || actionOnly.RequestRateLimitMax != 300 {
		t.Fatalf("window/max = %d/%d, want global 60/300", actionOnly.RequestRateLimitWindow, actionOnly.RequestRateLimitMax)
	}
	if actionOnly.RequestRateLimitAction != "drop" {
		t.Fatalf("action = %q, want site %q", actionOnly.RequestRateLimitAction, "drop")
	}

	inherited := mergeProtection(global, store.Site{
		// RateLimitEnabled == nil：从属字段必须全部被忽略。
		RateLimitWindow: 1,
		RateLimitMax:    1,
		RateLimitAction: "drop",
	})
	if !inherited.RequestRateLimitEnabled ||
		inherited.RequestRateLimitWindow != 60 ||
		inherited.RequestRateLimitMax != 300 ||
		inherited.RequestRateLimitAction != "rate_limit" {
		t.Fatalf("nil enabled should keep global values, got %+v", inherited)
	}
}

/**
 * TestMergeProtectionOWASPSiteEmptyMaxKeepsGlobal 固定 mergeProtection 的覆盖条件：
 * max <= 0 不覆盖全局值。配合 TestMergeProtectionRateLimitPartialOverrides 共同
 * 锚定 window/max >0、action/sensitivity 非空这四个覆盖条件。
 */
func TestMergeProtectionOWASPSiteEmptyMaxKeepsGlobal(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.RequestRateLimitEnabled = true
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300

	enabled := true
	merged := mergeProtection(global, store.Site{
		RateLimitEnabled: &enabled,
		RateLimitWindow:  30,
		RateLimitMax:     0, // 前端缺省 0：覆盖条件要求 >0，全局值保留
	})
	if !merged.RequestRateLimitEnabled || merged.RequestRateLimitWindow != 30 {
		t.Fatalf("enabled/window override should apply, got %+v", merged)
	}
	if merged.RequestRateLimitMax != 300 {
		t.Fatalf("max = %d, want global 300 (max > 0 required for override)", merged.RequestRateLimitMax)
	}
}
