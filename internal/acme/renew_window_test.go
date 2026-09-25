package acme

import (
	"testing"
	"time"
)

/**
 * TestShouldRenewAtWindow 验证续期窗口判定：
 * 未到窗口跳过、进入窗口续期、已过期强制续、未知过期时间与未配置窗口保留全量尝试。
 */
func TestShouldRenewAtWindow(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour
	day := 24 * time.Hour

	cases := []struct {
		name      string
		expiresAt time.Time
		renew     time.Duration
		want      bool
	}{
		{name: "未到窗口跳过", expiresAt: now.Add(60 * day), renew: window, want: false},
		{name: "窗口边界外跳过", expiresAt: now.Add(window).Add(time.Hour), renew: window, want: false},
		{name: "窗口边界进入续期", expiresAt: now.Add(window), renew: window, want: true},
		{name: "窗口内续期", expiresAt: now.Add(10 * day), renew: window, want: true},
		{name: "已过期强制续", expiresAt: now.Add(-1 * time.Hour), renew: window, want: true},
		{name: "未知过期时间保留尝试", expiresAt: time.Time{}, renew: window, want: true},
		{name: "未配置窗口全量尝试", expiresAt: now.Add(365 * day), renew: 0, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRenewAt(tc.expiresAt, now, tc.renew); got != tc.want {
				t.Errorf("ShouldRenewAt(%v, now, %v) = %v, want %v", tc.expiresAt, tc.renew, got, tc.want)
			}
		})
	}
}
