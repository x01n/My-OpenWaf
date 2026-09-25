package iprep

import (
	"net"
	"testing"
)

/**
 * TestIPHistoryStringReadOnly 验证方案 B 的只读 IP 史查询：
 * 违规计数与封禁态可查，且查询不改变计数/封禁语义。
 */
func TestIPHistoryStringReadOnly(t *testing.T) {
	rep := NewIPReputation()
	defer rep.Close()
	rep.ConfigureAutoBan(true, 3, 60, 3600)

	ip := net.ParseIP("203.0.113.9")

	// 初始状态：无违规、未封禁。
	if violations, banned := rep.IPHistoryString(ip.String()); violations != 0 || banned {
		t.Fatalf("IPHistoryString fresh ip = (%d, %t), want (0, false)", violations, banned)
	}

	// 两次违规后仍未被封禁，计数可查。
	if rep.RecordViolation(ip) || rep.RecordViolation(ip) {
		t.Fatal("two violations must not trigger auto-ban below threshold")
	}
	if violations, banned := rep.IPHistoryString(ip.String()); violations != 2 || banned {
		t.Fatalf("IPHistoryString two violations = (%d, %t), want (2, false)", violations, banned)
	}

	// 第三次违规触发自动封禁。
	if !rep.RecordViolation(ip) {
		t.Fatal("third violation must trigger auto-ban")
	}
	if violations, banned := rep.IPHistoryString(ip.String()); violations != 3 || !banned {
		t.Fatalf("IPHistoryString auto-banned = (%d, %t), want (3, true)", violations, banned)
	}

	// 查询是只读的：再次查询结果不变，且不额外累加违规。
	if violations, banned := rep.IPHistoryString(ip.String()); violations != 3 || !banned {
		t.Fatalf("IPHistoryString re-read = (%d, %t), want (3, true)", violations, banned)
	}
}

/**
 * TestIPHistoryStringEmptyAndUnknown 验证空串与未知 IP 返回零值。
 */
func TestIPHistoryStringEmptyAndUnknown(t *testing.T) {
	rep := NewIPReputation()
	defer rep.Close()

	if violations, banned := rep.IPHistoryString(""); violations != 0 || banned {
		t.Fatalf("IPHistoryString empty = (%d, %t), want (0, false)", violations, banned)
	}
	if violations, banned := rep.IPHistoryString("198.51.100.7"); violations != 0 || banned {
		t.Fatalf("IPHistoryString unknown = (%d, %t), want (0, false)", violations, banned)
	}
}
