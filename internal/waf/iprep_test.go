package waf

import (
	"net"
	"testing"
	"time"
)

func TestIPReputationBlackWhiteList(t *testing.T) {
	rep := NewIPReputation()
	defer rep.Close()

	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rep.SetLists(
		[]IPListEntry{{CIDR: cidr, Note: "internal blocked"}},
		[]IPListEntry{{Single: net.ParseIP("192.168.1.1"), Note: "admin"}},
	)

	// Whitelisted IP
	d := rep.Check(net.ParseIP("192.168.1.1"))
	if !d.Matched || !d.Allowed {
		t.Error("expected whitelist match for 192.168.1.1")
	}

	// Blacklisted IP
	d = rep.Check(net.ParseIP("10.1.2.3"))
	if !d.Matched || d.Allowed {
		t.Error("expected blacklist match for 10.1.2.3")
	}

	// Unknown IP
	d = rep.Check(net.ParseIP("8.8.8.8"))
	if d.Matched {
		t.Error("expected no match for 8.8.8.8")
	}
}

func TestIPReputationAutoBan(t *testing.T) {
	rep := NewIPReputation()
	defer rep.Close()
	rep.ConfigureAutoBan(true, 3, 60, 300)

	ip := net.ParseIP("1.2.3.4")

	// Record violations below threshold
	rep.RecordViolation(ip)
	rep.RecordViolation(ip)
	d := rep.Check(ip)
	if d.Matched {
		t.Error("expected no ban before threshold")
	}

	// Third violation triggers ban
	banned := rep.RecordViolation(ip)
	if !banned {
		t.Error("expected auto-ban on 3rd violation")
	}

	d = rep.Check(ip)
	if !d.Matched || d.Allowed {
		t.Error("expected banned status for 1.2.3.4")
	}
	if d.Category != "auto_ban" {
		t.Errorf("expected category auto_ban, got %q", d.Category)
	}

	// Different IP should not be affected
	d = rep.Check(net.ParseIP("5.6.7.8"))
	if d.Matched {
		t.Error("expected no ban for 5.6.7.8")
	}
}

func TestIPReputationActiveBans(t *testing.T) {
	rep := NewIPReputation()
	defer rep.Close()
	rep.ConfigureAutoBan(true, 1, 60, 300)

	ip := net.ParseIP("1.1.1.1")
	rep.RecordViolation(ip)

	bans := rep.ActiveBans()
	if len(bans) != 1 {
		t.Fatalf("expected 1 ban, got %d", len(bans))
	}
	if bans[0].IP != "1.1.1.1" {
		t.Errorf("expected IP 1.1.1.1, got %s", bans[0].IP)
	}
	if bans[0].BannedTil < time.Now().Unix() {
		t.Error("ban should be in the future")
	}
}

func TestParseIPListEntry(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		cidr  bool
	}{
		{"10.0.0.0/8", true, true},
		{"192.168.1.1", true, false},
		{"::1", true, false},
		{"invalid", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		e, ok := ParseIPListEntry(tt.input, "test")
		if ok != tt.ok {
			t.Errorf("ParseIPListEntry(%q) ok=%v, want %v", tt.input, ok, tt.ok)
		}
		if ok && tt.cidr && e.CIDR == nil {
			t.Errorf("ParseIPListEntry(%q) expected CIDR", tt.input)
		}
		if ok && !tt.cidr && e.Single == nil {
			t.Errorf("ParseIPListEntry(%q) expected Single IP", tt.input)
		}
	}
}
