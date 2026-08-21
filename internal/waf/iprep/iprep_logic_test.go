package iprep

import (
	"net"
	"testing"
	"time"
)

// ---- ParseIPListEntry edge cases ----

func TestParseIPListEntryEmptyStringReturnsFalse(t *testing.T) {
	_, ok := ParseIPListEntry("", "note")
	if ok {
		t.Fatal("empty string: want false")
	}
}

func TestParseIPListEntryInvalidReturnsFalse(t *testing.T) {
	_, ok := ParseIPListEntry("not-an-ip-or-cidr", "note")
	if ok {
		t.Fatal("invalid input: want false")
	}
}

func TestParseIPListEntryDefaultActionIsIntercept(t *testing.T) {
	e, ok := ParseIPListEntry("1.2.3.4", "note")
	if !ok {
		t.Fatal("want ok")
	}
	if e.Action != "intercept" {
		t.Fatalf("default action: want \"intercept\", got %q", e.Action)
	}
}

func TestParseIPListEntryDropActionNormalized(t *testing.T) {
	e, ok := ParseIPListEntry("1.2.3.4", "note", "block")
	if !ok {
		t.Fatal("want ok")
	}
	if e.Action != "drop" {
		t.Fatalf("block action: want \"drop\", got %q", e.Action)
	}
}

func TestParseIPListEntryWhitespaceTrimmed(t *testing.T) {
	e, ok := ParseIPListEntry("  10.0.0.1  ", "note")
	if !ok || e.Single == nil {
		t.Fatalf("whitespace trimmed: want single IP, got %#v %v", e, ok)
	}
}

// ---- entryMatchesAt ----

func TestEntryMatchesAtExpiredEntryDoesNotMatch(t *testing.T) {
	e := IPListEntry{Single: net.ParseIP("1.2.3.4"), ExpireAt: time.Now().Unix() - 1}
	if entryMatchesAt(e, net.ParseIP("1.2.3.4"), time.Now().Unix()) {
		t.Fatal("expired entry should not match")
	}
}

func TestEntryMatchesAtZeroExpireNeverExpires(t *testing.T) {
	e := IPListEntry{Single: net.ParseIP("1.2.3.4"), ExpireAt: 0}
	if !entryMatchesAt(e, net.ParseIP("1.2.3.4"), time.Now().Unix()+999999) {
		t.Fatal("zero ExpireAt should never expire")
	}
}

func TestEntryMatchesCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
	e := IPListEntry{CIDR: cidr}
	if !entryMatches(e, net.ParseIP("192.168.1.100")) {
		t.Fatal("CIDR should match contained IP")
	}
	if entryMatches(e, net.ParseIP("10.0.0.1")) {
		t.Fatal("CIDR should not match unrelated IP")
	}
}

// ---- Check: nil IP ----

func TestCheckNilIPAllowed(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	d := r.Check(nil)
	if !d.Allowed {
		t.Fatal("nil IP must be allowed")
	}
}

// ---- Check: whitelist / blacklist ----

func TestCheckWhitelistBeatsBlacklist(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	ip := net.ParseIP("5.5.5.5")
	black, _ := ParseIPListEntry("5.5.5.5", "blocked")
	white, _ := ParseIPListEntry("5.5.5.5", "trusted")
	r.SetLists([]IPListEntry{black}, []IPListEntry{white})

	d := r.Check(ip)
	if !d.Allowed || d.Category != "whitelist" {
		t.Fatalf("whitelist should beat blacklist: %+v", d)
	}
}

func TestCheckBlacklistedIPDenied(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	ip := net.ParseIP("6.6.6.6")
	black, _ := ParseIPListEntry("6.6.6.6", "malicious", "drop")
	r.SetLists([]IPListEntry{black}, nil)

	d := r.Check(ip)
	if d.Allowed || d.Category != "blacklist" || d.Action != "drop" {
		t.Fatalf("blacklisted IP: %+v", d)
	}
}

func TestCheckUnlistedIPAllowed(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	d := r.Check(net.ParseIP("8.8.8.8"))
	if !d.Allowed || d.Matched {
		t.Fatalf("unlisted IP should be allowed: %+v", d)
	}
}

// ---- Check: expired blacklist entry passes ----

func TestCheckExpiredBlacklistEntryAllowed(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	ip := net.ParseIP("9.9.9.9")
	e, _ := ParseIPListEntry("9.9.9.9", "expired")
	e.ExpireAt = time.Now().Unix() - 1
	r.SetLists([]IPListEntry{e}, nil)

	d := r.Check(ip)
	if !d.Allowed {
		t.Fatalf("expired blacklist entry should be allowed: %+v", d)
	}
}

// ---- RecordViolation + auto-ban ----

func TestRecordViolationDisabledReturnsFalse(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(false, 2, 60, 3600)
	if r.RecordViolation(net.ParseIP("1.1.1.1")) {
		t.Fatal("disabled auto-ban should not trigger")
	}
}

func TestRecordViolationTriggersAutoBan(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(true, 3, 60, 300)
	ip := net.ParseIP("2.2.2.2")

	// 前两次不触发
	if r.RecordViolation(ip) {
		t.Fatal("first violation should not trigger ban")
	}
	if r.RecordViolation(ip) {
		t.Fatal("second violation should not trigger ban")
	}
	// 第三次达到阈值，触发 ban
	if !r.RecordViolation(ip) {
		t.Fatal("third violation should trigger ban")
	}
}

func TestWhitelistedViolationDoesNotCreateBanAfterWhitelistRemoval(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	ip := net.ParseIP("6.6.6.6")
	whitelistEntry, ok := ParseIPListEntry("6.6.6.6", "trusted")
	if !ok {
		t.Fatal("whitelist entry should parse")
	}
	r.SetLists(nil, []IPListEntry{whitelistEntry})
	r.ConfigureAutoBan(true, 1, 60, 3600)

	if r.RecordViolation(ip) {
		t.Fatal("whitelisted violation must not trigger auto-ban")
	}

	r.SetLists(nil, nil)
	if decision := r.Check(ip); !decision.Allowed || decision.Matched || decision.Category != "" {
		t.Fatalf("removed whitelist must not reveal auto-ban: %+v", decision)
	}
	if bans := r.ActiveBans(); len(bans) != 0 {
		t.Fatalf("removed whitelist must not expose active ban: %+v", bans)
	}
}

func TestRecordViolationNilIPReturnsFalse(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(true, 1, 60, 300)
	if r.RecordViolation(nil) {
		t.Fatal("nil IP should return false")
	}
}

func TestCheckReturnsBannedAfterAutoBan(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(true, 2, 60, 3600)
	ip := net.ParseIP("3.3.3.3")

	r.RecordViolation(ip)
	r.RecordViolation(ip) // 触发 ban

	d := r.Check(ip)
	if d.Allowed || d.Category != "auto_ban" {
		t.Fatalf("auto-banned IP should be denied: %+v", d)
	}
}

// ---- ActiveBans ----

func TestActiveBansReturnsCurrentBans(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(true, 1, 60, 3600)
	ip := net.ParseIP("4.4.4.4")
	r.RecordViolation(ip) // 达到阈值 1

	bans := r.ActiveBans()
	if len(bans) != 1 || bans[0].IP != "4.4.4.4" {
		t.Fatalf("active bans: want 1 entry for 4.4.4.4, got %+v", bans)
	}
}

func TestActiveBansEmptyWhenNoBan(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBan(true, 5, 60, 3600)
	r.RecordViolation(net.ParseIP("5.5.5.5")) // 仅1次，未达阈值

	if bans := r.ActiveBans(); len(bans) != 0 {
		t.Fatalf("no ban triggered: want empty, got %+v", bans)
	}
}

// ---- ConfigureAutoBanAction ----

func TestConfigureAutoBanActionDrop(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBanAction("drop")
	r.ConfigureAutoBan(true, 1, 60, 3600)
	ip := net.ParseIP("6.6.6.6")
	r.RecordViolation(ip)

	d := r.Check(ip)
	if d.Action != "drop" {
		t.Fatalf("auto-ban action should be drop, got %q", d.Action)
	}
}

func TestConfigureAutoBanActionBlockNormalizesToDrop(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBanAction("block")
	act, _ := r.autoBanAction.Load().(string)
	if act != "drop" {
		t.Fatalf("block should normalize to drop, got %q", act)
	}
}

func TestConfigureAutoBanActionInterceptDefault(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBanAction("intercept")
	act, _ := r.autoBanAction.Load().(string)
	if act != "intercept" {
		t.Fatalf("intercept action: want \"intercept\", got %q", act)
	}
}

func TestConfigureAutoBanActionUnsupportedFallsBackToIntercept(t *testing.T) {
	r := NewIPReputation()
	defer r.Close()

	r.ConfigureAutoBanAction("chain_challenge")
	r.ConfigureAutoBan(true, 1, 60, 3600)
	ip := net.ParseIP("7.7.7.7")
	if !r.RecordViolation(ip) {
		t.Fatal("threshold-one violation should trigger auto-ban")
	}

	d := r.Check(ip)
	if d.Action != "intercept" {
		t.Fatalf("unsupported auto-ban action should fall back to intercept, got %q", d.Action)
	}
}
