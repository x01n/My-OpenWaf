package auth

import (
	"testing"
	"time"
)

// newTestManager 使用 nil DB，仅测试内存层逻辑。
func newTestManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SessionInfo),
		db:       nil,
	}
}

func TestCreateSessionAndGetSession(t *testing.T) {
	sm := newTestManager()
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("alice", "jti-1", "1.2.3.4", "TestUA", "desktop", exp)

	got := sm.GetSession("jti-1")
	if got == nil {
		t.Fatal("GetSession should return session after CreateSession")
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want \"alice\"", got.Username)
	}
	if got.JTI != "jti-1" {
		t.Errorf("JTI = %q, want \"jti-1\"", got.JTI)
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want \"1.2.3.4\"", got.IP)
	}
}

func TestGetSessionMissReturnsNil(t *testing.T) {
	sm := newTestManager()
	if sm.GetSession("nonexistent") != nil {
		t.Error("GetSession should return nil for unknown JTI")
	}
}

func TestGetSessionReturnsCopy(t *testing.T) {
	sm := newTestManager()
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("bob", "jti-copy", "5.6.7.8", "UA", "", exp)

	got1 := sm.GetSession("jti-copy")
	got2 := sm.GetSession("jti-copy")
	if got1 == got2 {
		t.Error("GetSession should return a copy, not the same pointer")
	}
}

func TestRemoveSession(t *testing.T) {
	sm := newTestManager()
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("carol", "jti-del", "0.0.0.0", "UA", "", exp)
	sm.RemoveSession("jti-del")

	if sm.GetSession("jti-del") != nil {
		t.Error("GetSession should return nil after RemoveSession")
	}
}

func TestRemoveSessionNonexistentNoError(t *testing.T) {
	sm := newTestManager()
	// 不应 panic
	sm.RemoveSession("no-such-jti")
}

func TestUpdateLastActive(t *testing.T) {
	sm := newTestManager()
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("dave", "jti-active", "1.1.1.1", "UA", "", exp)

	before := sm.GetSession("jti-active").LastActiveAt
	time.Sleep(2 * time.Millisecond)
	sm.UpdateLastActive("jti-active")
	after := sm.GetSession("jti-active").LastActiveAt

	if !after.After(before) {
		t.Error("UpdateLastActive should advance LastActiveAt")
	}
}

func TestListUserSessionsOnlyActiveNonExpired(t *testing.T) {
	sm := newTestManager()
	sm.CreateSession("eve", "jti-a", "1.1.1.1", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("eve", "jti-b", "1.1.1.1", "UA", "", time.Now().Add(time.Hour))
	// 已过期
	sm.CreateSession("eve", "jti-c", "1.1.1.1", "UA", "", time.Now().Add(-time.Hour))
	// 其他用户
	sm.CreateSession("frank", "jti-d", "2.2.2.2", "UA", "", time.Now().Add(time.Hour))

	sessions := sm.ListUserSessions("eve")
	if len(sessions) != 2 {
		t.Errorf("ListUserSessions(eve) = %d sessions, want 2", len(sessions))
	}
	for _, s := range sessions {
		if s.Username != "eve" {
			t.Errorf("ListUserSessions returned session for %q, want eve", s.Username)
		}
	}
}

func TestListAllSessionsOnlyNonExpired(t *testing.T) {
	sm := newTestManager()
	sm.CreateSession("g", "jti-1", "1.1.1.1", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("h", "jti-2", "2.2.2.2", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("i", "jti-3", "3.3.3.3", "UA", "", time.Now().Add(-time.Second))

	all := sm.ListAllSessions()
	if len(all) != 2 {
		t.Errorf("ListAllSessions = %d, want 2 (expired excluded)", len(all))
	}
}

func TestForceLogoutReturnsTrueForExistingSession(t *testing.T) {
	sm := newTestManager()
	sm.CreateSession("j", "jti-fl", "1.1.1.1", "UA", "", time.Now().Add(time.Hour))

	if !sm.ForceLogout("jti-fl") {
		t.Error("ForceLogout should return true for an existing session")
	}
	if sm.GetSession("jti-fl") != nil {
		t.Error("Session should be removed after ForceLogout")
	}
}

func TestForceLogoutReturnsFalseForMissing(t *testing.T) {
	sm := newTestManager()
	if sm.ForceLogout("no-such-jti") {
		t.Error("ForceLogout should return false for non-existing session")
	}
}

func TestRemoveUserSessionsReturnsJTIs(t *testing.T) {
	sm := newTestManager()
	sm.CreateSession("k", "jti-k1", "1.1.1.1", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("k", "jti-k2", "2.2.2.2", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("l", "jti-l1", "3.3.3.3", "UA", "", time.Now().Add(time.Hour))

	jtis := sm.RemoveUserSessions("k")
	if len(jtis) != 2 {
		t.Errorf("RemoveUserSessions(k) = %v, want 2 JTIs", jtis)
	}
	// k 的 session 应被移除，l 的应保留
	if sm.GetSession("jti-k1") != nil || sm.GetSession("jti-k2") != nil {
		t.Error("Sessions for user k should be removed")
	}
	if sm.GetSession("jti-l1") == nil {
		t.Error("Session for user l should be preserved")
	}
}
