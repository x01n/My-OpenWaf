package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/**
 * seedActiveSession 向内存库写入一条会话记录。
 * @param t 测试上下文
 * @param db 目标数据库
 * @param username 用户名
 * @param jti 会话 JTI
 * @param expiresAt 过期时间
 */
func seedActiveSession(t *testing.T, db *gorm.DB, username, jti string, expiresAt time.Time) {
	t.Helper()
	now := time.Now()
	if err := db.Create(&store.ActiveSession{
		Username:     username,
		JTI:          jti,
		IP:           "192.0.2.1",
		UserAgent:    "seed-agent",
		DeviceInfo:   "seed-device",
		LoginAt:      now,
		LastActiveAt: now,
		ExpiresAt:    expiresAt,
	}).Error; err != nil {
		t.Fatalf("seed active session %s: %v", jti, err)
	}
}

/**
 * countSessionRows 统计指定 JTI 在库中的行数。
 * @param t 测试上下文
 * @param db 目标数据库
 * @param jti 会话 JTI
 * @returns 行数
 */
func countSessionRows(t *testing.T, db *gorm.DB, jti string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&store.ActiveSession{}).Where("jti = ?", jti).Count(&n).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// ---------- 启动加载 ----------

// TestNewSessionManagerLoadsFromDB 重启场景：仅未过期会话应恢复到内存。
func TestNewSessionManagerLoadsFromDB(t *testing.T) {
	db := newAuthTestDB(t)
	seedActiveSession(t, db, "alice", "jti-live", time.Now().Add(time.Hour))
	seedActiveSession(t, db, "alice", "jti-expired", time.Now().Add(-time.Hour))

	sm := NewSessionManager(db)

	got := sm.GetSession("jti-live")
	if got == nil {
		t.Fatal("未过期会话应在启动时恢复")
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}
	if got.IP != "192.0.2.1" {
		t.Errorf("IP = %q, want 192.0.2.1", got.IP)
	}
	if got.UserAgent != "seed-agent" {
		t.Errorf("UserAgent = %q, want seed-agent", got.UserAgent)
	}
	if got.DeviceInfo != "seed-device" {
		t.Errorf("DeviceInfo = %q, want seed-device", got.DeviceInfo)
	}
	if got.ID == 0 {
		t.Error("从数据库恢复的会话应带有主键 ID")
	}

	if sm.GetSession("jti-expired") != nil {
		t.Error("已过期会话不应在启动时恢复")
	}
}

// TestNewSessionManagerNilDBNoPanic db 为 nil 时应可正常构造。
func TestNewSessionManagerNilDBNoPanic(t *testing.T) {
	sm := NewSessionManager(nil)
	if sm == nil {
		t.Fatal("NewSessionManager(nil) 不应返回 nil")
	}
	if len(sm.ListAllSessions()) != 0 {
		t.Error("nil DB 时会话列表应为空")
	}
}

// ---------- 持久化分支 ----------

func TestCreateSessionPersistsToDB(t *testing.T) {
	db := newAuthTestDB(t)
	sm := NewSessionManager(db)

	exp := time.Now().Add(time.Hour)
	sm.CreateSession("bob", "jti-persist", "203.0.113.5", "UA/1.0", "laptop", exp)

	var row store.ActiveSession
	if err := db.Where("jti = ?", "jti-persist").First(&row).Error; err != nil {
		t.Fatalf("会话应持久化到数据库: %v", err)
	}
	if row.Username != "bob" {
		t.Errorf("Username = %q, want bob", row.Username)
	}
	if row.IP != "203.0.113.5" {
		t.Errorf("IP = %q, want 203.0.113.5", row.IP)
	}
	if row.DeviceInfo != "laptop" {
		t.Errorf("DeviceInfo = %q, want laptop", row.DeviceInfo)
	}
}

func TestRemoveSessionDeletesFromDB(t *testing.T) {
	db := newAuthTestDB(t)
	sm := NewSessionManager(db)
	sm.CreateSession("carol", "jti-remove", "192.0.2.2", "UA", "", time.Now().Add(time.Hour))

	if countSessionRows(t, db, "jti-remove") != 1 {
		t.Fatal("前置条件：会话行应存在")
	}

	sm.RemoveSession("jti-remove")

	if n := countSessionRows(t, db, "jti-remove"); n != 0 {
		t.Errorf("RemoveSession 后数据库仍有 %d 行", n)
	}
	if sm.GetSession("jti-remove") != nil {
		t.Error("RemoveSession 后内存中不应保留会话")
	}
}

func TestForceLogoutDeletesFromDB(t *testing.T) {
	db := newAuthTestDB(t)
	sm := NewSessionManager(db)
	sm.CreateSession("dave", "jti-force", "192.0.2.3", "UA", "", time.Now().Add(time.Hour))

	if !sm.ForceLogout("jti-force") {
		t.Fatal("ForceLogout 对已存在会话应返回 true")
	}
	if n := countSessionRows(t, db, "jti-force"); n != 0 {
		t.Errorf("ForceLogout 后数据库仍有 %d 行", n)
	}
}

// TestRemoveUserSessionsDeletesOnlyTargetUser 仅删除目标用户的会话行。
func TestRemoveUserSessionsDeletesOnlyTargetUser(t *testing.T) {
	db := newAuthTestDB(t)
	sm := NewSessionManager(db)
	sm.CreateSession("eve", "jti-e1", "192.0.2.4", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("eve", "jti-e2", "192.0.2.5", "UA", "", time.Now().Add(time.Hour))
	sm.CreateSession("frank", "jti-f1", "192.0.2.6", "UA", "", time.Now().Add(time.Hour))

	jtis := sm.RemoveUserSessions("eve")
	if len(jtis) != 2 {
		t.Errorf("RemoveUserSessions 返回 %d 个 JTI, want 2", len(jtis))
	}

	if n := countSessionRows(t, db, "jti-e1"); n != 0 {
		t.Errorf("jti-e1 应从数据库删除，仍有 %d 行", n)
	}
	if n := countSessionRows(t, db, "jti-e2"); n != 0 {
		t.Errorf("jti-e2 应从数据库删除，仍有 %d 行", n)
	}
	if n := countSessionRows(t, db, "jti-f1"); n != 1 {
		t.Errorf("其他用户的会话行应保留，实际 %d 行", n)
	}
}

// TestRemoveUserSessionsUnknownUser 未知用户不应误删且返回空切片。
func TestRemoveUserSessionsUnknownUser(t *testing.T) {
	db := newAuthTestDB(t)
	sm := NewSessionManager(db)
	sm.CreateSession("grace", "jti-g1", "192.0.2.7", "UA", "", time.Now().Add(time.Hour))

	if jtis := sm.RemoveUserSessions("nobody"); len(jtis) != 0 {
		t.Errorf("未知用户应返回空 JTI 列表, got %v", jtis)
	}
	if n := countSessionRows(t, db, "jti-g1"); n != 1 {
		t.Errorf("既有会话不应被误删，实际 %d 行", n)
	}
}

// ---------- 序列化脱敏 ----------

// TestSessionInfoJSONHasNoCredentialFields 会话对象序列化后不得包含口令/令牌等凭据字段。
func TestSessionInfoJSONHasNoCredentialFields(t *testing.T) {
	sm := NewSessionManager(nil)
	sm.CreateSession("henry", "jti-json", "192.0.2.8", "UA/2.0", "phone", time.Now().Add(time.Hour))

	blob, err := json.Marshal(sm.GetSession("jti-json"))
	if err != nil {
		t.Fatalf("marshal SessionInfo: %v", err)
	}
	payload := strings.ToLower(string(blob))

	for _, forbidden := range []string{"password", "passwordhash", "password_hash", "secret", "refresh_token", "token_hash", "access_token"} {
		if strings.Contains(payload, forbidden) {
			t.Errorf("SessionInfo JSON 不应包含 %q 字段: %s", forbidden, blob)
		}
	}
}
