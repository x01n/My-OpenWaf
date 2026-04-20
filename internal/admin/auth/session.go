package auth

import (
	"sync"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// SessionInfo represents an active user session.
type SessionInfo struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	JTI          string    `json:"jti"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	DeviceInfo   string    `json:"device_info"`
	LoginAt      time.Time `json:"login_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionManager tracks active sessions in memory and persists to database.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo // jti -> session
	db       *gorm.DB
}

// NewSessionManager creates a new session manager.
func NewSessionManager(db *gorm.DB) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*SessionInfo),
		db:       db,
	}
	sm.loadFromDB()
	go sm.cleanupLoop()
	return sm
}

// CreateSession registers a new active session.
func (sm *SessionManager) CreateSession(username, jti, ip, userAgent, deviceInfo string, expiresAt time.Time) {
	now := time.Now()
	info := &SessionInfo{
		Username:     username,
		JTI:          jti,
		IP:           ip,
		UserAgent:    userAgent,
		DeviceInfo:   deviceInfo,
		LoginAt:      now,
		LastActiveAt: now,
		ExpiresAt:    expiresAt,
	}

	sm.mu.Lock()
	sm.sessions[jti] = info
	sm.mu.Unlock()

	// Persist to DB.
	if sm.db != nil {
		sm.db.Create(&store.ActiveSession{
			Username:     username,
			JTI:          jti,
			IP:           ip,
			UserAgent:    userAgent,
			DeviceInfo:   deviceInfo,
			LoginAt:      now,
			LastActiveAt: now,
			ExpiresAt:    expiresAt,
		})
	}
}

// RemoveSession deletes a session by JTI.
func (sm *SessionManager) RemoveSession(jti string) {
	sm.mu.Lock()
	delete(sm.sessions, jti)
	sm.mu.Unlock()

	if sm.db != nil {
		sm.db.Where("jti = ?", jti).Delete(&store.ActiveSession{})
	}
}

// UpdateLastActive updates the last activity timestamp for a session.
func (sm *SessionManager) UpdateLastActive(jti string) {
	sm.mu.Lock()
	if s, ok := sm.sessions[jti]; ok {
		s.LastActiveAt = time.Now()
	}
	sm.mu.Unlock()
}

// GetSession returns a session by JTI.
func (sm *SessionManager) GetSession(jti string) *SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[jti]
	if !ok {
		return nil
	}
	cp := *s
	return &cp
}

// ListUserSessions returns all active sessions for a given username.
func (sm *SessionManager) ListUserSessions(username string) []SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []SessionInfo
	now := time.Now()
	for _, s := range sm.sessions {
		if s.Username == username && s.ExpiresAt.After(now) {
			result = append(result, *s)
		}
	}
	return result
}

// ListAllSessions returns all active sessions (admin only).
func (sm *SessionManager) ListAllSessions() []SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []SessionInfo
	now := time.Now()
	for _, s := range sm.sessions {
		if s.ExpiresAt.After(now) {
			result = append(result, *s)
		}
	}
	return result
}

// ForceLogout removes a session and returns the JTI for blacklisting.
func (sm *SessionManager) ForceLogout(jti string) bool {
	sm.mu.Lock()
	_, existed := sm.sessions[jti]
	delete(sm.sessions, jti)
	sm.mu.Unlock()

	if sm.db != nil {
		sm.db.Where("jti = ?", jti).Delete(&store.ActiveSession{})
	}
	return existed
}

// RemoveUserSessions removes all sessions for a user and returns their JTIs.
func (sm *SessionManager) RemoveUserSessions(username string) []string {
	sm.mu.Lock()
	var jtis []string
	for jti, s := range sm.sessions {
		if s.Username == username {
			jtis = append(jtis, jti)
			delete(sm.sessions, jti)
		}
	}
	sm.mu.Unlock()

	if sm.db != nil {
		sm.db.Where("username = ?", username).Delete(&store.ActiveSession{})
	}
	return jtis
}

func (sm *SessionManager) loadFromDB() {
	if sm.db == nil {
		return
	}
	var sessions []store.ActiveSession
	sm.db.Where("expires_at > ?", time.Now()).Find(&sessions)
	for _, s := range sessions {
		sm.sessions[s.JTI] = &SessionInfo{
			ID:           s.ID,
			Username:     s.Username,
			JTI:          s.JTI,
			IP:           s.IP,
			UserAgent:    s.UserAgent,
			DeviceInfo:   s.DeviceInfo,
			LoginAt:      s.LoginAt,
			LastActiveAt: s.LastActiveAt,
			ExpiresAt:    s.ExpiresAt,
		}
	}
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sm.mu.Lock()
		for jti, s := range sm.sessions {
			if now.After(s.ExpiresAt) {
				delete(sm.sessions, jti)
			}
		}
		sm.mu.Unlock()

		// Cleanup expired from DB.
		if sm.db != nil {
			sm.db.Where("expires_at < ?", now).Delete(&store.ActiveSession{})
		}
	}
}
