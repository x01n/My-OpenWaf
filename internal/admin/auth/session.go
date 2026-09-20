package auth

import (
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// SessionInfo represents an active user session.
type SessionInfo struct {
	ID           uint   `json:"id"`
	Username     string `json:"username"`
	JTI          string `json:"jti"`
	refreshJTI   string
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	DeviceInfo   string    `json:"device_info"`
	LoginAt      time.Time `json:"login_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionManager tracks active sessions in memory and persists to database.
type SessionManager struct {
	mu            sync.RWMutex
	sessions      map[string]*SessionInfo // jti -> session
	lastPersisted map[string]time.Time
	db            *gorm.DB
	stopCh        chan struct{}
	wg            sync.WaitGroup
	closeOnce     sync.Once
}

// NewSessionManager creates a new session manager.
func NewSessionManager(db *gorm.DB) *SessionManager {
	sm := &SessionManager{
		sessions:      make(map[string]*SessionInfo),
		lastPersisted: make(map[string]time.Time),
		db:            db,
		stopCh:        make(chan struct{}),
	}
	sm.loadFromDB()
	sm.wg.Add(1)
	go sm.cleanupLoop()
	return sm
}

// CreateSession registers a new active session.
func (sm *SessionManager) CreateSession(username, jti, ip, userAgent, deviceInfo string, expiresAt time.Time) {
	sm.CreateSessionWithRefresh(username, jti, "", ip, userAgent, deviceInfo, expiresAt)
}

// CreateSessionWithRefresh registers an access session and links its rotating
// refresh JTI. The link remains server-side and is never serialized to clients.
func (sm *SessionManager) CreateSessionWithRefresh(username, jti, refreshJTI, ip, userAgent, deviceInfo string, expiresAt time.Time) {
	now := time.Now()
	info := &SessionInfo{
		Username:     username,
		JTI:          jti,
		refreshJTI:   refreshJTI,
		IP:           ip,
		UserAgent:    userAgent,
		DeviceInfo:   deviceInfo,
		LoginAt:      now,
		LastActiveAt: now,
		ExpiresAt:    expiresAt,
	}

	sm.mu.Lock()
	sm.sessions[jti] = info
	if sm.lastPersisted == nil {
		sm.lastPersisted = make(map[string]time.Time)
	}
	sm.lastPersisted[jti] = now
	sm.mu.Unlock()

	// Persist to DB.
	if sm.db != nil {
		row := store.ActiveSession{
			Username:     username,
			JTI:          jti,
			RefreshJTI:   refreshJTI,
			IP:           ip,
			UserAgent:    userAgent,
			DeviceInfo:   deviceInfo,
			LoginAt:      now,
			LastActiveAt: now,
			ExpiresAt:    expiresAt,
		}
		if err := sm.db.Create(&row).Error; err == nil && row.ID != 0 {
			sm.mu.Lock()
			if current, ok := sm.sessions[jti]; ok {
				current.ID = row.ID
			}
			sm.mu.Unlock()
		}
	}
}

// ReplaceSessionForRefresh rotates an existing access session in place. It
// prevents a proactive refresh from accumulating one database row per access
// token while preserving the stable session identity shown in the UI.
func (sm *SessionManager) ReplaceSessionForRefresh(oldRefreshJTI, newJTI, newRefreshJTI, ip, userAgent, deviceInfo string, expiresAt time.Time) bool {
	if oldRefreshJTI == "" {
		return false
	}
	now := time.Now()
	sm.mu.Lock()
	var oldKey string
	var info *SessionInfo
	for key, current := range sm.sessions {
		if current.refreshJTI == oldRefreshJTI {
			oldKey = key
			info = current
			break
		}
	}
	if info == nil {
		sm.mu.Unlock()
		return false
	}
	delete(sm.sessions, oldKey)
	delete(sm.lastPersisted, oldKey)
	info.JTI = newJTI
	info.refreshJTI = newRefreshJTI
	info.IP = ip
	info.UserAgent = userAgent
	info.DeviceInfo = deviceInfo
	info.LastActiveAt = now
	info.ExpiresAt = expiresAt
	if sm.lastPersisted == nil {
		sm.lastPersisted = make(map[string]time.Time)
	}
	sm.lastPersisted[newJTI] = now
	sm.sessions[newJTI] = info
	sm.mu.Unlock()

	if sm.db != nil {
		_ = sm.db.Model(&store.ActiveSession{}).
			Where("refresh_jti = ?", oldRefreshJTI).
			Updates(map[string]any{
				"jti":            newJTI,
				"refresh_jti":    newRefreshJTI,
				"ip":             ip,
				"user_agent":     userAgent,
				"device_info":    deviceInfo,
				"last_active_at": now,
				"expires_at":     expiresAt,
			}).Error
	}
	return true
}

// RemoveSession deletes a session by JTI.
func (sm *SessionManager) RemoveSession(jti string) {
	sm.mu.Lock()
	delete(sm.sessions, jti)
	delete(sm.lastPersisted, jti)
	sm.mu.Unlock()

	if sm.db != nil {
		sm.db.Where("jti = ?", jti).Delete(&store.ActiveSession{})
	}
}

// UpdateLastActive updates the last activity timestamp for a session.
func (sm *SessionManager) UpdateLastActive(jti string) {
	now := time.Now()
	persist := false
	sm.mu.Lock()
	if s, ok := sm.sessions[jti]; ok {
		s.LastActiveAt = now
		if sm.lastPersisted == nil {
			sm.lastPersisted = make(map[string]time.Time)
		}
		last := sm.lastPersisted[jti]
		if last.IsZero() || now.Sub(last) >= 30*time.Second {
			sm.lastPersisted[jti] = now
			persist = true
		}
	}
	sm.mu.Unlock()
	if persist && sm.db != nil {
		// 按固定间隔持久化活跃时间，避免每个管理 API 请求产生一条 UPDATE。
		_ = sm.db.Model(&store.ActiveSession{}).Where("jti = ?", jti).Update("last_active_at", now).Error
	}
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

// RefreshTokenJTI returns the server-side refresh-token link for an access JTI.
// It is intentionally not part of SessionInfo's JSON representation.
func (sm *SessionManager) RefreshTokenJTI(jti string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if session, ok := sm.sessions[jti]; ok {
		return session.refreshJTI
	}
	return ""
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
	sortSessionInfos(result)
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
	sortSessionInfos(result)
	return result
}

func sortSessionInfos(items []SessionInfo) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastActiveAt.Equal(items[j].LastActiveAt) {
			return items[i].JTI < items[j].JTI
		}
		return items[i].LastActiveAt.After(items[j].LastActiveAt)
	})
}

// ForceLogout removes a session and returns the JTI for blacklisting.
func (sm *SessionManager) ForceLogout(jti string) bool {
	sm.mu.Lock()
	_, existed := sm.sessions[jti]
	delete(sm.sessions, jti)
	delete(sm.lastPersisted, jti)
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
			delete(sm.lastPersisted, jti)
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
			refreshJTI:   s.RefreshJTI,
			IP:           s.IP,
			UserAgent:    s.UserAgent,
			DeviceInfo:   s.DeviceInfo,
			LoginAt:      s.LoginAt,
			LastActiveAt: s.LastActiveAt,
			ExpiresAt:    s.ExpiresAt,
		}
		if sm.lastPersisted == nil {
			sm.lastPersisted = make(map[string]time.Time)
		}
		sm.lastPersisted[s.JTI] = s.LastActiveAt
	}
}

// Close stops the session cleanup goroutine and is safe to call repeatedly.
func (sm *SessionManager) Close() {
	if sm == nil {
		return
	}
	sm.closeOnce.Do(func() {
		if sm.stopCh != nil {
			close(sm.stopCh)
		}
	})
	sm.wg.Wait()
}

func (sm *SessionManager) cleanupLoop() {
	defer sm.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-sm.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			sm.mu.Lock()
			for jti, s := range sm.sessions {
				if now.After(s.ExpiresAt) {
					delete(sm.sessions, jti)
					delete(sm.lastPersisted, jti)
				}
			}
			sm.mu.Unlock()

			// Cleanup expired from DB.
			if sm.db != nil {
				sm.db.Where("expires_at < ?", now).Delete(&store.ActiveSession{})
			}
		}
	}
}
