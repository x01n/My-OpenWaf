package accessgate

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// MemorySessionStore 基于内存的会话存储（生产环境可替换为 Redis/DB 后端）。
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo
}

// NewMemorySessionStore 创建内存会话存储。
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*SessionInfo),
	}
}

func (s *MemorySessionStore) Create(siteID uint, identity string, provider string, ttl int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	info := &SessionInfo{
		SiteID:    siteID,
		Token:     token,
		Identity:  identity,
		Provider:  provider,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	s.mu.Lock()
	s.sessions[token] = info
	s.mu.Unlock()

	return token, nil
}

func (s *MemorySessionStore) Validate(token string) (*SessionInfo, error) {
	s.mu.RLock()
	info, ok := s.sessions[token]
	s.mu.RUnlock()

	if !ok {
		return nil, nil
	}
	if time.Now().After(info.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return nil, nil
	}
	return info, nil
}

func (s *MemorySessionStore) Revoke(token string) error {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	return nil
}

func (s *MemorySessionStore) CleanExpired() error {
	now := time.Now()
	s.mu.Lock()
	for token, info := range s.sessions {
		if now.After(info.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
	return nil
}
