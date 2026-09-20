package detect

import (
	"encoding/json"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

const (
	owaspReadSnapshotTTL        = 10 * time.Second
	owaspReadSnapshotMaxEntries = 64
)

type owaspReadSnapshot struct {
	views []owaspRuleView
}

type owaspReadSnapshotEntry struct {
	value     owaspReadSnapshot
	expiresAt time.Time
}

type owaspReadSnapshotState struct {
	mu         sync.RWMutex
	entry      *owaspReadSnapshotEntry
	generation uint64
	flight     singleflight.Group
}

type owaspReadSnapshotKey struct {
	db       *gorm.DB
	policyID uint
}

type owaspReadSnapshotRegistryEntry struct {
	state      *owaspReadSnapshotState
	lastAccess uint64
}

type owaspReadSnapshotRegistry struct {
	mu      sync.Mutex
	clock   uint64
	entries map[owaspReadSnapshotKey]owaspReadSnapshotRegistryEntry
}

var globalOWASPReadSnapshots = owaspReadSnapshotRegistry{
	entries: make(map[owaspReadSnapshotKey]owaspReadSnapshotRegistryEntry),
}

/**
 * owaspSnapshotState 返回数据库与策略组合对应的有界缓存状态。
 *
 * 注册表最多保留 owaspReadSnapshotMaxEntries 个状态。被淘汰状态中的并发读取仍可
 * 安全结束，但不会重新写回注册表，也不会阻塞同键的新一轮读取。
 */
func owaspSnapshotState(db *gorm.DB, policyID uint) *owaspReadSnapshotState {
	key := owaspReadSnapshotKey{db: db, policyID: policyID}
	globalOWASPReadSnapshots.mu.Lock()
	defer globalOWASPReadSnapshots.mu.Unlock()

	globalOWASPReadSnapshots.clock++
	if entry, ok := globalOWASPReadSnapshots.entries[key]; ok {
		entry.lastAccess = globalOWASPReadSnapshots.clock
		globalOWASPReadSnapshots.entries[key] = entry
		return entry.state
	}
	if len(globalOWASPReadSnapshots.entries) >= owaspReadSnapshotMaxEntries {
		var oldestKey owaspReadSnapshotKey
		var oldestAccess uint64
		first := true
		for existingKey, entry := range globalOWASPReadSnapshots.entries {
			if first || entry.lastAccess < oldestAccess {
				oldestKey = existingKey
				oldestAccess = entry.lastAccess
				first = false
			}
		}
		delete(globalOWASPReadSnapshots.entries, oldestKey)
	}
	state := &owaspReadSnapshotState{}
	globalOWASPReadSnapshots.entries[key] = owaspReadSnapshotRegistryEntry{
		state:      state,
		lastAccess: globalOWASPReadSnapshots.clock,
	}
	return state
}

/**
 * loadOWASPReadSnapshot 一次性读取活动目录和指定策略覆盖，并生成不可共享修改的视图。
 */
func loadOWASPReadSnapshot(db *gorm.DB, policyID uint) (owaspReadSnapshot, error) {
	var catalog []store.OWASPRuleCatalog
	if err := db.Where("active = ?", true).Order("rule_id ASC").Find(&catalog).Error; err != nil {
		return owaspReadSnapshot{}, err
	}
	var configs []store.PolicyOWASPRuleConfig
	if err := db.Where("policy_id = ?", policyID).Find(&configs).Error; err != nil {
		return owaspReadSnapshot{}, err
	}
	byRule := make(map[string]store.PolicyOWASPRuleConfig, len(configs))
	for i := range configs {
		byRule[configs[i].RuleID] = configs[i]
	}

	views := make([]owaspRuleView, 0, len(catalog))
	for i := range catalog {
		item := catalog[i]
		view := owaspRuleView{
			ID:                 item.RuleID,
			CatalogID:          item.ID,
			BuiltinID:          item.RuleID,
			PolicyID:           policyID,
			Category:           item.Category,
			Name:               item.Name,
			Description:        item.Description,
			DefaultEnabled:     item.DefaultEnabled,
			DefaultAction:      item.DefaultAction,
			DefaultSensitivity: item.DefaultSensitivity,
			Enabled:            item.DefaultEnabled,
			Action:             item.DefaultAction,
			Sensitivity:        item.DefaultSensitivity,
		}
		if config, ok := byRule[item.RuleID]; ok {
			view.Overridden = true
			if config.Enabled != nil {
				view.Enabled = *config.Enabled
			}
			if config.Action != nil {
				view.Action = *config.Action
			}
			if config.Sensitivity != nil {
				view.Sensitivity = *config.Sensitivity
			}
			if config.StatusCode != nil {
				view.StatusCode = *config.StatusCode
			}
			if config.RedirectTo != nil {
				view.RedirectTo = *config.RedirectTo
			}
			if config.CaptchaType != nil {
				view.CaptchaType = *config.CaptchaType
			}
			if config.Whitelist != nil && *config.Whitelist != "" {
				_ = json.Unmarshal([]byte(*config.Whitelist), &view.Whitelist)
			}
			if config.Note != nil {
				view.Note = *config.Note
			}
		}
		if action.Normalize(action.Type(view.Action)) != action.CaptchaChallenge {
			view.CaptchaType = ""
		}
		views = append(views, view)
	}
	return owaspReadSnapshot{views: views}, nil
}

/**
 * snapshot 返回活动目录与策略覆盖的深复制。并发冷读由 singleflight 合并；写入期间
 * generation 变化时，冷读会重新回源，避免发布写入前的旧快照。
 */
func (s *owaspReadSnapshotState) snapshot(db *gorm.DB, policyID uint) (owaspReadSnapshot, error) {
	if snapshot, ok := s.cached(); ok {
		return snapshot, nil
	}
	value, err, _ := s.flight.Do("snapshot", func() (any, error) {
		if snapshot, ok := s.cached(); ok {
			return snapshot, nil
		}
		for {
			s.mu.RLock()
			generation := s.generation
			s.mu.RUnlock()

			snapshot, loadErr := loadOWASPReadSnapshot(db, policyID)
			if loadErr != nil {
				return nil, loadErr
			}

			s.mu.Lock()
			if generation != s.generation {
				s.mu.Unlock()
				continue
			}
			s.entry = &owaspReadSnapshotEntry{
				value:     snapshot,
				expiresAt: time.Now().Add(owaspReadSnapshotTTL),
			}
			s.mu.Unlock()
			return snapshot, nil
		}
	})
	if err != nil {
		return owaspReadSnapshot{}, err
	}
	return cloneOWASPReadSnapshot(value.(owaspReadSnapshot)), nil
}

func (s *owaspReadSnapshotState) cached() (owaspReadSnapshot, bool) {
	s.mu.RLock()
	entry := s.entry
	fresh := entry != nil && time.Now().Before(entry.expiresAt)
	s.mu.RUnlock()
	if !fresh {
		return owaspReadSnapshot{}, false
	}
	return cloneOWASPReadSnapshot(entry.value), true
}

func (s *owaspReadSnapshotState) invalidate() {
	s.mu.Lock()
	s.entry = nil
	s.generation++
	s.mu.Unlock()
	s.flight.Forget("snapshot")
}

func cloneOWASPReadSnapshot(source owaspReadSnapshot) owaspReadSnapshot {
	views := make([]owaspRuleView, len(source.views))
	for i := range source.views {
		views[i] = source.views[i]
		views[i].Whitelist = append([]string(nil), source.views[i].Whitelist...)
	}
	return owaspReadSnapshot{views: views}
}

func getOWASPReadSnapshot(db *gorm.DB, policyID uint) (owaspReadSnapshot, error) {
	return owaspSnapshotState(db, policyID).snapshot(db, policyID)
}

/**
 * invalidateOWASPReadSnapshot 使指定策略的目录与覆盖快照立即失效。
 */
func invalidateOWASPReadSnapshot(db *gorm.DB, policyID uint) {
	key := owaspReadSnapshotKey{db: db, policyID: policyID}
	globalOWASPReadSnapshots.mu.Lock()
	// 失效期间保持注册表锁；否则并发读取可在查找与 state.invalidate 之间淘汰
	// 当前条目并重建同键，使替代状态中的旧快照越过本次写入失效。
	if entry, ok := globalOWASPReadSnapshots.entries[key]; ok {
		entry.state.invalidate()
	}
	globalOWASPReadSnapshots.mu.Unlock()
}

/**
 * InvalidateOWASPReadSnapshots 使指定数据库的全部策略快照失效。
 * 备份恢复会批量替换多个策略覆盖，不能只按单个 policy_id 清理。
 */
func InvalidateOWASPReadSnapshots(db *gorm.DB) {
	globalOWASPReadSnapshots.mu.Lock()
	// 在注册表锁内逐项失效，避免淘汰/重建与全库失效竞争并留下写前快照。
	for key, entry := range globalOWASPReadSnapshots.entries {
		if key.db == db {
			entry.state.invalidate()
		}
	}
	globalOWASPReadSnapshots.mu.Unlock()
}
