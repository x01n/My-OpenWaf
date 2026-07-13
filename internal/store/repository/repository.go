package repository

import (
	"time"

	"gorm.io/gorm"
)

// WriteQueueBackend is the interface that allows repositories to submit async writes
// without importing the observability package (avoiding import cycles).
type WriteQueueBackend interface {
	Submit(fn func(tx *gorm.DB) error)
	SubmitWait(fn func(tx *gorm.DB) error) error
}

// HotCacheBackend is the interface for Redis-backed hot data caching.
// Defined here as an interface to avoid import cycles with the cache package.
type HotCacheBackend interface {
	Get(key string, dest any) bool
	Set(key string, value any, ttl time.Duration)
	Invalidate(key string)
	InvalidatePattern(pattern string)
	Available() bool
	GetListRaw(key string) (items []byte, total int64, ok bool)
	SetList(key string, items any, total int64, ttl time.Duration)
}

// Repos aggregates all entity repositories.
type Repos struct {
	Site             *SiteRepo
	Certificate      *CertificateRepo
	Policy           *PolicyRepo
	Rule             *RuleRepo
	SystemSettings   *SystemSettingsRepo
	AdminAPIKey      *AdminAPIKeyRepo
	AdminAccount     *AdminAccountRepo
	RefreshToken     *RefreshTokenRepo
	SecurityEvent    *SecurityEventRepo
	AccessLog        *AccessLogRepo
	IPList           *IPListRepo
	BotScore         *BotScoreRepo
	CVERule          *CVERuleRepo
	CVESyncLog       *CVESyncLogRepo
	DropEvent        *DropEventRepo
	SiteListener     *SiteListenerRepo
	AppRouteRule     *ApplicationRouteRuleRepo
	RecordedResource *RecordedResourceRepo
	AccessControl    *AccessControlRepo
	ThreatIntel        *ThreatIntelRepo
	ThreatIntelSyncLog *ThreatIntelSyncLogRepo
	FalsePositive      *FalsePositiveRepo
}

func New(db *gorm.DB) *Repos {
	return NewWithLogDB(db, db)
}

func NewWithLogDB(db *gorm.DB, logDB *gorm.DB) *Repos {
	if logDB == nil {
		logDB = db
	}
	return &Repos{
		Site:             NewSiteRepo(db),
		Certificate:      NewCertificateRepo(db),
		Policy:           NewPolicyRepo(db),
		Rule:             NewRuleRepo(db),
		SystemSettings:   NewSystemSettingsRepo(db),
		AdminAPIKey:      NewAdminAPIKeyRepo(db),
		AdminAccount:     NewAdminAccountRepo(db),
		RefreshToken:     NewRefreshTokenRepo(db),
		SecurityEvent:    NewSecurityEventRepo(logDB),
		AccessLog:        NewAccessLogRepo(logDB),
		IPList:           NewIPListRepo(db),
		BotScore:         NewBotScoreRepo(logDB),
		CVERule:          NewCVERuleRepo(db),
		CVESyncLog:       NewCVESyncLogRepo(db),
		DropEvent:        NewDropEventRepo(logDB),
		SiteListener:     NewSiteListenerRepo(db),
		AppRouteRule:     NewApplicationRouteRuleRepo(db),
		RecordedResource: NewRecordedResourceRepo(db),
		AccessControl:    NewAccessControlRepo(db),
		ThreatIntel:        NewThreatIntelRepo(db),
		ThreatIntelSyncLog: NewThreatIntelSyncLogRepo(db),
		FalsePositive:      NewFalsePositiveRepo(db),
	}
}

// SetHotCache wires Redis hot cache into repositories that support it.
func (r *Repos) SetHotCache(hc HotCacheBackend) {
	r.AccessLog.SetHotCache(hc)
	r.SecurityEvent.SetHotCache(hc)
}

// SetWriteQueue wires the async write queue into repositories that support it.
func (r *Repos) SetWriteQueue(wq WriteQueueBackend) {
	r.AccessLog.SetWriteQueue(wq)
	r.SecurityEvent.SetWriteQueue(wq)
	r.DropEvent.SetWriteQueue(wq)
}
