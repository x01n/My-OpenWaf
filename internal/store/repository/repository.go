package repository

import (
	"time"

	"gorm.io/gorm"
)

// WriteQueueBackend 让各 repository 无需 import observability 包
// 即可提交异步写入（从而避免 import cycle）。
type WriteQueueBackend interface {
	Submit(fn func(tx *gorm.DB) error)
	SubmitWait(fn func(tx *gorm.DB) error) error
}

// HotCacheBackend 是 Redis 热数据缓存所用接口。
// 在此以接口形式定义，是为了避免与 cache 包产生 import cycle。
type HotCacheBackend interface {
	Get(key string, dest any) bool
	Set(key string, value any, ttl time.Duration)
	Invalidate(key string)
	InvalidatePattern(pattern string)
	Available() bool
	GetListRaw(key string) (items []byte, total int64, ok bool)
	SetList(key string, items any, total int64, ttl time.Duration)
}

// Repos 汇总全部实体 repository。
type Repos struct {
	Site               *SiteRepo
	Certificate        *CertificateRepo
	Policy             *PolicyRepo
	Rule               *RuleRepo
	SystemSettings     *SystemSettingsRepo
	AdminAPIKey        *AdminAPIKeyRepo
	AdminAccount       *AdminAccountRepo
	RefreshToken       *RefreshTokenRepo
	SecurityEvent      *SecurityEventRepo
	AccessLog          *AccessLogRepo
	IPList             *IPListRepo
	BotScore           *BotScoreRepo
	CVERule            *CVERuleRepo
	CVESyncLog         *CVESyncLogRepo
	DropEvent          *DropEventRepo
	SiteListener       *SiteListenerRepo
	AppRouteRule       *ApplicationRouteRuleRepo
	RecordedResource   *RecordedResourceRepo
	AccessControl      *AccessControlRepo
	ThreatIntel        *ThreatIntelRepo
	ThreatIntelSyncLog *ThreatIntelSyncLogRepo
	FalsePositive      *FalsePositiveRepo
	LuaPlugin          *LuaPluginRepo
	JSPlugin           *JSPluginRepo
}

func New(db *gorm.DB) *Repos {
	return NewWithLogDB(db, db)
}

func NewWithLogDB(db *gorm.DB, logDB *gorm.DB) *Repos {
	if logDB == nil {
		logDB = db
	}
	return &Repos{
		Site:               NewSiteRepo(db),
		Certificate:        NewCertificateRepo(db),
		Policy:             NewPolicyRepo(db),
		Rule:               NewRuleRepo(db),
		SystemSettings:     NewSystemSettingsRepo(db),
		AdminAPIKey:        NewAdminAPIKeyRepo(db),
		AdminAccount:       NewAdminAccountRepo(db),
		RefreshToken:       NewRefreshTokenRepo(db),
		SecurityEvent:      NewSecurityEventRepo(logDB),
		AccessLog:          NewAccessLogRepo(logDB),
		IPList:             NewIPListRepo(db),
		BotScore:           NewBotScoreRepo(logDB),
		CVERule:            NewCVERuleRepo(db),
		CVESyncLog:         NewCVESyncLogRepo(db),
		DropEvent:          NewDropEventRepo(logDB),
		SiteListener:       NewSiteListenerRepo(db),
		AppRouteRule:       NewApplicationRouteRuleRepo(db),
		RecordedResource:   NewRecordedResourceRepo(db),
		AccessControl:      NewAccessControlRepo(db),
		ThreatIntel:        NewThreatIntelRepo(db),
		ThreatIntelSyncLog: NewThreatIntelSyncLogRepo(db),
		FalsePositive:      NewFalsePositiveRepo(db),
		LuaPlugin:          NewLuaPluginRepo(db),
		JSPlugin:           NewJSPluginRepo(db),
	}
}

// SetHotCache 把 Redis 热缓存接入支持它的 repository。
func (r *Repos) SetHotCache(hc HotCacheBackend) {
	r.AccessLog.SetHotCache(hc)
	r.SecurityEvent.SetHotCache(hc)
}

// SetWriteQueue 把异步写队列接入支持它的 repository。
func (r *Repos) SetWriteQueue(wq WriteQueueBackend) {
	r.AccessLog.SetWriteQueue(wq)
	r.SecurityEvent.SetWriteQueue(wq)
	r.DropEvent.SetWriteQueue(wq)
}
