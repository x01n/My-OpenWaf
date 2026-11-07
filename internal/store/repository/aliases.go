package repository

import (
	"gorm.io/gorm"

	"My-OpenWaf/internal/store/repository/acl"
	"My-OpenWaf/internal/store/repository/authn"
	"My-OpenWaf/internal/store/repository/bot"
	"My-OpenWaf/internal/store/repository/cert"
	"My-OpenWaf/internal/store/repository/cve"
	"My-OpenWaf/internal/store/repository/event"
	"My-OpenWaf/internal/store/repository/iplist"
	"My-OpenWaf/internal/store/repository/plugin"
	"My-OpenWaf/internal/store/repository/policy"
	"My-OpenWaf/internal/store/repository/setting"
	"My-OpenWaf/internal/store/repository/site"
	"My-OpenWaf/internal/store/repository/threat"
)

// 本文件是各叶子子包的门面：类型别名（带等号）保持既有调用点的类型同一性，
// 构造函数转发保持 `repository.NewXxxRepo` 的调用形式不变，因此外部消费者无需改动。

// SiteRepo 是 site 子包实现的别名。
type SiteRepo = site.SiteRepo

// SiteListenerRepo 是 site 子包实现的别名。
type SiteListenerRepo = site.SiteListenerRepo

// NewSiteRepo 转发到 site 子包的构造函数。
func NewSiteRepo(db *gorm.DB) *SiteRepo { return site.NewSiteRepo(db) }

// NewSiteListenerRepo 转发到 site 子包的构造函数。
func NewSiteListenerRepo(db *gorm.DB) *SiteListenerRepo { return site.NewSiteListenerRepo(db) }

// CertificateRepo 是 cert 子包实现的别名。
type CertificateRepo = cert.CertificateRepo

// NewCertificateRepo 转发到 cert 子包的构造函数。
func NewCertificateRepo(db *gorm.DB) *CertificateRepo { return cert.NewCertificateRepo(db) }

// PolicyRepo 是 policy 子包实现的别名。
type PolicyRepo = policy.PolicyRepo

// NewPolicyRepo 转发到 policy 子包的构造函数。
func NewPolicyRepo(db *gorm.DB) *PolicyRepo { return policy.NewPolicyRepo(db) }

// SystemSettingsRepo 是 setting 子包实现的别名。
type SystemSettingsRepo = setting.SystemSettingsRepo

// NewSystemSettingsRepo 转发到 setting 子包的构造函数。
func NewSystemSettingsRepo(db *gorm.DB) *SystemSettingsRepo {
	return setting.NewSystemSettingsRepo(db)
}

// AdminAccountRepo 是 authn 子包实现的别名。
type AdminAccountRepo = authn.AdminAccountRepo

// AdminAPIKeyRepo 是 authn 子包实现的别名。
type AdminAPIKeyRepo = authn.AdminAPIKeyRepo

// RefreshTokenRepo 是 authn 子包实现的别名。
type RefreshTokenRepo = authn.RefreshTokenRepo

// ErrRefreshTokenUnavailable 与 authn 子包共享同一个 error 值，保持 errors.Is 判定成立。
var ErrRefreshTokenUnavailable = authn.ErrRefreshTokenUnavailable

// NewAdminAccountRepo 转发到 authn 子包的构造函数。
func NewAdminAccountRepo(db *gorm.DB) *AdminAccountRepo { return authn.NewAdminAccountRepo(db) }

// NewAdminAPIKeyRepo 转发到 authn 子包的构造函数。
func NewAdminAPIKeyRepo(db *gorm.DB) *AdminAPIKeyRepo { return authn.NewAdminAPIKeyRepo(db) }

// NewRefreshTokenRepo 转发到 authn 子包的构造函数。
func NewRefreshTokenRepo(db *gorm.DB) *RefreshTokenRepo { return authn.NewRefreshTokenRepo(db) }

// IPListRepo 是 iplist 子包实现的别名。
type IPListRepo = iplist.IPListRepo

// NewIPListRepo 转发到 iplist 子包的构造函数。
func NewIPListRepo(db *gorm.DB) *IPListRepo { return iplist.NewIPListRepo(db) }

// BotScoreRepo 是 bot 子包实现的别名。
type BotScoreRepo = bot.BotScoreRepo

// BotScoreFilter 是 bot 子包实现的别名。
type BotScoreFilter = bot.BotScoreFilter

// BotScoreStats 是 bot 子包实现的别名。
type BotScoreStats = bot.BotScoreStats

// NewBotScoreRepo 转发到 bot 子包的构造函数。
func NewBotScoreRepo(db *gorm.DB) *BotScoreRepo { return bot.NewBotScoreRepo(db) }

// CVERuleRepo 是 cve 子包实现的别名。
type CVERuleRepo = cve.CVERuleRepo

// CVESyncLogRepo 是 cve 子包实现的别名。
type CVESyncLogRepo = cve.CVESyncLogRepo

// CVERuleFilter 是 cve 子包实现的别名。
type CVERuleFilter = cve.CVERuleFilter

// CVERuleCanonicalSnapshot 是 cve 子包实现的别名。
type CVERuleCanonicalSnapshot = cve.CVERuleCanonicalSnapshot

// NewCVERuleRepo 转发到 cve 子包的构造函数。
func NewCVERuleRepo(db *gorm.DB) *CVERuleRepo { return cve.NewCVERuleRepo(db) }

// NewCVESyncLogRepo 转发到 cve 子包的构造函数。
func NewCVESyncLogRepo(db *gorm.DB) *CVESyncLogRepo { return cve.NewCVESyncLogRepo(db) }

// FalsePositiveRepo 是 event 子包实现的别名。
type FalsePositiveRepo = event.FalsePositiveRepo

// NewFalsePositiveRepo 转发到 event 子包的构造函数。
func NewFalsePositiveRepo(db *gorm.DB) *FalsePositiveRepo { return event.NewFalsePositiveRepo(db) }

// ThreatIntelRepo 是 threat 子包实现的别名。
type ThreatIntelRepo = threat.ThreatIntelRepo

// ThreatIntelSyncLogRepo 是 threat 子包实现的别名。
type ThreatIntelSyncLogRepo = threat.ThreatIntelSyncLogRepo

// NewThreatIntelRepo 转发到 threat 子包的构造函数。
func NewThreatIntelRepo(db *gorm.DB) *ThreatIntelRepo { return threat.NewThreatIntelRepo(db) }

// NewThreatIntelSyncLogRepo 转发到 threat 子包的构造函数。
func NewThreatIntelSyncLogRepo(db *gorm.DB) *ThreatIntelSyncLogRepo {
	return threat.NewThreatIntelSyncLogRepo(db)
}

// JSPluginRepo 是 plugin 子包实现的别名。
type JSPluginRepo = plugin.JSPluginRepo

// LuaPluginRepo 是 plugin 子包实现的别名。
type LuaPluginRepo = plugin.LuaPluginRepo

// NewJSPluginRepo 转发到 plugin 子包的构造函数。
func NewJSPluginRepo(db *gorm.DB) *JSPluginRepo { return plugin.NewJSPluginRepo(db) }

// NewLuaPluginRepo 转发到 plugin 子包的构造函数。
func NewLuaPluginRepo(db *gorm.DB) *LuaPluginRepo { return plugin.NewLuaPluginRepo(db) }

// AccessControlRepo 是 acl 子包实现的别名。
type AccessControlRepo = acl.AccessControlRepo

// NewAccessControlRepo 转发到 acl 子包的构造函数。
func NewAccessControlRepo(db *gorm.DB) *AccessControlRepo { return acl.NewAccessControlRepo(db) }
