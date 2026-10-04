package store

// SystemSettings 是存放运行时配置的通用键值表。
type SystemSettings struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"size:128;uniqueIndex;not null" json:"key"`
	Value string `gorm:"type:text" json:"value"`
}

const (
	SettingKeyACMEConfig          = "acme_config"
	SettingKeyRedisConfig         = "redis_config"
	SettingKeyJWTSecret           = "jwt_secret"
	SettingKeyAPIKeySeedMarker    = "seed.api_key_initialized"
	SettingKeyHPKP                = "hpkp_enabled"
	SettingKeyHPKPValue           = "hpkp_value"
	SettingKeyHPKPReportOnly      = "hpkp_report_only_enabled"
	SettingKeyHPKPReportOnlyValue = "hpkp_report_only_value"
)

// ConfigRevision 是单调递增的快照修订号。
type ConfigRevision struct {
	ID       uint   `gorm:"primaryKey"`
	Revision uint64 `gorm:"not null"`
}
