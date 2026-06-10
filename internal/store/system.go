package store

// SystemSettings is a generic key/value table for runtime configuration.
type SystemSettings struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"size:128;uniqueIndex;not null" json:"key"`
	Value string `gorm:"type:text" json:"value"`
}

const (
	SettingKeyACMEConfig  = "acme_config"
	SettingKeyRedisConfig = "redis_config"
)

// ConfigRevision is a monotonically increasing snapshot revision number.
type ConfigRevision struct {
	ID       uint   `gorm:"primaryKey"`
	Revision uint64 `gorm:"not null"`
}
