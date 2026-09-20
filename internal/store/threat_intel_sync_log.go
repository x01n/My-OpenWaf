package store

import "time"

/**
 * ThreatIntelSyncLog 威胁情报订阅源单次同步的历史记录。
 *
 * 每次 Manager 触发同步（无论定时还是手动）都会写入一条记录，用于管理员
 * 审查订阅源健康度：成功次数、失败原因、拉取条目数、耗时等。
 */
type ThreatIntelSyncLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	FeedID   uint   `gorm:"index;not null" json:"feed_id"`
	FeedName string `gorm:"size:100" json:"feed_name"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMs int64     `json:"duration_ms"`

	// Success = true 表示 HTTP 拉取和解析都成功（哪怕条目为 0）。
	Success bool `gorm:"index" json:"success"`
	// EntriesAdded 本次同步新增/替换后条目总数。
	EntriesAdded int `json:"entries_added"`
	// EntriesSkipped 本次拉取内容中因格式非法被跳过的条目数。
	EntriesSkipped int `json:"entries_skipped"`
	// 拉取的原始行数（用于估算数据源规模）。
	LinesRead int `json:"lines_read"`

	// Trigger = "auto" | "manual"，标识是定时同步还是手动触发。
	Trigger string `gorm:"size:16;index" json:"trigger"`

	// Error 记录失败时的错误消息（若 Success=true 则为空）。
	Error string `gorm:"size:1000" json:"error,omitempty"`
}
