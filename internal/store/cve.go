package store

import (
	"time"

	"gorm.io/gorm"
)

// CVERuleRecord stores custom and feed-synchronised CVE rules.
type CVERuleRecord struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CVEID       string         `gorm:"size:32;index" json:"cve_id"`
	Category    string         `gorm:"size:32" json:"category"`
	Pattern     string         `gorm:"type:text" json:"pattern"`
	Target      string         `gorm:"size:32" json:"target"`
	Severity    string         `gorm:"size:16" json:"severity"`
	Action      string         `gorm:"size:32;default:drop" json:"action"`
	Enabled     bool           `gorm:"default:false" json:"enabled"`
	Description string         `gorm:"type:text" json:"description"`
	Source      string         `gorm:"size:32" json:"source"`
	Approved    bool           `gorm:"default:false" json:"approved"`
	CVSSScore   float64        `gorm:"default:0" json:"cvss_score"`
	CWEType     string         `gorm:"size:32" json:"cwe_type"`
}

func (CVERuleRecord) TableName() string { return "cve_rules" }

// CVESyncLog records the result of a CVE feed synchronisation run.
type CVESyncLog struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	Source     string    `gorm:"size:32" json:"source"` // nvd, github
	Status     string    `gorm:"size:16" json:"status"` // success, failed, running
	RulesAdded int       `json:"rules_added"`
	Error      string    `gorm:"size:512" json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
