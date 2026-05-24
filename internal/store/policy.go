package store

import (
	"time"

	"gorm.io/gorm"
)

// Policy is a named container for a group of rules.
type Policy struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name string `gorm:"size:128;not null" json:"name"`
}

type RulePhase string

const (
	PhaseACL       RulePhase = "acl"
	PhaseRateLimit RulePhase = "rate_limit"
	PhaseOWASP     RulePhase = "owasp_default"
	PhaseSignature RulePhase = "signature"
	PhaseCustom    RulePhase = "custom"
)

type RuleAction string

const (
	ActionAllow            RuleAction = "allow"
	ActionIntercept        RuleAction = "intercept"
	ActionObserve          RuleAction = "observe"
	ActionDrop             RuleAction = "drop"
	ActionChallenge        RuleAction = "challenge"
	ActionCaptchaChallenge RuleAction = "captcha_challenge"
	ActionShieldChallenge  RuleAction = "shield_challenge"
	ActionChainChallenge   RuleAction = "chain_challenge"
	ActionRedirect         RuleAction = "redirect"
	ActionRateLimit        RuleAction = "rate_limit"
	ActionTag              RuleAction = "tag"

	// Legacy values for backward compatibility with existing DB rows.
	ActionBlock   RuleAction = "block"
	ActionLogOnly RuleAction = "log_only"
)

// NormalizeAction maps legacy action strings to canonical form.
func NormalizeAction(a RuleAction) RuleAction {
	switch a {
	case ActionBlock:
		return ActionIntercept
	case ActionLogOnly:
		return ActionObserve
	default:
		return a
	}
}

// Rule is a single rule entry that belongs to a Policy.
type Rule struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name       string     `gorm:"size:128" json:"name"`
	PolicyID   uint       `gorm:"not null;index" json:"policy_id"`
	Phase      RulePhase  `gorm:"size:32;not null;index" json:"phase"`
	Pattern    string     `gorm:"type:text;not null" json:"pattern"`
	Action     RuleAction `gorm:"size:32;not null" json:"action"`
	Priority   int        `gorm:"default:100" json:"priority"`
	Enabled    bool       `gorm:"default:true" json:"enabled"`
	StatusCode int        `gorm:"default:0" json:"status_code"`
	RedirectTo string     `gorm:"size:2048" json:"redirect_to"`
}
