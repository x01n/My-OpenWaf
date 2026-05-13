package waf

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// CVEFeedManager manages background synchronisation of CVE data from external sources.
type CVEFeedManager struct {
	db           *gorm.DB
	detector     *CVEDetector
	syncInterval time.Duration
	nvdAPIKey    string
	autoApprove  bool
	feedEnabled  bool
	stopCh       chan struct{}
	log          *slog.Logger
	mu           sync.Mutex
	lastSync     time.Time
	lastError    string
	syncing      bool
}

// CVERuleModel is the database model for CVE rules (auto-generated or user-created).
type CVERuleModel struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CVEID       string         `gorm:"size:32;index" json:"cve_id"`
	Category    string         `gorm:"size:32" json:"category"`
	Pattern     string         `gorm:"type:text" json:"pattern"`
	Target      string         `gorm:"size:32" json:"target"` // url, body, header, cookie
	Severity    string         `gorm:"size:16" json:"severity"`
	Action      string         `gorm:"size:32;default:drop" json:"action"`
	Enabled     bool           `gorm:"default:false" json:"enabled"`
	Description string         `gorm:"type:text" json:"description"`
	Source      string         `gorm:"size:32" json:"source"` // auto_generated, manual, nvd, github
	Approved    bool           `gorm:"default:false" json:"approved"`
	CVSSScore   float64        `gorm:"default:0" json:"cvss_score"`
	CWEType     string         `gorm:"size:32" json:"cwe_type"`
}

// TableName for GORM.
func (CVERuleModel) TableName() string { return "cve_rules" }

// SyncStatus reports the current state of the CVE feed sync.
type SyncStatus struct {
	LastSync  time.Time `json:"last_sync"`
	LastError string    `json:"last_error,omitempty"`
	Syncing   bool      `json:"syncing"`
}

// NewCVEFeedManager creates a new feed manager.
func NewCVEFeedManager(db *gorm.DB, detector *CVEDetector, interval time.Duration, nvdAPIKey string, autoApprove bool, log *slog.Logger) *CVEFeedManager {
	return NewCVEFeedManagerWithFeed(db, detector, interval, nvdAPIKey, autoApprove, true, log)
}

func NewCVEFeedManagerWithFeed(db *gorm.DB, detector *CVEDetector, interval time.Duration, nvdAPIKey string, autoApprove bool, feedEnabled bool, log *slog.Logger) *CVEFeedManager {
	if log == nil {
		log = slog.Default()
	}
	return &CVEFeedManager{
		db:           db,
		detector:     detector,
		syncInterval: interval,
		nvdAPIKey:    nvdAPIKey,
		autoApprove:  autoApprove,
		feedEnabled:  feedEnabled,
		stopCh:       make(chan struct{}),
		log:          log,
	}
}

// Start begins the background sync loop. Non-blocking.
func (m *CVEFeedManager) Start() {
	// Auto-migrate the table.
	if err := m.db.AutoMigrate(&CVERuleModel{}); err != nil {
		m.log.Error("cve_feed: failed to migrate cve_rules table", slog.String("error", err.Error()))
		return
	}

	// Load existing rules into the detector.
	m.loadRulesIntoDetector()
	if !m.feedEnabled {
		m.log.Info("cve_feed: background sync disabled")
		return
	}

	go m.loop()
	m.log.Info("cve_feed: started", slog.Duration("interval", m.syncInterval))
}

// Stop signals the background loop to exit.
func (m *CVEFeedManager) Stop() {
	if m.feedEnabled {
		close(m.stopCh)
	}
}

// SyncNow triggers an immediate sync (blocking).
func (m *CVEFeedManager) SyncNow() error {
	return m.doSync()
}

// GetSyncStatus returns the current sync status.
func (m *CVEFeedManager) GetSyncStatus() SyncStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SyncStatus{
		LastSync:  m.lastSync,
		LastError: m.lastError,
		Syncing:   m.syncing,
	}
}

func (m *CVEFeedManager) ReloadRules() {
	m.loadRulesIntoDetector()
}

func (m *CVEFeedManager) loop() {
	// Run once at startup (non-fatal).
	_ = m.doSync()

	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = m.doSync()
		case <-m.stopCh:
			return
		}
	}
}

func (m *CVEFeedManager) doSync() error {
	m.mu.Lock()
	if m.syncing {
		m.mu.Unlock()
		return nil
	}
	m.syncing = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.syncing = false
		m.mu.Unlock()
	}()

	var errs []string

	if err := m.fetchFromNVD(); err != nil {
		m.log.Warn("cve_feed: NVD fetch failed", slog.String("error", err.Error()))
		errs = append(errs, "nvd: "+err.Error())
	}

	if err := m.fetchFromGitHubAdvisory(); err != nil {
		m.log.Warn("cve_feed: GitHub Advisory fetch failed", slog.String("error", err.Error()))
		errs = append(errs, "github: "+err.Error())
	}

	// Reload rules into the detector.
	m.loadRulesIntoDetector()

	m.mu.Lock()
	m.lastSync = time.Now()
	if len(errs) > 0 {
		m.lastError = strings.Join(errs, "; ")
	} else {
		m.lastError = ""
	}
	m.mu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *CVEFeedManager) loadRulesIntoDetector() {
	var rules []CVERuleModel
	if err := m.db.Where("enabled = ? AND approved = ?", true, true).Find(&rules).Error; err != nil {
		m.log.Error("cve_feed: failed to load rules", slog.String("error", err.Error()))
		return
	}
	custom := make([]CustomCVERule, len(rules))
	for i, r := range rules {
		custom[i] = CustomCVERule{
			ID:          r.ID,
			CVEID:       r.CVEID,
			Category:    r.Category,
			Pattern:     r.Pattern,
			Target:      r.Target,
			Severity:    r.Severity,
			Action:      r.Action,
			Enabled:     r.Enabled,
			Description: r.Description,
		}
	}
	m.detector.ReloadCustomRules(custom)
	m.log.Info("cve_feed: loaded rules into detector", slog.Int("count", len(custom)))
}

// ── NVD API v2.0 ──

type nvdResponse struct {
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string        `json:"id"`
	Descriptions []nvdDesc     `json:"descriptions"`
	Metrics      nvdMetrics    `json:"metrics"`
	Weaknesses   []nvdWeakness `json:"weaknesses"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSS `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSS `json:"cvssMetricV30"`
}

type nvdCVSS struct {
	CvssData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Description []nvdDesc `json:"description"`
}

func (m *CVEFeedManager) fetchFromNVD() error {
	client := &http.Client{Timeout: 30 * time.Second}

	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour) // last 24 hours

	apiURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&keywordSearch=web+application&resultsPerPage=50",
		start.Format("2006-01-02T15:04:05.000"),
		end.Format("2006-01-02T15:04:05.000"),
	)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if m.nvdAPIKey != "" {
		req.Header.Set("apiKey", m.nvdAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("NVD returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return fmt.Errorf("parse json: %w", err)
	}

	count := 0
	for _, v := range nvdResp.Vulnerabilities {
		if m.processNVDCVE(v.CVE) {
			count++
		}
	}
	m.log.Info("cve_feed: NVD sync complete", slog.Int("new_rules", count))
	return nil
}

func (m *CVEFeedManager) processNVDCVE(cve nvdCVE) bool {
	// Check if rule already exists.
	var existing CVERuleModel
	if err := m.db.Where("cve_id = ? AND source = ?", cve.ID, "nvd").First(&existing).Error; err == nil {
		return false // already exists
	}

	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(cve.Descriptions) > 0 {
		desc = cve.Descriptions[0].Value
	}

	cvss := 0.0
	if len(cve.Metrics.CvssMetricV31) > 0 {
		cvss = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
	} else if len(cve.Metrics.CvssMetricV30) > 0 {
		cvss = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
	}

	cweType := ""
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cweType = d.Value
				break
			}
		}
	}

	rule := m.generateRule(cve.ID, desc, cvss, cweType)
	if rule == nil {
		return false
	}

	approved := m.autoApprove
	rule.Approved = approved
	rule.Enabled = approved

	return m.db.Create(rule).Error == nil
}

// ── GitHub Advisory API ──

type ghAdvisory struct {
	GHSAID          string   `json:"ghsa_id"`
	CVEID           string   `json:"cve_id"`
	Summary         string   `json:"summary"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	CVSS            ghCVSS   `json:"cvss"`
	CWEs            []ghCWE  `json:"cwes"`
	Vulnerabilities []ghVuln `json:"vulnerabilities"`
}

type ghCVSS struct {
	Score float64 `json:"score"`
}

type ghCWE struct {
	CWEID string `json:"cwe_id"`
}

type ghVuln struct {
	Package ghPackage `json:"package"`
}

type ghPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

func (m *CVEFeedManager) fetchFromGitHubAdvisory() error {
	client := &http.Client{Timeout: 30 * time.Second}

	apiURL := "https://api.github.com/advisories?type=reviewed&per_page=30&sort=updated&direction=desc"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GitHub returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var advisories []ghAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return fmt.Errorf("parse json: %w", err)
	}

	count := 0
	for _, adv := range advisories {
		if adv.CVEID == "" {
			continue
		}
		// Only process web-related ecosystems.
		relevant := false
		for _, v := range adv.Vulnerabilities {
			eco := strings.ToLower(v.Package.Ecosystem)
			if eco == "npm" || eco == "composer" || eco == "maven" || eco == "pip" || eco == "go" {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}

		// Check if already exists.
		var existing CVERuleModel
		if err := m.db.Where("cve_id = ? AND source = ?", adv.CVEID, "github").First(&existing).Error; err == nil {
			continue
		}

		cweType := ""
		if len(adv.CWEs) > 0 {
			cweType = adv.CWEs[0].CWEID
		}

		rule := m.generateRule(adv.CVEID, adv.Description, adv.CVSS.Score, cweType)
		if rule == nil {
			continue
		}
		rule.Source = "github"
		approved := m.autoApprove
		rule.Approved = approved
		rule.Enabled = approved

		if m.db.Create(rule).Error == nil {
			count++
		}
	}

	m.log.Info("cve_feed: GitHub Advisory sync complete", slog.Int("new_rules", count))
	return nil
}

// generateRule creates a CVERuleModel from CVE metadata by mapping CWE to detection patterns.
func (m *CVEFeedManager) generateRule(cveID, description string, cvssScore float64, cweType string) *CVERuleModel {
	pattern, target, category := cweToPattern(cweType, description)
	if pattern == "" {
		return nil
	}

	severity := "medium"
	if cvssScore >= 9.0 {
		severity = "critical"
	} else if cvssScore >= 7.0 {
		severity = "high"
	} else if cvssScore >= 4.0 {
		severity = "medium"
	} else if cvssScore > 0 {
		severity = "low"
	}

	return &CVERuleModel{
		CVEID:       cveID,
		Category:    category,
		Pattern:     pattern,
		Target:      target,
		Severity:    severity,
		Action:      "drop",
		Source:      "auto_generated",
		Description: truncate(description, 500),
		CVSSScore:   cvssScore,
		CWEType:     cweType,
	}
}

// cweToPattern maps CWE types to generic detection regex patterns.
func cweToPattern(cweType, description string) (pattern, target, category string) {
	switch cweType {
	case "CWE-89": // SQL Injection
		return `(?i)(\b(union|select|insert|update|delete|drop)\b.*\b(from|into|table|where)\b)`, "all", "general"
	case "CWE-79": // XSS
		return `(?i)(<script[^>]*>|javascript:|on\w+\s*=)`, "all", "general"
	case "CWE-78", "CWE-77": // OS Command Injection
		return `(?i)(;\s*(ls|cat|id|whoami|uname|rm|wget|curl)\b|\|\s*(cat|id|whoami))`, "all", "general"
	case "CWE-22": // Path Traversal
		return `(?i)(\.\.(/|\\|%2[fF]|%5[cC])){2,}`, "url", "general"
	case "CWE-611": // XXE
		return `(?i)(<!DOCTYPE\s.*<!ENTITY\s|SYSTEM\s+["']file://)`, "body", "general"
	case "CWE-918": // SSRF
		return `(?i)(https?://(10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.|169\.254\.169\.254|localhost))`, "all", "general"
	case "CWE-502": // Deserialization
		return `(?i)(O:\d+:"|@type|java\.lang\.Runtime|__proto__)`, "all", "general"
	case "CWE-94", "CWE-95": // Code Injection
		return `(?i)(eval\s*\(|exec\s*\(|system\s*\(|child_process)`, "all", "general"
	case "CWE-113": // CRLF Injection
		return `(?i)(%0[dD]%0[aA])`, "all", "general"
	case "CWE-352": // CSRF (less useful for WAF but can flag)
		return "", "", ""
	default:
		// Try to extract patterns from the description keywords.
		return descriptionToPattern(description)
	}
}

// descriptionToPattern attempts to generate a detection pattern from CVE description text.
func descriptionToPattern(desc string) (pattern, target, category string) {
	dl := strings.ToLower(desc)
	switch {
	case strings.Contains(dl, "sql injection"):
		return `(?i)(\b(union|select|insert|update|delete)\b.*\b(from|into|table)\b)`, "all", "general"
	case strings.Contains(dl, "cross-site scripting") || strings.Contains(dl, "xss"):
		return `(?i)(<script|javascript:|on\w+=)`, "all", "general"
	case strings.Contains(dl, "remote code execution") || strings.Contains(dl, "rce"):
		return `(?i)(eval\s*\(|exec\s*\(|system\s*\()`, "all", "general"
	case strings.Contains(dl, "path traversal") || strings.Contains(dl, "directory traversal"):
		return `(?i)(\.\.(/|\\|%2[fF])){2,}`, "url", "general"
	case strings.Contains(dl, "ssrf") || strings.Contains(dl, "server-side request"):
		return `(?i)(https?://(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.))`, "all", "general"
	case strings.Contains(dl, "deserialization"):
		return `(?i)(O:\d+:"|@type|java\.lang\.Runtime)`, "all", "general"
	default:
		return "", "", "" // Cannot generate a useful pattern.
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
