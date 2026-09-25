package cve

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
	db                   *gorm.DB
	detector             *CVEDetector
	syncInterval         time.Duration
	nvdAPIKey            string
	nvdBaseURL           string        // 测试注入的 NVD API 基础地址；空值使用 nvdAPIBaseURL
	nvdPageDelayOverride time.Duration // 测试注入的页间延时；0 表示按是否配置 API key 选择默认值
	autoApprove          bool
	feedEnabled          bool
	stopCh               chan struct{}
	stopOnce             sync.Once
	log                  *slog.Logger
	mu                   sync.Mutex
	lastSync             time.Time
	lastError            string
	syncing              bool
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
	CaptchaType string         `gorm:"size:16" json:"captcha_type,omitempty"`
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
	if m == nil || !m.feedEnabled {
		return
	}
	m.stopOnce.Do(func() {
		if m.stopCh != nil {
			close(m.stopCh)
		}
	})
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
	if err := m.db.Where("approved = ? AND source <> ?", true, "catalog").Find(&rules).Error; err != nil {
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
			CaptchaType: r.CaptchaType,
			Enabled:     r.Enabled,
			Description: r.Description,
		}
	}
	m.detector.ReloadCustomRules(custom)
	m.log.Info("cve_feed: loaded rules into detector", slog.Int("count", len(custom)))
}

type nvdResponse struct {
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
	TotalResults    int       `json:"totalResults"`
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

// NVD API 2.0 拉取参数与限流相关常量。
const (
	// nvdAPIBaseURL 是 NVD CVE API 2.0 的基础地址，测试通过 nvdBaseURL 覆盖。
	nvdAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// nvdResultsPerPage 是单页拉取条数。NVD 官方允许的最大值为 200，
	// 此处保持与既有实现一致的 50 以避免单页响应体过大。
	nvdResultsPerPage = 50
	// nvdPageDelayNoKey 是未配置 API key 时每页之间的礼貌延时。
	// NVD 官方文档限定无 key 请求为滚动 30 秒窗口内 5 次（等效 6 秒 1 次），
	// 因此按 6 秒等待以保证不触发限流。
	nvdPageDelayNoKey = 6 * time.Second
	// nvdPageDelayWithKey 是配置 API key 时每页之间的礼貌延时。
	// NVD 官方文档限定有 key 请求为滚动 30 秒窗口内 50 次，单次同步页数
	// 很少，6 秒过于保守；1.2 秒既大幅低于限流又保证同步速度。
	nvdPageDelayWithKey = 1200 * time.Millisecond
	// nvdMaxPages 是单次同步最多拉取的页数（50 页 x 50 条 = 2500 条），
	// 防止无 key 形态下 6s/页的延时使单次同步被无限拉长。
	nvdMaxPages = 50
)

func (m *CVEFeedManager) fetchFromNVD() error {
	client := &http.Client{Timeout: 30 * time.Second}

	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour) // 最近 24 小时

	total := 0
	for page := 0; page < nvdMaxPages; page++ {
		startIndex := page * nvdResultsPerPage
		apiURL := fmt.Sprintf(
			"%s?pubStartDate=%s&pubEndDate=%s&keywordSearch=web+application&resultsPerPage=%d&startIndex=%d",
			m.nvdBaseURLOrDefault(),
			start.Format("2006-01-02T15:04:05.000"),
			end.Format("2006-01-02T15:04:05.000"),
			nvdResultsPerPage,
			startIndex,
		)

		count, totalResults, done, err := m.fetchNVDPage(client, apiURL, startIndex)
		if err != nil {
			return err
		}
		total += count
		if done {
			m.log.Info("cve_feed: NVD sync complete",
				slog.Int("new_rules", total),
				slog.Int("pages", page+1),
				slog.Int("total_results", totalResults),
			)
			return nil
		}

		// 仅在实际翻页前等待，最后一页无需延时。
		time.Sleep(m.pageDelay())
	}

	m.log.Warn("cve_feed: NVD sync hit page cap",
		slog.Int("max_pages", nvdMaxPages),
		slog.Int("new_rules", total),
	)
	return nil
}

// nvdBaseURLOrDefault 返回 NVD API 基础地址，测试可注入 nvdBaseURL 覆盖。
func (m *CVEFeedManager) nvdBaseURLOrDefault() string {
	if m.nvdBaseURL != "" {
		return m.nvdBaseURL
	}
	return nvdAPIBaseURL
}

// pageDelay 返回页间延时：测试注入优先，其次按是否配置 API key 选择默认常量。
func (m *CVEFeedManager) pageDelay() time.Duration {
	if m.nvdPageDelayOverride > 0 {
		return m.nvdPageDelayOverride
	}
	if m.nvdAPIKey != "" {
		return nvdPageDelayWithKey
	}
	return nvdPageDelayNoKey
}

// fetchNVDPage 拉取单个 startIndex 页并处理其中全部 CVE。
// 返回：本页新增规则数、服务端报告的 totalResults、以及是否应停止翻页；
// 任何网络/状态码/解析失败都以错误返回，绝不平滑吞页。
func (m *CVEFeedManager) fetchNVDPage(client *http.Client, apiURL string, startIndex int) (int, int, bool, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return 0, 0, false, fmt.Errorf("build request: %w", err)
	}
	if m.nvdAPIKey != "" {
		req.Header.Set("apiKey", m.nvdAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, false, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, 0, false, fmt.Errorf("NVD returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return 0, 0, false, fmt.Errorf("read body: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return 0, 0, false, fmt.Errorf("parse json: %w", err)
	}

	count := 0
	for _, v := range nvdResp.Vulnerabilities {
		if m.processNVDCVE(v.CVE) {
			count++
		}
	}

	// 停页条件按优先级：
	// 1. 本页为空——继续翻页只会空转或越界，立即停止。
	// 2. 服务端 totalResults 有效且 startIndex 加本页容量已覆盖总数：
	//    恰好整页时 startIndex+perPage == totalResults，同样停止。
	// 3. totalResults 缺失（旧版响应为 0）时，以本页不足一页作为停止信号。
	if len(nvdResp.Vulnerabilities) == 0 {
		return count, nvdResp.TotalResults, true, nil
	}
	if nvdResp.TotalResults > 0 && startIndex+nvdResultsPerPage >= nvdResp.TotalResults {
		return count, nvdResp.TotalResults, true, nil
	}
	if nvdResp.TotalResults == 0 && len(nvdResp.Vulnerabilities) < nvdResultsPerPage {
		return count, nvdResp.TotalResults, true, nil
	}
	return count, nvdResp.TotalResults, false, nil
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
	// generateRule 默认 Source="auto_generated"，NVD 拉取必须显式改回 "nvd"，
	// 否则入库来源与 processNVDCVE 的查重条件（source = "nvd"）不一致，
	// 每次翻页同步都会重复插入同一批 CVE。
	rule.Source = "nvd"

	approved := m.autoApprove
	rule.Approved = approved
	rule.Enabled = approved

	return m.db.Create(rule).Error == nil
}

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
