package cve

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newFeedTestDB 打开内存 SQLite 库并迁移出 cve_rules 表。
func newFeedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&CVERuleModel{}); err != nil {
		t.Fatalf("migrate cve_rules: %v", err)
	}
	return db
}

// newFeedTestManager 构造指向 httptest 服务端的订阅源管理器，并把页间延时
// 压到极小，使分页测试跑得快且绝不访问真实 NVD。
func newFeedTestManager(db *gorm.DB, baseURL string) *CVEFeedManager {
	return &CVEFeedManager{
		db:                   db,
		detector:             NewCVEDetector(),
		syncInterval:         time.Hour,
		nvdBaseURL:           baseURL,
		nvdPageDelayOverride: 10 * time.Millisecond,
		log:                  slog.Default(),
	}
}

// nvdTestPage 渲染一页 NVD API 2.0 风格的响应。
func nvdTestPage(startIndex, totalResults int, vulns []nvdVuln) string {
	if vulns == nil {
		vulns = []nvdVuln{}
	}
	payload := map[string]any{
		"resultsPerPage":  nvdResultsPerPage,
		"startIndex":      startIndex,
		"totalResults":    totalResults,
		"vulnerabilities": vulns,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// nvdTestVuln 构造一条能映射出非空正则的 CVE（CWE-89 → SQL 注入）。
func nvdTestVuln(id string) nvdVuln {
	return nvdVuln{CVE: nvdCVE{
		ID: id,
		Descriptions: []nvdDesc{{
			Lang:  "en",
			Value: "SQL injection in a web application allows attackers to run arbitrary SQL.",
		}},
		Metrics: nvdMetrics{
			CvssMetricV31: []nvdCVSS{{CvssData: nvdCVSSData{BaseScore: 9.8}}},
		},
		Weaknesses: []nvdWeakness{{
			Description: []nvdDesc{{Lang: "en", Value: "CWE-89"}},
		}},
	}}
}

// nvdTestVulns 生成 n 条共享同一 ID 前缀的不同 CVE。
func nvdTestVulns(prefix string, n int) []nvdVuln {
	vulns := make([]nvdVuln, n)
	for i := range vulns {
		vulns[i] = nvdTestVuln(prefix + strconv.Itoa(i))
	}
	return vulns
}

// TestFetchFromNVDPaginatesAllPages 验证两页订阅源被完整摄入：startIndex 游标
// 按 0 -> 50 递进，且每个请求都带上固定的分页大小。
func TestFetchFromNVDPaginatesAllPages(t *testing.T) {
	all := nvdTestVulns("CVE-2026-PAGE-", 80)
	var starts []int
	var perPages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		si, _ := strconv.Atoi(q.Get("startIndex"))
		starts = append(starts, si)
		perPages = append(perPages, q.Get("resultsPerPage"))
		lo := min(si, len(all))
		hi := min(si+nvdResultsPerPage, len(all))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdTestPage(si, len(all), all[lo:hi])))
	}))
	defer srv.Close()

	db := newFeedTestDB(t)
	m := newFeedTestManager(db, srv.URL)

	if err := m.fetchFromNVD(); err != nil {
		t.Fatalf("fetchFromNVD error: %v", err)
	}

	var count int64
	if err := db.Model(&CVERuleModel{}).Where("source = ?", "nvd").Count(&count).Error; err != nil {
		t.Fatalf("count stored rules: %v", err)
	}
	if count != int64(len(all)) {
		t.Fatalf("stored rules = %d, want %d", count, len(all))
	}

	wantStarts := []int{0, 50}
	if len(starts) != len(wantStarts) {
		t.Fatalf("page requests = %d (startIndex %v), want %d", len(starts), starts, len(wantStarts))
	}
	for i, want := range wantStarts {
		if starts[i] != want {
			t.Fatalf("request %d startIndex = %d, want %d", i, starts[i], want)
		}
		if perPages[i] != strconv.Itoa(nvdResultsPerPage) {
			t.Fatalf("request %d resultsPerPage = %q, want %d", i, perPages[i], nvdResultsPerPage)
		}
	}

	// AutoApprove 未开启时，自动生成规则仍保持 Approved=false / Enabled=false。
	var first CVERuleModel
	if err := db.Where("source = ?", "nvd").First(&first).Error; err != nil {
		t.Fatalf("load first nvd rule: %v", err)
	}
	if first.Approved || first.Enabled {
		t.Fatalf("rule %s: approved=%v enabled=%v, want both false", first.CVEID, first.Approved, first.Enabled)
	}
}

// TestFetchFromNVDPropagatesMidPageErrors 验证第二页失败会作为错误上抛，
// 而不是被静默丢弃。
func TestFetchFromNVDPropagatesMidPageErrors(t *testing.T) {
	all := nvdTestVulns("CVE-2026-ERR-", 60)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		si, _ := strconv.Atoi(q.Get("startIndex"))
		calls++
		if calls == 1 {
			lo := min(si, len(all))
			hi := min(si+nvdResultsPerPage, len(all))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nvdTestPage(si, len(all), all[lo:hi])))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	db := newFeedTestDB(t)
	m := newFeedTestManager(db, srv.URL)

	err := m.fetchFromNVD()
	if err == nil {
		t.Fatal("expected error when the second page fails, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %q, want it to mention the 503 status", err.Error())
	}
	if calls != 2 {
		t.Fatalf("page requests = %d, want 2", calls)
	}
}

// TestFetchFromNVDStopsOnShortLastPageWithoutTotal 验证缺失 totalResults 的响应
// 在遇到不足一页时立即停止，避免对旧版响应无限翻页。
func TestFetchFromNVDStopsOnShortLastPageWithoutTotal(t *testing.T) {
	first := nvdTestVulns("CVE-2026-SHORT-", 7)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		si, _ := strconv.Atoi(q.Get("startIndex"))
		calls++
		lo := min(si, len(first))
		hi := min(si+nvdResultsPerPage, len(first))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdTestPage(si, 0, first[lo:hi])))
	}))
	defer srv.Close()

	db := newFeedTestDB(t)
	m := newFeedTestManager(db, srv.URL)

	if err := m.fetchFromNVD(); err != nil {
		t.Fatalf("fetchFromNVD error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("page requests = %d, want 1", calls)
	}
	var count int64
	if err := db.Model(&CVERuleModel{}).Where("source = ?", "nvd").Count(&count).Error; err != nil {
		t.Fatalf("count stored rules: %v", err)
	}
	if count != 7 {
		t.Fatalf("stored rules = %d, want 7", count)
	}
}

// TestFetchFromNVDSetsAPIKeyHeader 验证仅在配置了 API key 时才发送 apiKey 请求头。
func TestFetchFromNVDSetsAPIKeyHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		si, _ := strconv.Atoi(q.Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdTestPage(si, 0, nil)))
	}))
	defer srv.Close()

	db := newFeedTestDB(t)
	withKey := newFeedTestManager(db, srv.URL)
	withKey.nvdAPIKey = "test-key"
	if err := withKey.fetchFromNVD(); err != nil {
		t.Fatalf("fetchFromNVD with key: %v", err)
	}

	got := ""
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("apiKey")
		q := r.URL.Query()
		si, _ := strconv.Atoi(q.Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdTestPage(si, 0, nil)))
	}))
	defer srv2.Close()

	noKey := newFeedTestManager(db, srv2.URL)
	if err := noKey.fetchFromNVD(); err != nil {
		t.Fatalf("fetchFromNVD without key: %v", err)
	}
	if got != "" {
		t.Fatalf("apiKey header = %q, want empty when no key configured", got)
	}
}
