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

// newFeedTestDB opens an in-memory SQLite database with the cve_rules table migrated.
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

// newFeedTestManager builds a feed manager pointed at the httptest server with a
// tiny page delay so pagination runs fast and never touches the real NVD.
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

// nvdTestPage renders one NVD API 2.0 style response page.
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

// nvdTestVuln builds one CVE that maps to a non-empty rule pattern (CWE-89 -> SQL injection).
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

// nvdTestVulns generates n distinct CVEs sharing the given ID prefix.
func nvdTestVulns(prefix string, n int) []nvdVuln {
	vulns := make([]nvdVuln, n)
	for i := range vulns {
		vulns[i] = nvdTestVuln(prefix + strconv.Itoa(i))
	}
	return vulns
}

// TestFetchFromNVDPaginatesAllPages verifies that a 2-page feed is fully ingested,
// the startIndex cursor advances 0 -> 50, and each request carries the fixed page size.
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

// TestFetchFromNVDPropagatesMidPageErrors verifies that a failing second page
// surfaces as an error instead of silently dropping the page.
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

// TestFetchFromNVDStopsOnShortLastPageWithoutTotal verifies that a response
// without totalResults stops as soon as a short page arrives, so pagination
// does not spin on legacy-style responses.
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

// TestFetchFromNVDSetsAPIKeyHeader verifies the apiKey header is sent only when configured.
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
