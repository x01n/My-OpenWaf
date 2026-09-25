package threatintel

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestParseEntriesValidatesAndDedups(t *testing.T) {
	sid := uint(7)
	feed := &store.ThreatIntelFeed{ID: 3, Name: "恶意源", Kind: "blacklist", Action: "drop", SiteID: &sid}
	body := []byte(`
# 注释行
1.1.1.1
2.2.2.0/24

   3.3.3.3
1.1.1.1
not-an-ip
999.999.999.999
4.4.4.4 # 行内注释
2001:db8::/32
`)
	entries := parseEntries(body, feed)

	// 合法且去重后应为: 1.1.1.1, 2.2.2.0/24, 3.3.3.3, 4.4.4.4, 2001:db8::/32
	if len(entries) != 5 {
		values := make([]string, len(entries))
		for i, e := range entries {
			values[i] = e.Value
		}
		t.Fatalf("期望 5 条合法条目, 实得 %d: %v", len(entries), values)
	}

	for _, e := range entries {
		if e.Kind != store.IPListBlack {
			t.Errorf("条目 %s Kind 应继承 blacklist, 实得 %s", e.Value, e.Kind)
		}
		if e.Action != "drop" {
			t.Errorf("条目 %s Action 应继承 drop, 实得 %s", e.Value, e.Action)
		}
		if e.SiteID == nil || *e.SiteID != 7 {
			t.Errorf("条目 %s SiteID 应继承 7", e.Value)
		}
		if e.FeedID == nil || *e.FeedID != 3 {
			t.Errorf("条目 %s FeedID 应为 3", e.Value)
		}
		if !e.Enabled {
			t.Errorf("条目 %s 应默认启用", e.Value)
		}
		if e.Note != "来自订阅: 恶意源" {
			t.Errorf("条目 %s Note 不符: %s", e.Value, e.Note)
		}
	}
}

func TestParseEntriesEmpty(t *testing.T) {
	feed := &store.ThreatIntelFeed{ID: 1, Name: "空", Kind: "whitelist", Action: "intercept"}
	if got := parseEntries([]byte("# 全是注释\n\n   \n"), feed); len(got) != 0 {
		t.Fatalf("期望 0 条, 实得 %d", len(got))
	}
}

// TestParseEntriesTabSeparatedColumns 验证行级切列：tab 分隔行取第一列，
// 与行内注释可以共存。
func TestParseEntriesTabSeparatedColumns(t *testing.T) {
	feed := &store.ThreatIntelFeed{ID: 9, Name: "列式源", Kind: "blacklist", Action: "intercept"}
	body := []byte("9.9.9.9\tremark here\tthird column\n10.10.10.0/24\t# 备注以注释开头\n11.11.11.11 # tail comment\nnot-an-ip\t9.9.9.9\n\t12.12.12.12\tleading tab column\n")
	entries := parseEntries(body, feed)

	want := []string{"9.9.9.9", "10.10.10.0/24", "11.11.11.11", "12.12.12.12"}
	if len(entries) != len(want) {
		got := make([]string, len(entries))
		for i, e := range entries {
			got[i] = e.Value
		}
		t.Fatalf("tab 切列后应得 %v 条, 实得 %d: %v", want, len(entries), got)
	}
	for i, e := range entries {
		if e.Value != want[i] {
			t.Errorf("条目 %d = %q, 期望 %q", i, e.Value, want[i])
		}
	}
}

// TestFetchAndParseAuthHeader 验证可选认证头仅在两字段都非空时装配，
// 并声明 Accept-Encoding: gzip。
func TestFetchAndParseAuthHeader(t *testing.T) {
	feed := &store.ThreatIntelFeed{
		ID: 1, Name: "认证源", URL: "", Kind: "blacklist", Action: "intercept",
		AuthHeaderName: "X-Auth-Token", AuthHeaderValue: "secret-token-123",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(feed.AuthHeaderName); got != feed.AuthHeaderValue {
			t.Errorf("%s = %q, 期望 %q", feed.AuthHeaderName, got, feed.AuthHeaderValue)
		}
		if accept := r.Header.Get("Accept-Encoding"); !strings.Contains(accept, "gzip") {
			t.Errorf("Accept-Encoding = %q, 期望包含 gzip", accept)
		}
		_, _ = w.Write([]byte("8.8.8.8\n"))
	}))
	defer srv.Close()
	feed.URL = srv.URL

	m := &Manager{client: &http.Client{Timeout: 5 * time.Second}}
	entries, err := m.fetchAndParse(feed)
	if err != nil {
		t.Fatalf("fetchAndParse: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "8.8.8.8" {
		t.Fatalf("条目 = %v, 期望 [8.8.8.8]", entries)
	}

	// 认证值缺失或整体为空时不应发出认证头。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["X-Auth-Token"]; present {
			t.Errorf("未配置认证头却发出了 X-Auth-Token")
		}
		_, _ = w.Write([]byte("8.8.4.4\n"))
	}))
	defer srv2.Close()
	feed.URL = srv2.URL
	feed.AuthHeaderValue = ""
	if _, err := m.fetchAndParse(feed); err != nil {
		t.Fatalf("无认证配置时 fetchAndParse: %v", err)
	}
}

// TestFetchAndParseGzip 验证 Content-Encoding: gzip 响应被正确解压解析。
func TestFetchAndParseGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("7.7.7.7\n")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	m := &Manager{client: &http.Client{Timeout: 5 * time.Second}}
	entries, err := m.fetchAndParse(&store.ThreatIntelFeed{ID: 1, Name: "gzip源", URL: srv.URL, Kind: "blacklist"})
	if err != nil {
		t.Fatalf("fetchAndParse: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "7.7.7.7" {
		t.Fatalf("gzip 解压条目 = %v, 期望 [7.7.7.7]", entries)
	}
}

// TestFetchAndParseZlib 验证 deflate（标准 zlib 流）响应被解压。
func TestFetchAndParseZlib(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte("6.6.6.6\n")); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	m := &Manager{client: &http.Client{Timeout: 5 * time.Second}}
	entries, err := m.fetchAndParse(&store.ThreatIntelFeed{ID: 1, Name: "zlib源", URL: srv.URL, Kind: "blacklist"})
	if err != nil {
		t.Fatalf("fetchAndParse: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "6.6.6.6" {
		t.Fatalf("zlib 解压条目 = %v, 期望 [6.6.6.6]", entries)
	}
}

// TestFetchAndParseBareDeflate 验证裸 deflate（RFC 1951）响应被解压。
func TestFetchAndParseBareDeflate(t *testing.T) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := fw.Write([]byte("5.5.5.5\n")); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	m := &Manager{client: &http.Client{Timeout: 5 * time.Second}}
	entries, err := m.fetchAndParse(&store.ThreatIntelFeed{ID: 1, Name: "裸deflate源", URL: srv.URL, Kind: "blacklist"})
	if err != nil {
		t.Fatalf("fetchAndParse: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "5.5.5.5" {
		t.Fatalf("裸 deflate 解压条目 = %v, 期望 [5.5.5.5]", entries)
	}
}

// TestFetchAndParseGzipErrorRecordsLastError 验证解压失败如实进入 LastError，
// 允许直接构造 decompressBody 无法通过 fetchAndParse 覆盖的错误路径。
func TestDecompressBodyGzipError(t *testing.T) {
	if _, err := decompressBody([]byte("definitely not gzip"), "gzip"); err == nil {
		t.Fatal("损坏的 gzip 应返回解压错误")
	}
}

// TestDecompressBodyDispatch 直接覆盖 encoding 分派：identity 原样、
// gzip 解压、deflate 解压。
func TestDecompressBodyDispatch(t *testing.T) {
	// 未声明压缩：原样返回。
	if got, err := decompressBody([]byte("1.2.3.4\n"), ""); err != nil || string(got) != "1.2.3.4\n" {
		t.Fatalf("identity 应原样返回: %q %v", string(got), err)
	}

	var gzbuf bytes.Buffer
	gw := gzip.NewWriter(&gzbuf)
	_, _ = gw.Write([]byte("1.2.3.4\n"))
	_ = gw.Close()
	got, err := decompressBody(gzbuf.Bytes(), "gzip")
	if err != nil || string(got) != "1.2.3.4\n" {
		t.Fatalf("gzip 解压: %q %v", string(got), err)
	}

	var zlbuf bytes.Buffer
	zw := zlib.NewWriter(&zlbuf)
	_, _ = zw.Write([]byte("1.2.3.4\n"))
	_ = zw.Close()
	got, err = decompressBody(zlbuf.Bytes(), "deflate")
	if err != nil || string(got) != "1.2.3.4\n" {
		t.Fatalf("deflate 解压: %q %v", string(got), err)
	}

	// 未知编码（如 br）原样透传。
	if got, err := decompressBody([]byte("raw-bytes"), "br"); err != nil || string(got) != "raw-bytes" {
		t.Fatalf("br 应原样透传: %q %v", string(got), err)
	}
}

// TestSyncFeedAuthHeaderGzipColumnar 端到端验证：认证头 + gzip 响应 + tab 切列
// 同时生效并落库。
func TestSyncFeedAuthHeaderGzipColumnar(t *testing.T) {
	m, db := newManagerForTest(t)

	body := "1.2.3.4\tbad actor\tdetail\n5.6.7.0/24\tscan source\n"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(body))
	_ = gw.Close()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	feed := &store.ThreatIntelFeed{
		Name: "组合源", URL: srv.URL, Kind: "blacklist", Action: "intercept",
		Enabled:         true,
		SyncInterval:    3600,
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer abc123",
	}
	if err := db.Create(feed).Error; err != nil {
		t.Fatalf("create feed: %v", err)
	}
	if err := m.SyncFeed(feed.ID); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gotAuth != "Bearer abc123" {
		t.Fatalf("服务端收到的 Authorization = %q, 期望 Bearer abc123", gotAuth)
	}

	var count int64
	db.Model(&store.IPListEntry{}).Where("feed_id = ?", feed.ID).Count(&count)
	if count != 2 {
		t.Fatalf("落库条目 = %d, 期望 2", count)
	}
}

func TestIsValidIPOrCIDR(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":       true,
		"10.0.0.0/8":    true,
		"::1":           true,
		"2001:db8::/32": true,
		"1.2.3.4/33":    false,
		"1.2.3.256":     false,
		"foo":           false,
		"":              false,
	}
	for in, want := range cases {
		if got := isValidIPOrCIDR(in); got != want {
			t.Errorf("isValidIPOrCIDR(%q)=%v, 期望 %v", in, got, want)
		}
	}
}

func newManagerForTest(t *testing.T) (*Manager, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ThreatIntelFeed{}, &store.IPListEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	reloaded := 0
	m := NewManager(db, nil, func() error { reloaded++; return nil })
	return m, db
}

func TestSyncFeedReplacesEntriesAndRecordsStatus(t *testing.T) {
	m, db := newManagerForTest(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("5.5.5.5\n6.6.6.0/24\nbad-line\n"))
	}))
	defer srv.Close()

	feed := &store.ThreatIntelFeed{Name: "t", URL: srv.URL, Kind: "blacklist", Action: "intercept", Enabled: true, SyncInterval: 3600}
	if err := db.Create(feed).Error; err != nil {
		t.Fatalf("create feed: %v", err)
	}

	if err := m.SyncFeed(feed.ID); err != nil {
		t.Fatalf("sync: %v", err)
	}

	var count int64
	db.Model(&store.IPListEntry{}).Where("feed_id = ?", feed.ID).Count(&count)
	if count != 2 {
		t.Fatalf("期望写入 2 条条目, 实得 %d", count)
	}

	var updated store.ThreatIntelFeed
	if err := db.First(&updated, feed.ID).Error; err != nil {
		t.Fatalf("reload feed: %v", err)
	}
	if updated.LastSyncAt == nil {
		t.Errorf("LastSyncAt 应被设置")
	}
	if updated.LastError != "" {
		t.Errorf("成功同步 LastError 应为空, 实得 %s", updated.LastError)
	}
	if updated.EntryCount != 2 {
		t.Errorf("EntryCount 应为 2, 实得 %d", updated.EntryCount)
	}
}

func TestSyncFeedHTTPErrorRecordsLastError(t *testing.T) {
	m, db := newManagerForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	feed := &store.ThreatIntelFeed{Name: "t", URL: srv.URL, Kind: "blacklist", Action: "intercept", Enabled: true}
	if err := db.Create(feed).Error; err != nil {
		t.Fatalf("create feed: %v", err)
	}

	if err := m.SyncFeed(feed.ID); err == nil {
		t.Fatalf("期望同步返回错误")
	}

	var updated store.ThreatIntelFeed
	db.First(&updated, feed.ID)
	if updated.LastError == "" {
		t.Errorf("失败同步应记录 LastError")
	}
}

func TestIsDue(t *testing.T) {
	m := &Manager{}
	now := time.Now()
	// 从未同步过 -> 到期
	if !m.isDue(store.ThreatIntelFeed{SyncInterval: 60}, now) {
		t.Errorf("未同步过的 feed 应到期")
	}
	recent := now.Add(-30 * time.Second)
	if m.isDue(store.ThreatIntelFeed{SyncInterval: 60, LastSyncAt: &recent}, now) {
		t.Errorf("30 秒前同步、间隔 60 秒的 feed 不应到期")
	}
	old := now.Add(-120 * time.Second)
	if !m.isDue(store.ThreatIntelFeed{SyncInterval: 60, LastSyncAt: &old}, now) {
		t.Errorf("120 秒前同步、间隔 60 秒的 feed 应到期")
	}
}

func TestThreatIntelManagerStopIsIdempotent(t *testing.T) {
	m := &Manager{stopCh: make(chan struct{})}
	m.Stop()
	m.Stop()
	var zero Manager
	zero.Stop()
}

func TestTruncate(t *testing.T) {
	// ASCII 边界：内容超限时按字节截断。
	if got, want := truncate("abcdef", 3), "abc"; got != want {
		t.Errorf("truncate(abcdef, 3) = %q, want %q", got, want)
	}
	// 多字节边界：maxLen 落在多字节字符中间时回退到 rune 边界，结果合法。
	multiCases := map[int]string{
		3: "你",  // 落在 "好" 第 1 字节中间，回退保留 1 个 rune
		4: "你",  // 同上
		5: "你",  // 同上
		6: "你好", // 恰好两个 rune
	}
	in := "你好世界"
	for maxLen, want := range multiCases {
		got := truncate(in, maxLen)
		if got != want {
			t.Errorf("truncate(%q, %d) = %q, want %q", in, maxLen, got, want)
		}
		if len(got) > maxLen {
			t.Errorf("truncate(%q, %d) 输出 %d 字节超过上限 %d", in, maxLen, len(got), maxLen)
		}
	}
	// 恰等于上限：原样返回。
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("truncate(hello, 5) = %q, want hello", got)
	}
	// 空串恒为空。
	if got := truncate("", 100); got != "" {
		t.Errorf("truncate(empty, 100) = %q, want empty", got)
	}
}
