package dataplane

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/store"
	botrepo "My-OpenWaf/internal/store/repository/bot"
	"My-OpenWaf/internal/waf/bot/tlsfp"
)

/**
 * 本文件覆盖 Bot 评分日志在「只写 bot 行、没有配套访问日志」时的 SNI 存在性。
 *
 * 场景来源：采样关闭时普通 2xx 请求不写访问日志，但 Bot 检测仍会写一条
 * BotScoreLog（internal/dataplane/handler.go 的 RecordBotScore）。此时请求追踪页
 * 的 bot_scores 页签（frontend/app/(dashboard)/request-trace/page.tsx:517-532）
 * 是该请求唯一的 SNI 展示位，读取路径必须自带判定。
 *
 * 读取入口刻意选 internal/admin/event/request.go 用的同一个
 * *botrepo.BotScoreRepo.List，而不是直接读 GORM 模型，以覆盖真实出口。
 */

/**
 * TestBotScoreLogPresenceDerivedFromStoredColumns 断言 Bot 评分日志的读侧派生
 * 覆盖四种已落库形态，其中第三种（握手成功但 JA4 缺位）是 H2WS_PEEKER_OFF
 * 路径的真实产物。
 */
func TestBotScoreLogPresenceDerivedFromStoredColumns(t *testing.T) {
	db := openBotPresenceLogDB(t)
	repo := botrepo.NewBotScoreRepo(db)

	seeds := []store.BotScoreLog{
		// 域名客户端：JA4 第 4 位 d。
		{RequestID: "bot-domain", Host: "app.example", Path: "/bot", TLSVersion: "TLS13", TLSSNI: "app.example", TLSJA4: "t13d1516h2_8daaf6152771_02713d6af862", TotalScore: 90},
		// IP 字面量客户端：SNI 名为空、JA4 第 4 位 i。
		{RequestID: "bot-ip-literal", Host: "127.0.0.1:443", Path: "/bot", TLSVersion: "TLS13", TLSJA4: "t13i1515h2_8daaf6152771_b79b8b93dec7", TotalScore: 90},
		// 握手成功但 JA4 缺位（未启用 ClientHello 窃读）：仍是权威的「客户端没发 SNI」。
		{RequestID: "bot-handshake-only", Host: "app.example", Path: "/bot", TLSVersion: "TLS13", TotalScore: 90},
		// 明文请求：无任何握手证据，必须留在 unknown。
		{RequestID: "bot-plaintext", Host: "app.example", Path: "/bot", TotalScore: 90},
	}
	for i := range seeds {
		if err := repo.Create(&seeds[i]); err != nil {
			t.Fatalf("seed bot score %q: %v", seeds[i].RequestID, err)
		}
	}

	want := map[string]string{
		"bot-domain":         tlsfp.SNIPresencePresent,
		"bot-ip-literal":     tlsfp.SNIPresenceAbsent,
		"bot-handshake-only": tlsfp.SNIPresenceAbsent,
		"bot-plaintext":      tlsfp.SNIPresenceUnknown,
	}
	for requestID, wantPresence := range want {
		items, total, err := repo.List(0, 10, botrepo.BotScoreFilter{RequestID: requestID})
		if err != nil {
			t.Fatalf("list bot scores for %q: %v", requestID, err)
		}
		if total != 1 || len(items) != 1 {
			t.Fatalf("%s: list returned total=%d len=%d, want 1/1", requestID, total, len(items))
		}
		if got := items[0].TLSSNIPresence; got != wantPresence {
			t.Fatalf("%s: read tls_sni_presence = %q, want %q", requestID, got, wantPresence)
		}
	}
}

/**
 * TestBotScoreOnlyRequestKeepsPresenceInTraceShape 是上面静态种子用例的机制补强。
 *
 * 值从真实的记录函数进入库（UnifiedWriter.RecordBotScore → 单事务 flush），
 * 再经 BotScoreRepo.List 读回；覆盖「只有 bot 行」的请求形态。
 */
func TestBotScoreOnlyRequestKeepsPresenceInTraceShape(t *testing.T) {
	db := openBotPresenceLogDB(t)
	repo := botrepo.NewBotScoreRepo(db)

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(writer.Close)

	// 与 handler.go 的 RecordBotScore 入参同形：同一次 TLS 握手，SNI 为空、
	// JA4 第 4 位 i。
	const requestID = "bot-only-request"
	const botJA4 = "t13i1515h2_8daaf6152771_b79b8b93dec7"
	writer.RecordBotScore(store.BotScoreLog{
		SiteID:     1,
		RequestID:  requestID,
		ClientIP:   "127.0.0.1",
		Host:       "127.0.0.1:443",
		Path:       "/bot-only",
		UserAgent:  "tls-sni-presence-probe",
		TLSVersion: "TLS13",
		TLSJA4:     botJA4,
		TotalScore: 90,
		IsHighRisk: true,
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		items, total, err := repo.List(0, 10, botrepo.BotScoreFilter{RequestID: requestID})
		if err == nil && total == 1 && len(items) == 1 {
			entry := items[0]
			if entry.TLSSNIPresence != tlsfp.SNIPresenceAbsent {
				t.Fatalf("bot-only request presence = %q, want %q", entry.TLSSNIPresence, tlsfp.SNIPresenceAbsent)
			}
			if entry.TLSSNI != "" {
				t.Fatalf("bot-only request tls_sni = %q, want empty", entry.TLSSNI)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bot score log %q did not appear: %v", requestID, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

/**
 * openBotPresenceLogDB 打开一个日志库并迁移日志表。
 *
 * 与 tls_sni_presence_probe_test.go 的日志库一致，用文件而不是 ":memory:"：
 * 写入经 UnifiedWriter 的独立 goroutine + 连接池，内存库的「每连接各自一个
 * 私有库」会让写连接建的表在读连接上消失。
 */
func openBotPresenceLogDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "waf_logs.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	return db
}
