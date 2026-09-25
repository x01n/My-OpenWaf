package observability

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"

	"My-OpenWaf/internal/store"
)

// fakeNonSQLiteDialector 只用于验证方言分支：sqliteFlusherFor 仅读
// Dialector.Name()，其余 gorm.Dialector 方法在此 stub 为空实现。
type fakeNonSQLiteDialector struct{}

func (fakeNonSQLiteDialector) Name() string                                          { return "mysql" }
func (fakeNonSQLiteDialector) Initialize(*gorm.DB) error                             { return nil }
func (fakeNonSQLiteDialector) Migrator(*gorm.DB) gorm.Migrator                       { return nil }
func (fakeNonSQLiteDialector) DataTypeOf(*schema.Field) string                       { return "" }
func (fakeNonSQLiteDialector) DefaultValueOf(*schema.Field) clause.Expression        { return nil }
func (fakeNonSQLiteDialector) BindVarTo(clause.Writer, *gorm.Statement, interface{}) {}
func (fakeNonSQLiteDialector) QuoteTo(clause.Writer, string)                         {}
func (fakeNonSQLiteDialector) Explain(string, ...interface{}) string                 { return "" }

// TestSQLiteBulkFlusherDisabledOnForeignDialect 守护方言分支：
// 非 sqlite 方言必须得到 nil 快路径（flushBuffered 落回 GORM）。
func TestSQLiteBulkFlusherDisabledOnForeignDialect(t *testing.T) {
	db := &gorm.DB{Config: &gorm.Config{Dialector: fakeNonSQLiteDialector{}}}
	// sqliteFlusherFor 只读方言名，不触连接池。
	w := &UnifiedWriter{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if got := w.sqliteFlusherFor(); got != nil {
		t.Fatalf("sqliteFlusherFor() = %v, want nil on non-sqlite dialect", got)
	}
}

// bulkEquivCase 描述一类日志表的双路等价比对。
type bulkEquivCase struct {
	table string
	// mkRows 生成该类的测试行：prefix 区分行源（写入 request_id 的
	// 前缀位，无 request_id 的模型用 Detail 承载），行为必须一致。
	mkRows func(prefix string) []any
	// gormWrite 与 stmtWrite 把行写进各自隔离库；stmt 侧走 flushBuffered 的
	// 对应入口，确保检验的就是生产路径。
	gormWrite func(t *testing.T, db *gorm.DB, rows []any)
	stmtWrite func(t *testing.T, w *UnifiedWriter, db *gorm.DB, rows []any)
	// normRequestID 把读回行里的 request_id 归一（去前缀）；无 request_id
	// 的表返回空字符串（行对齐完全靠 ORDER BY id）。
}

// TestSQLiteBulkFlusherEquivalentRows 是 E2.2 的核心等价性测试：
// 四类日志表（security_events / access_logs / drop_events / bot_score_logs）
// 各自的同一批行分别经 GORM CreateInBatches(64)（生产原路径）与统一
// 长期语句路径写入两个同 schema 库，读回 ORDER BY id 逐行逐列比对。
// 专项覆盖：fingerprint_key 派生字段、显式 created_at 逐值保留、
// 零值 created_at 的 now 补写（两路时刻差 < 2s）。
func TestSQLiteBulkFlusherEquivalentRows(t *testing.T) {
	cases := []bulkEquivCase{
		bulkSecurityEventEquivCase(),
		bulkAccessLogEquivCase(),
		bulkDropEventEquivCase(),
		bulkBotScoreEquivCase(),
	}
	for _, tc := range cases {
		t.Run(tc.table, func(t *testing.T) {
			gormDB := newLogTestDB(t)
			stmtDB := newLogTestDB(t)

			gRows := tc.mkRows("g-")
			sRows := tc.mkRows("s-")
			if len(gRows) == 0 || len(sRows) == 0 {
				t.Fatal("equiv rows are empty")
			}
			tc.gormWrite(t, gormDB, gRows)
			w := &UnifiedWriter{
				db:         stmtDB,
				log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				batchSize:  64,
				drainLimit: 256,
			}
			tc.stmtWrite(t, w, stmtDB, sRows)
			if got := w.Stats(); got.FlushErrorsTotal != 0 || got.TotalFlushedRecords != int64(len(sRows)) {
				t.Fatalf("stmt side stats = %+v, want %d persisted / 0 errors", got, len(sRows))
			}

			gotRows := readTableOrdered(t, gormDB, tc.table)
			wantRows := readTableOrdered(t, stmtDB, tc.table)
			if len(gotRows) != len(gRows) || len(wantRows) != len(sRows) {
				t.Fatalf("read-back rows gorm=%d stmt=%d, want %d/%d",
					len(gotRows), len(wantRows), len(gRows), len(sRows))
			}
			compareEquivRows(t, tc, gotRows, wantRows)

			// fingerprint_key 派生字段专项断言：读回值必须等于 store 的
			// 权威哈希（两路都须如此，且两侧相等已在逐列比对里覆盖）。
			assertFingerprintColumn(t, gormDB, tc.table, gotRows)
		})
	}
}

// compareEquivRows 按行序逐列比对两路读回：id 跳过，request_id 去前缀
// 对齐，created_at 区分显式/零值语义，其余列全等。
func compareEquivRows(t *testing.T, tc bulkEquivCase, gRows, sRows []map[string]any) {
	t.Helper()
	rows := len(gRows)
	if len(sRows) != rows {
		t.Fatalf("row count diverged: gorm=%d stmt=%d", rows, len(sRows))
	}
	for i := 0; i < rows; i++ {
		for col, gv := range gRows[i] {
			switch col {
			case "id":
				continue // 自增主键由 SQLite 分配，两库各自递增。
			case "created_at":
				gt, err1 := parseLogTime(gv)
				st, err2 := parseLogTime(sRows[i][col])
				if err1 != nil || err2 != nil {
					t.Fatalf("row %d created_at parse: gorm=%v (%v) stmt=%v (%v)", i, gv, err1, sRows[i][col], err2)
				}
				if gt.Equal(fixedTime()) {
					// 显式时间行：两侧都必须逐值保留 mkRows 里固定时间戳。
					if !st.Equal(gt) {
						t.Fatalf("row %d explicit created_at must be preserved: gorm=%v stmt=%v", i, gt, st)
					}
				} else {
					// 零值时间行：两侧各自补 now，只允许 < 2s 差。
					var d time.Duration
					if d = gt.Sub(st); d < 0 {
						d = -d
					}
					if d >= 2*time.Second {
						t.Fatalf("row %d zero created_at drift gorm=%v stmt=%v", i, gt, st)
					}
				}
				continue
			default:
				gf, sf := rowCellText(gv), rowCellText(sRows[i][col])
				// drop_events 无 request_id 列，前缀承载在 source 上；
				// 其余表承载在 request_id 上。统一按列名剥离两路前缀。
				if col == "request_id" || col == "source" {
					gf = strings.TrimPrefix(gf, "g-")
					sf = strings.TrimPrefix(sf, "s-")
				}
				if gf != sf {
					t.Fatalf("row %d column %q diverged: gorm=%q stmt=%q", i, col, gf, sf)
				}
			}
		}
	}
}

// fixedTime 是等价测试 mkRows 里显式时间行的固定时间戳：读回值等于它就
// 必须是逐值保留路径，否则是零值补写路径。
func fixedTime() time.Time {
	return time.Date(2026, 9, 21, 9, 30, 45, 123456000, time.UTC)
}

// assertFingerprintColumn 只对 access_logs 断言 fingerprint_key 与
// store.ComputeAccessLogFingerprintKey 一致（其余表无该列）。
func assertFingerprintColumn(t *testing.T, db *gorm.DB, table string, rows []map[string]any) {
	t.Helper()
	if table != "access_logs" {
		return
	}
	for i, row := range rows {
		want := store.ComputeAccessLogFingerprintKey(
			rowCellText(row["tls_ja3_hash"]),
			rowCellText(row["tls_ja4"]),
			rowCellText(row["tls_version"]),
			rowCellText(row["tls_alpn"]),
			rowCellText(row["tls_sni"]),
			rowCellText(row["tls_cipher_suites"]),
			rowCellText(row["tls_extensions"]),
			rowCellText(row["tls_curves"]),
			rowCellText(row["tls_point_formats"]),
		)
		if got := rowCellText(row["fingerprint_key"]); got != want {
			t.Fatalf("row %d fingerprint_key = %q, want %q (derived column must match store hash)", i, got, want)
		}
	}
}

// readTableOrdered 读回整表按 id 排序，返回 []map[column]any。
func readTableOrdered(t *testing.T, db *gorm.DB, table string) []map[string]any {
	t.Helper()
	rows, err := db.Raw("SELECT * FROM " + table + " ORDER BY id").Rows()
	if err != nil {
		t.Fatalf("read-back %s: %v", table, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("%s columns: %v", table, err)
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan %s row: %v", table, err)
		}
		row := map[string]any{}
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	return out
}

// rowCellText 把读回单元格归一为字符串（[]byte / string / 其余 %v）。
func rowCellText(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// parseLogTime 解析库内 created_at 的驱动形态（glebarez 常规读回为字符串，
// 兼容 time.Time 以防扫描形态差异）。
func parseLogTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x, nil
	case string:
		for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
			if t, err := time.Parse(layout, x); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("unrecognized created_at format %q", x)
	case nil:
		return time.Time{}, fmt.Errorf("created_at is NULL")
	default:
		return time.Time{}, fmt.Errorf("unexpected created_at type %T", v)
	}
}

// ---- 四类样例与写入器 ----

func bulkSecurityEventEquivCase() bulkEquivCase {
	mk := func(prefix string) []any {
		full := store.SecurityEvent{
			RequestID:            prefix + "full",
			CreatedAt:            fixedTime(),
			SiteID:               3,
			ClientIP:             "198.51.100.11",
			Host:                 "sec.example.test",
			Path:                 "/sec",
			QueryString:          "q=sec",
			Method:               "POST",
			UserAgent:            "sec-agent/1",
			RuleID:               42,
			RuleIDStr:            "sec-rule-42",
			Phase:                "owasp",
			Action:               "observe",
			Category:             "sqli",
			MatchDesc:            "matched union select",
			RequestHeaders:       `{"x":"1"}`,
			RequestBodyPreview:   "preview",
			RequestBodyTruncated: true,
			RequestSize:          128,
			TLSVersion:           "1.3",
			TLSSNI:               "sec.example.test",
			TLSALPN:              "h2",
			TLSJA3:               "sec-ja3",
			TLSJA3Hash:           "beefbeefbeefbeefbeefbeefbeefbeef",
			TLSJA4:               "sec-ja4",
			TLSCipherSuites:      "4865",
			TLSExtensions:        "0,10",
			TLSCurves:            "29",
			TLSPointFormats:      "0",
			HeaderOrder:          "host",
			GeoCountry:           "CN",
			GeoCity:              "SecCity",
			StatusCode:           403,
		}
		zero := store.SecurityEvent{RequestID: prefix + "zero", Host: "secz.example.test", Path: "/z", Method: "GET"}
		return []any{&full, &zero}
	}
	return bulkEquivCase{
		table:  "security_events",
		mkRows: mk,
		gormWrite: func(t *testing.T, db *gorm.DB, rows []any) {
			s := make([]store.SecurityEvent, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.SecurityEvent)
			}
			if err := db.Transaction(func(tx *gorm.DB) error {
				return tx.CreateInBatches(s, 64).Error
			}); err != nil {
				t.Fatalf("gorm side write: %v", err)
			}
		},
		stmtWrite: func(t *testing.T, w *UnifiedWriter, _ *gorm.DB, rows []any) {
			s := make([]store.SecurityEvent, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.SecurityEvent)
			}
			w.flushBuffered(s, nil, nil, nil)
		},
	}
}

func bulkAccessLogEquivCase() bulkEquivCase {
	mk := func(prefix string) []any {
		full := store.AccessLog{
			RequestID:                prefix + "full",
			CreatedAt:                fixedTime(),
			SiteID:                   7,
			ClientIP:                 "198.51.100.77",
			Host:                     "equiv.example.test",
			Path:                     "/equiv-full",
			QueryString:              "a=1&b=two",
			Method:                   "POST",
			StatusCode:               201,
			WAFAction:                "observe",
			CacheState:               "HIT",
			Upstream:                 "upstream-eq:8080",
			UserAgent:                "equiv-agent/1.0",
			RequestHeaders:           `{"x-one":"v1"}`,
			RequestSize:              4096,
			ResponseHeaders:          `{"content-type":"text/plain"}`,
			HTTPProtocol:             "HTTP/2",
			TLSVersion:               "1.3",
			TLSSNI:                   "equiv.example.test",
			TLSALPN:                  "h2",
			TLSJA3:                   "ja3-equiv",
			TLSJA3Hash:               "abcd1234abcd1234abcd1234abcd1234",
			TLSJA4:                   "t13d1516h2_000000000000_000000000000",
			TLSCipherSuites:          "4865,4866",
			TLSExtensions:            "0,10,11",
			TLSCurves:                "29,23",
			TLSPointFormats:          "0",
			HeaderOrder:              "host,content-type",
			VisitorFusionScore:       -3,
			VisitorFusionClass:       "probe",
			VisitorFusionConsistency: "full",
			UpstreamLatencyMs:        51,
			ResponseSize:             2048,
		}
		emptyFp := full
		emptyFp.RequestID = prefix + "emptyfp"
		emptyFp.TLSJA3Hash = ""
		emptyFp.TLSJA4 = ""
		zero := store.AccessLog{RequestID: prefix + "zero", Host: "equvz.example.test", Path: "/z", Method: "GET"}
		return []any{&full, &zero, &emptyFp}
	}
	return bulkEquivCase{
		table:  "access_logs",
		mkRows: mk,
		gormWrite: func(t *testing.T, db *gorm.DB, rows []any) {
			s := make([]store.AccessLog, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.AccessLog)
			}
			if err := db.Transaction(func(tx *gorm.DB) error {
				return tx.CreateInBatches(s, 64).Error
			}); err != nil {
				t.Fatalf("gorm side write: %v", err)
			}
		},
		stmtWrite: func(t *testing.T, w *UnifiedWriter, _ *gorm.DB, rows []any) {
			s := make([]store.AccessLog, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.AccessLog)
			}
			w.flushBuffered(nil, s, nil, nil)
		},
	}
}

func bulkDropEventEquivCase() bulkEquivCase {
	mk := func(prefix string) []any {
		full := store.DropEvent{
			SiteID:    9,
			ClientIP:  "198.51.100.99",
			Source:    prefix + "full",
			RuleID:    "drop-rule-1",
			Detail:    "drop detail",
			Host:      "drop.example.test",
			Path:      "/drop",
			CreatedAt: fixedTime(),
		}
		zero := store.DropEvent{ClientIP: "198.51.100.98", Source: prefix + "zero"}
		return []any{&full, &zero}
	}
	return bulkEquivCase{
		table:  "drop_events",
		mkRows: mk,
		gormWrite: func(t *testing.T, db *gorm.DB, rows []any) {
			s := make([]store.DropEvent, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.DropEvent)
			}
			if err := db.Transaction(func(tx *gorm.DB) error {
				return tx.CreateInBatches(s, 64).Error
			}); err != nil {
				t.Fatalf("gorm side write: %v", err)
			}
		},
		stmtWrite: func(t *testing.T, w *UnifiedWriter, _ *gorm.DB, rows []any) {
			s := make([]store.DropEvent, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.DropEvent)
			}
			w.flushBuffered(nil, nil, s, nil)
		},
	}
}

func bulkBotScoreEquivCase() bulkEquivCase {
	mk := func(prefix string) []any {
		full := store.BotScoreLog{
			RequestID:        prefix + "full",
			SiteID:           5,
			ClientIP:         "198.51.100.55",
			Host:             "bot.example.test",
			Path:             "/bot",
			UserAgent:        "bot-agent/1",
			TLSJA3Hash:       "cafe1234cafe1234cafe1234cafe1234",
			TLSJA4:           "bot-ja4",
			TLSVersion:       "1.3",
			TLSSNI:           "bot.example.test",
			TLSALPN:          "h2",
			HeaderOrder:      "host,accept",
			TotalScore:       88,
			GeoIPScore:       10,
			FingerprintScore: 20,
			BehaviorScore:    30,
			IPRepScore:       28,
			IsHighRisk:       true,
			Action:           "observe",
			Details:          "bot details",
			CreatedAt:        fixedTime(),
		}
		zero := store.BotScoreLog{RequestID: prefix + "zero", ClientIP: "198.51.100.56"}
		return []any{&full, &zero}
	}
	return bulkEquivCase{
		table:  "bot_score_logs",
		mkRows: mk,
		gormWrite: func(t *testing.T, db *gorm.DB, rows []any) {
			s := make([]store.BotScoreLog, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.BotScoreLog)
			}
			if err := db.Transaction(func(tx *gorm.DB) error {
				return tx.CreateInBatches(s, 64).Error
			}); err != nil {
				t.Fatalf("gorm side write: %v", err)
			}
		},
		stmtWrite: func(t *testing.T, w *UnifiedWriter, _ *gorm.DB, rows []any) {
			s := make([]store.BotScoreLog, len(rows))
			for i, r := range rows {
				s[i] = *r.(*store.BotScoreLog)
			}
			w.flushBuffered(nil, nil, nil, s)
		},
	}
}

// TestSQLiteBulkFlusherTypeIsolationMatchesGORMPath 补「单类失败、后续类
// 仍写出」场景：delete drop_events 表后四类同批毫发——security/access/
// bot 三类必须全部落库，失败的 drop_events 只计入 failedRecords。
// 本测试用 bf 路径（flushBuffered 的 sqlite 分支），其语义必须与既有
// TestUnifiedWriterFlushIsolatesFailingRecordType 一致。
func TestSQLiteBulkFlusherTypeIsolationMatchesGORMPath(t *testing.T) {
	db := newLogTestDB(t)
	if err := db.Migrator().DropTable(&store.DropEvent{}); err != nil {
		t.Fatalf("drop drop_events table: %v", err)
	}

	w := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchSize:  64,
		drainLimit: 256,
	}
	w.flushBuffered(
		[]store.SecurityEvent{{RequestID: "iso2-evt", Host: "iso2.example.test", Path: "/e", Method: "GET"}},
		[]store.AccessLog{{RequestID: "iso2-al", Host: "iso2.example.test", Path: "/a", Method: "GET"}},
		[]store.DropEvent{{ClientIP: "203.0.113.7"}},
		[]store.BotScoreLog{{RequestID: "iso2-bot", ClientIP: "203.0.113.8"}},
	)

	// 三类仍落在同库，失败类只计失败。bf 路径的隔离由外层 flushType 保证。
	for table, cond := range map[string]string{
		"security_events": "request_id = ?",
		"access_logs":     "request_id = ?",
		"bot_score_logs":  "request_id = ?",
	} {
		var c int64
		err := db.Table(table).Where(cond, map[string]string{
			"security_events": "iso2-evt",
			"access_logs":     "iso2-al",
			"bot_score_logs":  "iso2-bot",
		}[table]).Count(&c).Error
		if err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if c != 1 {
			t.Fatalf("%s persisted = %d, want 1 (types after failing one must survive)", table, c)
		}
	}

	// 统计口径：3 条落库 + 1 条失败，与既有 GORM 路径测试的期望同构。
	stats := w.Stats()
	if stats.FlushErrorsTotal != 1 {
		t.Fatalf("FlushErrorsTotal = %d, want 1", stats.FlushErrorsTotal)
	}
	if stats.TotalFlushedRecords != 3 || stats.LastFlushRecords != 3 {
		t.Fatalf("persisted records = total:%d last:%d, want 3/3",
			stats.TotalFlushedRecords, stats.LastFlushRecords)
	}
	if stats.FailedRecordsTotal != 1 || stats.LastFlushFailedRecords != 1 {
		t.Fatalf("failed records = total:%d last:%d, want 1/1",
			stats.FailedRecordsTotal, stats.LastFlushFailedRecords)
	}
}

// ---- wave6 多值组路径测试 ----

// mkMultiAccessLogRows 生成 n 行含序号的行：request_id 带序号、path 带序号；
// 第 0 行显式 created_at=time.Now()，其余零值（由 flush 补 now），两时间
// 语义同批混排，验证多值组路径与逐行路径的时间序列化一致；另加 TLS 字段与
// 业务列保证 41 列全部有值（与 GORM 路径读回逐列比对时无 NULL 歧义）。
func mkMultiAccessLogRows(prefix string, n int) []any {
	rows := make([]any, n)
	for i := 0; i < n; i++ {
		a := store.AccessLog{
			RequestID:                fmt.Sprintf("%s-%02d", prefix, i),
			SiteID:                   7,
			ClientIP:                 "198.51.100.77",
			Host:                     "multi.example.test",
			Path:                     fmt.Sprintf("/multi/%d", i),
			QueryString:              "a=1&b=two",
			Method:                   "POST",
			StatusCode:               201,
			WAFAction:                "observe",
			CacheState:               "HIT",
			Upstream:                 "upstream-multi:8080",
			UserAgent:                "multi-agent/1.0",
			RequestHeaders:           `{"x-one":"v1"}`,
			RequestSize:              4096,
			ResponseHeaders:          `{"content-type":"text/plain"}`,
			HTTPProtocol:             "HTTP/2",
			TLSVersion:               "1.3",
			TLSSNI:                   "multi.example.test",
			TLSALPN:                  "h2",
			TLSJA3:                   "ja3-multi",
			TLSJA3Hash:               "abcd1234abcd1234abcd1234abcd1234",
			TLSJA4:                   "t13d1516h2_000000000000_000000000000",
			TLSCipherSuites:          "4865,4866",
			TLSExtensions:            "0,10,11",
			TLSCurves:                "29,23",
			TLSPointFormats:          "0",
			HeaderOrder:              "host,content-type",
			VisitorFusionScore:       i - 2,
			VisitorFusionClass:       "probe",
			VisitorFusionConsistency: "full",
			UpstreamLatencyMs:        int64(51 + i),
			ResponseSize:             2048,
		}
		if i == 0 {
			a.CreatedAt = fixedTime() // 显式时间行
		}
		rows[i] = &a
	}
	return rows
}

// mkMultiSecurityEventRows 生成 n 行含序号的安全事件（多值组路径等价对照用）。
func mkMultiSecurityEventRows(prefix string, n int) []any {
	rows := make([]any, n)
	for i := 0; i < n; i++ {
		s := store.SecurityEvent{
			RequestID:      fmt.Sprintf("%s-%02d", prefix, i),
			SiteID:         3,
			ClientIP:       "198.51.100.11",
			Host:           "sec-multi.example.test",
			Path:           fmt.Sprintf("/sec/%d", i),
			QueryString:    "q=multi",
			Method:         "POST",
			UserAgent:      "sec-multi/1",
			RuleID:         uint(42 + i),
			RuleIDStr:      fmt.Sprintf("sec-rule-%d", i),
			Phase:          "owasp",
			Action:         "observe",
			Category:       "sqli",
			MatchDesc:      "matched union select",
			RequestHeaders: `{"x":"1"}`,
			RequestSize:    128,
			StatusCode:     403,
			TLSVersion:     "1.3",
			TLSSNI:         "sec-multi.example.test",
			TLSALPN:        "h2",
			TLSJA3:         "sec-ja3",
			TLSJA3Hash:     "beefbeefbeefbeefbeefbeefbeefbeef",
			TLSJA4:         "sec-ja4",
			HeaderOrder:    "host",
			GeoCountry:     "CN",
			GeoCity:        "MultiCity",
		}
		if i == 0 {
			s.CreatedAt = fixedTime() // 显式时间行
		}
		rows[i] = &s
	}
	return rows
}

// TestSQLiteBulkFlusherMultiGroupEquivalentRows 是 wave6 的多值组等价性
// 测试：在同一批 9 行里，多值组路径（8 行一条多值 INSERT + 1 行余数单行）
// 与 GORM CreateInBatches(64) 路径写两个同 schema 库，读回 ORDER BY id
// 逐行逐列比对。行数 9 刻意不整除组大小（8），把「多值段 + 末尾余数组」
// 两种执行介质都纳入同一比对。
func TestSQLiteBulkFlusherMultiGroupEquivalentRows(t *testing.T) {
	for _, table := range []string{"access_logs", "security_events"} {
		t.Run(table, func(t *testing.T) {
			gormDB := newLogTestDB(t)
			stmtDB := newLogTestDB(t)

			mk := mkMultiAccessLogRows
			if table == "security_events" {
				mk = mkMultiSecurityEventRows
			}
			gRows := mk("g-", 9)
			sRows := mk("s-", 9)

			w := &UnifiedWriter{
				db:         stmtDB,
				log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				batchSize:  64,
				drainLimit: 256,
			}
			bf := w.sqliteFlusherFor()
			if bf == nil {
				t.Fatal("sqlite bulk flusher must be available on sqlite dialect")
			}
			if got := bf.specs[table].groupSize; got < 2 {
				t.Fatalf("%s groupSize = %d, want >= 2 (multi-row path)", table, got)
			}

			// GORM 路径（对照，与既有 case 同构）。
			var gormWrite func(tx *gorm.DB) error
			if table == "access_logs" {
				s := make([]store.AccessLog, len(gRows))
				for i, r := range gRows {
					s[i] = *r.(*store.AccessLog)
				}
				gormWrite = func(tx *gorm.DB) error { return tx.CreateInBatches(s, 64).Error }
			} else {
				s := make([]store.SecurityEvent, len(gRows))
				for i, r := range gRows {
					s[i] = *r.(*store.SecurityEvent)
				}
				gormWrite = func(tx *gorm.DB) error { return tx.CreateInBatches(s, 64).Error }
			}
			if err := gormDB.Transaction(gormWrite); err != nil {
				t.Fatalf("gorm side write: %v", err)
			}

			// 多值组路径（生产 flushBuffered 入口）。
			if table == "access_logs" {
				s := make([]store.AccessLog, len(sRows))
				for i, r := range sRows {
					s[i] = *r.(*store.AccessLog)
				}
				w.flushBuffered(nil, s, nil, nil)
			} else {
				s := make([]store.SecurityEvent, len(sRows))
				for i, r := range sRows {
					s[i] = *r.(*store.SecurityEvent)
				}
				w.flushBuffered(s, nil, nil, nil)
			}
			if got := w.Stats(); got.FlushErrorsTotal != 0 || got.TotalFlushedRecords != 9 {
				t.Fatalf("stmt side stats = %+v, want 9 persisted / 0 errors", got)
			}
			// 多值组语句必须已被 prepare 并使用：ensureMultiStmtFor 只在
			// execRowsInTx 的多值段尝试里调用。
			if bf.multStmts[table] == nil {
				t.Fatalf("multi stmt for %s not prepared: multi-row path not exercised", table)
			}

			gotRows := readTableOrdered(t, gormDB, table)
			wantRows := readTableOrdered(t, stmtDB, table)
			if len(gotRows) != 9 || len(wantRows) != 9 {
				t.Fatalf("read-back rows gorm=%d stmt=%d, want 9/9", len(gotRows), len(wantRows))
			}
			tc := bulkEquivCase{table: table}
			if table == "security_events" {
				tc = bulkSecurityEventEquivCase()
			}
			compareEquivRows(t, tc, gotRows, wantRows)
			assertFingerprintColumn(t, gormDB, table, gotRows)
		})
	}
}

// TestSQLiteBulkFlusherMultiGroupBoundaries 是 wave6 的组边界测试：
// 行数 1、N-1、N、N+1、2N 五档各写一批 access_logs，读回校验行数、
// request_id 序列（ORDER BY id）与 created_at 逐行一致；任何组切分、
// 余数组或参数错位的割批错误都会在序列比对里显形。
func TestSQLiteBulkFlusherMultiGroupBoundaries(t *testing.T) {
	db := newLogTestDB(t)
	w := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchSize:  64,
		drainLimit: 256,
	}
	bf := w.sqliteFlusherFor()
	if bf == nil {
		t.Fatal("sqlite bulk flusher must be available on sqlite dialect")
	}
	n := bf.specs["access_logs"].groupSize
	if n < 2 {
		t.Fatalf("access_logs groupSize = %d, want >= 2 for boundary test", n)
	}

	total := 0
	for _, count := range []int{1, n - 1, n, n + 1, 2 * n} {
		prefix := fmt.Sprintf("boundary-%d", count)
		mk := mkMultiAccessLogRows(prefix, count)
		accs := make([]store.AccessLog, count)
		for i, r := range mk {
			accs[i] = *r.(*store.AccessLog)
		}
		w.flushBuffered(nil, accs, nil, nil)
		total += count

		var got []store.AccessLog
		if err := db.Where("request_id LIKE ?", prefix+"-%").Order("id").Find(&got).Error; err != nil {
			t.Fatalf("read-back %s: %v", prefix, err)
		}
		if len(got) != count {
			t.Fatalf("boundary count=%d persisted %d rows", count, len(got))
		}
		for i, row := range got {
			wantID := fmt.Sprintf("%s-%02d", prefix, i)
			if row.RequestID != wantID {
				t.Fatalf("boundary count=%d row %d request_id=%q, want %q (row order diverged)",
					count, i, row.RequestID, wantID)
			}
			if row.CreatedAt.IsZero() {
				t.Fatalf("boundary count=%d row %d created_at is zero after read-back", count, i)
			}
		}
	}
	if stats := w.Stats(); stats.TotalFlushedRecords != int64(total) || stats.FlushErrorsTotal != 0 {
		t.Fatalf("boundary stats = %+v, want %d persisted / 0 errors", stats, total)
	}
	if bf.multStmts["access_logs"] == nil {
		t.Fatal("multi stmt for access_logs not prepared: multi-row path not exercised")
	}
}

// TestSQLiteMultiGroupSizeFor 守护组大小钳制公式：列数越多组越小，且
// len(cols)×N 永不越过 driverMaxVariableNumber；上限极端时退化为 1。
func TestSQLiteMultiGroupSizeFor(t *testing.T) {
	cases := []struct {
		cols int
		want int
	}{
		{41, 8},     // access_logs：42 列去 id = 41 绑定列，8×41=328 < 999
		{7, 8},      // drop_events：999/7=142 远大于默认 8
		{124, 8},    // 124×8=992 ≤ 999：恰在界内
		{125, 7},    // 125×8=1000 > 999：钳到 7（125×7=875）
		{200, 4},    // 999/200=4
		{500, 1},    // 999/500=1
		{999, 1},    // 999/999=1
		{1001, 1},   // 999/1001=0 → 保底 1
		{100000, 1}, // 极端列数：保底 1
		{1, 8},      // 单列：999/1 远大于默认 8
	}
	for _, tc := range cases {
		if got := multiGroupSizeFor(tc.cols); got != tc.want {
			t.Errorf("multiGroupSizeFor(%d) = %d, want %d", tc.cols, got, tc.want)
		}
	}
}

// TestSQLiteInsertMultiSQLText 守护多值语句文本结构：列名只出现一份，
// VALUES 组数 = n，占位符总数 = len(cols)×n。
func TestSQLiteInsertMultiSQLText(t *testing.T) {
	cols := []string{"created_at", "site_id", "request_id"}
	for _, n := range []int{1, 2, 4, 8} {
		sqlText := insertMultiSQLText("access_logs", cols, n)
		if got := strings.Count(sqlText, "access_logs"); got != 1 {
			t.Errorf("n=%d: table name count = %d, want 1", n, got)
		}
		if got := strings.Count(sqlText, "VALUES "); got != 1 {
			t.Errorf("n=%d: VALUES keyword count = %d, want 1", n, got)
		}
		if got := strings.Count(sqlText, "("); got != n+1 {
			t.Errorf("n=%d: '(' count = %d, want %d (n rows + 1 col list)", n, got, n+1)
		}
		if got := strings.Count(sqlText, "?"); got != len(cols)*n {
			t.Errorf("n=%d: placeholder count = %d, want %d", n, got, len(cols)*n)
		}
	}
}
