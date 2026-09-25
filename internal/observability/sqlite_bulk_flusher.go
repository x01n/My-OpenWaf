package observability

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"My-OpenWaf/internal/store"
)

const (
	defaultMultiGroupSize   = 8
	driverMaxVariableNumber = 999
)

type sqliteBulkFlusher struct {
	log *slog.Logger

	// stmts 以表名为键的单行长期语句；multStmts 为多值组语句模板。
	stmts     map[string]*sql.Stmt
	multStmts map[string]*sql.Stmt

	// specs 以表名为键的模型元信息与行取值函数。
	specs map[string]bulkModelSpec

	// sqlDB 是长期语句的 Prepare 载体（由 attachSQLDB 从 LogDB 取出）。
	sqlDB *sql.DB
}

// bulkModelSpec 汇集一张日志表生成长期 INSERT 所需的全部信息。
type bulkModelSpec struct {
	tableName string
	model     any      // 构建期 schema.Parse 的模型引用，仅 newSQLiteBulkFlusher 内部用
	cols      []string // 绑定列，顺序即语句占位符顺序
	groupSize int      // 当前生效的每组行数（构建期按下限放宽）
	values    func(v any, created time.Time) []any
}

// newSQLiteBulkFlusher 构建四张日志表的长期语句快路径。
//
// 任一模型的列清单无法对齐时返回 nil 并告警：调用方（flushBuffered）见 nil
// 即回退 GORM 原路径——长期语句因此只是一个可自愈的加速器，不会让审计
// 落库整体失败。
func newSQLiteBulkFlusher(log *slog.Logger) *sqliteBulkFlusher {
	specs := []bulkModelSpec{
		{tableName: "access_logs", model: &store.AccessLog{}, values: accessLogSpecValues},
		{tableName: "security_events", model: &store.SecurityEvent{}, values: securityEventSpecValues},
		{tableName: "drop_events", model: &store.DropEvent{}, values: dropEventSpecValues},
		// BotScoreLog 经 NamingStrategy{} 复数化为 bot_score_logs（AutoMigrateLogs
		// 的实际物理表名，internal/store/migrate.go:102-108）。
		{tableName: "bot_score_logs", model: &store.BotScoreLog{}, values: botScoreSpecValues},
	}

	bf := &sqliteBulkFlusher{
		log:       log,
		stmts:     map[string]*sql.Stmt{},
		multStmts: map[string]*sql.Stmt{},
		specs:     map[string]bulkModelSpec{},
	}
	// 共享 schema 缓存店面：四个模型只建一次结构。
	var cache sync.Map
	for _, spec := range specs {
		model := spec.model
		sch, err := schema.ParseWithSpecialTableName(model, &cache, schema.NamingStrategy{}, spec.tableName)
		if err != nil {
			bf.disable("schema parse rejected", spec.tableName, "err", err)
			return nil
		}
		var cols []string
		for _, dbName := range sch.DBNames {
			field, ok := sch.FieldsByDBName[dbName]
			if !ok {
				bf.disable("schema missing field", spec.tableName, "column", dbName)
				return nil
			}
			if field.PrimaryKey && field.AutoIncrement {
				continue // id：自增主键由 SQLite 分配，不参与绑定。
			}
			if field.HasDefaultValue && field.DefaultValueInterface == nil {
				continue // DB-default 列（default:0 / default:false），由缺省值生成。
			}
			if !field.Creatable {
				continue
			}
			cols = append(cols, dbName)
		}
		if len(cols) == 0 {
			bf.disable("no creatable columns", spec.tableName, "column", nil)
			return nil
		}
		// multiGroupSizeFor 按单类绑定列数求多值组大小：N = min(defaultMultiGroupSize,
		// driverMaxVariableNumber / len(cols))，至少 1（保底退化逐行）。
		n := multiGroupSizeFor(len(cols))
		spec.cols = cols
		spec.groupSize = n
		bf.specs[spec.tableName] = spec
	}
	return bf
}

// multiGroupSizeFor 是组大小与驱动参数上限的钳制公式：绑定列数越多组越小，
// 确保 len(cols)×N 永不越过 driverMaxVariableNumber；上限极端小时退化为 1
// （多值组路径失效，走单行长期语句——与构建期否决同级的自愈行为）。
func multiGroupSizeFor(cols int) int {
	n := defaultMultiGroupSize
	if maxN := driverMaxVariableNumber / cols; maxN < n {
		n = maxN
	}
	if n < 1 {
		n = 1
	}
	return n
}

// disable 记录否决原因，让上层直接落回 GORM 路径。
func (bf *sqliteBulkFlusher) disable(msg, table, kvMsg string, detail any) {
	if bf.log != nil {
		bf.log.Warn("sqlite bulk flusher disabled: "+msg,
			slog.String("table", table), slog.String(kvMsg, fmt.Sprint(detail)))
	}
}

// attachSQLDB 把 UnifiedWriter 的 LogDB 底层连接池绑定到 flusher。
// SQLite 连接无轮换（internal/core/database/gorm.go 的 ConnMaxLifetime(0)），
// 长期持有合法。
func (bf *sqliteBulkFlusher) attachSQLDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("sqlite bulk flusher: resolve conn pool: %w", err)
	}
	bf.sqlDB = sqlDB
	return nil
}

// insertSQLText 生成单行 INSERT 语句文本；首次 prepare 时生成一次。
func insertSQLText(tableName string, cols []string) string {
	var sb strings.Builder
	sb.Grow(len(tableName) + len(cols)*16 + 32)
	sb.WriteString("INSERT INTO ")
	sb.WriteString(tableName)
	sb.WriteString("(")
	sb.WriteString(strings.Join(cols, ","))
	sb.WriteString(") VALUES(")
	for i := range cols {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('?')
	}
	sb.WriteByte(')')
	return sb.String()
}

// insertMultiSQLText 生成「每组 n 行拼接」的多值 INSERT 语句文本，列名
// 取单组列清单（多值只需一份列名），VALUES 组数与组行数严格一致。
func insertMultiSQLText(tableName string, cols []string, n int) string {
	var sb strings.Builder
	sb.Grow(len(tableName) + len(cols)*2 + n*(len(cols)*2+3) + 16)
	sb.WriteString("INSERT INTO ")
	sb.WriteString(tableName)
	sb.WriteString("(")
	sb.WriteString(strings.Join(cols, ","))
	sb.WriteString(") VALUES ")
	for r := 0; r < n; r++ {
		if r > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('(')
		for i := range cols {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteByte('?')
		}
		sb.WriteByte(')')
	}
	return sb.String()
}

// ensureStmtFor 惰性取得某张表的长期语句。Prepare 失败时上层在本类内
// 报错并回退——不在栈里 panic，审计路径不因加速器失败而翻车。
func (bf *sqliteBulkFlusher) ensureStmtFor(table string) (*sql.Stmt, error) {
	if stmt := bf.stmts[table]; stmt != nil {
		return stmt, nil
	}
	spec, ok := bf.specs[table]
	if !ok {
		return nil, fmt.Errorf("sqlite bulk flusher: unknown table %q", table)
	}
	if bf.sqlDB == nil {
		return nil, fmt.Errorf("sqlite bulk flusher: conn pool not attached for %q", table)
	}
	stmt, err := bf.sqlDB.Prepare(insertSQLText(spec.tableName, spec.cols))
	if err != nil {
		return nil, fmt.Errorf("sqlite bulk flusher: prepare %q: %w", spec.tableName, err)
	}
	bf.stmts[table] = stmt
	return stmt, nil
}

// ensureMultiStmtFor 惰性取得某张表的多值组语句模板（每组 spec.groupSize
// 行）。prepare 失败（或组大小退回 1）调用方落回单行 ensureStmtFor 路径，
// 与本类其余失败语义一致：审计路径不因加速器失败而翻车。
func (bf *sqliteBulkFlusher) ensureMultiStmtFor(table string) (*sql.Stmt, int, error) {
	spec, ok := bf.specs[table]
	if !ok {
		return nil, 0, fmt.Errorf("sqlite bulk flusher: unknown table %q", table)
	}
	if spec.groupSize <= 1 {
		return nil, 0, fmt.Errorf("sqlite bulk flusher: multi row group disabled for %q", table)
	}
	if stmt := bf.multStmts[table]; stmt != nil {
		return stmt, spec.groupSize, nil
	}
	if bf.sqlDB == nil {
		return nil, 0, fmt.Errorf("sqlite bulk flusher: conn pool not attached for %q", table)
	}
	stmt, err := bf.sqlDB.Prepare(insertMultiSQLText(spec.tableName, spec.cols, spec.groupSize))
	if err != nil {
		return nil, 0, fmt.Errorf("sqlite bulk flusher: prepare multi %q: %w", spec.tableName, err)
	}
	bf.multStmts[table] = stmt
	return stmt, spec.groupSize, nil
}

// closeAll 释放全部已准备语句（UnifiedWriter 排空完成后调用，幂等）。
func (bf *sqliteBulkFlusher) closeAll() {
	for table, stmt := range bf.stmts {
		_ = stmt.Close()
		delete(bf.stmts, table)
	}
	for table, stmt := range bf.multStmts {
		_ = stmt.Close()
		delete(bf.multStmts, table)
	}
}

// execRowsInTx 在当前 *gorm.DB 事务内写入一类审计行。
//
// 事务与 SAVEPOINT 完全交还外层 flushType 统一管理
// （internal/observability/unified_writer.go:757-782）：本函数在事务内只做
// 「绑定长期语句 → 写入 → 首错中止」，不再自行打保存点——内层自加
// 同名 SAVEPOINT 会与外层保存点栈失衡（失败类之后的其它类被外层错误路径
// 连带回滚），违反四类独立隔离语义；缺陷与修复记录见
// /tmp/owaf-perf-r3/wave3-report.md 的「SAVEPOINT 双层缺陷与修复」一节。
//
// 写入路径（wave6）：指定表的多值组语句可用时按每组 groupSize 行拼成
// 一条多值 INSERT 执行，摊平逐行 bind 与语句执行；末尾余数组（< groupSize）
// 落回单行长期语句逐行写完，避免拼接参数数与模板占位符数不一致。多值
// 语句准备失败的类只在此次 flush 逐行写完——仍是同一事务同一
// flushType 保存点内，失败语义不变。
//
// 行执行载体：PreparedStmtTX 只是长期语句缓存的地盘，这里绕开语料缓存，
// 直接取 tx.Statement.ConnPool.(stmtRunner).StmtContext(ctx, stmt) 把长期语句
// 绑到当前事务连接——*sql.Tx 与 *PreparedStmtTX 都实现该接口
// （gorm 1.31.2 prepare_stmt.go:147-150 / interfaces.go:59-63）。
//
// 返回值：成功写入条数；错误时返回出错前已写入的条数。调用方依据错误把
// 本类计入 failedRecords（flushBuffered 既有口径）。
func (bf *sqliteBulkFlusher) execRowsInTx(tx *gorm.DB, table string, rows []any) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	stmt, err := bf.ensureStmtFor(table)
	if err != nil {
		return 0, err
	}
	spec, ok := bf.specs[table]
	if !ok {
		return 0, fmt.Errorf("sqlite bulk flusher: unknown table %q", table)
	}
	runner, ok := tx.Statement.ConnPool.(stmtRunner)
	if !ok {
		return 0, fmt.Errorf("sqlite bulk flusher: conn pool of %q cannot run long-lived stmt", table)
	}

	ctx := context.Background()
	now := bf.nowFunc(tx)

	// 多值组语句可选：准备失败即退回单行路径（本次 flush 本类仍走
	// 长期语句；GORM 兜底由 flushBuffered 的 bf==nil 分支承担）。
	multiStmt := (*sql.Stmt)(nil)
	groupSize := 0
	if mStmt, mN, mErr := bf.ensureMultiStmtFor(table); mErr == nil {
		multiStmt, groupSize = mStmt, mN
	}

	written := 0
	i := 0
	if multiStmt != nil && groupSize > 1 {
		// 整组多值段。
		for ; i+groupSize <= len(rows); i += groupSize {
			group := rows[i : i+groupSize]
			args := make([]any, 0, len(group)*len(spec.cols))
			for _, row := range group {
				args = append(args, spec.values(row, now)...)
			}
			if _, execErr := runner.StmtContext(ctx, multiStmt).ExecContext(ctx, args...); execErr != nil {
				return written, execErr
			}
			written += len(group)
		}
	}
	// 末尾余数组（或整批）逐行写完。go-sqlite 的 Result.RowsAffected
	// 每次 Exec 后自 c.changes() 重建，数值为常量 SQLITE_CHANGES=1
	// （v1.23.0 sqlite.go:132-144、1090）；这里不读取 Result，失败语义
	// 由外层 SAVEPOINT 隔离负责。
	for ; i < len(rows); i++ {
		if _, execErr := runner.StmtContext(ctx, stmt).ExecContext(ctx, spec.values(rows[i], now)...); execErr != nil {
			return written, execErr
		}
		written++
	}
	return written, nil
}

// nowFunc 取与 GORM 同源的当前时间：db.NowFunc()（gorm.go:186-187 默认
// time.Now().Local()）。生产未覆盖 NowFunc，此处等价于 time.Now()；构建期
// 校验过零值模型后无固定时间透出。
func (bf *sqliteBulkFlusher) nowFunc(tx *gorm.DB) time.Time {
	if tx.Config.NowFunc != nil {
		return tx.Config.NowFunc()
	}
	return time.Now()
}

// stmtRunner 是长期语句执行所需的最小接口：*sql.Tx 与 gorm 的
// *PreparedStmtTX 均实现。
type stmtRunner interface {
	StmtContext(ctx context.Context, stmt *sql.Stmt) *sql.Stmt
}

// rowsToAny 把四类缓冲切片桥接成 []any（持原切片元素地址，零拷贝）。
func rowsToAny[T any](items []T) []any {
	out := make([]any, len(items))
	for i := range items {
		out[i] = &items[i]
	}
	return out
}

// 四模型取值函数：列顺序必须与其构建出的列清单一致（构建期由 newSQLiteBulkFlusher
// 跑通校验零值实例，列数与值数不匹配即否决整个 flusher）。

// accessLogSpecValues 预应用 store.AccessLog.BeforeSave
// （internal/store/events.go:155-171）：该钩子唯一动作是设置 derived 字段
// fingerprint_key，这里用同一 store.ComputeAccessLogFingerprintKey 复现。
//
// 时间等价：显式非零 CreatedAt 原样透传；零值以参数 created 填充（调用方
// 每类取一次 db.NowFunc()，语义 = GORM 的 AutoCreateTime now 补写）。
func accessLogSpecValues(v any, created time.Time) []any {
	a := v.(*store.AccessLog)
	a.FingerprintKey = store.ComputeAccessLogFingerprintKey(
		a.TLSJA3Hash, a.TLSJA4, a.TLSVersion, a.TLSALPN, a.TLSSNI,
		a.TLSCipherSuites, a.TLSExtensions, a.TLSCurves, a.TLSPointFormats)
	createdAt := a.CreatedAt
	if createdAt.IsZero() {
		createdAt = created
	}
	return []any{
		createdAt, a.SiteID, a.RequestID, a.ClientIP, a.Host, a.Path, a.QueryString,
		a.Method, a.StatusCode, a.WAFAction, a.CacheState, a.Upstream, a.UserAgent,
		a.RequestHeaders, a.RequestBodyPreview, a.RequestBodyTruncated, a.RequestSize,
		a.ResponseHeaders, a.HTTPProtocol, a.UpstreamHTTPProtocol,
		a.TLSVersion, a.TLSSNI, a.TLSALPN, a.TLSJA3, a.TLSJA3Hash, a.TLSJA4, a.FingerprintKey,
		a.TLSCipherSuites, a.TLSExtensions, a.TLSCurves, a.TLSPointFormats, a.HeaderOrder,
		a.VisitorFusionClass, a.VisitorFusionScore, a.VisitorFusionClientFamily,
		a.VisitorFusionUAClaim, a.VisitorFusionConsistency, a.VisitorFusionEvidenceSufficient,
		a.VisitorFusionReasons, a.UpstreamLatencyMs, a.ResponseSize,
	}
}

// securityEventSpecValues 对应 SecurityEvent 全部可创建列。该模型无钩子
// （internal/store 全树 grep：仅 AccessLog / app_route.RecordedResource 有 BeforeSave）。
// created_at 同 accessLogSpecValues 的显式/零值规则。
func securityEventSpecValues(v any, created time.Time) []any {
	s := v.(*store.SecurityEvent)
	createdAt := s.CreatedAt
	if createdAt.IsZero() {
		createdAt = created
	}
	return []any{
		createdAt, s.SiteID, s.RequestID, s.ClientIP, s.Host, s.Path, s.QueryString,
		s.Method, s.UserAgent, s.RuleID, s.RuleIDStr, s.Phase, s.Action, s.Category, s.MatchDesc,
		s.RequestHeaders, s.RequestBodyPreview, s.RequestBodyTruncated, s.RequestSize,
		s.TLSVersion, s.TLSSNI, s.TLSALPN, s.TLSJA3, s.TLSJA3Hash, s.TLSJA4,
		s.TLSCipherSuites, s.TLSExtensions, s.TLSCurves, s.TLSPointFormats, s.HeaderOrder,
		s.GeoCountry, s.GeoCity, s.StatusCode,
	}
}

// dropEventSpecValues 对应 DropEvent 全部可创建列。
// created_at 是模型最后一个字段，列清单同序（place 顺序与值顺序必须一致）；
// 显式非零 CreatedAt 原样透传，零值以参数 created 填充。
func dropEventSpecValues(v any, created time.Time) []any {
	d := v.(*store.DropEvent)
	createdAt := d.CreatedAt
	if createdAt.IsZero() {
		createdAt = created
	}
	return []any{d.SiteID, d.ClientIP, d.Source, d.RuleID, d.Detail, d.Host, d.Path, createdAt}
}

// botScoreSpecValues 对应 BotScoreLog 全部可创建列。
// created_at 是模型最后一个字段，列清单同序；显式/零值规则同上。
func botScoreSpecValues(v any, created time.Time) []any {
	b := v.(*store.BotScoreLog)
	createdAt := b.CreatedAt
	if createdAt.IsZero() {
		createdAt = created
	}
	return []any{
		b.SiteID, b.RequestID, b.ClientIP, b.Host, b.Path, b.UserAgent,
		b.TLSJA3Hash, b.TLSJA4, b.TLSVersion, b.TLSSNI, b.TLSALPN, b.HeaderOrder,
		b.TotalScore, b.GeoIPScore, b.FingerprintScore, b.BehaviorScore, b.IPRepScore,
		b.IsHighRisk, b.Action, b.Details, createdAt,
	}
}
