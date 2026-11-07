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
	// savePoints 以保存点名称为键的 SAVEPOINT 长期语句。flushType 每批
	// 对四类各执行一次 SAVEPOINT，走 database/sql 的动态 SQL 会每次重新
	// prepare（sqlite 解析器成本可观），因此与 INSERT 一样复用语句。
	savePoints map[string]*sql.Stmt

	// specs 以表名为键的模型元信息与行取值函数。
	specs map[string]bulkModelSpec

	// sqlDB 是长期语句的 Prepare 载体（由 attachSQLDB 从 LogDB 取出）。
	sqlDB *sql.DB
	// conn 是专用于日志落库的固定连接。长期语句绑定连接，只有始终复用
	// 同一条连接，驱动层缓存的编译语句（modernc stmt.pstmt）才能跨批命中；
	// 若每次 flush 重新从池里借连接，事务切换会让语句反复重新解析。
	conn *sql.Conn

	// now 与 GORM 的 NowFunc 同源，供批量取值函数填充零值创建时间。
	now func() time.Time
}

// bulkModelSpec 汇集一张日志表生成长期 INSERT 所需的全部信息。
type bulkModelSpec struct {
	tableName string
	model     any      // 构建期 schema.Parse 的模型引用，仅 newSQLiteBulkFlusher 内部用
	cols      []string // 绑定列，顺序即语句占位符顺序
	groupSize int      // 当前生效的每组行数（构建期按下限放宽）
	values    func(v any, created time.Time) []any
}

/**
 * newSQLiteBulkFlusher 构建四张日志表的长期语句快路径。
 *
 * 任一模型的列清单无法对齐时返回 nil 并告警：调用方（flushBuffered）见 nil
 * 即回退 GORM 原路径——长期语句因此只是一个可自愈的加速器，不会让审计
 * 落库整体失败。
 */
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
		log:        log,
		stmts:      map[string]*sql.Stmt{},
		multStmts:  map[string]*sql.Stmt{},
		savePoints: map[string]*sql.Stmt{},
		specs:      map[string]bulkModelSpec{},
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
		// 构建期校验列清单与行取值函数等长。
		//
		// cols 由 GORM schema 动态生成，values 是手写清单；模型新增字段后若不
		// 同步 values，运行期每次 execRowsInTx 都会得到 "N values for M columns"
		// 而整批落库失败——表现为「访问日志静默全部丢失」，比直接回退 GORM 路径
		// 严重得多。这里提前否决并回退，让缺失字段只损失加速能力，不损失数据。
		if got, want := len(spec.values(spec.model, time.Time{})), len(cols); got != want {
			bf.disable("values/columns mismatch", spec.tableName,
				"values", fmt.Sprintf("%d values for %d columns", got, want))
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

var testHookMultiGroupSize func() int

func pendingMultiGroupSize() int {
	h := testHookMultiGroupSize
	testHookMultiGroupSize = nil
	if h == nil {
		return 0
	}
	return h()
}

func multiGroupSizeFor(cols int) int {
	n := defaultMultiGroupSize
	if h := pendingMultiGroupSize(); h > 0 {
		// testHookMultiGroupSize 是测试组大小的运行时选择，介入仅发生在
		// 基准构建期，生产执行永不生效。
		n = h
	}
	if maxN := driverMaxVariableNumber / cols; maxN < n {
		n = maxN
	}
	if n < 1 {
		n = 1
	}
	return n
}

func multiGroupSizeClamped(cols int) bool {
	return driverMaxVariableNumber/cols < defaultMultiGroupSize
}

// disable 记录否决原因，让上层直接落回 GORM 路径。
func (bf *sqliteBulkFlusher) disable(msg, table, kvMsg string, detail any) {
	if bf.log != nil {
		bf.log.Warn("sqlite bulk flusher disabled: "+msg,
			slog.String("table", table), slog.String(kvMsg, fmt.Sprint(detail)))
	}
}

/**
 * attachSQLDB 把 UnifiedWriter 的 LogDB 底层连接池绑定到 flusher。
 *
 * 这里只保存连接池，真正的固定连接在首次 flush 时通过 [(*sqliteBulkFlusher).beginTx]
 * 借出并长期持有。借出失败（连接池已关闭等）不在此处报错：flusher 保持
 * 可用状态，调用方下次 flush 会再试，期间落回 GORM 路径。
 *
 * SQLite 连接无轮换（internal/core/database/gorm.go 的 ConnMaxLifetime(0)），
 * 长期持有合法。
 */
func (bf *sqliteBulkFlusher) attachSQLDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("sqlite bulk flusher: resolve conn pool: %w", err)
	}
	bf.sqlDB = sqlDB
	bf.now = db.Config.NowFunc
	return nil
}

/**
 * ensureConn 取得（或复用）日志落库专用连接。
 *
 * @return 固定连接；连接池不可用或上下文取消时返回错误。
 */
func (bf *sqliteBulkFlusher) ensureConn(ctx context.Context) (*sql.Conn, error) {
	if bf.conn != nil {
		return bf.conn, nil
	}
	if bf.sqlDB == nil {
		return nil, fmt.Errorf("sqlite bulk flusher: conn pool not attached")
	}
	conn, err := bf.sqlDB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlite bulk flusher: acquire conn: %w", err)
	}
	bf.conn = conn
	return conn, nil
}

/**
 * beginTx 在固定连接上开启一个原生事务。
 *
 * 不使用 GORM 的 Transaction：GORM 会从连接池另借连接，随后长期语句的
 * Prepare 只能在第二条连接上执行；对 :memory: 这类「每连接独立库」的 DSN
 * 会直接看不到表，对文件库则让语句缓存失去意义。
 *
 * @param ctx 事务上下文。
 * @return 当前 flush 事务。
 */
func (bf *sqliteBulkFlusher) beginTx(ctx context.Context) (*sql.Tx, error) {
	conn, err := bf.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sqlite bulk flusher: begin tx: %w", err)
	}
	return tx, nil
}

/**
 * prepareStmt 在固定连接上准备一条长期语句。
 *
 * 连接池级 sql.DB.Prepare 会把语句绑到任意空闲连接，既无法与 flush
 * 事务共享，又会在连接切换时重复解析。统一走 bf.conn 后，语句句柄
 * 与事务始终在同一条物理连接上。
 */
func (bf *sqliteBulkFlusher) prepareStmt(ctx context.Context, query string) (*sql.Stmt, error) {
	conn, err := bf.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.PrepareContext(ctx, query)
}

/**
 * insertSQLText 生成单行 INSERT 语句文本；首次 prepare 时生成一次。
 *
 * 列名必须按 SQLite 标识符转义：references 是 SQL 保留字，未加双引号时
 * 语句在解析阶段即报 "near \"references\": syntax error"。
 */
func insertSQLText(tableName string, cols []string) string {
	var sb strings.Builder
	sb.Grow(len(tableName) + len(cols)*16 + 32)
	sb.WriteString("INSERT INTO ")
	sb.WriteString(tableName)
	sb.WriteString("(")
	for i, col := range cols {
		if i > 0 {
			sb.WriteByte(',')
		}
		writeQuotedIdentifier(&sb, col)
	}
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
	for i, col := range cols {
		if i > 0 {
			sb.WriteByte(',')
		}
		writeQuotedIdentifier(&sb, col)
	}
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

// writeQuotedIdentifier 输出双引号包裹的 SQL 标识符，内部双引号按 SQL 规则
// 转义为两个双引号。列名来自 GORM schema 的 DBNames，不含用户输入。
func writeQuotedIdentifier(sb *strings.Builder, name string) {
	sb.WriteByte('"')
	sb.WriteString(strings.ReplaceAll(name, `"`, `""`))
	sb.WriteByte('"')
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
	stmt, err := bf.prepareStmt(context.Background(), insertSQLText(spec.tableName, spec.cols))
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
	stmt, err := bf.prepareStmt(context.Background(), insertMultiSQLText(spec.tableName, spec.cols, spec.groupSize))
	if err != nil {
		return nil, 0, fmt.Errorf("sqlite bulk flusher: prepare multi %q: %w", spec.tableName, err)
	}
	bf.multStmts[table] = stmt
	return stmt, spec.groupSize, nil
}

// closeAll 释放全部已准备语句与固定连接（UnifiedWriter 排空完成后调用，幂等）。
func (bf *sqliteBulkFlusher) closeAll() {
	for table, stmt := range bf.stmts {
		_ = stmt.Close()
		delete(bf.stmts, table)
	}
	for table, stmt := range bf.multStmts {
		_ = stmt.Close()
		delete(bf.multStmts, table)
	}
	for name, stmt := range bf.savePoints {
		_ = stmt.Close()
		delete(bf.savePoints, name)
	}
	if bf.conn != nil {
		_ = bf.conn.Close()
		bf.conn = nil
	}
}

// reset 丢弃当前固定连接及其全部长期语句，供连接失效后重建。
// 调用后下一次 flush 会重新借连接并重新 prepare。
func (bf *sqliteBulkFlusher) reset() {
	bf.closeAll()
}

// ensureSavePointStmtFor 惰性取得某个保存点的长期 SAVEPOINT 语句。
//
// 保存点名称只来自 flushType 的固定表名（security_events/access_logs/
// drop_events/bot_scores），不含外部输入，因此直接拼入语句文本与 GORM
// sqlite 方言的 SavePoint 实现一致（gorm.io/driver/sqlite: `SAVEPOINT `+name）。
func (bf *sqliteBulkFlusher) ensureSavePointStmtFor(name string) (*sql.Stmt, error) {
	if stmt := bf.savePoints[name]; stmt != nil {
		return stmt, nil
	}
	if bf.sqlDB == nil {
		return nil, fmt.Errorf("sqlite bulk flusher: conn pool not attached for savepoint %q", name)
	}
	stmt, err := bf.prepareStmt(context.Background(), "SAVEPOINT "+name)
	if err != nil {
		return nil, fmt.Errorf("sqlite bulk flusher: prepare savepoint %q: %w", name, err)
	}
	bf.savePoints[name] = stmt
	return stmt, nil
}

// execSavePointInTx 在当前事务内打保存点。
//
// 语句绑定在 flusher 的固定连接上，而事务也在同一条连接上开启，因此直接
// 执行语句即可；改走 Tx.StmtContext 反而会因为 database/sql 认为「该语句
// 已属于某个连接」而重新 prepare 一次，使语句缓存完全失效。
//
// @param name 保存点名称（固定表名）。
// @return 错误；调用方按「打点失败则不回滚该类」的既有语义处理。
func (bf *sqliteBulkFlusher) execSavePointInTx(name string) error {
	stmt, err := bf.ensureSavePointStmtFor(name)
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, err = stmt.ExecContext(ctx)
	return err
}

// rollbackToInTx 回滚到指定保存点，保留事务本身与后续类的写入能力。
func (bf *sqliteBulkFlusher) rollbackToInTx(tx *sql.Tx, name string) error {
	if bf.conn == nil {
		return fmt.Errorf("sqlite bulk flusher: conn not attached for rollback %q", name)
	}
	// 保存点名只来自固定表名，不含外部输入；动态语句每次重新 prepare 的
	// 成本只会发生在类型写入失败后的异常路径，不值得再引入一条长期语句。
	_, err := tx.ExecContext(context.Background(), "ROLLBACK TO "+name)
	return err
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
// 行执行载体：语句在固定连接上 prepare，事务也在同一条连接上开启。直接
// 执行长期语句即可；Tx.StmtContext 会把「来自 *sql.Conn 的语句」判定为已
// 归属连接并重新 prepare，反而让缓存失效（见 execSavePointInTx 注释）。
//
// 返回值：成功写入条数；错误时返回出错前已写入的条数。调用方依据错误把
// 本类计入 failedRecords（flushBuffered 既有口径）。
func (bf *sqliteBulkFlusher) execRowsInTx(table string, rows []any) (int, error) {
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

	ctx := context.Background()
	now := bf.nowFunc()

	// 多值组语句可选：仅当本批行数足够整组时才准备——不足一组的类
	// 会整批落回单行语句，提前 prepare 一条用不上的多值语句纯属浪费。
	// sqlite 的 prepared statement 绑定连接，事务切换后 database/sql
	// 需要在事务连接上重新 prepare，因此每条多值语句的文本解析成本
	// 会按 flush 次数重复支付。
	multiStmt := (*sql.Stmt)(nil)
	groupSize := 0
	if len(rows) >= spec.groupSize && spec.groupSize > 1 {
		if mStmt, mN, mErr := bf.ensureMultiStmtFor(table); mErr == nil {
			multiStmt, groupSize = mStmt, mN
		}
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
			if _, execErr := multiStmt.ExecContext(ctx, args...); execErr != nil {
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
		if _, execErr := stmt.ExecContext(ctx, spec.values(rows[i], now)...); execErr != nil {
			return written, execErr
		}
		written++
	}
	return written, nil
}

// nowFunc 取与 GORM 同源的当前时间：db.NowFunc()（gorm.go:186-187 默认
// time.Now().Local()）。生产未覆盖 NowFunc，此处等价于 time.Now()；构建期
// 校验过零值模型后无固定时间透出。
func (bf *sqliteBulkFlusher) nowFunc() time.Time {
	if bf.now != nil {
		return bf.now()
	}
	return time.Now()
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
		a.VisitorFusionReasons, a.ZeroRTT, a.UpstreamLatencyMs, a.ResponseSize,
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
		s.Method, s.UserAgent, s.RuleID, s.RuleIDStr,
		s.RuleName, s.RuleDesc, s.MatchScore, s.MatchSnippet, s.MatchPart,
		s.Severity, s.Source, s.CVSSScore, s.CWEType, s.References,
		s.Phase, s.Action, s.Category, s.MatchDesc,
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
		b.TotalScore, b.UAScore, b.GeoIPScore, b.FingerprintScore, b.BehaviorScore, b.IPRepScore,
		b.IsHighRisk, b.Dangerous, b.DangerReasons, b.Action, b.Details, createdAt,
	}
}
