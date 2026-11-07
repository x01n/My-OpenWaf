package migrations

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync/atomic"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	v12AccessLogFingerprintBatchSize = 1000
	v12AccessLogFingerprintMarkerKey = "migration_v12_access_log_fingerprint_key"
)

// v12LogMigrationRecord 是日志库（waf_logs.db）自己的迁移标记表。
// 日志库与主库物理分离，不能复用主库的 system_settings。
type v12LogMigrationRecord struct {
	Key   string `gorm:"column:key;primaryKey"`
	Value string `gorm:"column:value"`
}

func (v12LogMigrationRecord) TableName() string { return "log_schema_migrations" }

// v12AccessLogFingerprintScheduled 是进程级单飞标志：同一进程只调度一次
// 回填，避免测试或重复调用路径同时起多个扫描 goroutine。
var v12AccessLogFingerprintScheduled atomic.Bool

// v12AccessLogFingerprintTable 刻意独立于 store.AccessLog，
// 以免 migrations 包引入 import cycle。
type v12AccessLogFingerprintTable struct {
	FingerprintKey string `gorm:"column:fingerprint_key;type:char(64);index:idx_al_fingerprint_key"`
}

func (v12AccessLogFingerprintTable) TableName() string { return "access_logs" }

type v12AccessLogFingerprintRow struct {
	ID              uint
	TLSJA3Hash      string
	TLSJA4          string
	TLSVersion      string
	TLSALPN         string
	TLSSNI          string
	TLSCipherSuites string
	TLSExtensions   string
	TLSCurves       string
	TLSPointFormats string
}

/**
 * V12EnsureAccessLogFingerprintKey 同步补齐 fingerprint_key 列、索引与日志库
 * 迁移标记表。
 *
 * SQLite 的 ADD COLUMN 只改元数据、不重写数据页，因此可以安全地放在启动
 * 关键路径；真正的历史行回填由 V12StartAccessLogFingerprintBackfill 异步完成。
 *
 * @param db 日志库句柄。
 * @return 结构补齐过程中的错误。
 */
func V12EnsureAccessLogFingerprintKey(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("access_logs") {
		return nil
	}
	if err := db.AutoMigrate(&v12LogMigrationRecord{}); err != nil {
		return fmt.Errorf("failed to create log_schema_migrations: %w", err)
	}
	table := &v12AccessLogFingerprintTable{}
	if !db.Migrator().HasColumn(table, "fingerprint_key") {
		if err := db.Migrator().AddColumn(table, "FingerprintKey"); err != nil {
			return fmt.Errorf("failed to add access_logs.fingerprint_key: %w", err)
		}
	}
	if !db.Migrator().HasIndex(table, "idx_al_fingerprint_key") {
		if err := db.Migrator().CreateIndex(table, "FingerprintKey"); err != nil {
			return fmt.Errorf("failed to create access_logs fingerprint index: %w", err)
		}
	}
	return nil
}

/**
 * V12StartAccessLogFingerprintBackfill 在后台回填历史访问日志的指纹摘要。
 *
 * 回填在 13GB / 1310 万行量级上会持续数十秒，不能放在启动关键路径阻塞
 * readyz。标记表保证成功后不再重扫；中途退出时标记未写入，下次启动会重新
 * 执行，但 keyset 游标与 WHERE 条件会过滤已回填行，重复工作量仅限未完成部分。
 *
 * @param db      日志库句柄。
 * @param onError 异步错误回调，可为 nil（nil 时写默认 slog）。
 */
func V12StartAccessLogFingerprintBackfill(db *gorm.DB, onError func(error)) {
	if db == nil || !db.Migrator().HasTable("access_logs") {
		return
	}
	if !v12AccessLogFingerprintScheduled.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer v12AccessLogFingerprintScheduled.Store(false)
		if err := V12BackfillAccessLogFingerprintKey(db); err != nil {
			if onError != nil {
				onError(err)
				return
			}
			slog.Error("access log fingerprint backfill failed", slog.Any("err", err))
		}
	}()
}

/**
 * V12MigrateAccessLogFingerprintKey 同步完成列补齐与历史回填。
 *
 * 保留该入口供需要确定性的调用方（测试、离线工具）使用；生产启动路径应改用
 * V12EnsureAccessLogFingerprintKey + V12StartAccessLogFingerprintBackfill，
 * 避免阻塞 readyz。
 *
 * @param db 日志库句柄。
 * @return 补齐或回填过程中的错误。
 */
func V12MigrateAccessLogFingerprintKey(db *gorm.DB) error {
	if err := V12EnsureAccessLogFingerprintKey(db); err != nil {
		return err
	}
	return V12BackfillAccessLogFingerprintKey(db)
}

/**
 * V12BackfillAccessLogFingerprintKey 同步执行历史回填，成功后写入迁移标记。
 *
 * 只回填含 JA3 或 JA4 的行，因为两者皆空的行本就被指纹汇总排除在外。
 * keyset 游标让内存占用保持有界，在体量较大的 SQLite 日志库上依然高效。
 *
 * @param db 日志库句柄。
 * @return 回填或标记写入错误。
 */
func V12BackfillAccessLogFingerprintKey(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("access_logs") {
		return nil
	}
	if !db.Migrator().HasTable(&v12LogMigrationRecord{}) {
		if err := db.AutoMigrate(&v12LogMigrationRecord{}); err != nil {
			return fmt.Errorf("failed to create log_schema_migrations: %w", err)
		}
	}
	done, err := v12AccessLogFingerprintBackfillDone(db)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	var lastID uint
	for {
		var rows []v12AccessLogFingerprintRow
		query := db.Table("access_logs").
			Select("id, tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats").
			Where("id > ? AND (fingerprint_key IS NULL OR fingerprint_key = ?) AND (tls_ja3_hash <> ? OR tls_ja4 <> ?)", lastID, "", "", "").
			Order("id ASC").
			Limit(v12AccessLogFingerprintBatchSize)
		if err := query.Find(&rows).Error; err != nil {
			return fmt.Errorf("failed to read access_logs fingerprint rows after id %d: %w", lastID, err)
		}
		if len(rows) == 0 {
			break
		}

		updates := make(map[string][]uint, len(rows))
		for _, row := range rows {
			key := v12ComputeAccessLogFingerprintKey(row)
			if key == "" {
				lastID = row.ID
				continue
			}
			updates[key] = append(updates[key], row.ID)
			lastID = row.ID
		}
		for key, ids := range updates {
			if err := db.Table("access_logs").Where("id IN ?", ids).Update("fingerprint_key", key).Error; err != nil {
				return fmt.Errorf("failed to backfill access_logs fingerprint rows through id %d: %w", lastID, err)
			}
		}
		if len(rows) < v12AccessLogFingerprintBatchSize {
			break
		}
	}
	return v12MarkAccessLogFingerprintBackfillDone(db)
}

/**
 * v12AccessLogFingerprintBackfillDone 读取迁移标记，判断历史回填是否已完成。
 *
 * @param db 日志库句柄。
 * @return 标记是否存在；读取错误。
 */
func v12AccessLogFingerprintBackfillDone(db *gorm.DB) (bool, error) {
	var count int64
	if err := db.Table("log_schema_migrations").
		Where("key = ?", v12AccessLogFingerprintMarkerKey).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to read access log fingerprint migration marker: %w", err)
	}
	return count > 0, nil
}

/**
 * v12MarkAccessLogFingerprintBackfillDone 持久化「回填已完成」标记。
 *
 * @param db 日志库句柄。
 * @return 写入错误。
 */
func v12MarkAccessLogFingerprintBackfillDone(db *gorm.DB) error {
	record := v12LogMigrationRecord{Key: v12AccessLogFingerprintMarkerKey, Value: "true"}
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&record).Error; err != nil {
		return fmt.Errorf("failed to store access log fingerprint migration marker: %w", err)
	}
	return nil
}

func v12ComputeAccessLogFingerprintKey(row v12AccessLogFingerprintRow) string {
	if row.TLSJA3Hash == "" && row.TLSJA4 == "" {
		return ""
	}
	h := sha256.New()
	var encodedLength [binary.MaxVarintLen64]byte
	for _, value := range []string{
		row.TLSJA3Hash,
		row.TLSJA4,
		row.TLSVersion,
		row.TLSALPN,
		row.TLSSNI,
		row.TLSCipherSuites,
		row.TLSExtensions,
		row.TLSCurves,
		row.TLSPointFormats,
	} {
		n := binary.PutUvarint(encodedLength[:], uint64(len(value)))
		_, _ = h.Write(encodedLength[:n])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}
