package migrations

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"gorm.io/gorm"
)

const v12AccessLogFingerprintBatchSize = 1000

// v12AccessLogFingerprintTable is deliberately independent from store.AccessLog
// so the migrations package does not introduce an import cycle.
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
 * V12MigrateAccessLogFingerprintKey adds and backfills the indexed fingerprint
 * digest used by cold fingerprint aggregation queries.
 *
 * Only rows that contain JA3 or JA4 are backfilled because rows without either
 * value are intentionally excluded from fingerprint summaries. The keyset
 * cursor keeps memory bounded and remains efficient on large SQLite log files.
 */
func V12MigrateAccessLogFingerprintKey(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("access_logs") {
		return nil
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
			return nil
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
			return nil
		}
	}
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
