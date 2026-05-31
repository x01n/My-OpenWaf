package migrations

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// V2MigrateSingleSite consolidates Listener and ForwardingProfile into Site.
// This migration:
// 1. Adds new columns to sites table
// 2. Migrates data from listeners and forwarding_profiles
// 3. Backs up old tables with _backup suffix
// 4. Drops original listener and forwarding_profile tables
func V2MigrateSingleSite(db *gorm.DB) error {
	// Check if migration already applied
	if !db.Migrator().HasTable("listeners") {
		return nil // Already migrated
	}

	// Start transaction
	return db.Transaction(func(tx *gorm.DB) error {
		// Step 1: Add new columns to sites table if they don't exist
		if err := addSiteColumns(tx); err != nil {
			return fmt.Errorf("failed to add site columns: %w", err)
		}

		// Step 2: Migrate data from listeners to sites
		if err := migrateListenerData(tx); err != nil {
			return fmt.Errorf("failed to migrate listener data: %w", err)
		}

		// Step 3: Migrate data from forwarding_profiles to sites
		if err := migrateForwardingProfileData(tx); err != nil {
			return fmt.Errorf("failed to migrate forwarding profile data: %w", err)
		}

		// Step 4: Backup old tables
		timestamp := time.Now().Format("20060102_150405")
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE listeners RENAME TO listeners_backup_%s", timestamp)).Error; err != nil {
			return fmt.Errorf("failed to backup listeners table: %w", err)
		}
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE forwarding_profiles RENAME TO forwarding_profiles_backup_%s", timestamp)).Error; err != nil {
			return fmt.Errorf("failed to backup forwarding_profiles table: %w", err)
		}

		return nil
	})
}

func addSiteColumns(tx *gorm.DB) error {
	columns := []struct {
		name     string
		dataType string
	}{
		{"bind", "VARCHAR(255) NOT NULL DEFAULT ':80'"},
		{"network", "VARCHAR(16) DEFAULT 'tcp'"},
		{"enabled", "BOOLEAN DEFAULT true"},
		{"tls_enabled", "BOOLEAN DEFAULT false"},
		{"min_tls_version", "VARCHAR(32) DEFAULT 'TLS12'"},
		{"max_tls_version", "VARCHAR(32) DEFAULT 'TLS13'"},
		{"cipher_suites", "TEXT"},
		{"alpn", "VARCHAR(255) DEFAULT 'h2,http/1.1'"},
		{"bot_protection_enabled", "BOOLEAN DEFAULT false"},
		{"bot_protection_level", "VARCHAR(16) DEFAULT 'medium'"},
		{"attack_protection_level", "VARCHAR(16) DEFAULT 'medium'"},
		{"xff_mode", "VARCHAR(64) DEFAULT 'strip_all_and_set_remote'"},
		{"trusted_cidr", "TEXT"},
		{"preserve_original_host", "BOOLEAN DEFAULT false"},
	}

	for _, col := range columns {
		if !tx.Migrator().HasColumn(&siteTable{}, col.name) {
			if err := tx.Exec(fmt.Sprintf("ALTER TABLE sites ADD COLUMN %s %s", col.name, col.dataType)).Error; err != nil {
				return fmt.Errorf("failed to add column %s: %w", col.name, err)
			}
		}
	}

	return nil
}

func migrateListenerData(tx *gorm.DB) error {
	// Query all sites with their listener data
	rows, err := tx.Raw(`
		SELECT
			s.id,
			l.bind,
			l.network,
			l.enabled,
			l.tls_enabled,
			l.min_tls_version,
			l.max_tls_version,
			l.alpn
		FROM sites s
		INNER JOIN listeners l ON s.listener_id = l.id
		WHERE l.role = 'data'
	`).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	// Update each site with listener configuration
	for rows.Next() {
		var (
			siteID                              uint
			bind, network, minTLS, maxTLS, alpn string
			enabled, tlsEnabled                 bool
		)
		if err := rows.Scan(&siteID, &bind, &network, &enabled, &tlsEnabled, &minTLS, &maxTLS, &alpn); err != nil {
			return err
		}

		if err := tx.Exec(`
			UPDATE sites
			SET bind = ?, network = ?, enabled = ?, tls_enabled = ?,
			    min_tls_version = ?, max_tls_version = ?, alpn = ?
			WHERE id = ?
		`, bind, network, enabled, tlsEnabled, minTLS, maxTLS, alpn, siteID).Error; err != nil {
			return err
		}
	}

	return nil
}

func migrateForwardingProfileData(tx *gorm.DB) error {
	// Query all sites with their forwarding profile data
	rows, err := tx.Raw(`
		SELECT
			s.id,
			fp.xff_mode,
			fp.trusted_c_id_r,
			fp.preserve_original_host
		FROM sites s
		INNER JOIN forwarding_profiles fp ON s.forwarding_profile_id = fp.id
	`).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	// Update each site with forwarding configuration
	for rows.Next() {
		var (
			siteID               uint
			xffMode, trustedCIDR string
			preserveOriginalHost bool
		)
		if err := rows.Scan(&siteID, &xffMode, &trustedCIDR, &preserveOriginalHost); err != nil {
			return err
		}

		if err := tx.Exec(`
			UPDATE sites
			SET xff_mode = ?, trusted_cidr = ?, preserve_original_host = ?
			WHERE id = ?
		`, xffMode, trustedCIDR, preserveOriginalHost, siteID).Error; err != nil {
			return err
		}
	}

	return nil
}

// siteTable is a dummy struct for GORM Migrator column checks
type siteTable struct {
	Bind                  string
	Network               string
	Enabled               bool
	TLSEnabled            bool
	MinTLSVersion         string
	MaxTLSVersion         string
	CipherSuites          string
	ALPN                  string
	BotProtectionEnabled  bool
	BotProtectionLevel    string
	AttackProtectionLevel string
	XFFMode               string
	TrustedCIDR           string
	PreserveOriginalHost  bool
}

func (siteTable) TableName() string {
	return "sites"
}
