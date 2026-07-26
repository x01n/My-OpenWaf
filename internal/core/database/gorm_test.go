package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenUnsupportedDriverReturnsError(t *testing.T) {
	_, err := Open(Options{Driver: "oracle"})
	if err == nil {
		t.Fatal("expected error for unsupported driver, got nil")
	}
	if !strings.Contains(err.Error(), "oracle") {
		t.Errorf("error should mention driver name, got: %v", err)
	}
}

func TestOpenSQLiteInMemory(t *testing.T) {
	db, err := Open(Options{Driver: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("Open(sqlite, :memory:) error: %v", err)
	}
	sqlDB, _ := db.DB()
	if pingErr := sqlDB.Ping(); pingErr != nil {
		t.Errorf("Ping failed: %v", pingErr)
	}
	sqlDB.Close()
}

func TestOpenSQLiteEmptyDriverDefaultsToSQLite(t *testing.T) {
	db, err := Open(Options{Driver: "", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("Open(driver='', DSN=:memory:) error: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.Close()
}

func TestOpenSQLiteDefaultPathFromDataDir(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(Options{Driver: "sqlite", DataDir: dir})
	if err != nil {
		t.Fatalf("Open(sqlite, DataDir=%s) error: %v", dir, err)
	}
	sqlDB, _ := db.DB()
	sqlDB.Close()

	if _, statErr := os.Stat(filepath.Join(dir, "waf.db")); os.IsNotExist(statErr) {
		t.Error("expected waf.db to be created in DataDir")
	}
}

func TestOpenMySQLEmptyDSNReturnsError(t *testing.T) {
	_, err := Open(Options{Driver: "mysql", DSN: ""})
	if err == nil {
		t.Fatal("expected error for mysql with empty DSN")
	}
	if !strings.Contains(err.Error(), "MY_OPENWAF_DSN") {
		t.Errorf("error should mention MY_OPENWAF_DSN, got: %v", err)
	}
}

func TestOpenPostgresEmptyDSNReturnsError(t *testing.T) {
	_, err := Open(Options{Driver: "postgres", DSN: ""})
	if err == nil {
		t.Fatal("expected error for postgres with empty DSN")
	}
	if !strings.Contains(err.Error(), "MY_OPENWAF_DSN") {
		t.Errorf("error should mention MY_OPENWAF_DSN, got: %v", err)
	}
}

func TestOpenPostgresqlAliasEmptyDSNReturnsError(t *testing.T) {
	_, err := Open(Options{Driver: "postgresql", DSN: ""})
	if err == nil {
		t.Fatal("expected error for postgresql alias with empty DSN")
	}
}

func TestOpenSQLiteCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nestedPath := filepath.Join(dir, "sub", "nested", "waf.db")
	db, err := Open(Options{Driver: "sqlite", DSN: nestedPath})
	if err != nil {
		t.Fatalf("Open(sqlite, nested path) error: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.Close()

	if _, statErr := os.Stat(nestedPath); os.IsNotExist(statErr) {
		t.Error("expected nested db file to be created")
	}
}
