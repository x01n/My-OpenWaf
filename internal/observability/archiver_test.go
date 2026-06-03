package observability

import (
	"log/slog"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestArchiverDoesNotCleanupImmediatelyOnStart(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	archiver := NewArchiver(db, nil, nil, nil, slog.Default(), 30)
	defer archiver.Close()

	select {
	case <-archiver.stopCh:
		t.Fatal("archiver stopped unexpectedly")
	case <-time.After(20 * time.Millisecond):
	}
}
