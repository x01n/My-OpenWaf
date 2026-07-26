package system

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

func newBackupDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// 用 store.BackupModels 而非手写清单，新增备份模型时不会漏。
	if err := db.AutoMigrate(store.BackupModels()...); err != nil {
		t.Fatalf("migrate backup db: %v", err)
	}
	return db
}

func invokeBackupHandler(t *testing.T, handler app.HandlerFunc, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/backup/import")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestImportBackupRejectsVersionZero(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCalled := false
	reload := func() error { reloadCalled = true; return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": 0},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("version=0 status = %d, want 400; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload must not be called when version is invalid")
	}
}

func TestImportBackupRejectsVersionTooHigh(t *testing.T) {
	db := newBackupDBForTest(t)
	reload := func() error { return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": store.BackupVersion + 99},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("version too high status = %d, want 400; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	respStr := string(bytes.TrimSpace(ctx.Response.Body()))
	if !strings.Contains(respStr, "unsupported backup version") {
		t.Fatalf("error message = %q, want 'unsupported backup version'", respStr)
	}
}

func TestImportBackupCallsReloadOnSuccess(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": store.BackupVersion},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("import status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload called %d times, want 1", reloadCount)
	}
}

func TestImportBackupRejectsInvalidJSON(t *testing.T) {
	db := newBackupDBForTest(t)
	reload := func() error { return nil }

	ctx := invokeBackupHandler(t, ImportBackup(db, reload), []byte(`{not-valid-json`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid json status = %d, want 400", ctx.Response.StatusCode())
	}
}

func TestExportBackupSetsContentDisposition(t *testing.T) {
	db := newBackupDBForTest(t)

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/backup/export")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ExportBackup(db)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	cd := string(ctx.Response.Header.Get("Content-Disposition"))
	if !strings.HasPrefix(cd, "attachment;") {
		t.Fatalf("Content-Disposition = %q, want 'attachment;...'", cd)
	}
	if !strings.Contains(cd, "owaf-backup-") {
		t.Fatalf("Content-Disposition = %q, want filename containing 'owaf-backup-'", cd)
	}

	var data store.BackupData
	if err := json.Unmarshal(ctx.Response.Body(), &data); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	if data.Version != store.BackupVersion {
		t.Fatalf("backup version = %d, want %d", data.Version, store.BackupVersion)
	}
}
