package event

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newFalsePositiveRepoForTest(t *testing.T) *repository.FalsePositiveRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.FalsePositiveReport{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repository.NewFalsePositiveRepo(db)
}

func invokeFalsePositiveHandler(t *testing.T, handler app.HandlerFunc, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/false-positives")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

// TestCreateFalsePositiveRequiresEventIDOrRequestID 验证两者均为空时返回 400。
func TestCreateFalsePositiveRequiresEventIDOrRequestID(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repo), []byte(`{"note":"test"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 when both IDs empty, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestCreateFalsePositiveWithSecurityEventID 验证 security_event_id 非零时可以提交。
func TestCreateFalsePositiveWithSecurityEventID(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	body := []byte(`{"security_event_id":42,"category":"sqli","note":"false alarm"}`)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repo), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("expected 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var rec store.FalsePositiveReport
	if err := json.Unmarshal(ctx.Response.Body(), &rec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rec.SecurityEventID != 42 || rec.Category != "sqli" || rec.Status != "pending" {
		t.Fatalf("unexpected created record: %#v", rec)
	}
}

// TestCreateFalsePositiveWithRequestID 验证 request_id 非空时可以提交。
func TestCreateFalsePositiveWithRequestID(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	body := []byte(`{"request_id":"req-abc123","rule_id_str":"R100"}`)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repo), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("expected 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var rec store.FalsePositiveReport
	if err := json.Unmarshal(ctx.Response.Body(), &rec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rec.RequestID != "req-abc123" || rec.RuleIDStr != "R100" || rec.Status != "pending" {
		t.Fatalf("unexpected created record: %#v", rec)
	}
}

// TestUpdateFalsePositiveStatusRejectsInvalidStatus 验证非法 status 值返回 400。
func TestUpdateFalsePositiveStatusRejectsInvalidStatus(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	// 先创建一条记录
	createCtx := invokeFalsePositiveHandler(t, CreateFalsePositive(repo), []byte(`{"security_event_id":1}`))
	if createCtx.Response.StatusCode() != 201 {
		t.Fatalf("seed create failed: %d", createCtx.Response.StatusCode())
	}
	var created store.FalsePositiveReport
	if err := json.Unmarshal(createCtx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	for _, badStatus := range []string{"approved", "done", "open", ""} {
		body, _ := json.Marshal(map[string]string{"status": badStatus})
		var req protocol.Request
		req.SetMethod("POST")
		req.SetRequestURI("/api/v1/false-positives/1/update")
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		ctx.Params = param.Params{{Key: "id", Value: "1"}}
		UpdateFalsePositiveStatus(repo)(context.Background(), ctx)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("status %q should return 400, got %d", badStatus, ctx.Response.StatusCode())
		}
	}
}

// TestUpdateFalsePositiveStatusAcceptsValidValues 验证 pending/confirmed/rejected 均接受。
func TestUpdateFalsePositiveStatusAcceptsValidValues(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	for _, validStatus := range []string{"confirmed", "rejected", "pending"} {
		createCtx := invokeFalsePositiveHandler(t, CreateFalsePositive(repo), []byte(`{"security_event_id":1}`))
		if createCtx.Response.StatusCode() != 201 {
			t.Fatalf("seed create failed: %d", createCtx.Response.StatusCode())
		}
		var created store.FalsePositiveReport
		if err := json.Unmarshal(createCtx.Response.Body(), &created); err != nil {
			t.Fatalf("decode created: %v", err)
		}
		idStr := json.Number(bytes.TrimSpace([]byte{}))
		_ = idStr
		idParam := "1"
		if created.ID > 0 {
			idParam = json.Number(string(rune('0' + created.ID))).String()
			// 直接格式化
			idParam = formatUint(created.ID)
		}

		body, _ := json.Marshal(map[string]string{"status": validStatus})
		var req protocol.Request
		req.SetMethod("POST")
		req.SetRequestURI("/api/v1/false-positives/" + idParam + "/update")
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		ctx.Params = param.Params{{Key: "id", Value: idParam}}
		UpdateFalsePositiveStatus(repo)(context.Background(), ctx)
		if ctx.Response.StatusCode() != 200 {
			t.Errorf("valid status %q should return 200, got %d: %s", validStatus, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

func formatUint(n uint) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// TestListFalsePositivesPageSizeClamp 验证 page_size 超过 200 时 fallback 为 20。
func TestListFalsePositivesPageSizeClamp(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/false-positives?page_size=999")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ListFalsePositives(repo)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["page_size"].(float64) != 20 {
		t.Fatalf("expected page_size to clamp to 20, got %v", resp["page_size"])
	}
}
