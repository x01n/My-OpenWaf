package event

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type falsePositiveTestRepos struct {
	falsePositive *repository.FalsePositiveRepo
	securityEvent *repository.SecurityEventRepo
}

func newFalsePositiveReposForTest(t *testing.T) falsePositiveTestRepos {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.FalsePositiveReport{}, &store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return falsePositiveTestRepos{
		falsePositive: repository.NewFalsePositiveRepo(db),
		securityEvent: repository.NewSecurityEventRepo(db),
	}
}

func createSecurityEventForFalsePositiveTest(t *testing.T, repo *repository.SecurityEventRepo) *store.SecurityEvent {
	t.Helper()
	event := &store.SecurityEvent{
		RequestID:  "req-abc123",
		RuleIDStr:  "owasp:sqli:1001",
		Category:   "sqli",
		ClientIP:   "203.0.113.7",
		Host:       "app.example.test",
		Path:       "/api/login",
		MatchDesc:  "source event match",
		Action:     "intercept",
		Phase:      "owasp",
		StatusCode: 403,
	}
	if err := repo.Create(event); err != nil {
		t.Fatalf("create source security event: %v", err)
	}
	return event
}

func invokeFalsePositiveHandler(t *testing.T, handler app.HandlerFunc, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateFalsePositiveRequiresSecurityEventID(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repos.falsePositive, repos.securityEvent), "/api/v1/false-positives", nil, []byte(`{"note":"test"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateFalsePositiveUsesAuthoritativeSecurityEvent(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	event := createSecurityEventForFalsePositiveTest(t, repos.securityEvent)
	payload := []byte(`{"security_event_id":` + strconv.FormatUint(uint64(event.ID), 10) + `,"note":"false alarm","rule_id_str":"forged","category":"forged","client_ip":"198.51.100.9","host":"forged.example","path":"/forged","match_desc":"forged"}`)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repos.falsePositive, repos.securityEvent), "/api/v1/false-positives", nil, payload)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("status = %d, want 201: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var rec store.FalsePositiveReport
	if err := json.Unmarshal(ctx.Response.Body(), &rec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rec.SecurityEventID != event.ID || rec.RequestID != event.RequestID || rec.RuleIDStr != event.RuleIDStr || rec.Category != event.Category || rec.ClientIP != event.ClientIP || rec.Host != event.Host || rec.Path != event.Path || rec.MatchDesc != event.MatchDesc {
		t.Fatalf("record did not use source event fields: %#v", rec)
	}
	if rec.Note != "false alarm" || rec.Status != "pending" {
		t.Fatalf("record note/status = %q/%q", rec.Note, rec.Status)
	}
}

func TestCreateFalsePositiveRejectsMissingSecurityEvent(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	ctx := invokeFalsePositiveHandler(t, CreateFalsePositive(repos.falsePositive, repos.securityEvent), "/api/v1/false-positives", nil, []byte(`{"security_event_id":42,"note":"test"}`))
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("status = %d, want 404: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateFalsePositiveIsIdempotentPerSourceEvent(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	event := createSecurityEventForFalsePositiveTest(t, repos.securityEvent)
	payload := []byte(`{"security_event_id":` + strconv.FormatUint(uint64(event.ID), 10) + `,"note":"first"}`)
	handler := CreateFalsePositive(repos.falsePositive, repos.securityEvent)

	first := invokeFalsePositiveHandler(t, handler, "/api/v1/false-positives", nil, payload)
	if first.Response.StatusCode() != 201 {
		t.Fatalf("first status = %d, want 201: %s", first.Response.StatusCode(), bytes.TrimSpace(first.Response.Body()))
	}
	second := invokeFalsePositiveHandler(t, handler, "/api/v1/false-positives", nil, payload)
	if second.Response.StatusCode() != 200 {
		t.Fatalf("second status = %d, want 200: %s", second.Response.StatusCode(), bytes.TrimSpace(second.Response.Body()))
	}
	items, total, err := repos.falsePositive.List(0, 10, "")
	if err != nil {
		t.Fatalf("list false positives: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("stored records = %d/%d, want 1/1", total, len(items))
	}
}

func TestUpdateFalsePositiveStatusRejectsInvalidStatus(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	event := createSecurityEventForFalsePositiveTest(t, repos.securityEvent)
	created := invokeFalsePositiveHandler(t, CreateFalsePositive(repos.falsePositive, repos.securityEvent), "/api/v1/false-positives", nil, []byte(`{"security_event_id":`+strconv.FormatUint(uint64(event.ID), 10)+`}`))
	if created.Response.StatusCode() != 201 {
		t.Fatalf("seed create status = %d", created.Response.StatusCode())
	}

	for _, badStatus := range []string{"approved", "done", "open", ""} {
		body, err := json.Marshal(map[string]string{"status": badStatus})
		if err != nil {
			t.Fatalf("marshal status: %v", err)
		}
		ctx := invokeFalsePositiveHandler(t, UpdateFalsePositiveStatus(repos.falsePositive), "/api/v1/false-positives/1/status", param.Params{{Key: "id", Value: "1"}}, body)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("status %q returned %d, want 400", badStatus, ctx.Response.StatusCode())
		}
	}
}

func TestUpdateFalsePositiveStatusAcceptsValidValues(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	handler := CreateFalsePositive(repos.falsePositive, repos.securityEvent)

	for _, status := range []string{"confirmed", "rejected", "pending"} {
		event := createSecurityEventForFalsePositiveTest(t, repos.securityEvent)
		created := invokeFalsePositiveHandler(t, handler, "/api/v1/false-positives", nil, []byte(`{"security_event_id":`+strconv.FormatUint(uint64(event.ID), 10)+`}`))
		if created.Response.StatusCode() != 201 {
			t.Fatalf("seed create status = %d", created.Response.StatusCode())
		}
		var rec store.FalsePositiveReport
		if err := json.Unmarshal(created.Response.Body(), &rec); err != nil {
			t.Fatalf("decode created record: %v", err)
		}
		body, err := json.Marshal(map[string]string{"status": status})
		if err != nil {
			t.Fatalf("marshal status: %v", err)
		}
		id := strconv.FormatUint(uint64(rec.ID), 10)
		ctx := invokeFalsePositiveHandler(t, UpdateFalsePositiveStatus(repos.falsePositive), "/api/v1/false-positives/"+id+"/status", param.Params{{Key: "id", Value: id}}, body)
		if ctx.Response.StatusCode() != 200 {
			t.Errorf("status %q returned %d, want 200: %s", status, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

func TestListFalsePositivesPageSizeClamp(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/false-positives?page_size=999")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ListFalsePositives(repos.falsePositive)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["page_size"].(float64) != 20 {
		t.Fatalf("page_size = %v, want 20", resp["page_size"])
	}
}

func TestUpdateFalsePositiveStatusMissingRecordReturns404(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	body, err := json.Marshal(map[string]string{"status": "confirmed"})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	ctx := invokeFalsePositiveHandler(t, UpdateFalsePositiveStatus(repos.falsePositive), "/api/v1/false-positives/4242/status", param.Params{{Key: "id", Value: "4242"}}, body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("status = %d, want 404: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] == "" {
		t.Fatalf("response missing error field: %s", bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestDeleteFalsePositiveMissingRecordReturns404(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	ctx := invokeFalsePositiveHandler(t, DeleteFalsePositive(repos.falsePositive), "/api/v1/false-positives/4242/delete", param.Params{{Key: "id", Value: "4242"}}, nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("status = %d, want 404: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] == "" {
		t.Fatalf("response missing error field: %s", bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestDeleteFalsePositiveExistingRecord(t *testing.T) {
	repos := newFalsePositiveReposForTest(t)
	event := createSecurityEventForFalsePositiveTest(t, repos.securityEvent)
	created := invokeFalsePositiveHandler(t, CreateFalsePositive(repos.falsePositive, repos.securityEvent), "/api/v1/false-positives", nil, []byte(`{"security_event_id":`+strconv.FormatUint(uint64(event.ID), 10)+`}`))
	if created.Response.StatusCode() != 201 {
		t.Fatalf("seed create status = %d: %s", created.Response.StatusCode(), bytes.TrimSpace(created.Response.Body()))
	}
	var rec store.FalsePositiveReport
	if err := json.Unmarshal(created.Response.Body(), &rec); err != nil {
		t.Fatalf("decode created record: %v", err)
	}

	id := strconv.FormatUint(uint64(rec.ID), 10)
	ctx := invokeFalsePositiveHandler(t, DeleteFalsePositive(repos.falsePositive), "/api/v1/false-positives/"+id+"/delete", param.Params{{Key: "id", Value: id}}, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("status = %d, want 204: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, err := repos.falsePositive.Get(rec.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("get after delete = %v, want gorm.ErrRecordNotFound", err)
	}
	// 删除后同一 id 的状态更新与再次删除都应报告 404。
	body, err := json.Marshal(map[string]string{"status": "confirmed"})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	again := invokeFalsePositiveHandler(t, UpdateFalsePositiveStatus(repos.falsePositive), "/api/v1/false-positives/"+id+"/status", param.Params{{Key: "id", Value: id}}, body)
	if again.Response.StatusCode() != 404 {
		t.Fatalf("update after delete status = %d, want 404: %s", again.Response.StatusCode(), bytes.TrimSpace(again.Response.Body()))
	}
}
