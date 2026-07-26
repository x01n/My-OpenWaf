package event

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/route/param"
)

func TestListAccessLogsReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewAccessLogRepo(db)
	ctx := invokeHandler(ListAccessLogs(repo), "GET", "/api/v1/access-logs", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["items"] == nil {
		t.Error("expected items field in response")
	}
}

func TestGetAccessLogInvalidIDReturns400(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewAccessLogRepo(db)
	ctx := invokeHandler(GetAccessLog(repo), "GET", "/api/v1/access-logs/bad",
		nil, param.Params{{Key: "id", Value: "bad"}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid id, got %d", ctx.Response.StatusCode())
	}
}

func TestGetAccessLogNotFoundReturns404(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewAccessLogRepo(db)
	ctx := invokeHandler(GetAccessLog(repo), "GET", "/api/v1/access-logs/9999",
		nil, param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing log, got %d", ctx.Response.StatusCode())
	}
}

func TestListTLSFingerprintsReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewAccessLogRepo(db)
	ctx := invokeHandler(ListTLSFingerprints(repo), "GET", "/api/v1/tls-fingerprints", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
}
