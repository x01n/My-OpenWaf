//go:build !cgo || !quickjs

package jsplugin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestStubReportsUnavailable(t *testing.T) {
	if _, err := Compile("test", "function handle() {}", ScriptOptions{}); !errors.Is(err, ErrCGODisabled) {
		t.Fatalf("Compile error = %v, want ErrCGODisabled", err)
	}
	if _, err := NewEngine(EngineOptions{}); !errors.Is(err, ErrCGODisabled) {
		t.Fatalf("NewEngine error = %v, want ErrCGODisabled", err)
	}
	var engine Engine
	if _, err := engine.Evaluate(context.Background(), nil, RequestSnapshot{}); !errors.Is(err, ErrCGODisabled) {
		t.Fatalf("Evaluate error = %v, want ErrCGODisabled", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
}

func TestPublicTypesAndSiteMatching(t *testing.T) {
	script := &Script{}
	if !script.AppliesTo(1) {
		t.Fatal("zero-value script should be global for interface-level checks")
	}
	invalid := MutationPlan{SetHeaders: map[string]string{"X-Test": "bad\r\nvalue"}}
	if err := validateMutationPlan(invalid); err == nil {
		t.Fatal("CR/LF mutation header should be rejected")
	}
	if err := validateMutationPlan(MutationPlan{}); err != nil {
		t.Fatal(err)
	}
}

func TestStubRejectsCrossStageBeforeRuntimeError(t *testing.T) {
	engine := &Engine{}
	responseScript := &Script{stage: store.JSStageResponse}
	if _, err := engine.Evaluate(context.Background(), responseScript, RequestSnapshot{}); err == nil || !strings.Contains(err.Error(), "cannot use") {
		t.Fatalf("Evaluate error = %v, want cross-stage error", err)
	}
	requestScript := &Script{stage: store.JSStageRequest}
	if _, err := engine.EvaluateResponse(context.Background(), requestScript, ResponseSnapshot{}); err == nil || !strings.Contains(err.Error(), "cannot use") {
		t.Fatalf("EvaluateResponse error = %v, want cross-stage error", err)
	}
}

func TestStubReportsUnavailableForResponseExecution(t *testing.T) {
	engine := &Engine{}
	script := &Script{stage: store.JSStageResponse}
	if _, err := engine.ExecuteResponse(context.Background(), script, ResponseSnapshot{SiteID: 1}); !errors.Is(err, ErrCGODisabled) {
		t.Fatalf("ExecuteResponse error = %v, want ErrCGODisabled", err)
	}
	if _, err := engine.ValidateResponse(context.Background(), script, ResponseSnapshot{SiteID: 1}); !errors.Is(err, ErrCGODisabled) {
		t.Fatalf("ValidateResponse error = %v, want ErrCGODisabled", err)
	}
}
