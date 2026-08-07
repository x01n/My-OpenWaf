//go:build !cgo

package jsplugin

import (
	"context"
	"errors"
	"testing"
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
	if err := validateMutationPlan(MutationPlan{}); err != nil {
		t.Fatal(err)
	}
}
