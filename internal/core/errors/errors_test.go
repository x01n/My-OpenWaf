package errors

import (
	stderrors "errors"
	"testing"
)

func TestConfigErrorMessage(t *testing.T) {
	e := &ConfigError{Field: "listen_addr", Message: "must not be empty"}
	got := e.Error()
	want := "config: listen_addr: must not be empty"
	if got != want {
		t.Errorf("ConfigError.Error() = %q, want %q", got, want)
	}
}

func TestConfigErrorEmptyFields(t *testing.T) {
	e := &ConfigError{}
	got := e.Error()
	if got != "config: : " {
		t.Errorf("ConfigError{}.Error() = %q, want \"config: : \"", got)
	}
}

func TestRuleCompileErrorMessage(t *testing.T) {
	e := &RuleCompileError{RuleID: 42, Pattern: "(?i)select.*from", Reason: "invalid group"}
	got := e.Error()
	want := `rule 42: compile "(?i)select.*from": invalid group`
	if got != want {
		t.Errorf("RuleCompileError.Error() = %q, want %q", got, want)
	}
}

func TestRuleCompileErrorZeroID(t *testing.T) {
	e := &RuleCompileError{RuleID: 0, Pattern: "pat", Reason: "reason"}
	got := e.Error()
	want := `rule 0: compile "pat": reason`
	if got != want {
		t.Errorf("RuleCompileError.Error() = %q, want %q", got, want)
	}
}

func TestPipelineErrorMessage(t *testing.T) {
	inner := stderrors.New("unexpected EOF")
	e := &PipelineError{Phase: "owasp", Err: inner}
	got := e.Error()
	want := "pipeline[owasp]: unexpected EOF"
	if got != want {
		t.Errorf("PipelineError.Error() = %q, want %q", got, want)
	}
}

func TestPipelineErrorUnwrap(t *testing.T) {
	inner := stderrors.New("inner error")
	e := &PipelineError{Phase: "bot", Err: inner}
	if !stderrors.Is(e, inner) {
		t.Error("errors.Is should traverse PipelineError.Unwrap()")
	}
}

func TestPipelineErrorNilInner(t *testing.T) {
	e := &PipelineError{Phase: "acl", Err: nil}
	got := e.Error()
	want := "pipeline[acl]: <nil>"
	if got != want {
		t.Errorf("PipelineError{nil}.Error() = %q, want %q", got, want)
	}
}

func TestSentinelErrorsNonNil(t *testing.T) {
	for name, sentinel := range map[string]error{
		"ErrNoSiteMatch":  ErrNoSiteMatch,
		"ErrSnapshotNil":  ErrSnapshotNil,
		"ErrUpstreamNone": ErrUpstreamNone,
		"ErrCertInvalid":  ErrCertInvalid,
		"ErrTokenInvalid": ErrTokenInvalid,
	} {
		if sentinel == nil {
			t.Errorf("%s should not be nil", name)
		}
		if sentinel.Error() == "" {
			t.Errorf("%s.Error() should not be empty", name)
		}
	}
}

func TestSentinelErrorsDistinct(t *testing.T) {
	sentinels := []error{ErrNoSiteMatch, ErrSnapshotNil, ErrUpstreamNone, ErrCertInvalid, ErrTokenInvalid}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && stderrors.Is(a, b) {
				t.Errorf("sentinel errors should be distinct: [%d]=%v and [%d]=%v", i, a, j, b)
			}
		}
	}
}
