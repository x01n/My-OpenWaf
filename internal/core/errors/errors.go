package errors

import "fmt"

// ConfigError indicates a configuration validation failure.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config: %s: %s", e.Field, e.Message)
}

// RuleCompileError indicates a rule pattern that cannot be compiled.
type RuleCompileError struct {
	RuleID  uint
	Pattern string
	Reason  string
}

func (e *RuleCompileError) Error() string {
	return fmt.Sprintf("rule %d: compile %q: %s", e.RuleID, e.Pattern, e.Reason)
}

// PipelineError wraps an error from a specific pipeline phase.
type PipelineError struct {
	Phase string
	Err   error
}

func (e *PipelineError) Error() string {
	return fmt.Sprintf("pipeline[%s]: %v", e.Phase, e.Err)
}

func (e *PipelineError) Unwrap() error { return e.Err }

// Sentinel errors.
var (
	ErrNoSiteMatch  = fmt.Errorf("no site matched for host")
	ErrSnapshotNil  = fmt.Errorf("configuration snapshot not loaded")
	ErrUpstreamNone = fmt.Errorf("no upstream configured for site")
	ErrCertInvalid  = fmt.Errorf("invalid certificate/key pair")
	ErrTokenInvalid = fmt.Errorf("invalid or expired API token")
)
