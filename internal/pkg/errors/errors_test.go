package errors

import (
	stderrors "errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	for _, sentinel := range []error{ErrNotFound, ErrConflict, ErrValidation, ErrUnauthorized, ErrForbidden} {
		if sentinel == nil {
			t.Fatalf("sentinel error should not be nil")
		}
		if sentinel.Error() == "" {
			t.Errorf("sentinel error message should not be empty")
		}
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	errs := []error{ErrNotFound, ErrConflict, ErrValidation, ErrUnauthorized, ErrForbidden}
	for i, a := range errs {
		for j, b := range errs {
			if i != j && stderrors.Is(a, b) {
				t.Errorf("sentinel errors should be distinct: %v and %v", a, b)
			}
		}
	}
}

func TestValidationErrorMessage(t *testing.T) {
	e := &ValidationError{Field: "username", Message: "must not be empty"}
	got := e.Error()
	if got != "username: must not be empty" {
		t.Errorf("ValidationError.Error() = %q, want %q", got, "username: must not be empty")
	}
}

func TestValidationErrorEmptyFields(t *testing.T) {
	e := &ValidationError{}
	if e.Error() != ": " {
		t.Errorf("ValidationError{}.Error() = %q, want \": \"", e.Error())
	}
}

func TestIsWrapsStdlibIs(t *testing.T) {
	wrapped := New("wrapped")
	// Is(wrapped, wrapped) 应为 true
	if !Is(wrapped, wrapped) {
		t.Error("Is(err, err) should be true for same error")
	}
	// 不同错误应为 false
	other := New("other")
	if Is(wrapped, other) {
		t.Error("Is(wrapped, other) should be false for different errors")
	}
}

func TestIsWithSentinels(t *testing.T) {
	if !Is(ErrNotFound, ErrNotFound) {
		t.Error("Is(ErrNotFound, ErrNotFound) should be true")
	}
	if Is(ErrNotFound, ErrConflict) {
		t.Error("Is(ErrNotFound, ErrConflict) should be false")
	}
}

func TestAsWithValidationError(t *testing.T) {
	var ve *ValidationError
	err := error(&ValidationError{Field: "f", Message: "m"})
	if !As(err, &ve) {
		t.Error("As should succeed for *ValidationError")
	}
	if ve.Field != "f" {
		t.Errorf("As: ve.Field = %q, want \"f\"", ve.Field)
	}
}

func TestAsFailsForMismatchedType(t *testing.T) {
	err := New("plain error")
	var ve *ValidationError
	if As(err, &ve) {
		t.Error("As should fail for non-ValidationError")
	}
}

func TestNewReturnsNonNilError(t *testing.T) {
	e := New("something went wrong")
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.Error() != "something went wrong" {
		t.Errorf("New().Error() = %q", e.Error())
	}
}
