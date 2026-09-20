package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestNewManagerDefaultDirectoryURL(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	if m.directoryURL != DefaultDirectoryURL {
		t.Errorf("directoryURL = %q, want %q", m.directoryURL, DefaultDirectoryURL)
	}
}

func TestNewManagerCustomDirectoryURL(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com", DirectoryURL: StagingDirectoryURL})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	if m.directoryURL != StagingDirectoryURL {
		t.Errorf("directoryURL = %q, want %q", m.directoryURL, StagingDirectoryURL)
	}
}

func TestNewManagerDefaultLogIsSet(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	if m.log == nil {
		t.Error("log should be non-nil when Config.Log is nil")
	}
}

func TestManagerEmail(t *testing.T) {
	m, err := NewManager(Config{Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	if m.Email() != "admin@example.com" {
		t.Errorf("Email() = %q, want admin@example.com", m.Email())
	}
}

func TestHandleHTTP01ChallengeValidToken(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m.challengeMu.Lock()
	m.challenges["mytoken"] = "mytoken.response"
	m.challengeMu.Unlock()

	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/mytoken", nil)
	w := httptest.NewRecorder()
	handled := m.HandleHTTP01Challenge(w, req)
	if !handled {
		t.Fatal("expected HandleHTTP01Challenge to return true for valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "mytoken.response" {
		t.Errorf("body = %q, want mytoken.response", w.Body.String())
	}
}

func TestHandleHTTP01ChallengeUnknownToken(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknowntoken", nil)
	w := httptest.NewRecorder()
	handled := m.HandleHTTP01Challenge(w, req)
	if handled {
		t.Fatal("expected HandleHTTP01Challenge to return false for unknown token")
	}
}

func TestHandleHTTP01ChallengeEmptyTokenPath(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	w := httptest.NewRecorder()
	handled := m.HandleHTTP01Challenge(w, req)
	if handled {
		t.Fatal("expected HandleHTTP01Challenge to return false when token is empty")
	}
}

func TestHandleHTTP01ChallengePlainPath(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	req := httptest.NewRequest("GET", "/other/path", nil)
	w := httptest.NewRecorder()
	handled := m.HandleHTTP01Challenge(w, req)
	if handled {
		t.Fatal("expected HandleHTTP01Challenge to return false for non-challenge path")
	}
}

func TestGetChallengeResponseFound(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m.challengeMu.Lock()
	m.challenges["tok42"] = "tok42.resp"
	m.challengeMu.Unlock()

	resp, ok := m.GetChallengeResponse("tok42")
	if !ok {
		t.Fatal("expected GetChallengeResponse to return ok=true")
	}
	if resp != "tok42.resp" {
		t.Errorf("response = %q, want tok42.resp", resp)
	}
}

func TestGetChallengeResponseNotFound(t *testing.T) {
	m, err := NewManager(Config{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	_, ok := m.GetChallengeResponse("missing")
	if ok {
		t.Fatal("expected GetChallengeResponse to return ok=false for missing token")
	}
}

func TestIsAlreadyRegisteredNilError(t *testing.T) {
	if isAlreadyRegistered(nil) {
		t.Error("isAlreadyRegistered(nil) should return false")
	}
}

func TestIsAlreadyRegistered409(t *testing.T) {
	aerr := &acme.Error{StatusCode: 409}
	if !isAlreadyRegistered(aerr) {
		t.Error("isAlreadyRegistered(*acme.Error{409}) should return true")
	}
}

func TestIsAlreadyRegistered400(t *testing.T) {
	aerr := &acme.Error{StatusCode: 400}
	if isAlreadyRegistered(aerr) {
		t.Error("isAlreadyRegistered(*acme.Error{400}) should return false")
	}
}
