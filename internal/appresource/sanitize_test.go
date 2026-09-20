package appresource

import (
	"net/http"
	"strings"
	"testing"
)

// --- isSensitiveRecordedKey ---

func TestIsSensitiveRecordedKey(t *testing.T) {
	sensitive := []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"cookie", "Cookie",
		"token", "access_token", "auth_token",
		"secret", "api-key", "apikey", "csrf",
		"password", "passwd", "pwd",
		"session", "session_id",
		"credential", "credentials",
		"x-api-key",
	}
	for _, key := range sensitive {
		if !isSensitiveRecordedKey(key) {
			t.Errorf("isSensitiveRecordedKey(%q) = false, want true", key)
		}
	}
	notSensitive := []string{
		"Content-Type", "Accept", "User-Agent",
		"X-Forwarded-For", "Host", "Referer",
		"Cache-Control", "Accept-Language",
	}
	for _, key := range notSensitive {
		if isSensitiveRecordedKey(key) {
			t.Errorf("isSensitiveRecordedKey(%q) = true, want false", key)
		}
	}
}

// --- truncateRecordedValue ---

func TestTruncateRecordedValue(t *testing.T) {
	t.Run("short value unchanged", func(t *testing.T) {
		got := truncateRecordedValue("hello", 100)
		if got != "hello" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("exact limit unchanged", func(t *testing.T) {
		s := strings.Repeat("a", 10)
		got := truncateRecordedValue(s, 10)
		if got != s {
			t.Errorf("got %q", got)
		}
	})
	t.Run("over limit truncated with suffix", func(t *testing.T) {
		s := strings.Repeat("a", 20)
		got := truncateRecordedValue(s, 10)
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Errorf("expected ...[truncated] suffix, got %q", got)
		}
		if !strings.HasPrefix(got, strings.Repeat("a", 10)) {
			t.Errorf("expected first 10 chars preserved, got %q", got)
		}
	})
}

// --- sanitizeRecordedText ---

func TestSanitizeRecordedText(t *testing.T) {
	t.Run("no sensitive content unchanged", func(t *testing.T) {
		got := sanitizeRecordedText("hello world from user")
		if got != "hello world from user" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("password= redacted", func(t *testing.T) {
		got := sanitizeRecordedText("password=abc123")
		if strings.Contains(got, "abc123") {
			t.Errorf("password value should be redacted, got %q", got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("expected [redacted] in output, got %q", got)
		}
	})
	t.Run("token: redacted", func(t *testing.T) {
		got := sanitizeRecordedText(`token: "mySecretToken"`)
		if strings.Contains(got, "mySecretToken") {
			t.Errorf("token value should be redacted, got %q", got)
		}
	})
	t.Run("empty string unchanged", func(t *testing.T) {
		if sanitizeRecordedText("") != "" {
			t.Error("empty string should remain empty")
		}
	})
}

// --- sanitizeRecordedQueryString ---

func TestSanitizeRecordedQueryString(t *testing.T) {
	t.Run("empty returns empty", func(t *testing.T) {
		if sanitizeRecordedQueryString("") != "" {
			t.Error("expected empty")
		}
	})
	t.Run("sensitive key redacted", func(t *testing.T) {
		got := sanitizeRecordedQueryString("token=abc&name=alice")
		if strings.Contains(got, "abc") {
			t.Errorf("token value should be redacted, got %q", got)
		}
		// url.Values.Encode() URL-encodes '[' and ']' in the redacted marker
		if !strings.Contains(got, "redacted") {
			t.Errorf("expected redacted marker, got %q", got)
		}
		if !strings.Contains(got, "name=alice") {
			t.Errorf("non-sensitive key should remain, got %q", got)
		}
	})
	t.Run("password key redacted", func(t *testing.T) {
		got := sanitizeRecordedQueryString("password=hunter2&user=bob")
		if strings.Contains(got, "hunter2") {
			t.Errorf("password should be redacted, got %q", got)
		}
	})
	t.Run("non-sensitive keys preserved", func(t *testing.T) {
		got := sanitizeRecordedQueryString("page=1&sort=desc")
		if !strings.Contains(got, "page=1") && !strings.Contains(got, "page%3D1") {
			t.Errorf("non-sensitive key should be preserved, got %q", got)
		}
	})
}

// --- sanitizeRecordedJSONValue ---

func TestSanitizeRecordedJSONValue(t *testing.T) {
	t.Run("map with sensitive key redacted", func(t *testing.T) {
		input := map[string]any{"password": "secret123", "username": "alice"}
		got := sanitizeRecordedJSONValue(input).(map[string]any)
		if got["password"] != "[redacted]" {
			t.Errorf("password should be redacted, got %v", got["password"])
		}
		if got["username"] != "alice" {
			t.Errorf("username should be preserved, got %v", got["username"])
		}
	})
	t.Run("nested map sensitive key redacted", func(t *testing.T) {
		input := map[string]any{
			"auth": map[string]any{"token": "abc", "user": "bob"},
		}
		got := sanitizeRecordedJSONValue(input).(map[string]any)
		inner := got["auth"].(map[string]any)
		if inner["token"] != "[redacted]" {
			t.Errorf("nested token should be redacted, got %v", inner["token"])
		}
		if inner["user"] != "bob" {
			t.Errorf("nested user should be preserved, got %v", inner["user"])
		}
	})
	t.Run("array values sanitized", func(t *testing.T) {
		input := []any{"safe text", "password=leaked"}
		got := sanitizeRecordedJSONValue(input).([]any)
		if strings.Contains(got[1].(string), "leaked") {
			t.Errorf("sensitive value in array should be sanitized, got %v", got[1])
		}
	})
	t.Run("non-string scalar unchanged", func(t *testing.T) {
		got := sanitizeRecordedJSONValue(42)
		if got != 42 {
			t.Errorf("int should be unchanged, got %v", got)
		}
	})
	t.Run("bool unchanged", func(t *testing.T) {
		got := sanitizeRecordedJSONValue(true)
		if got != true {
			t.Errorf("bool should be unchanged, got %v", got)
		}
	})
}

// --- sanitizeRecordedBodySnippet ---

func TestSanitizeRecordedBodySnippet(t *testing.T) {
	t.Run("empty body returns empty", func(t *testing.T) {
		if sanitizeRecordedBodySnippet("", "application/json") != "" {
			t.Error("empty body should return empty")
		}
	})
	t.Run("JSON sensitive keys are redacted", func(t *testing.T) {
		got := sanitizeRecordedBodySnippet(`{"password":"password-secret","ticket":"ticket-secret","env":{"token":"token-secret"},"user":"alice"}`, "application/json")
		for _, secret := range []string{"password-secret", "ticket-secret", "token-secret"} {
			if strings.Contains(got, secret) {
				t.Errorf("JSON body leaked %q: %q", secret, got)
			}
		}
		if !strings.Contains(got, "alice") {
			t.Errorf("non-sensitive JSON value should remain, got %q", got)
		}
	})
	t.Run("form-urlencoded sensitive key redacted", func(t *testing.T) {
		got := sanitizeRecordedBodySnippet("password=hunter2&user=bob", "application/x-www-form-urlencoded")
		if strings.Contains(got, "hunter2") {
			t.Errorf("form password should be redacted, got %q", got)
		}
	})

	body := "Authorization: Bearer auth-secret\r\n continuation-secret\r\n" +
		"Proxy-Authorization: Basic proxy-secret\r\n" +
		"Cookie: sid=cookie-secret\r\n" +
		"Set-Cookie: refresh=response-secret; HttpOnly\r\n"
	for _, tc := range []struct {
		name        string
		body        string
		contentType string
	}{
		{name: "plain text", body: body, contentType: "text/plain"},
		{name: "malformed JSON", body: "{\"unterminated\":\n" + body, contentType: "application/json"},
		{name: "truncated sample", body: body + strings.Repeat("x", recordedHeaderValueLimit), contentType: "text/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeRecordedBodySnippet(tc.body, tc.contentType)
			for _, secret := range []string{"auth-secret", "continuation-secret", "proxy-secret", "cookie-secret", "response-secret"} {
				if strings.Contains(got, secret) {
					t.Fatalf("recorded body snippet leaked %q: %q", secret, got)
				}
			}
			for _, field := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
				if !strings.Contains(got, field+": [redacted]") {
					t.Fatalf("recorded body snippet did not retain redacted %s field: %q", field, got)
				}
			}
		})
	}
}

func TestSanitizeRecordedBodySnippetRedactsMalformedSecrets(t *testing.T) {
	headerBody := `{"Authorization":"Bearer auth-secret"`
	got := sanitizeRecordedBodySnippet(headerBody, "application/json")
	if strings.Contains(got, "auth-secret") {
		t.Fatalf("malformed JSON leaked quoted authorization value: %s", got)
	}

	envBody := `{"env":{"nested":"env-secret"}`
	got = sanitizeRecordedBodySnippet(envBody, "application/json")
	if strings.Contains(got, "env-secret") {
		t.Fatalf("malformed JSON leaked nested env value: %s", got)
	}

	truncated := `{"env":{"nested":"env-secret"},` + strings.Repeat("x", recordedHeaderValueLimit)
	got = sanitizeRecordedBodySnippet(truncated, "application/json")
	if strings.Contains(got, "env-secret") {
		t.Fatalf("truncated JSON leaked nested env value: %s", got)
	}
}

// --- captureRecordedHTTPHeaders ---

func TestCaptureRecordedHTTPHeaders(t *testing.T) {
	t.Run("nil header returns empty", func(t *testing.T) {
		got := captureRecordedHTTPHeaders(nil, recordedHeaderCaptureText|recordedHeaderCaptureJSON)
		if got.text != "" || got.json != "" {
			t.Errorf("nil header should return empty capture, got %+v", got)
		}
	})
	t.Run("sensitive header redacted in json mode", func(t *testing.T) {
		h := http.Header{
			"Authorization": []string{"Bearer token123"},
			"Content-Type":  []string{"application/json"},
		}
		got := captureRecordedHTTPHeaders(h, recordedHeaderCaptureJSON)
		if strings.Contains(got.json, "token123") {
			t.Errorf("Authorization should be redacted in json, got %q", got.json)
		}
		if !strings.Contains(got.json, "[redacted]") {
			t.Errorf("expected [redacted] in json output, got %q", got.json)
		}
		if !strings.Contains(got.json, "application/json") {
			t.Errorf("Content-Type should be present, got %q", got.json)
		}
	})
	t.Run("text mode produces key-value lines", func(t *testing.T) {
		h := http.Header{
			"X-Test": []string{"value1"},
		}
		got := captureRecordedHTTPHeaders(h, recordedHeaderCaptureText)
		if !strings.Contains(got.text, "X-Test: value1") {
			t.Errorf("text output should contain header line, got %q", got.text)
		}
		if got.json != "" {
			t.Error("json mode not requested, should be empty")
		}
	})
}
