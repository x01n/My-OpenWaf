package security

import (
	"testing"
)

// --- ForwardedForHeaderValue ---

func TestForwardedForHeaderValue(t *testing.T) {
	cases := []struct {
		input []string
		want  string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"1.2.3.4"}, "1.2.3.4"},
		{[]string{"  1.2.3.4  "}, "1.2.3.4"},
		{[]string{"1.2.3.4", "5.6.7.8"}, "1.2.3.4, 5.6.7.8"},
		{[]string{"1.2.3.4, 5.6.7.8", "9.10.11.12"}, "1.2.3.4, 5.6.7.8, 9.10.11.12"},
		{[]string{"1.2.3.4", "", "5.6.7.8"}, "1.2.3.4, 5.6.7.8"},
		{[]string{"  ", "1.2.3.4"}, "1.2.3.4"},
		{[]string{"  ", "  "}, ""},
	}
	for _, c := range cases {
		got := ForwardedForHeaderValue(c.input)
		if got != c.want {
			t.Errorf("ForwardedForHeaderValue(%v) = %q, want %q", c.input, got, c.want)
		}
	}
}

// --- ForwardedForHeaderValueBytes ---

func TestForwardedForHeaderValueBytes(t *testing.T) {
	cases := []struct {
		input [][]byte
		want  string
	}{
		{nil, ""},
		{[][]byte{}, ""},
		{[][]byte{[]byte("1.2.3.4")}, "1.2.3.4"},
		{[][]byte{[]byte("  1.2.3.4  ")}, "1.2.3.4"},
		{[][]byte{[]byte("1.2.3.4"), []byte("5.6.7.8")}, "1.2.3.4, 5.6.7.8"},
		{[][]byte{[]byte("1.2.3.4"), []byte(""), []byte("5.6.7.8")}, "1.2.3.4, 5.6.7.8"},
		{[][]byte{[]byte("  "), []byte("1.2.3.4")}, "1.2.3.4"},
	}
	for _, c := range cases {
		got := ForwardedForHeaderValueBytes(c.input)
		if got != c.want {
			t.Errorf("ForwardedForHeaderValueBytes(%v) = %q, want %q", c.input, got, c.want)
		}
	}
}

// --- NormalizeHostHeaderValue ---

func TestNormalizeHostHeaderValue(t *testing.T) {
	t.Run("empty string returns empty", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("")
		if err != nil || got != "" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
	t.Run("whitespace-only returns empty", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("   ")
		if err != nil || got != "" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
	t.Run("plain host passes through", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("example.com")
		if err != nil || got != "example.com" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
	t.Run("host with port passes through", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("example.com:8080")
		if err != nil || got != "example.com:8080" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
	t.Run("leading/trailing whitespace stripped", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("  example.com  ")
		if err != nil || got != "example.com" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
	t.Run("invalid host returns error", func(t *testing.T) {
		_, err := NormalizeHostHeaderValue("not a valid\x00host")
		if err == nil {
			t.Error("expected error for invalid host")
		}
	})
	t.Run("localhost valid", func(t *testing.T) {
		got, err := NormalizeHostHeaderValue("localhost")
		if err != nil || got != "localhost" {
			t.Errorf("got %q, err %v", got, err)
		}
	})
}
