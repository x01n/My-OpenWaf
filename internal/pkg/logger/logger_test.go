package logger

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfigureSetsLevel(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"warn", "WARN"},
		{"WARNING", "WARN"},
		{"error", "ERROR"},
		{"ERROR", "ERROR"},
		{"info", "INFO"},
		{"INFO", "INFO"},
		{"", "INFO"},        // 空串回落 info
		{"invalid", "INFO"}, // 未知值回落 info
	}

	for _, c := range cases {
		Configure(Config{Level: c.input})
		got := GetLevel()
		if got != c.want {
			t.Errorf("Configure(%q) → GetLevel() = %q, want %q", c.input, got, c.want)
		}
	}

	// 还原到 INFO，避免影响其他测试
	Configure(Config{Level: "INFO"})
}

func TestGetLevelReturnsCurrentLevel(t *testing.T) {
	Configure(Config{Level: "DEBUG"})
	if got := GetLevel(); got != "DEBUG" {
		t.Errorf("GetLevel() = %q after Configure(debug), want DEBUG", got)
	}
	Configure(Config{Level: "INFO"})
}

func TestNewReturnsNonNil(t *testing.T) {
	Configure(Config{Level: "INFO"})
	l := New("test-section")
	if l == nil {
		t.Fatal("New() returned nil logger")
	}
}

func TestFormatLevelNoColor(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DBG"},
		{slog.LevelInfo, "INF"},
		{slog.LevelWarn, "WRN"},
		{slog.LevelError, "ERR"},
	}
	for _, c := range cases {
		got := formatLevel(c.level, false)
		if len(got) < len(c.want) {
			t.Errorf("formatLevel(%v, false) = %q, want to contain %q", c.level, got, c.want)
		}
		found := false
		for i := 0; i <= len(got)-len(c.want); i++ {
			if got[i:i+len(c.want)] == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("formatLevel(%v, false) = %q, want to contain %q", c.level, got, c.want)
		}
	}
}

func TestFormatValueString(t *testing.T) {
	v := slog.AnyValue("hello")
	got := formatValue(v, false)
	if got != "hello" {
		t.Errorf("formatValue(string:hello, false) = %q, want \"hello\"", got)
	}
}

func TestFormatValueStringWithSpaceGetsQuoted(t *testing.T) {
	v := slog.AnyValue("hello world")
	got := formatValue(v, false)
	if got != `"hello world"` {
		t.Errorf("formatValue(string with space, false) = %q, want quoted", got)
	}
}

func TestFormatValueTime(t *testing.T) {
	ts := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	v := slog.TimeValue(ts)
	got := formatValue(v, false)
	if got != "2026-07-24T12:00:00Z" {
		t.Errorf("formatValue(time, false) = %q, want RFC3339", got)
	}
}

func TestFormatValueDuration(t *testing.T) {
	v := slog.DurationValue(5 * time.Second)
	got := formatValue(v, false)
	if got != "5s" {
		t.Errorf("formatValue(duration:5s, false) = %q, want \"5s\"", got)
	}
}

func TestSetOutputRedirectsLogs(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	t.Cleanup(func() { SetOutput(os.Stdout) })

	l := New("test-set-output")
	l.Info("hello from set output")

	out := buf.String()
	if !strings.Contains(out, "hello from set output") {
		t.Errorf("expected log output to contain message, got: %q", out)
	}
}

func TestSetLevelAffectsGlobalLevel(t *testing.T) {
	orig := GetLevel()
	t.Cleanup(func() { Configure(Config{Level: orig}) })

	SetLevel("debug")
	if got := GetLevel(); got != "DEBUG" {
		t.Errorf("SetLevel(debug) → GetLevel() = %q, want DEBUG", got)
	}
	SetLevel("warn")
	if got := GetLevel(); got != "WARN" {
		t.Errorf("SetLevel(warn) → GetLevel() = %q, want WARN", got)
	}
}

func TestCloseWhenNoLogFile(t *testing.T) {
	logFile = nil
	if err := Close(); err != nil {
		t.Errorf("Close() with nil logFile should return nil, got %v", err)
	}
}

func TestPrettyHandlerEnabled(t *testing.T) {
	h := newPrettyHandler(os.Stdout, slog.LevelWarn, false)

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled(Debug) should be false when handler level is Warn")
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled(Info) should be false when handler level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Enabled(Warn) should be true when handler level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Enabled(Error) should be true when handler level is Warn")
	}
}

func TestPrettyHandlerHandleWritesOutput(t *testing.T) {
	var buf bytes.Buffer
	h := newPrettyHandler(&buf, slog.LevelDebug, false)

	r := slog.NewRecord(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"))

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "test message") {
		t.Errorf("Handle() output does not contain message, got: %q", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Errorf("Handle() output does not contain attr, got: %q", out)
	}
}

func TestPrettyHandlerHandleWithColor(t *testing.T) {
	var buf bytes.Buffer
	h := newPrettyHandler(&buf, slog.LevelDebug, true)

	r := slog.NewRecord(time.Now(), slog.LevelError, "colored error", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle() with color error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "colored error") {
		t.Errorf("Handle() with color does not contain message, got: %q", out)
	}
	if !strings.Contains(out, "\033[") {
		t.Error("Handle() with color=true should contain ANSI escape codes")
	}
}

func TestPrettyHandlerWithSection(t *testing.T) {
	var buf bytes.Buffer
	h := newPrettyHandler(&buf, slog.LevelDebug, false)
	h2 := h.WithAttrs([]slog.Attr{slog.String("section", "my-section")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "sectioned", 0)
	if err := h2.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[my-section]") {
		t.Errorf("expected [my-section] in output, got: %q", out)
	}
	if strings.Contains(out, "section=") {
		t.Errorf("section should not appear as key=value, got: %q", out)
	}
}

func TestPrettyHandlerWithAttrsPreservesExisting(t *testing.T) {
	h := newPrettyHandler(os.Stdout, slog.LevelDebug, false)
	h2 := h.WithAttrs([]slog.Attr{slog.String("a", "1")})
	h3 := h2.WithAttrs([]slog.Attr{slog.String("b", "2")})

	ph, ok := h3.(*prettyHandler)
	if !ok {
		t.Fatal("WithAttrs should return *prettyHandler")
	}
	if len(ph.attrs) != 2 {
		t.Errorf("expected 2 attrs, got %d", len(ph.attrs))
	}
}

func TestPrettyHandlerWithGroup(t *testing.T) {
	h := newPrettyHandler(os.Stdout, slog.LevelDebug, false)
	h2 := h.WithGroup("grp")

	ph, ok := h2.(*prettyHandler)
	if !ok {
		t.Fatal("WithGroup should return *prettyHandler")
	}
	if ph.group != "grp" {
		t.Errorf("WithGroup: group = %q, want %q", ph.group, "grp")
	}
}

func TestFormatLevelWithColor(t *testing.T) {
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	for _, l := range levels {
		got := formatLevel(l, true)
		if !strings.Contains(got, "\033[") {
			t.Errorf("formatLevel(%v, true) should contain ANSI codes, got: %q", l, got)
		}
	}
}

func TestFormatValueWithColor(t *testing.T) {
	cases := []struct {
		val  slog.Value
		desc string
	}{
		{slog.AnyValue("hello"), "plain string"},
		{slog.AnyValue("hello world"), "string with space"},
	}
	for _, c := range cases {
		got := formatValue(c.val, true)
		if !strings.Contains(got, "\033[") {
			t.Errorf("formatValue(%s, true) should contain ANSI codes, got: %q", c.desc, got)
		}
	}
}

func TestBannerDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Banner panicked: %v", r)
		}
	}()
	Banner("Line 1", "A much longer line 2", "L3")
}

func TestBuildConfiguredOutputWithFile(t *testing.T) {
	f, err := os.CreateTemp("", "logger-test-*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := f.Name()
	f.Close()
	t.Cleanup(func() {
		Close()
		os.Remove(path)
	})

	w := buildConfiguredOutput(path, false)
	if w == nil {
		t.Fatal("buildConfiguredOutput returned nil")
	}
	if _, err := w.Write([]byte("test log line\n")); err != nil {
		t.Fatalf("write to file writer: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(content), "test log line") {
		t.Errorf("log file content = %q, want to contain 'test log line'", string(content))
	}
}

func TestBuildConfiguredOutputAlsoStdout(t *testing.T) {
	f, err := os.CreateTemp("", "logger-also-stdout-*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := f.Name()
	f.Close()
	t.Cleanup(func() {
		Close()
		os.Remove(path)
	})

	w := buildConfiguredOutput(path, true)
	if w == nil {
		t.Fatal("buildConfiguredOutput(alsoStdout=true) returned nil")
	}
	if _, err := w.Write([]byte("multi-writer test\n")); err != nil {
		t.Fatalf("write to multi-writer: %v", err)
	}
}
