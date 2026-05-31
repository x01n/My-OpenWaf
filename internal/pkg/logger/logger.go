package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// ── color codes ──

const (
	reset   = "\033[0m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[90m"
	white   = "\033[97m"
	bold    = "\033[1m"
)

// ── global singleton ──

var (
	initOnce      sync.Once
	globalHandler slog.Handler
	globalLevel   *levelVar
	logFile       *os.File
)

type levelVar struct {
	mu    sync.RWMutex
	level slog.Level
}

func (l *levelVar) Level() slog.Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

func (l *levelVar) Set(level slog.Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

func init() {
	initOnce.Do(func() {
		globalLevel = &levelVar{level: parseLevel()}
		w := buildOutput()
		globalHandler = newPrettyHandler(w, globalLevel.Level(), useColor())
	})
}

// New returns a logger tagged with the given section name.
// All loggers share the same global handler (single output stream, no duplication).
func New(section string) *slog.Logger {
	return slog.New(globalHandler).With(slog.String("section", section))
}

// SetOutput replaces the global output writer (useful for testing).
func SetOutput(w io.Writer) {
	globalHandler = newPrettyHandler(w, globalLevel.Level(), false)
}

// SetLevel 动态设置全局日志级别。
func SetLevel(level string) {
	Configure(Config{
		Level:      level,
		FilePath:   os.Getenv("MY_OPENWAF_LOG_FILE"),
		AlsoStdout: os.Getenv("MY_OPENWAF_LOG_ALSO_STDOUT") == "1",
	})
}

type Config struct {
	Level      string
	FilePath   string
	AlsoStdout bool
}

func Configure(cfg Config) {
	var l slog.Level
	switch strings.ToUpper(strings.TrimSpace(cfg.Level)) {
	case "DEBUG":
		l = slog.LevelDebug
	case "WARN", "WARNING":
		l = slog.LevelWarn
	case "ERROR":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	globalLevel.Set(l)
	w := buildConfiguredOutput(cfg.FilePath, cfg.AlsoStdout)
	globalHandler = newPrettyHandler(w, l, useColor())
}

func GetLevel() string {
	switch globalLevel.Level() {
	case slog.LevelDebug:
		return "DEBUG"
	case slog.LevelWarn:
		return "WARN"
	case slog.LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func Close() error {
	if logFile == nil {
		return nil
	}
	err := logFile.Close()
	logFile = nil
	return err
}

func buildOutput() io.Writer {
	filePath := os.Getenv("MY_OPENWAF_LOG_FILE")
	alsoStdout := os.Getenv("MY_OPENWAF_LOG_ALSO_STDOUT") == "1"
	return buildConfiguredOutput(filePath, alsoStdout)
}

func buildConfiguredOutput(filePath string, alsoStdout bool) io.Writer {
	if filePath == "" {
		return os.Stdout
	}

	// 创建日志目录
	dir := filePath[:max(strings.LastIndex(filePath, "/"), strings.LastIndex(filePath, "\\"))]
	if dir != "" {
		os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: failed to open log file %s: %v\n", filePath, err)
		return os.Stdout
	}

	if err := Close(); err != nil {
		fmt.Fprintf(os.Stderr, "logger: failed to close previous log file: %v\n", err)
	}
	logFile = f

	// 如果设置了同时输出到控制台
	if alsoStdout {
		return io.MultiWriter(os.Stdout, f)
	}
	return f
}

func parseLevel() slog.Level {
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("MY_OPENWAF_LOG_LEVEL"))) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func useColor() bool {
	if v := os.Getenv("MY_OPENWAF_LOG_COLOR"); v != "" {
		return v == "1" || strings.EqualFold(v, "true")
	}
	// Auto-detect: color if stdout is a terminal (char device).
	fi, err := os.Stdout.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return true
	}
	return false
}

// ── pretty handler ──

type prettyHandler struct {
	level slog.Level
	w     io.Writer
	mu    sync.Mutex
	color bool
	attrs []slog.Attr
	group string
}

func newPrettyHandler(w io.Writer, level slog.Level, color bool) *prettyHandler {
	return &prettyHandler{w: w, level: level, color: color}
}

func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	// Timestamp: 2006-01-02 15:04:05.000
	ts := r.Time.Format("2006-01-02 15:04:05.000")
	if h.color {
		b.WriteString(gray)
		b.WriteString(ts)
		b.WriteString(reset)
	} else {
		b.WriteString(ts)
	}
	b.WriteByte(' ')

	// Level badge
	lvl := formatLevel(r.Level, h.color)
	b.WriteString(lvl)
	b.WriteByte(' ')

	// Section (from pre-attached attrs)
	section := ""
	for _, a := range h.attrs {
		if a.Key == "section" {
			section = a.Value.String()
			break
		}
	}
	if section != "" {
		if h.color {
			b.WriteString(cyan)
			b.WriteByte('[')
			b.WriteString(section)
			b.WriteByte(']')
			b.WriteString(reset)
		} else {
			b.WriteByte('[')
			b.WriteString(section)
			b.WriteByte(']')
		}
		b.WriteByte(' ')
	}

	// Message
	if h.color {
		b.WriteString(white)
		b.WriteString(r.Message)
		b.WriteString(reset)
	} else {
		b.WriteString(r.Message)
	}

	// Inline attrs (from pre-attached + record)
	writeAttrs := func(a slog.Attr) {
		if a.Key == "section" {
			return // already rendered as [section]
		}
		b.WriteByte(' ')
		if h.color {
			b.WriteString(blue)
			b.WriteString(a.Key)
			b.WriteString(reset)
			b.WriteByte('=')
			b.WriteString(formatValue(a.Value, h.color))
		} else {
			b.WriteString(a.Key)
			b.WriteByte('=')
			b.WriteString(formatValue(a.Value, false))
		}
	}
	for _, a := range h.attrs {
		writeAttrs(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttrs(a)
		return true
	})

	b.WriteByte('\n')

	h.mu.Lock()
	_, err := io.WriteString(h.w, b.String())
	h.mu.Unlock()
	return err
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	newAttrs = append(newAttrs, attrs...)
	return &prettyHandler{
		level: h.level,
		w:     h.w,
		color: h.color,
		attrs: newAttrs,
		group: h.group,
	}
}

func (h *prettyHandler) WithGroup(name string) slog.Handler {
	return &prettyHandler{
		level: h.level,
		w:     h.w,
		color: h.color,
		attrs: h.attrs,
		group: name,
	}
}

func formatLevel(l slog.Level, color bool) string {
	var tag string
	var c string
	switch {
	case l >= slog.LevelError:
		tag = "ERR"
		c = red
	case l >= slog.LevelWarn:
		tag = "WRN"
		c = yellow
	case l >= slog.LevelInfo:
		tag = "INF"
		c = green
	default:
		tag = "DBG"
		c = magenta
	}
	if color {
		return fmt.Sprintf("%s%s%-3s%s", bold, c, tag, reset)
	}
	return fmt.Sprintf("%-3s", tag)
}

func formatValue(v slog.Value, color bool) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " \t\n\"") {
			if color {
				return fmt.Sprintf("%s\"%s\"%s", yellow, s, reset)
			}
			return fmt.Sprintf("\"%s\"", s)
		}
		if color {
			return yellow + s + reset
		}
		return s
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindDuration:
		return v.Duration().String()
	default:
		return v.String()
	}
}

// Banner prints a prominent multi-line banner for critical first-run information.
// Not affected by log level — always printed.
func Banner(lines ...string) {
	var b strings.Builder
	maxLen := 0
	for _, l := range lines {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	border := strings.Repeat("═", maxLen+4)

	c := useColor()
	if c {
		b.WriteString(bold)
		b.WriteString(yellow)
	}
	b.WriteString("\n╔")
	b.WriteString(border)
	b.WriteString("╗\n")
	for _, l := range lines {
		b.WriteString("║  ")
		b.WriteString(l)
		b.WriteString(strings.Repeat(" ", maxLen-len(l)))
		b.WriteString("  ║\n")
	}
	b.WriteString("╚")
	b.WriteString(border)
	b.WriteString("╝\n")
	if c {
		b.WriteString(reset)
	}

	fmt.Fprint(os.Stdout, b.String())
}
