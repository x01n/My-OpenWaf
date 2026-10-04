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

/**
 * New 返回一个带指定分段名标签的 logger。
 *
 * 所有 logger 共享同一个全局 handler，因此输出只有一个流、不会重复。
 *
 * @param section 分段名，作为 section 属性附着到 logger 上。
 * @return 附带 section 属性的 logger 实例。
 */
func New(section string) *slog.Logger {
	return slog.New(globalHandler).With(slog.String("section", section))
}

/**
 * SetOutput 替换全局输出写入器，便于测试接管输出。
 *
 * 替换后关闭颜色，避免测试断言里混入 ANSI 转义序列。
 *
 * @param w 新的输出目标，取代默认的 stdout 或日志文件。
 */
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
	separator := max(strings.LastIndex(filePath, "/"), strings.LastIndex(filePath, "\\"))
	if separator >= 0 {
		dir := filePath[:separator]
		if dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
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
	// 自动判定：stdout 是终端（字符设备）时才上色
	fi, err := os.Stdout.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return true
	}
	return false
}

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

	// 时间戳，格式 "2006-01-02 15:04:05.000"
	ts := r.Time.Format("2006-01-02 15:04:05.000")
	if h.color {
		b.WriteString(gray)
		b.WriteString(ts)
		b.WriteString(reset)
	} else {
		b.WriteString(ts)
	}
	b.WriteByte(' ')

	// 级别徽标
	lvl := formatLevel(r.Level, h.color)
	b.WriteString(lvl)
	b.WriteByte(' ')

	// 分段名（取自预先附着的 attrs）
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

	// 消息正文
	if h.color {
		b.WriteString(white)
		b.WriteString(r.Message)
		b.WriteString(reset)
	} else {
		b.WriteString(r.Message)
	}

	// 行内 attrs（预先附着的 + record 自带的）
	writeAttrs := func(a slog.Attr) {
		if a.Key == "section" {
			return // 已渲染为 [section] 前缀
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

/**
 * Banner 打印多行醒目横幅，用于首次启动的关键提示信息。
 *
 * 横幅不走日志级别过滤，始终直接写入 stdout，因此不受当前日志级别影响。
 *
 * @param lines 横幅正文，每个元素占一行。
 */
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
