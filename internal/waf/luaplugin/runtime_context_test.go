package luaplugin

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// recordedLog 是一次落在宿主 logger 上的日志。
type recordedLog struct {
	level   slog.Level
	message string
	attrs   map[string]string
}

// recordingHandler 记录日志记录与 WithAttrs 携带的属性。
//
// 用自定义 handler 而不是解析文本输出：断言的是「日志落到了哪个 logger、
// 带什么属性、用什么级别」，文本格式属于 logger 包的职责，不该被本包测试锁定。
type recordingHandler struct {
	mu      *sync.Mutex
	records *[]recordedLog
	attrs   []slog.Attr
}

func newRecordingLogger() (*slog.Logger, *[]recordedLog) {
	mu := &sync.Mutex{}
	records := &[]recordedLog{}
	return slog.New(&recordingHandler{mu: mu, records: records}), records
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]string, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, recordedLog{level: r.Level, message: r.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &recordingHandler{mu: h.mu, records: h.records, attrs: merged}
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// TestEngineWiresScriptLogHooks 验证线上路径（经引擎执行）的 ctx.log / ctx.debug
// 真正落到宿主 logger 上，且带上脚本名与阶段。
//
// 这是本文件存在的理由：SetRuntimeHooks 此前只有测试调用，生产零调用，
// 脚本里的 ctx.log 是静默空操作——脚本作者会以为是自己写错了。
func TestEngineWiresScriptLogHooks(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	script := mustCompile(t, StagePre, `
function handle(ctx)
  ctx.log("warn", "policy hit")
  ctx.debug("branch taken")
  return "observe"
end`)
	script.SetID(7)
	e.Reload([]*Script{script})

	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.Action != "observe" {
		t.Fatalf("判定被日志调用改变：%+v", dec)
	}

	got := *records
	if len(got) != 2 {
		t.Fatalf("宿主 logger 收到 %d 条日志，want 2：%+v", len(got), got)
	}
	if got[0].level != slog.LevelWarn || got[0].message != "policy hit" {
		t.Errorf("ctx.log(warn) 未按 warn 落盘：%+v", got[0])
	}
	if got[1].level != slog.LevelDebug || got[1].message != "branch taken" {
		t.Errorf("ctx.debug 未按 debug 落盘：%+v", got[1])
	}
	for i, rec := range got {
		if rec.attrs["script"] != "test" || rec.attrs["stage"] != string(StagePre) {
			t.Errorf("第 %d 条日志缺少脚本溯源属性：%+v", i, rec.attrs)
		}
	}
}

// TestEngineLogLevelMapping 验证脚本传入的 level 用词与 logger 配置级别一致。
//
// 无法识别的 level 落到 info 而不是被丢弃：脚本的笔误不该让整条日志消失。
func TestEngineLogLevelMapping(t *testing.T) {
	cases := []struct {
		scriptLevel string
		want        slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"verbose", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tc := range cases {
		t.Run(tc.scriptLevel, func(t *testing.T) {
			logger, records := newRecordingLogger()
			e := NewEngine(testKV{available: true}, logger)
			e.Reload([]*Script{mustCompile(t, StagePre,
				`function handle(ctx) ctx.log("`+tc.scriptLevel+`", "x") return nil end`)})

			e.Evaluate(context.Background(), StagePre, RequestView{})
			if len(*records) != 1 {
				t.Fatalf("日志条数 = %d, want 1", len(*records))
			}
			if level := (*records)[0].level; level != tc.want {
				t.Errorf("level %q 落盘为 %v, want %v", tc.scriptLevel, level, tc.want)
			}
		})
	}
}

// TestEngineLogSanitizesMessage 验证脚本日志被条带化并限长。
//
// 脚本能读到原始 Host 与请求头值，CR/LF 未净化时一条脚本日志能伪造出多行
// 日志条目；限长则避免脚本把日志文件当作内存放大的出口。
func TestEngineLogSanitizesMessage(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  ctx.log("info", "first\r\nsecond")
  ctx.log("info", string.rep("A", 8192))
  return nil
end`)})

	e.Evaluate(context.Background(), StagePre, RequestView{})

	got := *records
	if len(got) != 2 {
		t.Fatalf("日志条数 = %d, want 2", len(got))
	}
	if strings.ContainsAny(got[0].message, "\r\n") {
		t.Errorf("CR/LF 未净化：%q", got[0].message)
	}
	if got[0].message != "first  second" {
		t.Errorf("净化后的消息 = %q", got[0].message)
	}
	if len(got[1].message) != maxScriptLogMessageBytes {
		t.Errorf("超长消息未被截断：%d, want %d", len(got[1].message), maxScriptLogMessageBytes)
	}
	// 消息同时进入记录消息与 message 属性：换用只读属性的 handler 时内容不丢。
	if got[0].attrs["message"] != got[0].message {
		t.Errorf("message 属性 = %q, 记录消息 = %q", got[0].attrs["message"], got[0].message)
	}
}

// TestInjectedViewHooksWinOverScriptHooks 验证视图注入的回调优先于脚本级回调。
//
// 两条路径的关系是固定的：脚本级回调供线上使用，视图注入供试运行与测试
// 按次覆盖，后者优先，且不会串到下一次请求。
func TestInjectedViewHooksWinOverScriptHooks(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	first := mustCompile(t, StagePre, `function handle(ctx) ctx.log("info", "one") return nil end`)
	second := mustCompile(t, StagePre, `function handle(ctx) ctx.log("info", "two") return nil end`)
	muted := 0
	second.SetRuntimeHooks(func(string, string) { muted++ }, nil)
	e.Reload([]*Script{first, second})

	var injected []string
	req := RequestView{}
	req.SetRuntimeHooks(func(level, message string) { injected = append(injected, message) }, nil)
	e.Evaluate(context.Background(), StagePre, req)

	if len(injected) != 2 {
		t.Fatalf("视图注入的回调应接管全部脚本，实际 %v", injected)
	}
	if len(*records) != 0 {
		t.Fatalf("视图注入时应绕开宿主 logger，实际写入 %d 条", len(*records))
	}
	if muted != 0 {
		t.Fatalf("脚本级回调不应被调用：%d", muted)
	}
}

// TestScriptLevelHooksArePerScript 验证不同脚本各自持有回调，互不串用。
func TestScriptLevelHooksArePerScript(t *testing.T) {
	e := NewEngine(testKV{available: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := mustCompile(t, StagePre, `function handle(ctx) return nil end`)
	second := mustCompile(t, StagePost, `function handle(ctx) return nil end`)
	second.SetRuntimeHooks(nil, nil)
	e.Reload([]*Script{first, second})

	if first.logFn == nil || first.debugFn == nil {
		t.Fatal("pre 脚本应带回调")
	}
	if second.logFn == nil || second.debugFn == nil {
		t.Fatal("后置脚本的装载应覆盖外部注入，而不是保留 nil")
	}
	if &first.logFn == &second.logFn {
		t.Fatal("两个脚本应各自持有回调字段")
	}
}

// TestRuntimeHooksNeverLeakAcrossRequests 验证回调不会在池化状态机之间串场。
//
// 注入只作用于本次调用的视图副本；下一次请求（不带回调）应回落到脚本级回调。
func TestRuntimeHooksNeverLeakAcrossRequests(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx) ctx.log("info", "x") return nil end`)})

	var injected int
	first := RequestView{}
	first.SetRuntimeHooks(func(string, string) { injected++ }, nil)
	e.Evaluate(context.Background(), StagePre, first)
	e.Evaluate(context.Background(), StagePre, RequestView{})

	if injected != 1 {
		t.Fatalf("注入回调被调用 %d 次，want 1", injected)
	}
	if n := len(*records); n != 1 {
		t.Fatalf("第二次请求未回落到宿主 logger：%d 条", n)
	}
}

// TestScriptRunWithoutHooksIsNoop 验证未经引擎装载、视图也未注入回调时，
// ctx.log / ctx.debug 是安全空操作：不报错、不改变判定。
func TestScriptRunWithoutHooksIsNoop(t *testing.T) {
	script, err := Compile("standalone", StagePre, `
function handle(ctx)
  ctx.log("error", "ignored")
  ctx.debug("ignored")
  return "observe"
end`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	dec, runErr := script.Run(context.Background(), newVMPool(), RequestView{}, testKV{available: true})
	if runErr != nil {
		t.Fatalf("无回调时脚本不应报错：%v", runErr)
	}
	if dec.Action != "observe" {
		t.Fatalf("判定被空操作日志改变：%+v", dec)
	}
}

// TestDryRunLogHooksStayDisabled 验证试运行不会把脚本日志写进生产日志。
//
// dry-run 由控制面触发，若沿用引擎 logger，用户试运行一段带 ctx.log 的脚本
// 就能往数据面日志里灌内容。
func TestDryRunLogHooksStayDisabled(t *testing.T) {
	res := DryRun(StagePre, `
function handle(ctx)
  ctx.log("warn", "dry run should not log")
  return "observe"
end`, RequestView{}, nil, 0)
	if res.RuntimeError != "" {
		t.Fatalf("dry-run 运行出错：%s", res.RuntimeError)
	}
	if res.Decision.Action != "observe" {
		t.Fatalf("dry-run 判定 = %+v", res.Decision)
	}
}

// TestMissingRuntimeConfigMetricsAreEmptyNotErrors 验证未注入的 ctx.config /
// ctx.metrics 保持可索引的空表：脚本读到的缺失键是 nil，不是运行时报错。
//
// Config 与 Metrics 在数据面没有写入方，脚本必须能安全地探测它们是否存在。
// Runtime 由调用方（rules.BuildLuaRequestView）填写，本包内直接调用 Evaluate
// 时不含该填充，因此这里显式给一个，才有资格断言缺失键的读法。
func TestMissingRuntimeConfigMetricsAreEmptyNotErrors(t *testing.T) {
	logger, _ := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  if type(ctx.config) ~= "table" or type(ctx.metrics) ~= "table" then return "intercept" end
  if ctx.config.mode ~= nil then return "intercept" end
  if ctx.metrics.requests ~= nil then return "intercept" end
  if ctx.runtime.stage ~= "pre" then return "intercept" end
  if ctx.runtime.phase ~= "lua_pre" then return "intercept" end
  if ctx.runtime.no_such_key ~= nil then return "intercept" end
  return "observe"
end`)})

	req := RequestView{Runtime: map[string]string{"stage": "pre", "phase": "lua_pre"}}
	if dec := e.Evaluate(context.Background(), StagePre, req); dec.Action != "observe" {
		t.Fatalf("空表访问不应改变判定：%+v", dec)
	}
}

// TestScriptLevelHooksAreOverwrittenOnReload 验证脚本级回调归引擎所有：
// 装载是唯一发布点，外部对 Script 的空设置会被下一次装载覆盖。
//
// 需要按调用屏蔽日志的场景必须走 RequestView 注入，见
// TestInjectedHooksTakePrecedence 与 TestDryRunLogHooksStayDisabled。
func TestScriptLevelHooksAreOverwrittenOnReload(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	script := mustCompile(t, StagePre, `function handle(ctx) ctx.log("warn", "x") return nil end`)
	script.SetRuntimeHooks(nil, nil)
	e.Reload([]*Script{script})

	e.Evaluate(context.Background(), StagePre, RequestView{})
	if len(*records) != 1 {
		t.Fatalf("装载应恢复脚本回调，实际写入 %d 条日志", len(*records))
	}
}

// TestNilSetRuntimeHooksIsSafe 验证对 nil 脚本/视图调用注入接口不会 panic。
func TestNilScriptAndViewHooksAreSafe(t *testing.T) {
	var s *Script
	s.SetRuntimeHooks(func(string, string) {}, func(string) {}) // 不应 panic
	s.SetRuntimeHooks(nil, nil)

	var view *RequestView
	view.SetRuntimeHooks(func(string, string) {}, func(string) {}) // 不应 panic
	view.SetRuntimeHooks(nil, nil)
}

// TestEngineLogHooksSurviveReload 验证热重载后新脚本集合带回调，旧脚本不受影响。
func TestEngineLogHooksSurviveReload(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) ctx.log("info", "v1") return nil end`)})

	old := e.scriptsFor(StagePre)[0]
	e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) ctx.log("info", "v2") return nil end`)})

	e.Evaluate(context.Background(), StagePre, RequestView{})
	// 旧脚本集合已不在服务中，但持有它的在途调用仍应能写日志（回调随脚本固定）。
	if _, err := old.Run(context.Background(), newVMPool(), RequestView{}, testKV{available: true}); err != nil {
		t.Fatalf("旧脚本执行出错：%v", err)
	}

	got := *records
	if len(got) != 2 || got[0].message != "v2" || got[1].message != "v1" {
		t.Fatalf("热重载后的日志 = %+v", got)
	}
}

// TestLoggerToRuntimeHooksNilLogger 验证 nil logger 得到 nil 回调，
// 由调用方决定降级方式，而不是在回调里 panic。
func TestLoggerToRuntimeHooksNilLogger(t *testing.T) {
	logFn, debugFn := loggerToRuntimeHooks(nil)
	if logFn != nil || debugFn != nil {
		t.Fatal("nil logger 应返回 nil 回调")
	}
}

func TestSanitizeScriptLogMessageLimit(t *testing.T) {
	if got := sanitizeScriptLogMessage("abc", 0); got != "" {
		t.Errorf("limit<=0 应返回空串，得到 %q", got)
	}
	if got := sanitizeScriptLogMessage("abc", 2); got != "ab" {
		t.Errorf("截断结果 = %q", got)
	}
	if got := sanitizeScriptLogMessage("a\nb", 10); got != "a b" {
		t.Errorf("换行净化结果 = %q", got)
	}
}

// TestScriptHooksArePerScriptNotShared 验证同一引擎内不同脚本的回调互相独立。
func TestScriptLoggerCarriesIdentity(t *testing.T) {
	logger, records := newRecordingLogger()
	e := NewEngine(testKV{available: true}, logger)
	script := mustCompile(t, StagePost, `function handle(ctx) return nil end`)
	scriptLogger := e.scriptLogger(script)
	if scriptLogger == nil {
		t.Fatal("scriptLogger 不应返回 nil")
	}
	scriptLogger.Info("hello")

	got := *records
	if len(got) != 1 {
		t.Fatalf("日志条数 = %d", len(got))
	}
	if got[0].attrs["script"] != "test" || got[0].attrs["stage"] != string(StagePost) {
		t.Errorf("溯源属性 = %+v", got[0].attrs)
	}

	var nilEngine *Engine
	if nilEngine.scriptLogger(script) != nil {
		t.Error("nil 引擎不应派生 logger")
	}
	if e.scriptLogger(nil) != nil {
		t.Error("nil 脚本不应派生 logger")
	}
}
