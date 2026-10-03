package jsplugin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
)

// TestObserveScriptFaultRecordsFailure 锁定失败可见性的核心契约：数据面
// 上报的脚本失败会被记录到脚本上，管理端据此展示「脚本上次执行错误」。
func TestObserveScriptFaultRecordsFailure(t *testing.T) {
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err == nil {
		// cgo 构建：真实引擎可用。
		defer engine.Close()
	} else {
		// 无 QuickJS 的构建：失败记录与执行后端无关，用一个零值引擎验证。
		engine = &Engine{}
	}
	script := &Script{id: 7, name: "faulty"}
	ObserveScriptFault(engine, script, store.JSStageRequest, errors.New("boom"))
	record := script.LastFault()
	if record == nil {
		t.Fatal("LastFault() = nil, want a recorded failure")
	}
	if record.Message != "boom" || record.Stage != store.JSStageRequest || record.Count != 1 {
		t.Fatalf("fault record = %#v", record)
	}
}

// TestObserveScriptFaultIgnoresForeignExecutor 确认非本包引擎与 nil 输入都是
// 安全空操作：运行时不可用的降级路径不应产生额外分支或 panic。
func TestObserveScriptFaultIgnoresForeignExecutor(t *testing.T) {
	script := &Script{id: 7, name: "faulty"}
	ObserveScriptFault(nil, script, store.JSStageRequest, errors.New("boom"))
	ObserveScriptFault("not-an-engine", script, store.JSStageRequest, errors.New("boom"))
	ObserveScriptFault(&Engine{}, script, store.JSStageRequest, nil)
	if record := script.LastFault(); record != nil {
		t.Fatalf("LastFault() = %#v, want nil", record)
	}
	ObserveScriptFault(&Engine{}, nil, store.JSStageRequest, errors.New("boom"))
}

// TestScriptRecordsIndependentFaults 确认失败记录挂在脚本上而不是引擎上：
// 两个脚本各自维护自己的失败。
func TestScriptRecordsIndependentFaults(t *testing.T) {
	engine := &Engine{}
	first := &Script{id: 1, name: "first"}
	second := &Script{id: 2, name: "second"}
	ObserveScriptFault(engine, first, store.JSStageRequest, errors.New("boom"))
	if second.LastFault() != nil {
		t.Fatalf("second script fault = %#v, want nil", second.LastFault())
	}
	if first.LastFault() == nil {
		t.Fatal("first script fault = nil, want recorded failure")
	}
}

// TestScriptLastFaultNilForUnusedScript 确认从未失败的脚本返回 nil，
// 管理端据此渲染空字段而不是零值时间。
func TestScriptLastFaultNilForUnusedScript(t *testing.T) {
	if record := (&Script{id: 3}).LastFault(); record != nil {
		t.Fatalf("LastFault() = %#v, want nil", record)
	}
	var nilScript *Script
	if record := nilScript.LastFault(); record != nil {
		t.Fatalf("nil script LastFault() = %#v, want nil", record)
	}
}

// TestFaultRecordCountsRepeats 确认重复失败累加次数，失败原因变化时消息更新。
func TestFaultRecordCountsRepeats(t *testing.T) {
	script := &Script{id: 7, name: "faulty"}
	for i := 0; i < 5; i++ {
		script.recordFault(store.JSStageRequest, "boom")
	}
	record := script.LastFault()
	if record.Count != 5 || record.Message != "boom" {
		t.Fatalf("fault record = %#v, want count 5 and message boom", record)
	}
	script.recordFault(store.JSStageRequest, "timeout")
	record = script.LastFault()
	if record.Message != "timeout" || record.Count != 6 {
		t.Fatalf("fault record = %#v, want count 6 and message timeout", record)
	}
}

// TestSanitizeFaultMessageStripsNewlines 锁定日志伪造防护：脚本失败消息里的
// CR/LF 必须条带化，否则一条失败能伪装成多条日志。
func TestSanitizeFaultMessageStripsNewlines(t *testing.T) {
	got := sanitizeFaultMessage("first\r\nsecond\nthird")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitized message = %q, still contains newlines", got)
	}
	if got != "first  second third" {
		t.Fatalf("sanitized message = %q", got)
	}
	long := sanitizeFaultMessage(strings.Repeat("x", reportMaxMessageBytes+100))
	if len(long) != reportMaxMessageBytes {
		t.Fatalf("sanitized message length = %d, want %d", len(long), reportMaxMessageBytes)
	}
}

// TestFaultRecordStampsTime 确认记录带时间戳，管理端据此展示「上次执行错误」。
func TestFaultRecordStampsTime(t *testing.T) {
	started := time.Now().Add(-time.Second)
	script := &Script{id: 1}
	script.recordFault(store.JSStageRequest, "boom")
	record := script.LastFault()
	if record.At.Before(started) || record.At.After(time.Now().Add(time.Second)) {
		t.Fatalf("fault time = %v, want around now", record.At)
	}
}

// TestRecordFaultSuppressesDuplicateLogging 确认重复的同一失败不重复写日志，
// 只有首次与失败原因变化时返回 shouldLog。
func TestRecordFaultSuppressesDuplicateLogging(t *testing.T) {
	script := &Script{id: 5}
	if _, shouldLog := script.recordFault(store.JSStageRequest, "boom"); !shouldLog {
		t.Fatal("first fault should be logged")
	}
	if _, shouldLog := script.recordFault(store.JSStageRequest, "boom"); shouldLog {
		t.Fatal("duplicate fault should not be logged")
	}
	if _, shouldLog := script.recordFault(store.JSStageRequest, "changed"); !shouldLog {
		t.Fatal("changed fault message should be logged")
	}
	if _, shouldLog := script.recordFault(store.JSStageResponse, "changed"); !shouldLog {
		t.Fatal("changed fault stage should be logged")
	}
}

// TestEngineLoggerFallsBackToDefault 确认未装配 logger 时失败日志落点非 nil，
// recordFault 不会因 nil logger panic。
func TestEngineLoggerFallsBackToDefault(t *testing.T) {
	var nilEngine *Engine
	if got := nilEngine.logger(); got == nil {
		t.Fatal("nil engine logger() = nil, want slog default")
	}
	if got := (&Engine{}).logger(); got == nil {
		t.Fatal("zero-value engine logger() = nil, want slog default")
	}
}

// TestObserveScriptFaultTracksFailClosedMode 确认 fail-closed 与 fail-open
// 的失败都被记录，模式只影响日志级别、不影响可见性。
func TestObserveScriptFaultTracksFailClosedMode(t *testing.T) {
	engine := &Engine{}
	script := &Script{id: 9, name: "closed", failureMode: jsFailureModeClosed}
	ObserveScriptFault(engine, script, store.JSStageResponse, errors.New("closed boom"))
	record := script.LastFault()
	if record == nil || record.Stage != store.JSStageResponse {
		t.Fatalf("fault record = %#v", record)
	}
	if got := jsFailureModeClosed; got != store.JSFailureModeClosed {
		t.Fatalf("jsFailureModeClosed = %q, want %q", got, store.JSFailureModeClosed)
	}
}
