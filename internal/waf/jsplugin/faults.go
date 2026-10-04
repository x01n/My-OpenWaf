package jsplugin

import (
	"log/slog"
	"strings"
	"time"
)

// reportMaxMessageBytes 限制落入失败摘要的消息长度。
//
// 与 luaplugin 的 maxScriptLogMessageBytes 同量级：脚本失败消息里可能带
// 源码片段或请求快照内容，过长会把日志冲成噪声，也让失败摘要成为内存放大的
// 出口。
const reportMaxMessageBytes = 2 * 1024

// jsFailureModeClosed 是 store.JSFailureModeClosed 的字面值。
//
// 逐字复制是为了让本文件不依赖 internal/store：失败记录只需要这一个常量，
// 引入整个 store 包会把脚本运行时与数据模型耦合在一起。
const jsFailureModeClosed = "fail_closed"

/**
 * FaultRecord 是一次脚本失败的稳定记录，供管理端展示「脚本上次执行错误」。
 *
 * Message 已经过 CR/LF 条带化与长度截断。Count 是该脚本的失败累计次数，
 * 与 Script.Stats 的 failures 计数同源语义但独立计数：failures 由执行器
 * 在记录统计时递增，Count 只在经过失败记录路径时递增。
 */
type FaultRecord struct {
	// At 是最近一次失败时间。
	At time.Time
	// Stage 是脚本阶段（request / response）。
	Stage string
	// Message 是失败原因的简短描述。
	Message string
	// Count 是失败累计次数。
	Count int64
}

// faultState 是单脚本的失败状态；由 faultMu 保护。
type faultState struct {
	record FaultRecord
	// logged 记录当前这条失败是否已经写过宿主日志，用于抑制重复日志。
	logged bool
}

/**
 * recordFault 记录一次失败；返回是否应在宿主日志里补一条记录。
 *
 * 同一脚本的同一失败原因只记一次日志，其余只累加 Count：一个坏脚本每请求都
 * 失败，若每次都写日志会把数据面日志刷满。失败原因变化时重新记一条，用户
 * 才能看到「错误变了」。
 *
 * 失败是罕见路径，用互斥锁而不是 CAS 循环：逻辑更直白，且不必为每次失败
 * 分配新的记录对象。
 *
 * @param stage 脚本阶段（request / response）。
 * @param message 失败原因描述，进入记录前会条带化并截断。
 * @return 失败记录与「是否应写宿主日志」。
 */
func (s *Script) recordFault(stage, message string) (FaultRecord, bool) {
	if s == nil {
		return FaultRecord{}, false
	}
	message = sanitizeFaultMessage(message)
	s.faultMu.Lock()
	defer s.faultMu.Unlock()
	shouldLog := !s.fault.logged || s.fault.record.Stage != stage || s.fault.record.Message != message
	s.fault.record = FaultRecord{
		At:      time.Now(),
		Stage:   stage,
		Message: message,
		Count:   s.fault.record.Count + 1,
	}
	s.fault.logged = true
	return s.fault.record, shouldLog
}

/**
 * LastFault 返回该脚本最近一次失败的记录；从未失败时返回 nil。
 *
 * 与 Stats() 一样是只读快照：管理端遍历 snapshot 里的脚本逐个读取，无需
 * 引擎侧的额外索引。
 */
func (s *Script) LastFault() *FaultRecord {
	if s == nil {
		return nil
	}
	s.faultMu.Lock()
	defer s.faultMu.Unlock()
	if s.fault.record.Count == 0 {
		return nil
	}
	record := s.fault.record
	return &record
}

/**
 * recordFault 记录失败并在首次（或失败原因变化时）写一条宿主日志。
 *
 * 日志级别按失败处理方式区分：fail-closed 的失败会终止请求，按 Error 记；
 * fail-open 只是跳过一个脚本，按 Warn 记，默认级别下两类都可见。
 *
 * @param script 出错的脚本。
 * @param stage 脚本阶段。
 * @param err 执行器返回的错误。
 */
func (e *Engine) recordFault(script *Script, stage string, err error) {
	if script == nil {
		return
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	record, shouldLog := script.recordFault(stage, message)
	if !shouldLog {
		return
	}
	attributes := []any{
		slog.String("script", script.Name()),
		slog.Uint64("script_id", uint64(script.ID())),
		slog.String("stage", record.Stage),
		slog.String("message", record.Message),
		slog.Int64("occurrences", record.Count),
	}
	if script.FailureMode() == jsFailureModeClosed {
		e.logger().Error("JavaScript plugin failed (fail-closed)", attributes...)
		return
	}
	e.logger().Warn("JavaScript plugin failed (fail-open, request continues)", attributes...)
}

// logger 返回引擎日志；未配置时回退到 slog 默认 logger。
func (e *Engine) logger() *slog.Logger {
	if e == nil || e.log == nil {
		return slog.Default()
	}
	return e.log
}

/**
 * sanitizeFaultMessage 条带化并截断失败消息。
 *
 * 脚本失败消息可能回显源码片段或请求快照内容，其中的 CR/LF 会伪造出多行
 * 日志条目，因此与 luaplugin 的脚本日志走同一套净化。
 *
 * @param message 执行器给出的原始失败消息。
 * @return 截断并条带化后的消息。
 */
func sanitizeFaultMessage(message string) string {
	if len(message) > reportMaxMessageBytes {
		message = message[:reportMaxMessageBytes]
	}
	if !strings.ContainsAny(message, "\r\n") {
		return message
	}
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(message)
}

/**
 * ObserveScriptFault 记录一次脚本失败，供数据面在执行器之外统一上报。
 *
 * 调用点是数据面「已经判定这个脚本这次没成功」的两处：执行器返回错误，以及
 * 变更计划无法应用。后者发生在执行器之外（计划已通过校验、但在写回 hertz
 * 请求时失败），只在执行器内埋点会漏掉；因此上报做成显式调用而不是包装器。
 *
 * executor 不是本包引擎（例如测试替身或禁用 cgo 的 stub）时安全忽略：
 * 运行时不可用的降级路径不应因为缺一台引擎而产生额外分支。
 *
 * @param executor 脚本执行器，可为 *Engine 或 Engine。
 * @param script 出错的脚本。
 * @param stage 脚本阶段。
 * @param err 失败原因。
 */
func ObserveScriptFault(executor any, script *Script, stage string, err error) {
	if script == nil || err == nil {
		return
	}
	var engine *Engine
	switch value := executor.(type) {
	case *Engine:
		engine = value
	case Engine:
		engine = &value
	default:
		return
	}
	engine.recordFault(script, stage, err)
}
