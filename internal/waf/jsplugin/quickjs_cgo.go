//go:build cgo && quickjs

package jsplugin

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quickjs "github.com/buke/quickjs-go"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// Compile validates a QuickJS plugin and returns an immutable script descriptor.
func Compile(name, source string, opts ScriptOptions) (*Script, error) {
	if opts.Name == "" {
		opts.Name = name
	}
	if len(source) == 0 {
		return nil, errors.New("jsplugin: script source is empty")
	}
	if len(source) > MaxScriptBytes {
		return nil, fmt.Errorf("jsplugin: script exceeds %d bytes", MaxScriptBytes)
	}
	requestedTimeout := opts.Timeout
	normalized, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	transformed, err := transformedSource(source)
	if err != nil {
		return nil, err
	}
	if err := validateSource(source, transformed, normalized.MemoryLimit, normalized.StackLimit, normalized.Timeout); err != nil {
		return nil, err
	}
	siteIDs := make(map[uint]bool, len(normalized.SiteIDs))
	for _, id := range normalized.SiteIDs {
		siteIDs[id] = true
	}
	return &Script{
		name:            normalized.Name,
		source:          transformed,
		siteIDs:         siteIDs,
		memoryLimit:     normalized.MemoryLimit,
		stackLimit:      normalized.StackLimit,
		timeout:         normalized.Timeout,
		timeoutOverride: requestedTimeout != 0,
	}, nil
}

func validateSource(source, transformed string, memoryLimit, stackLimit uint64, timeout time.Duration) error {
	var result error
	runOnThread(func() {
		// runOnThread owns all native handles on one pinned goroutine. The library's
		// stack-based owner check is redundant here and dominates short executions.
		rt := quickjs.NewRuntime(
			quickjs.WithMemoryLimit(memoryLimit),
			quickjs.WithMaxStackSize(stackLimit),
			quickjs.WithModuleImport(false),
			quickjs.WithOwnerGoroutineCheck(false),
		)
		if rt == nil {
			result = errors.New("jsplugin: failed to create QuickJS runtime")
			return
		}
		defer rt.Close()
		ctx := rt.NewBareContext()
		if ctx == nil {
			result = errors.New("jsplugin: failed to create QuickJS context")
			return
		}
		defer ctx.Close()
		deadline := time.Now().Add(timeout)
		timedOut := false
		rt.SetInterruptHandler(func() int {
			if time.Now().After(deadline) {
				timedOut = true
				return 1
			}
			return 0
		})
		if result = validateModuleSource(ctx, source); result == nil {
			var plugin *quickjs.Value
			plugin, result = evaluatePlugin(ctx, transformed)
			if result == nil {
				defer plugin.Free()
				result = validatePlugin(plugin)
			}
		}
		rt.ClearInterruptHandler()
		if timedOut {
			result = ErrScriptTimeout
		}
	})
	return result
}

func validateModuleSource(ctx *quickjs.Context, source string) error {
	result := ctx.Eval(
		source,
		quickjs.EvalFileName("<js-plugin>"),
		quickjs.EvalFlagModule(true),
		quickjs.EvalFlagCompileOnly(true),
	)
	if result == nil {
		return errors.New("jsplugin: QuickJS module compilation failed")
	}
	defer result.Free()
	if result.IsException() {
		if err := ctx.Exception(); err != nil {
			return fmt.Errorf("jsplugin: compile failed: %w", err)
		}
		return errors.New("jsplugin: compile failed")
	}
	return nil
}

func evaluatePlugin(ctx *quickjs.Context, source string) (*quickjs.Value, error) {
	plugin := ctx.Eval(source, quickjs.EvalFileName("<js-plugin>"))
	if plugin == nil {
		return nil, errors.New("jsplugin: QuickJS evaluation failed")
	}
	if plugin.IsException() {
		defer plugin.Free()
		if err := ctx.Exception(); err != nil {
			return nil, fmt.Errorf("jsplugin: plugin evaluation failed: %w", err)
		}
		return nil, errors.New("jsplugin: plugin evaluation failed")
	}
	return plugin, nil
}

func validatePlugin(plugin *quickjs.Value) error {
	if !plugin.IsObject() {
		return errors.New("jsplugin: default export must be an object")
	}
	fetch := plugin.Get("fetch")
	if fetch == nil {
		return errors.New("jsplugin: default export fetch is missing")
	}
	defer fetch.Free()
	if !fetch.IsFunction() {
		return errors.New("jsplugin: default export fetch must be a function")
	}
	return nil
}

func transformedSource(source string) (string, error) {
	ast, err := js.Parse(parse.NewInputString(source), js.Options{})
	if err != nil {
		return "", fmt.Errorf("jsplugin: parse module: %w", err)
	}

	var body strings.Builder
	var defaultExport *js.ExportStmt
	for _, statement := range ast.List {
		switch statement := statement.(type) {
		case *js.ImportStmt:
			return "", errors.New("jsplugin: imports are not supported")
		case *js.ExportStmt:
			if !statement.Default || statement.Decl == nil || len(statement.List) != 0 || statement.Module != nil {
				return "", errors.New("jsplugin: only a default export is supported")
			}
			if defaultExport != nil {
				return "", errors.New("jsplugin: script must contain exactly one default export")
			}
			defaultExport = statement
		default:
			statement.JS(&body)
			body.WriteByte('\n')
		}
	}
	if defaultExport == nil {
		return "", errors.New("jsplugin: script must export default")
	}

	var transformed strings.Builder
	transformed.WriteString("(function () {\n\"use strict\";\n")
	transformed.WriteString(body.String())
	transformed.WriteString("return ")
	defaultExport.Decl.JS(&transformed)
	transformed.WriteString(";\n}())")
	return transformed.String(), nil
}

// NewEngine creates a bounded pool of owner-goroutine QuickJS execution slots.
func NewEngine(opts EngineOptions) (*Engine, error) {
	normalized, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	e := &Engine{opts: normalized}
	e.slots = make([]*executionSlot, normalized.PoolSize)
	for i := range e.slots {
		slot := &executionSlot{requests: make(chan executionRequest, 1), ready: make(chan error, 1), stop: make(chan struct{}), done: make(chan struct{})}
		e.slots[i] = slot
		go slot.run(normalized)
	}
	for _, slot := range e.slots {
		if err := <-slot.ready; err != nil {
			e.Close()
			return nil, err
		}
	}
	return e, nil
}

// Engine executes scripts through a bounded QuickJS slot pool.
type Engine struct {
	opts      EngineOptions
	slots     []*executionSlot
	next      atomic.Uint64
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	wait      sync.WaitGroup
}

type executionRequest struct {
	ctx     context.Context
	script  *Script
	reqJSON string
	result  chan executionResult
}

type executionResult struct {
	plan MutationPlan
	err  error
}

type executionSlot struct {
	requests      chan executionRequest
	stop          chan struct{}
	ready         chan error
	done          chan struct{}
	rt            *quickjs.Runtime
	ctx           *quickjs.Context
	compiled      map[*Script]compiledScript
	compiledOrder *list.List
	compiledLimit int
}

type compiledScript struct {
	plugin  *quickjs.Value
	element *list.Element
}

func (s *executionSlot) run(opts EngineOptions) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	// The slot goroutine owns this locked OS thread for its full lifetime, so
	// native QuickJS access cannot race across goroutines.
	s.rt = quickjs.NewRuntime(
		quickjs.WithMemoryLimit(opts.MemoryLimit),
		quickjs.WithMaxStackSize(opts.StackLimit),
		quickjs.WithModuleImport(false),
		quickjs.WithOwnerGoroutineCheck(false),
	)
	if s.rt == nil {
		s.ready <- errors.New("jsplugin: failed to create QuickJS runtime")
		close(s.done)
		return
	}
	s.ctx = s.rt.NewBareContext()
	if s.ctx == nil {
		s.rt.Close()
		s.ready <- errors.New("jsplugin: failed to create QuickJS context")
		close(s.done)
		return
	}
	s.compiled = make(map[*Script]compiledScript)
	s.compiledOrder = list.New()
	s.compiledLimit = opts.CompiledCacheSize
	s.ready <- nil
	defer func() {
		for _, entry := range s.compiled {
			entry.plugin.Free()
		}
		s.ctx.Close()
		s.rt.Close()
		close(s.done)
	}()
	for {
		select {
		case <-s.stop:
			s.rejectQueued(ErrEngineClosed)
			return
		default:
		}
		select {
		case request := <-s.requests:
			// Close may race with receiving a queued request. Never start a
			// request after the slot has entered its shutdown state.
			select {
			case <-s.stop:
				request.result <- executionResult{err: ErrEngineClosed}
				s.rejectQueued(ErrEngineClosed)
				return
			default:
			}
			s.execute(request, opts)
		case <-s.stop:
			s.rejectQueued(ErrEngineClosed)
			return
		}
	}
}

func (s *executionSlot) rejectQueued(err error) {
	for {
		select {
		case request := <-s.requests:
			request.result <- executionResult{err: err}
		default:
			return
		}
	}
}

func (s *executionSlot) execute(request executionRequest, opts EngineOptions) {
	if request.ctx != nil {
		select {
		case <-request.ctx.Done():
			request.result <- executionResult{err: request.ctx.Err()}
			return
		default:
		}
	}
	request.script.runs.Add(1)
	started := time.Now()
	defer func() { request.script.totalNanos.Add(time.Since(started).Nanoseconds()) }()
	timeout := opts.Timeout
	if request.script.timeoutOverride {
		timeout = request.script.timeout
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	var timedOut atomic.Bool
	s.rt.SetMemoryLimit(request.script.memoryLimit)
	s.rt.SetMaxStackSize(request.script.stackLimit)
	s.rt.SetInterruptHandler(func() int {
		if time.Now().After(deadline) {
			timedOut.Store(true)
			return 1
		}
		if request.ctx != nil {
			select {
			case <-request.ctx.Done():
				return 1
			default:
			}
		}
		return 0
	})
	defer s.rt.ClearInterruptHandler()
	plan, err := s.evaluate(request.script, request.reqJSON)
	if timedOut.Load() {
		request.script.timeouts.Add(1)
		err = ErrScriptTimeout
		plan = MutationPlan{}
	} else if err != nil {
		request.script.failures.Add(1)
		plan = MutationPlan{}
	}
	request.result <- executionResult{plan: plan, err: err}
}

func (s *executionSlot) loadCompiled(script *Script) (*quickjs.Value, bool) {
	entry, ok := s.compiled[script]
	if !ok {
		return nil, false
	}
	s.compiledOrder.MoveToFront(entry.element)
	return entry.plugin, true
}

func (s *executionSlot) storeCompiled(script *Script, plugin *quickjs.Value) {
	element := s.compiledOrder.PushFront(script)
	s.compiled[script] = compiledScript{plugin: plugin, element: element}
	if s.compiledOrder.Len() <= s.compiledLimit {
		return
	}
	oldest := s.compiledOrder.Back()
	oldestScript, ok := oldest.Value.(*Script)
	if !ok {
		panic("jsplugin: invalid compiled cache entry")
	}
	entry := s.compiled[oldestScript]
	delete(s.compiled, oldestScript)
	s.compiledOrder.Remove(oldest)
	entry.plugin.Free()
}

func (s *executionSlot) evaluate(script *Script, reqJSON string) (MutationPlan, error) {
	plugin, ok := s.loadCompiled(script)
	if !ok {
		compiled, err := evaluatePlugin(s.ctx, script.source)
		if err != nil {
			return MutationPlan{}, err
		}
		if err := validatePlugin(compiled); err != nil {
			compiled.Free()
			return MutationPlan{}, err
		}
		plugin = compiled
		s.storeCompiled(script, plugin)
	}
	fetch := plugin.Get("fetch")
	if fetch == nil {
		return MutationPlan{}, errors.New("jsplugin: default export fetch is missing")
	}
	defer fetch.Free()
	requestValue := s.ctx.ParseJSON(reqJSON)
	if requestValue == nil {
		return MutationPlan{}, errors.New("jsplugin: request snapshot parsing failed")
	}
	defer requestValue.Free()
	if requestValue.IsException() {
		if err := s.ctx.Exception(); err != nil {
			return MutationPlan{}, fmt.Errorf("jsplugin: request snapshot parsing failed: %w", err)
		}
		return MutationPlan{}, errors.New("jsplugin: request snapshot parsing failed")
	}
	env := s.ctx.NewObject()
	defer env.Free()
	hostCtx := s.ctx.NewObject()
	defer hostCtx.Free()
	result := fetch.Execute(plugin, requestValue, env, hostCtx)
	if result == nil {
		return MutationPlan{}, errors.New("jsplugin: fetch invocation failed")
	}
	if result.IsPromise() {
		if result.PromiseState() == quickjs.PromisePending {
			result.Free()
			return MutationPlan{}, ErrAsyncPromise
		}
		awaited := s.ctx.Await(result)
		if awaited == nil {
			return MutationPlan{}, errors.New("jsplugin: failed to await Promise")
		}
		result = awaited
	}
	defer result.Free()
	if result.IsException() {
		if err := s.ctx.Exception(); err != nil {
			return MutationPlan{}, err
		}
		return MutationPlan{}, errors.New("jsplugin: fetch raised an exception")
	}
	if result.IsNull() || result.IsUndefined() {
		return MutationPlan{}, nil
	}
	var plan MutationPlan
	if err := s.ctx.Unmarshal(result, &plan); err != nil {
		return MutationPlan{}, fmt.Errorf("jsplugin: invalid mutation plan: %w", err)
	}
	if err := validateMutationPlan(plan); err != nil {
		return MutationPlan{}, err
	}
	return plan, nil
}

// Execute implements Executor for the QuickJS engine.
func (e *Engine) Execute(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	return e.Evaluate(ctx, script, req)
}

// Evaluate executes one request, returning an empty plan on every error.
func (e *Engine) Evaluate(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil || script == nil {
		return MutationPlan{}, errors.New("jsplugin: script is nil")
	}
	if !script.AppliesTo(req.SiteID) {
		return MutationPlan{}, nil
	}
	encodedReq, err := encodeRequestSnapshot(req)
	if err != nil {
		return MutationPlan{}, err
	}
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return MutationPlan{}, ErrEngineClosed
	}
	if len(e.slots) == 0 {
		e.mu.RUnlock()
		return MutationPlan{}, ErrNoSlot
	}
	if err := ctx.Err(); err != nil {
		e.mu.RUnlock()
		return MutationPlan{}, err
	}
	request := executionRequest{ctx: ctx, script: script, reqJSON: encodedReq, result: make(chan executionResult, 1)}
	start := int(e.next.Add(1) % uint64(len(e.slots)))
	queued := false
	for i := 0; i < len(e.slots); i++ {
		slot := e.slots[(start+i)%len(e.slots)]
		select {
		case <-ctx.Done():
			e.mu.RUnlock()
			return MutationPlan{}, ctx.Err()
		default:
		}
		select {
		case slot.requests <- request:
			queued = true
		case <-ctx.Done():
			e.mu.RUnlock()
			return MutationPlan{}, ctx.Err()
		default:
			continue
		}
		if queued {
			break
		}
	}
	if !queued {
		e.mu.RUnlock()
		return MutationPlan{}, ErrNoSlot
	}
	e.mu.RUnlock()
	select {
	case result := <-request.result:
		return result.plan, result.err
	case <-ctx.Done():
		return MutationPlan{}, ctx.Err()
	}
}

// Close stops all execution slots and releases every native QuickJS handle.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		for _, slot := range e.slots {
			close(slot.stop)
		}
		e.mu.Unlock()
		for _, slot := range e.slots {
			<-slot.done
		}
	})
	return nil
}

func runOnThread(fn func()) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	fn()
}

func newScript(source string, opts ScriptOptions) *Script {
	normalized, _ := opts.normalized()
	return &Script{name: normalized.Name, source: source, memoryLimit: normalized.MemoryLimit, stackLimit: normalized.StackLimit, timeout: normalized.Timeout}
}
