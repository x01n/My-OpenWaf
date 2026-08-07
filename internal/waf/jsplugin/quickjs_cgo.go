//go:build cgo

package jsplugin

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quickjs "github.com/buke/quickjs-go"
)

// Compile validates a QuickJS plugin and returns an immutable script descriptor.
func Compile(name, source string, opts ScriptOptions) (*Script, error) {
	if len(source) == 0 {
		return nil, errors.New("jsplugin: script source is empty")
	}
	if len(source) > MaxScriptBytes {
		return nil, fmt.Errorf("jsplugin: script exceeds %d bytes", MaxScriptBytes)
	}
	if !strings.Contains(source, "export default") {
		return nil, errors.New("jsplugin: script must export default")
	}
	requestedTimeout := opts.Timeout
	normalized, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	if err := validateSource(source, normalized.MemoryLimit, normalized.StackLimit, normalized.Timeout); err != nil {
		return nil, err
	}
	siteIDs := make(map[uint]bool, len(normalized.SiteIDs))
	for _, id := range normalized.SiteIDs {
		siteIDs[id] = true
	}
	return &Script{
		name:            normalized.Name,
		source:          source,
		siteIDs:         siteIDs,
		memoryLimit:     normalized.MemoryLimit,
		stackLimit:      normalized.StackLimit,
		timeout:         normalized.Timeout,
		timeoutOverride: requestedTimeout != 0,
	}, nil
}

func validateSource(source string, memoryLimit, stackLimit uint64, timeout time.Duration) error {
	var result error
	runOnThread(func() {
		rt := quickjs.NewRuntime(
			quickjs.WithMemoryLimit(memoryLimit),
			quickjs.WithMaxStackSize(stackLimit),
			quickjs.WithModuleImport(false),
			quickjs.WithOwnerGoroutineCheck(true),
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
		result = validateInContext(ctx, source)
	})
	return result
}

func validateInContext(ctx *quickjs.Context, source string) error {
	result := ctx.Eval(transformedSource(source), quickjs.EvalFileName("<js-plugin>"))
	if result == nil {
		return errors.New("jsplugin: QuickJS evaluation failed")
	}
	defer result.Free()
	if result.IsException() {
		if err := ctx.Exception(); err != nil {
			return fmt.Errorf("jsplugin: compile failed: %w", err)
		}
		return errors.New("jsplugin: compile failed")
	}
	plugin := ctx.Globals().Get("__owaf_plugin")
	if plugin == nil {
		return errors.New("jsplugin: default export is missing")
	}
	defer plugin.Free()
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

func transformedSource(source string) string {
	return "globalThis.__owaf_plugin = undefined;\n" + strings.Replace(source, "export default", "globalThis.__owaf_plugin =", 1)
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
	ctx    context.Context
	script *Script
	req    RequestSnapshot
	result chan executionResult
}

type executionResult struct {
	plan MutationPlan
	err  error
}

type executionSlot struct {
	requests chan executionRequest
	stop     chan struct{}
	ready    chan error
	done     chan struct{}
	rt       *quickjs.Runtime
	ctx      *quickjs.Context
}

func (s *executionSlot) run(opts EngineOptions) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.rt = quickjs.NewRuntime(
		quickjs.WithMemoryLimit(opts.MemoryLimit),
		quickjs.WithMaxStackSize(opts.StackLimit),
		quickjs.WithModuleImport(false),
		quickjs.WithOwnerGoroutineCheck(true),
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
	s.ready <- nil
	defer func() {
		s.ctx.Close()
		s.rt.Close()
		close(s.done)
	}()
	for {
		select {
		case request := <-s.requests:
			s.execute(request, opts)
		case <-s.stop:
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
	plan, err := s.evaluate(request.script, request.req)
	if timedOut.Load() {
		request.script.timeouts.Add(1)
		err = ErrScriptTimeout
		plan = MutationPlan{}
	}
	if err != nil {
		request.script.failures.Add(1)
		plan = MutationPlan{}
	}
	request.result <- executionResult{plan: plan, err: err}
}

func (s *executionSlot) evaluate(script *Script, req RequestSnapshot) (MutationPlan, error) {
	if err := validateInContext(s.ctx, script.source); err != nil {
		return MutationPlan{}, err
	}
	plugin := s.ctx.Globals().Get("__owaf_plugin")
	if plugin == nil {
		return MutationPlan{}, errors.New("jsplugin: default export is missing")
	}
	defer plugin.Free()
	fetch := plugin.Get("fetch")
	if fetch == nil {
		return MutationPlan{}, errors.New("jsplugin: default export fetch is missing")
	}
	defer fetch.Free()
	requestValue, err := s.ctx.Marshal(req)
	if err != nil {
		return MutationPlan{}, err
	}
	defer requestValue.Free()
	env := s.ctx.NewObject()
	defer env.Free()
	hostCtx := s.ctx.NewObject()
	defer hostCtx.Free()
	result := fetch.Execute(plugin, requestValue, env, hostCtx)
	if result == nil {
		return MutationPlan{}, errors.New("jsplugin: fetch invocation failed")
	}
	if result.IsPromise() {
		result = s.ctx.Await(result)
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
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return MutationPlan{}, ErrEngineClosed
	}
	slot := e.slots[e.next.Add(1)%uint64(len(e.slots))]
	request := executionRequest{ctx: ctx, script: script, req: req, result: make(chan executionResult, 1)}
	select {
	case slot.requests <- request:
		e.mu.RUnlock()
	case <-ctx.Done():
		e.mu.RUnlock()
		return MutationPlan{}, ctx.Err()
	default:
		e.mu.RUnlock()
		return MutationPlan{}, ErrNoSlot
	}
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
