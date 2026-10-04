package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudwego/hertz/pkg/app/server"
)

// defaultShutdownTimeout 是单个服务器的默认优雅关闭超时。
const defaultShutdownTimeout = 10 * time.Second

// 热重载移除必须尽快归还调用方；完整进程关闭则沿用上面的较长超时。
const defaultRemoveShutdownTimeout = 500 * time.Millisecond

const hertzEngineNotRunningError = "engine is not running"

// Server 是生命周期管理器管辖的任意可停止服务器。
type Server interface {
	Spin()
	Shutdown(ctx context.Context) error
}

// Readiness 报告服务器是否已完成监听启动。
type Readiness interface {
	Ready() bool
	Err() error
}

// hertzServer 把 *server.Hertz 适配到 Server 接口。
type hertzServer struct {
	h    *server.Hertz
	done chan struct{}
}

func (s *hertzServer) Spin() {
	defer close(s.done)
	s.h.Spin()
}
func (s *hertzServer) Shutdown(ctx context.Context) error { return s.h.Shutdown(ctx) }
func (s *hertzServer) Ready() bool                        { return s.h.IsRunning() }
func (s *hertzServer) Err() error {
	if s.Ready() {
		return nil
	}
	select {
	case <-s.done:
		return fmt.Errorf("hertz server stopped before becoming ready")
	default:
		return nil
	}
}

func serverAlreadyStopped(err error) bool {
	return err != nil && strings.TrimSpace(err.Error()) == hertzEngineNotRunningError
}

// Manager 协调多个服务器的启动、关闭与信号处理。
type Manager struct {
	log     *slog.Logger
	entries map[string]entry
	mu      sync.Mutex
}

type entry struct {
	name string
	srv  Server
	// tag 是用于检测配置漂移的不透明指纹。调谐时，若已存在同名服务器的
	// tag 发生变化，调用方应当执行 Remove+Add，用新配置重启该服务器。
	tag string
}

// New 使用给定日志器创建生命周期管理器。
func New(log *slog.Logger) *Manager {
	return &Manager{log: log, entries: make(map[string]entry)}
}

// AddHertz 以可读名称注册一个 Hertz 服务器。
func (m *Manager) AddHertz(name string, h *server.Hertz) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: &hertzServer{h: h, done: make(chan struct{})}}
}

// AddHertzWithTag 注册带配置标签的 Hertz 服务器。
// 标签用于调谐时的漂移检测。
func (m *Manager) AddHertzWithTag(name string, h *server.Hertz, tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: &hertzServer{h: h, done: make(chan struct{})}, tag: tag}
}

// Add 注册一个通用服务器。
func (m *Manager) Add(name string, srv Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: srv}
}

// AddWithTag 注册带配置标签的通用服务器，标签用于漂移检测。
func (m *Manager) AddWithTag(name string, srv Server, tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: srv, tag: tag}
}

// Tag 返回具名服务器的配置标签，不存在时返回空字符串。
func (m *Manager) Tag(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[name]; ok {
		return e.tag
	}
	return ""
}

// Has 报告是否已注册给定名称的服务器。
func (m *Manager) Has(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[name]
	return ok
}

// Names 返回全部已注册服务器的名称。
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for name := range m.entries {
		out = append(out, name)
	}
	return out
}

// Remove 优雅关闭并按名称移除一个服务器。
func (m *Manager) Remove(name string) {
	m.mu.Lock()
	ent, ok := m.entries[name]
	if ok {
		delete(m.entries, name)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	m.log.Info("removing server", slog.String("name", name))
	ctx, cancel := context.WithTimeout(context.Background(), defaultRemoveShutdownTimeout)
	defer cancel()
	if err := ent.srv.Shutdown(ctx); err != nil {
		if serverAlreadyStopped(err) {
			m.log.Info("server removed", slog.String("name", name))
			return
		}
		m.log.Error("remove shutdown error", slog.String("name", name), slog.Any("err", err))
	} else {
		m.log.Info("server removed", slog.String("name", name))
	}
}

// StartOne 在后台 goroutine 中启动单个具名服务器。
func (m *Manager) StartOne(name string) error {
	m.mu.Lock()
	ent, ok := m.entries[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("server %q is not registered", name)
	}
	go func() {
		m.log.Info("server starting", slog.String("name", ent.name))
		ent.srv.Spin()
		m.log.Info("server stopped", slog.String("name", ent.name))
	}()
	return waitReady(name, ent.srv)
}

// Start 在后台 goroutine 中启动全部已注册服务器。
func (m *Manager) Start() error {
	m.mu.Lock()
	entries := make([]entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
		go func(ent entry) {
			m.log.Info("server starting", slog.String("name", ent.name))
			ent.srv.Spin()
			m.log.Info("server stopped", slog.String("name", ent.name))
		}(e)
	}
	m.mu.Unlock()
	for _, e := range entries {
		if err := waitReady(e.name, e.srv); err != nil {
			return err
		}
	}
	return nil
}

func waitReady(name string, srv Server) error {
	status, ok := srv.(Readiness)
	if !ok {
		return nil
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if status.Ready() {
			return nil
		}
		if err := status.Err(); err != nil {
			return fmt.Errorf("server %q failed to become ready: %w", name, err)
		}
		select {
		case <-deadline.C:
			return fmt.Errorf("server %q did not become ready", name)
		case <-ticker.C:
		}
	}
}

// Ready 仅在全部已注册服务器都报告监听就绪时才返回 true。
func (m *Manager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) == 0 {
		return false
	}
	for _, ent := range m.entries {
		status, ok := ent.srv.(Readiness)
		if !ok || !status.Ready() {
			return false
		}
	}
	return true
}

// Shutdown 按给定 context 截止时间优雅停止全部服务器。
func (m *Manager) Shutdown(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, defaultShutdownTimeout)
	defer cancel()

	m.mu.Lock()
	entries := make([]entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func(ent entry) {
			defer wg.Done()
			if err := ent.srv.Shutdown(shutdownCtx); err != nil {
				if serverAlreadyStopped(err) {
					m.log.Info("server shutdown complete", slog.String("name", ent.name))
					return
				}
				m.log.Error("shutdown error", slog.String("name", ent.name), slog.Any("err", err))
			} else {
				m.log.Info("server shutdown complete", slog.String("name", ent.name))
			}
		}(e)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-shutdownCtx.Done():
		m.log.Warn("shutdown deadline exceeded", slog.Any("err", shutdownCtx.Err()))
	}
}

// WaitForSignal 阻塞直到收到 SIGINT 或 SIGTERM，然后调用 Shutdown。
func (m *Manager) WaitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	m.log.Info("received signal, shutting down", slog.String("signal", s.String()))
	ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()
	m.Shutdown(ctx)
}
