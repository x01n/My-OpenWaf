package lifecycle

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudwego/hertz/pkg/app/server"
)

// Default graceful shutdown timeout for individual servers.
const defaultShutdownTimeout = 10 * time.Second

// Server is any stoppable server managed by the lifecycle manager.
type Server interface {
	Spin()
	Shutdown(ctx context.Context) error
}

// hertzServer adapts *server.Hertz to the Server interface.
type hertzServer struct{ h *server.Hertz }

func (s *hertzServer) Spin()                              { s.h.Spin() }
func (s *hertzServer) Shutdown(ctx context.Context) error { return s.h.Shutdown(ctx) }

// Manager coordinates startup, shutdown, and signal handling for multiple servers.
type Manager struct {
	log     *slog.Logger
	entries map[string]entry
	mu      sync.Mutex
}

type entry struct {
	name string
	srv  Server
	// tag is an opaque fingerprint used to detect configuration drift.
	// When reconciling, if the tag for an existing name has changed the
	// caller should Remove+Add to restart the server with new settings.
	tag string
}

// New creates a lifecycle manager with the given logger.
func New(log *slog.Logger) *Manager {
	return &Manager{log: log, entries: make(map[string]entry)}
}

// AddHertz registers a Hertz server under a human-readable name.
func (m *Manager) AddHertz(name string, h *server.Hertz) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: &hertzServer{h: h}}
}

// AddHertzWithTag registers a Hertz server with a configuration tag.
// The tag is used for drift detection during reconciliation.
func (m *Manager) AddHertzWithTag(name string, h *server.Hertz, tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: &hertzServer{h: h}, tag: tag}
}

// Add registers a generic server.
func (m *Manager) Add(name string, srv Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: srv}
}

// AddWithTag registers a generic server with a configuration tag for drift detection.
func (m *Manager) AddWithTag(name string, srv Server, tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[name] = entry{name: name, srv: srv, tag: tag}
}

// Tag returns the configuration tag for the named server, or empty string.
func (m *Manager) Tag(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[name]; ok {
		return e.tag
	}
	return ""
}

// Has returns true if a server with the given name is registered.
func (m *Manager) Has(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[name]
	return ok
}

// Names returns all registered server names.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for name := range m.entries {
		out = append(out, name)
	}
	return out
}

// Remove gracefully shuts down and removes a server by name.
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()
	if err := ent.srv.Shutdown(ctx); err != nil {
		m.log.Error("remove shutdown error", slog.String("name", name), slog.Any("err", err))
	} else {
		m.log.Info("server removed", slog.String("name", name))
	}
}

// StartOne starts a single named server in a background goroutine.
func (m *Manager) StartOne(name string) {
	m.mu.Lock()
	ent, ok := m.entries[name]
	m.mu.Unlock()
	if !ok {
		return
	}
	go func() {
		m.log.Info("server starting", slog.String("name", ent.name))
		ent.srv.Spin()
		m.log.Info("server stopped", slog.String("name", ent.name))
	}()
}

// Start spins up all registered servers in background goroutines.
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		go func(ent entry) {
			m.log.Info("server starting", slog.String("name", ent.name))
			ent.srv.Spin()
			m.log.Info("server stopped", slog.String("name", ent.name))
		}(e)
	}
}

// Shutdown gracefully stops all servers with the given context deadline.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var wg sync.WaitGroup
	for _, e := range m.entries {
		wg.Add(1)
		go func(ent entry) {
			defer wg.Done()
			if err := ent.srv.Shutdown(ctx); err != nil {
				m.log.Error("shutdown error", slog.String("name", ent.name), slog.Any("err", err))
			} else {
				m.log.Info("server shutdown complete", slog.String("name", ent.name))
			}
		}(e)
	}
	wg.Wait()
}

// WaitForSignal blocks until SIGINT or SIGTERM, then calls Shutdown.
func (m *Manager) WaitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	m.log.Info("received signal, shutting down", slog.String("signal", s.String()))
	m.Shutdown(context.Background())
}
