package lifecycle

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cloudwego/hertz/pkg/app/server"
)

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
	entries []entry
	mu      sync.Mutex
}

type entry struct {
	name string
	srv  Server
}

// New creates a lifecycle manager with the given logger.
func New(log *slog.Logger) *Manager {
	return &Manager{log: log}
}

// AddHertz registers a Hertz server under a human-readable name.
func (m *Manager) AddHertz(name string, h *server.Hertz) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry{name: name, srv: &hertzServer{h: h}})
}

// Add registers a generic server.
func (m *Manager) Add(name string, srv Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry{name: name, srv: srv})
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
