package upstream

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type State struct {
	Healthy   bool
	CheckedAt time.Time
	FailCount int
}

type Pool struct {
	mu     sync.RWMutex
	states map[string]State
}

type ProbeFunc func(context.Context, string) error

func NewPool() *Pool {
	return &Pool{states: make(map[string]State)}
}

func (p *Pool) Pick(urls []string, next func(uint32) uint32) (string, bool) {
	if len(urls) == 0 {
		return "", false
	}
	start := int(next(uint32(len(urls))))
	for offset := range urls {
		idx := (start + offset) % len(urls)
		candidate := urls[idx]
		if p.IsAvailable(candidate) {
			return candidate, true
		}
	}
	return urls[start], true
}

func (p *Pool) IsAvailable(raw string) bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	st, ok := p.states[raw]
	p.mu.RUnlock()
	return !ok || st.Healthy
}

func (p *Pool) Mark(raw string, err error) {
	if p == nil || raw == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.states[raw]
	st.CheckedAt = time.Now()
	if err == nil {
		st.Healthy = true
		st.FailCount = 0
	} else {
		st.FailCount++
		st.Healthy = st.FailCount < 2
	}
	p.states[raw] = st
}

func (p *Pool) Snapshot() map[string]State {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]State, len(p.states))
	for k, v := range p.states {
		out[k] = v
	}
	return out
}

func (p *Pool) Probe(ctx context.Context, urls []string, probe ProbeFunc) {
	if p == nil || probe == nil {
		return
	}
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		key := Normalize(raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.Mark(raw, probe(ctx, raw))
	}
}

func (p *Pool) Start(ctx context.Context, urls func() []string, interval time.Duration, probe ProbeFunc) {
	if p == nil || urls == nil || probe == nil {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	p.Probe(ctx, urls(), probe)
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.Probe(ctx, urls(), probe)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func HTTPProbe(timeout time.Duration) ProbeFunc {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, raw string) error {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, Normalize(raw), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
			return getProbe(client, reqCtx, raw)
		}
		return nil
	}
}

func getProbe(client *http.Client, ctx context.Context, raw string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Normalize(raw), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func Normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
