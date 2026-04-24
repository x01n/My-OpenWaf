package waf

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// DropStats tracks drop action statistics with atomic counters for concurrency safety.
type DropStats struct {
	TotalDropped  atomic.Int64
	DroppedByBot  atomic.Int64
	DroppedByCVE  atomic.Int64
	DroppedByRule atomic.Int64
	LastDropTime  atomic.Value // stores time.Time
}

// DropExecutor handles TCP connection termination without sending any HTTP response.
type DropExecutor struct {
	stats   *DropStats
	enabled bool
	log     *slog.Logger
}

// DropReason describes why a connection was dropped.
type DropReason struct {
	Source    string // "bot", "cve", "rule", "ip_reputation"
	RuleID    string // rule that triggered the drop
	Detail    string // human-readable explanation
	ClientIP  string
	Host      string
	Path      string
	Timestamp time.Time
}

// NewDropExecutor creates a new DropExecutor.
func NewDropExecutor(enabled bool, log *slog.Logger) *DropExecutor {
	if log == nil {
		log = slog.Default()
	}
	return &DropExecutor{
		stats:   &DropStats{},
		enabled: enabled,
		log:     log,
	}
}

// Enabled returns whether the drop executor is active.
func (d *DropExecutor) Enabled() bool {
	return d.enabled
}

// SetEnabled toggles the drop executor on or off.
func (d *DropExecutor) SetEnabled(v bool) {
	d.enabled = v
}

// Execute closes the TCP connection immediately without writing any response.
// It is safe to call even if conn is nil or already closed.
func (d *DropExecutor) Execute(conn net.Conn, reason DropReason) error {
	if conn == nil {
		return nil
	}

	// Close the connection immediately — no HTTP response is sent.
	err := conn.Close()

	// Record stats regardless of close error (connection may already be closed).
	d.recordStats(reason)

	// Log the drop event.
	d.log.Warn("connection dropped",
		slog.String("source", reason.Source),
		slog.String("rule_id", reason.RuleID),
		slog.String("client_ip", reason.ClientIP),
		slog.String("host", reason.Host),
		slog.String("path", reason.Path),
		slog.String("detail", reason.Detail),
	)

	return err
}

// recordStats updates atomic counters based on the drop reason source.
func (d *DropExecutor) recordStats(reason DropReason) {
	d.stats.TotalDropped.Add(1)
	d.stats.LastDropTime.Store(reason.Timestamp)

	switch reason.Source {
	case "bot":
		d.stats.DroppedByBot.Add(1)
	case "cve":
		d.stats.DroppedByCVE.Add(1)
	case "rule", "ip_reputation":
		d.stats.DroppedByRule.Add(1)
	default:
		d.stats.DroppedByRule.Add(1)
	}
}

// GetStats returns a snapshot of the current drop statistics.
func (d *DropExecutor) GetStats() *DropStats {
	s := &DropStats{}
	s.TotalDropped.Store(d.stats.TotalDropped.Load())
	s.DroppedByBot.Store(d.stats.DroppedByBot.Load())
	s.DroppedByCVE.Store(d.stats.DroppedByCVE.Load())
	s.DroppedByRule.Store(d.stats.DroppedByRule.Load())
	if v := d.stats.LastDropTime.Load(); v != nil {
		s.LastDropTime.Store(v)
	}
	return s
}

// ResetStats clears all drop statistics.
func (d *DropExecutor) ResetStats() {
	d.stats.TotalDropped.Store(0)
	d.stats.DroppedByBot.Store(0)
	d.stats.DroppedByCVE.Store(0)
	d.stats.DroppedByRule.Store(0)
	d.stats.LastDropTime.Store(time.Time{})
}
