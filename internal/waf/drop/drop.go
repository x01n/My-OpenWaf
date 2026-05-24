package drop

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

type DropStats struct {
	TotalDropped  atomic.Int64
	DroppedByBot  atomic.Int64
	DroppedByCVE  atomic.Int64
	DroppedByRule atomic.Int64
	LastDropTime  atomic.Value
}

type DropExecutor struct {
	stats   *DropStats
	enabled bool
	log     *slog.Logger
}

type DropReason struct {
	Source    string
	RuleID    string
	Detail    string
	ClientIP  string
	Host      string
	Path      string
	Timestamp time.Time
}

func NewDropExecutor(enabled bool, log *slog.Logger) *DropExecutor {
	if log == nil {
		log = slog.Default()
	}
	return &DropExecutor{stats: &DropStats{}, enabled: enabled, log: log}
}

func (d *DropExecutor) Enabled() bool { return d.enabled }
func (d *DropExecutor) SetEnabled(v bool) { d.enabled = v }
func (d *DropExecutor) Reconfigure(enabled bool) { d.enabled = enabled }

func (d *DropExecutor) Execute(conn net.Conn, reason DropReason) error {
	if conn == nil {
		return nil
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	err := conn.Close()
	d.recordStats(reason)
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

func (d *DropExecutor) ResetStats() {
	d.stats.TotalDropped.Store(0)
	d.stats.DroppedByBot.Store(0)
	d.stats.DroppedByCVE.Store(0)
	d.stats.DroppedByRule.Store(0)
	d.stats.LastDropTime.Store(time.Time{})
}
