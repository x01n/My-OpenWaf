package upstream

import (
	"context"
	"sort"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/upstream"
)

type UpstreamStatusItem struct {
	URL                string `json:"url"`
	ConfiguredProtocol string `json:"configured_protocol,omitempty"`
	LastHTTPProtocol   string `json:"last_http_protocol,omitempty"`
	Healthy            bool   `json:"healthy"`
	FailCount          int    `json:"fail_count"`
	LastFailureKind    string `json:"last_failure_kind,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	LastLatencyMs      int64  `json:"last_latency_ms"`
	AverageLatencyMs   int64  `json:"average_latency_ms"`
	CheckedAt          string `json:"checked_at,omitempty"`
	LastSuccessAt      string `json:"last_success_at,omitempty"`
}

func UpstreamStatus(pool *upstream.Pool) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items := BuildUpstreamStatus(pool)
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

func BuildUpstreamStatus(pool *upstream.Pool) []UpstreamStatusItem {
	states := pool.Snapshot()
	items := make([]UpstreamStatusItem, 0, len(states))
	for raw, st := range states {
		item := UpstreamStatusItem{
			URL:                raw,
			ConfiguredProtocol: upstream.ConfiguredProtocol(raw),
			LastHTTPProtocol:   st.LastHTTPProtocol,
			Healthy:            st.Healthy,
			FailCount:          st.FailCount,
			LastFailureKind:    st.LastFailureKind,
			LastError:          st.LastError,
			LastLatencyMs:      st.LastLatencyMs,
			AverageLatencyMs:   st.AverageLatencyMs,
		}
		if !st.CheckedAt.IsZero() {
			item.CheckedAt = st.CheckedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		if !st.LastSuccessAt.IsZero() {
			item.LastSuccessAt = st.LastSuccessAt.Format("2006-01-02T15:04:05Z07:00")
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].URL < items[j].URL })
	return items
}
