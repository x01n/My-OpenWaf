package system

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/websocket"

	"My-OpenWaf/internal/core/health"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/upstream"
)

const realtimeSchema = "admin.realtime.v1"
const realtimeClientQueueSize = 8

const (
	realtimeTopicDashboard    = "dashboard"
	realtimeTopicRuntime      = "runtime"
	realtimeTopicUpstreams    = "upstreams"
	realtimeTopicAudit        = "audit"
	realtimeTopicFingerprints = "fingerprints"
	realtimeTopicHeartbeat    = "heartbeat"
	realtimeTopicAll          = "all"
)

type RealtimeHub struct {
	dashboard      *DashboardDeps
	upstreams      *upstream.Pool
	health         *health.Checker
	accessLogs     *repository.AccessLogRepo
	securityEvents *repository.SecurityEventRepo
	upgrader       websocket.HertzUpgrader
	seq            atomic.Uint64

	mu      sync.Mutex
	tickets map[string]time.Time
	clients map[*realtimeClient]struct{}
}

type realtimeMessage struct {
	Schema  string `json:"schema"`
	Type    string `json:"type"`
	Seq     uint64 `json:"seq"`
	SentAt  string `json:"sent_at"`
	Payload any    `json:"payload"`
}

type realtimeClient struct {
	conn   *websocket.Conn
	send   chan realtimeMessage
	done   chan struct{}
	topics map[string]struct{}
	once   sync.Once
}

type realtimeAccessLog struct {
	ID                   uint      `json:"id"`
	CreatedAt            time.Time `json:"created_at"`
	SiteID               uint      `json:"site_id"`
	RequestID            string    `json:"request_id"`
	ClientIP             string    `json:"client_ip"`
	Host                 string    `json:"host"`
	Path                 string    `json:"path"`
	QueryString          string    `json:"query_string"`
	Method               string    `json:"method"`
	StatusCode           int       `json:"status_code"`
	WAFAction            string    `json:"waf_action"`
	CacheState           string    `json:"cache_state"`
	Upstream             string    `json:"upstream"`
	UserAgent            string    `json:"user_agent"`
	RequestSize          int64     `json:"request_size"`
	HTTPProtocol         string    `json:"http_protocol"`
	UpstreamHTTPProtocol string    `json:"upstream_http_protocol"`
	TLSVersion           string    `json:"tls_version"`
	TLSSNI               string    `json:"tls_sni"`
	TLSALPN              string    `json:"tls_alpn"`
	TLSJA3Hash           string    `json:"tls_ja3_hash"`
	TLSJA4               string    `json:"tls_ja4"`
	TLSCipherSuites      string    `json:"tls_cipher_suites"`
	TLSExtensions        string    `json:"tls_extensions"`
	TLSCurves            string    `json:"tls_curves"`
	TLSPointFormats      string    `json:"tls_point_formats"`
	HeaderOrder          string    `json:"header_order"`
	UpstreamLatencyMs    int64     `json:"upstream_latency_ms"`
	ResponseSize         int64     `json:"response_size"`
}

type realtimeSecurityEvent struct {
	ID              uint      `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	SiteID          uint      `json:"site_id"`
	RequestID       string    `json:"request_id"`
	ClientIP        string    `json:"client_ip"`
	Host            string    `json:"host"`
	Path            string    `json:"path"`
	Method          string    `json:"method"`
	RuleID          uint      `json:"rule_id"`
	RuleIDStr       string    `json:"rule_id_str"`
	Phase           string    `json:"phase"`
	Action          string    `json:"action"`
	Category        string    `json:"category"`
	MatchDesc       string    `json:"match_desc"`
	TLSVersion      string    `json:"tls_version"`
	TLSSNI          string    `json:"tls_sni"`
	TLSALPN         string    `json:"tls_alpn"`
	TLSJA3Hash      string    `json:"tls_ja3_hash"`
	TLSJA4          string    `json:"tls_ja4"`
	TLSCipherSuites string    `json:"tls_cipher_suites"`
	TLSExtensions   string    `json:"tls_extensions"`
	TLSCurves       string    `json:"tls_curves"`
	TLSPointFormats string    `json:"tls_point_formats"`
	HeaderOrder     string    `json:"header_order"`
	StatusCode      int       `json:"status_code"`
}

type realtimeFingerprintSummary struct {
	TLSJA3Hash      string    `json:"tls_ja3_hash"`
	TLSJA4          string    `json:"tls_ja4"`
	TLSVersion      string    `json:"tls_version"`
	TLSALPN         string    `json:"tls_alpn"`
	TLSSNI          string    `json:"tls_sni"`
	TLSCipherSuites string    `json:"tls_cipher_suites"`
	TLSExtensions   string    `json:"tls_extensions"`
	TLSCurves       string    `json:"tls_curves"`
	TLSPointFormats string    `json:"tls_point_formats"`
	Count           int64     `json:"count"`
	HighRiskCount   int64     `json:"high_risk_count"`
	AvgBotScore     float64   `json:"avg_bot_score"`
	LastSeen        time.Time `json:"last_seen"`
	LastUserAgent   string    `json:"last_user_agent"`
	LastClientIP    string    `json:"last_client_ip"`
	LastHeaderOrder string    `json:"last_header_order"`
}

func NewRealtimeHub(dashboard *DashboardDeps, upstreams *upstream.Pool, healthChecker *health.Checker, accessLogs *repository.AccessLogRepo, securityEvents *repository.SecurityEventRepo) *RealtimeHub {
	return &RealtimeHub{
		dashboard:      dashboard,
		upstreams:      upstreams,
		health:         healthChecker,
		accessLogs:     accessLogs,
		securityEvents: securityEvents,
		upgrader:       websocket.HertzUpgrader{},
		tickets:        make(map[string]time.Time),
		clients:        make(map[*realtimeClient]struct{}),
	}
}

func (h *RealtimeHub) TicketHandler() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ticket := randomTicket()
		expiresAt := time.Now().Add(60 * time.Second)
		h.mu.Lock()
		h.tickets[ticket] = expiresAt
		h.cleanupTicketsLocked(time.Now())
		h.mu.Unlock()
		c.JSON(200, map[string]any{"ticket": ticket, "expires_at": expiresAt.Format(time.RFC3339)})
	}
}

func (h *RealtimeHub) WebSocketHandler() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ticket := string(c.Query("ticket"))
		if !h.consumeTicket(ticket) {
			c.JSON(401, map[string]string{"error": "invalid realtime ticket"})
			return
		}
		topics := parseRealtimeTopics(string(c.Query("topics")))
		if err := h.upgrader.Upgrade(c, func(conn *websocket.Conn) {
			client := h.addClient(conn, topics)
			defer h.removeClient(client)
			client.enqueue(h.message("hello", map[string]any{
				"connection": "established",
				"topics":     realtimeTopicList(topics),
			}))
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}); err != nil {
			return
		}
	}
}

func (h *RealtimeHub) Start(ctx context.Context) {
	dashboardTicker := time.NewTicker(2 * time.Second)
	runtimeTicker := time.NewTicker(5 * time.Second)
	auditTicker := time.NewTicker(3 * time.Second)
	fingerprintTicker := time.NewTicker(15 * time.Second)
	go func() {
		defer dashboardTicker.Stop()
		defer runtimeTicker.Stop()
		defer auditTicker.Stop()
		defer fingerprintTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-dashboardTicker.C:
				if h.hasSubscribers(realtimeTopicDashboard) {
					h.broadcast(realtimeTopicDashboard, h.message("dashboard_snapshot", map[string]any{"dashboard": BuildDashboardSnapshot(h.dashboard)}))
				}
			case <-runtimeTicker.C:
				if h.hasSubscribers(realtimeTopicRuntime) {
					h.broadcast(realtimeTopicRuntime, h.message("runtime_snapshot", map[string]any{"runtime": h.health.StatusSnapshot()}))
				}
				if h.hasSubscribers(realtimeTopicUpstreams) {
					upstreams := BuildUpstreamStatus(h.upstreams)
					h.broadcast(realtimeTopicUpstreams, h.message("upstream_snapshot", map[string]any{"upstreams": map[string]any{"items": upstreams, "total": len(upstreams)}}))
				}
				if h.hasSubscribers(realtimeTopicHeartbeat) {
					h.broadcast(realtimeTopicHeartbeat, h.message("heartbeat", map[string]any{"connection": "active"}))
				}
			case <-auditTicker.C:
				if h.hasSubscribers(realtimeTopicAudit) && h.accessLogs != nil {
					items, total, err := BuildAccessLogSnapshot(h.accessLogs)
					if err == nil {
						h.broadcast(realtimeTopicAudit, h.message("access_log_snapshot", map[string]any{"access_logs": map[string]any{"items": items, "total": total, "page": 1}}))
					}
				}
				if h.hasSubscribers(realtimeTopicAudit) && h.securityEvents != nil {
					items, total, err := BuildSecurityEventSnapshot(h.securityEvents)
					if err == nil {
						h.broadcast(realtimeTopicAudit, h.message("security_event_snapshot", map[string]any{"security_events": map[string]any{"items": items, "total": total, "page": 1}}))
					}
				}
			case <-fingerprintTicker.C:
				if h.hasSubscribers(realtimeTopicFingerprints) && h.accessLogs != nil {
					items, total, err := BuildFingerprintSnapshot(h.accessLogs)
					if err == nil {
						h.broadcast(realtimeTopicFingerprints, h.message("fingerprint_snapshot", map[string]any{"fingerprints": map[string]any{"items": items, "total": total, "page": 1}}))
					}
				}
			}
		}
	}()
}

func BuildAccessLogSnapshot(repo *repository.AccessLogRepo) ([]realtimeAccessLog, int64, error) {
	items, total, err := repo.List(0, 20, repository.AccessLogFilter{})
	if err != nil {
		return nil, 0, err
	}
	return mapAccessLogSnapshot(items), total, nil
}

func BuildSecurityEventSnapshot(repo *repository.SecurityEventRepo) ([]realtimeSecurityEvent, int64, error) {
	items, total, err := repo.List(0, 20, repository.SecurityEventFilter{})
	if err != nil {
		return nil, 0, err
	}
	return mapSecurityEventSnapshot(items), total, nil
}

func BuildFingerprintSnapshot(repo *repository.AccessLogRepo) ([]realtimeFingerprintSummary, int64, error) {
	items, total, err := repo.ListFingerprints(0, 20, repository.FingerprintFilter{})
	if err != nil {
		return nil, 0, err
	}
	return mapFingerprintSnapshot(items), total, nil
}

func mapAccessLogSnapshot(items []store.AccessLog) []realtimeAccessLog {
	out := make([]realtimeAccessLog, 0, len(items))
	for _, item := range items {
		out = append(out, realtimeAccessLog{
			ID:                   item.ID,
			CreatedAt:            item.CreatedAt,
			SiteID:               item.SiteID,
			RequestID:            item.RequestID,
			ClientIP:             item.ClientIP,
			Host:                 item.Host,
			Path:                 item.Path,
			QueryString:          item.QueryString,
			Method:               item.Method,
			StatusCode:           item.StatusCode,
			WAFAction:            item.WAFAction,
			CacheState:           item.CacheState,
			Upstream:             item.Upstream,
			UserAgent:            item.UserAgent,
			RequestSize:          item.RequestSize,
			HTTPProtocol:         item.HTTPProtocol,
			UpstreamHTTPProtocol: item.UpstreamHTTPProtocol,
			TLSVersion:           item.TLSVersion,
			TLSSNI:               item.TLSSNI,
			TLSALPN:              item.TLSALPN,
			TLSJA3Hash:           item.TLSJA3Hash,
			TLSJA4:               item.TLSJA4,
			TLSCipherSuites:      item.TLSCipherSuites,
			TLSExtensions:        item.TLSExtensions,
			TLSCurves:            item.TLSCurves,
			TLSPointFormats:      item.TLSPointFormats,
			HeaderOrder:          item.HeaderOrder,
			UpstreamLatencyMs:    item.UpstreamLatencyMs,
			ResponseSize:         item.ResponseSize,
		})
	}
	return out
}

func mapFingerprintSnapshot(items []repository.FingerprintSummary) []realtimeFingerprintSummary {
	out := make([]realtimeFingerprintSummary, 0, len(items))
	for _, item := range items {
		out = append(out, realtimeFingerprintSummary{
			TLSJA3Hash:      item.TLSJA3Hash,
			TLSJA4:          item.TLSJA4,
			TLSVersion:      item.TLSVersion,
			TLSALPN:         item.TLSALPN,
			TLSSNI:          item.TLSSNI,
			TLSCipherSuites: item.TLSCipherSuites,
			TLSExtensions:   item.TLSExtensions,
			TLSCurves:       item.TLSCurves,
			TLSPointFormats: item.TLSPointFormats,
			Count:           item.Count,
			HighRiskCount:   item.HighRiskCount,
			AvgBotScore:     item.AvgBotScore,
			LastSeen:        item.LastSeen,
			LastUserAgent:   item.LastUserAgent,
			LastClientIP:    item.LastClientIP,
			LastHeaderOrder: item.LastHeaderOrder,
		})
	}
	return out
}

func mapSecurityEventSnapshot(items []store.SecurityEvent) []realtimeSecurityEvent {
	out := make([]realtimeSecurityEvent, 0, len(items))
	for _, item := range items {
		out = append(out, realtimeSecurityEvent{
			ID:              item.ID,
			CreatedAt:       item.CreatedAt,
			SiteID:          item.SiteID,
			RequestID:       item.RequestID,
			ClientIP:        item.ClientIP,
			Host:            item.Host,
			Path:            item.Path,
			Method:          item.Method,
			RuleID:          item.RuleID,
			RuleIDStr:       item.RuleIDStr,
			Phase:           item.Phase,
			Action:          item.Action,
			Category:        item.Category,
			MatchDesc:       item.MatchDesc,
			TLSVersion:      item.TLSVersion,
			TLSSNI:          item.TLSSNI,
			TLSALPN:         item.TLSALPN,
			TLSJA3Hash:      item.TLSJA3Hash,
			TLSJA4:          item.TLSJA4,
			TLSCipherSuites: item.TLSCipherSuites,
			TLSExtensions:   item.TLSExtensions,
			TLSCurves:       item.TLSCurves,
			TLSPointFormats: item.TLSPointFormats,
			HeaderOrder:     item.HeaderOrder,
			StatusCode:      item.StatusCode,
		})
	}
	return out
}

func (h *RealtimeHub) message(kind string, payload any) realtimeMessage {
	return realtimeMessage{
		Schema:  realtimeSchema,
		Type:    kind,
		Seq:     h.seq.Add(1),
		SentAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Payload: payload,
	}
}

func (h *RealtimeHub) addClient(conn *websocket.Conn, topics map[string]struct{}) *realtimeClient {
	client := &realtimeClient{
		conn:   conn,
		send:   make(chan realtimeMessage, realtimeClientQueueSize),
		done:   make(chan struct{}),
		topics: topics,
	}
	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()
	go client.writeLoop()
	return client
}

func (h *RealtimeHub) removeClient(client *realtimeClient) {
	h.mu.Lock()
	delete(h.clients, client)
	h.mu.Unlock()
	client.close()
}

func (h *RealtimeHub) hasSubscribers(topic string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		if client.subscribes(topic) {
			return true
		}
	}
	return false
}

func (h *RealtimeHub) broadcast(topic string, msg realtimeMessage) {
	h.mu.Lock()
	clients := make([]*realtimeClient, 0, len(h.clients))
	for client := range h.clients {
		if client.subscribes(topic) {
			clients = append(clients, client)
		}
	}
	h.mu.Unlock()
	for _, client := range clients {
		if !client.enqueue(msg) {
			h.removeClient(client)
		}
	}
}

func (c *realtimeClient) subscribes(topic string) bool {
	if len(c.topics) == 0 {
		return true
	}
	_, ok := c.topics[topic]
	return ok
}

func parseRealtimeTopics(raw string) map[string]struct{} {
	topics := map[string]struct{}{
		realtimeTopicRuntime:   {},
		realtimeTopicUpstreams: {},
		realtimeTopicHeartbeat: {},
	}
	for _, token := range strings.Split(raw, ",") {
		topic := strings.TrimSpace(token)
		if topic == "" {
			continue
		}
		if topic == realtimeTopicAll {
			return map[string]struct{}{}
		}
		if !isRealtimeTopic(topic) {
			continue
		}
		topics[topic] = struct{}{}
	}
	return topics
}

func isRealtimeTopic(topic string) bool {
	switch topic {
	case realtimeTopicDashboard,
		realtimeTopicRuntime,
		realtimeTopicUpstreams,
		realtimeTopicAudit,
		realtimeTopicFingerprints,
		realtimeTopicHeartbeat:
		return true
	default:
		return false
	}
}

func realtimeTopicList(topics map[string]struct{}) []string {
	if len(topics) == 0 {
		return []string{realtimeTopicAll}
	}
	values := make([]string, 0, len(topics))
	for topic := range topics {
		values = append(values, topic)
	}
	sort.Strings(values)
	return values
}

func (c *realtimeClient) enqueue(msg realtimeMessage) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- msg:
		return true
	default:
		select {
		case <-c.send:
		default:
		}
		select {
		case c.send <- msg:
			return true
		case <-c.done:
			return false
		default:
			return false
		}
	}
}

func (c *realtimeClient) writeLoop() {
	defer c.close()
	for {
		select {
		case <-c.done:
			return
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err := c.conn.WriteJSON(msg); err != nil {
				return
			}
		}
	}
}

func (c *realtimeClient) close() {
	c.once.Do(func() {
		close(c.done)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

func (h *RealtimeHub) consumeTicket(ticket string) bool {
	if ticket == "" {
		return false
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	expiresAt, ok := h.tickets[ticket]
	if !ok || now.After(expiresAt) {
		delete(h.tickets, ticket)
		return false
	}
	delete(h.tickets, ticket)
	return true
}

func (h *RealtimeHub) cleanupTicketsLocked(now time.Time) {
	for ticket, expiresAt := range h.tickets {
		if now.After(expiresAt) {
			delete(h.tickets, ticket)
		}
	}
}

func randomTicket() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
