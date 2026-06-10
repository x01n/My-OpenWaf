package system

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"github.com/hertz-contrib/websocket"
	"gorm.io/gorm"
)

func newRealtimeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}, &store.SecurityEvent{}, &store.BotScoreLog{}); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	return db
}

func newRealtimeTestHubWithTicket(t *testing.T, ticket string) *RealtimeHub {
	t.Helper()
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)
	hub.mu.Lock()
	hub.tickets[ticket] = time.Now().Add(time.Minute)
	hub.mu.Unlock()
	return hub
}

func startRealtimeTestServer(t *testing.T, hub *RealtimeHub) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen realtime test server: %v", err)
	}
	srv := server.Default(server.WithListener(ln))
	srv.NoHijackConnPool = true
	srv.GET("/realtime", hub.WebSocketHandler())
	go srv.Spin()
	deadline := time.Now().Add(time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatalf("realtime test server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func realtimeTestURL(addr string, values url.Values) string {
	return "http://" + addr + "/realtime?" + values.Encode()
}

func dialRealtimeTestWebSocket(t *testing.T, addr string, values url.Values) *websocket.Conn {
	t.Helper()
	c, err := client.NewClient(client.WithDialer(standard.NewDialer()))
	if err != nil {
		t.Fatalf("create realtime websocket client: %v", err)
	}
	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(realtimeTestURL(addr, values))
	req.SetMethod("GET")
	upgrader := &websocket.ClientUpgrader{}
	upgrader.PrepareRequest(req)
	if err := c.Do(context.Background(), req, resp); err != nil {
		t.Fatalf("dial realtime websocket: %v", err)
	}
	conn, err := upgrader.UpgradeResponse(req, resp)
	if err != nil {
		t.Fatalf("upgrade realtime websocket: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

func readRealtimeHello(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	var msg realtimeMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read realtime hello: %v", err)
	}
	if msg.Type != "hello" {
		t.Fatalf("expected hello message, got %s", msg.Type)
	}
	payload, ok := msg.Payload.(map[string]any)
	if !ok {
		t.Fatalf("hello payload should be object, got %#v", msg.Payload)
	}
	if payload["connection"] != "established" {
		t.Fatalf("unexpected hello connection value %#v", payload["connection"])
	}
	return payload
}

func assertRealtimeHelloTopics(t *testing.T, payload map[string]any, want ...string) {
	t.Helper()
	rawTopics, ok := payload["topics"].([]any)
	if !ok {
		t.Fatalf("hello topics should be array, got %#v", payload["topics"])
	}
	got := make(map[string]struct{}, len(rawTopics))
	for _, raw := range rawTopics {
		topic, ok := raw.(string)
		if !ok {
			t.Fatalf("hello topic should be string, got %#v", raw)
		}
		got[topic] = struct{}{}
	}
	if len(got) != len(want) {
		t.Fatalf("hello topics length mismatch: got %#v want %#v", got, want)
	}
	for _, topic := range want {
		if _, ok := got[topic]; !ok {
			t.Fatalf("hello topics missing %s in %#v", topic, got)
		}
	}
}

func TestBuildAccessLogSnapshotUsesDefaultPageAndLightDTO(t *testing.T) {
	db := newRealtimeTestDB(t)
	repo := repository.NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{
			SiteID:             1,
			RequestID:          "req-old",
			ClientIP:           "192.0.2.10",
			Host:               "old.example",
			Path:               "/old",
			Method:             "GET",
			StatusCode:         200,
			WAFAction:          "observe",
			RequestHeaders:     `{"authorization":["secret"]}`,
			RequestBodyPreview: "password=secret",
			ResponseHeaders:    `{"set-cookie":["secret"]}`,
			CreatedAt:          now.Add(-time.Minute),
			UpstreamLatencyMs:  12,
		},
		{
			SiteID:             1,
			RequestID:          "req-new",
			ClientIP:           "192.0.2.11",
			Host:               "new.example",
			Path:               "/new",
			QueryString:        "page=1",
			Method:             "POST",
			StatusCode:         403,
			WAFAction:          "intercept",
			CacheState:         "bypass",
			Upstream:           "https://upstream.example",
			UserAgent:          "ua-new",
			RequestHeaders:     `{"cookie":["secret"]}`,
			RequestBodyPreview: "token=secret",
			RequestSize:        128,
			ResponseHeaders:    `{"authorization":["secret"]}`,
			HTTPProtocol:       "https",
			TLSVersion:         "TLS13",
			TLSSNI:             "new.example",
			TLSALPN:            "h2",
			TLSJA3:             "full-ja3-string",
			TLSJA3Hash:         "d4f68581a02a302e6ed609df31fc84cd",
			TLSJA4:             "t13i191000_9dc949149365_e5728521abd4",
			HeaderOrder:        "Host,User-Agent",
			CreatedAt:          now,
			UpstreamLatencyMs:  34,
			ResponseSize:       256,
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create access logs: %v", err)
	}

	got, total, err := BuildAccessLogSnapshot(repo)
	if err != nil {
		t.Fatalf("build access log snapshot: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("unexpected snapshot total=%d len=%d", total, len(got))
	}
	if got[0].RequestID != "req-new" || got[1].RequestID != "req-old" {
		t.Fatalf("snapshot should use id desc default page, got %#v", got)
	}
	if got[0].HTTPProtocol != "https" || got[0].TLSVersion != "TLS13" || got[0].TLSJA3Hash == "" || got[0].TLSJA4 == "" {
		t.Fatalf("access log realtime dto missed TLS metadata: %#v", got[0])
	}
	if got[0].HeaderOrder != "Host,User-Agent" || got[0].ResponseSize != 256 || got[0].RequestSize != 128 {
		t.Fatalf("access log realtime dto missed size/header metadata: %#v", got[0])
	}
	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal access log dto: %v", err)
	}
	for _, field := range []string{"request_headers", "request_body_preview", "response_headers", "tls_ja3"} {
		if jsonContainsKey(raw, field) {
			t.Fatalf("access log realtime dto leaked %s: %s", field, raw)
		}
	}
}

func TestBuildSecurityEventSnapshotUsesLightDTO(t *testing.T) {
	db := newRealtimeTestDB(t)
	repo := repository.NewSecurityEventRepo(db)
	items := []store.SecurityEvent{
		{
			SiteID:             1,
			RequestID:          "sec-1",
			ClientIP:           "198.51.100.10",
			Host:               "app.example",
			Path:               "/admin",
			Method:             "GET",
			RuleID:             7,
			RuleIDStr:          "owasp:sqli",
			Phase:              "custom",
			Action:             "intercept",
			Category:           "sqli",
			MatchDesc:          "union select",
			RequestHeaders:     `{"authorization":["secret"]}`,
			RequestBodyPreview: "password=secret",
			TLSVersion:         "TLS13",
			TLSSNI:             "sec.example",
			TLSALPN:            "h2",
			TLSJA3:             "full-ja3-string",
			TLSJA3Hash:         "d4f68581a02a302e6ed609df31fc84cd",
			TLSJA4:             "t13i191000_9dc949149365_e5728521abd4",
			HeaderOrder:        "Host,User-Agent",
			StatusCode:         403,
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := BuildSecurityEventSnapshot(repo)
	if err != nil {
		t.Fatalf("build security event snapshot: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "sec-1" {
		t.Fatalf("unexpected security snapshot total=%d items=%#v", total, got)
	}
	if got[0].TLSVersion != "TLS13" || got[0].TLSSNI != "sec.example" || got[0].TLSJA3Hash == "" || got[0].TLSJA4 == "" || got[0].HeaderOrder == "" {
		t.Fatalf("security event realtime dto missed TLS metadata: %#v", got[0])
	}
	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal security event dto: %v", err)
	}
	for _, field := range []string{"request_headers", "request_body_preview", "tls_ja3"} {
		if jsonContainsKey(raw, field) {
			t.Fatalf("security event realtime dto leaked %s: %s", field, raw)
		}
	}
}

func TestBuildFingerprintSnapshotUsesDefaultPage(t *testing.T) {
	db := newRealtimeTestDB(t)
	accessRepo := repository.NewAccessLogRepo(db)
	now := time.Now()
	logs := []store.AccessLog{
		{SiteID: 1, Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", UserAgent: "ua-old", ClientIP: "203.0.113.10", HeaderOrder: "h1,h2", CreatedAt: now.Add(-time.Minute)},
		{SiteID: 1, Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", UserAgent: "ua-new", ClientIP: "203.0.113.11", HeaderOrder: "h2,h1", CreatedAt: now},
		{SiteID: 1, Host: "api.example.com", TLSJA3Hash: "bbb", TLSJA4: "ja4-b", TLSVersion: "TLS12", TLSALPN: "http/1.1", TLSSNI: "api.example.com", UserAgent: "ua-b", ClientIP: "203.0.113.12", HeaderOrder: "h3,h4", CreatedAt: now.Add(-2 * time.Minute)},
		{SiteID: 1, Host: "empty.example", CreatedAt: now},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("create access logs: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", TotalScore: 80, IsHighRisk: true, CreatedAt: now}).Error; err != nil {
		t.Fatalf("create bot score: %v", err)
	}

	got, total, err := BuildFingerprintSnapshot(accessRepo)
	if err != nil {
		t.Fatalf("build fingerprint snapshot: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("expected two fingerprint groups, total=%d items=%#v", total, got)
	}
	if got[0].TLSJA3Hash != "aaa" || got[0].Count != 2 || got[0].HighRiskCount != 1 || got[0].AvgBotScore != 80 {
		t.Fatalf("unexpected first fingerprint aggregate: %#v", got[0])
	}
	if got[0].LastUserAgent != "ua-new" || got[0].LastClientIP != "203.0.113.11" {
		t.Fatalf("expected latest client details, got %#v", got[0])
	}
}

func TestConsumeTicketConsumesValidTicketOnce(t *testing.T) {
	hub := &RealtimeHub{
		tickets: map[string]time.Time{
			"ticket-1": time.Now().Add(time.Minute),
		},
	}

	if hub.consumeTicket("") {
		t.Fatalf("empty ticket should be rejected")
	}
	if !hub.consumeTicket("ticket-1") {
		t.Fatalf("valid ticket should be accepted")
	}
	if _, ok := hub.tickets["ticket-1"]; ok {
		t.Fatalf("accepted ticket should be deleted")
	}
	if hub.consumeTicket("ticket-1") {
		t.Fatalf("ticket should be single-use")
	}
}

func TestConsumeTicketRejectsExpiredTicketAndDeletesIt(t *testing.T) {
	fresh := time.Now().Add(time.Minute)
	hub := &RealtimeHub{
		tickets: map[string]time.Time{
			"expired": time.Now().Add(-time.Minute),
			"fresh":   fresh,
		},
	}

	if hub.consumeTicket("expired") {
		t.Fatalf("expired ticket should be rejected")
	}
	if _, ok := hub.tickets["expired"]; ok {
		t.Fatalf("expired ticket should be deleted")
	}
	if got := hub.tickets["fresh"]; !got.Equal(fresh) {
		t.Fatalf("fresh ticket should remain, got %v want %v", got, fresh)
	}
	if hub.consumeTicket("unknown") {
		t.Fatalf("unknown ticket should be rejected")
	}
	if _, ok := hub.tickets["fresh"]; !ok {
		t.Fatalf("unknown ticket should not delete other tickets")
	}
}

func TestCleanupTicketsLockedDeletesOnlyExpiredTickets(t *testing.T) {
	now := time.Now()
	hub := &RealtimeHub{
		tickets: map[string]time.Time{
			"expired": now.Add(-time.Nanosecond),
			"at-now":  now,
			"fresh":   now.Add(time.Minute),
		},
	}

	hub.mu.Lock()
	hub.cleanupTicketsLocked(now)
	hub.mu.Unlock()

	if _, ok := hub.tickets["expired"]; ok {
		t.Fatalf("expired ticket should be deleted")
	}
	for _, key := range []string{"at-now", "fresh"} {
		if _, ok := hub.tickets[key]; !ok {
			t.Fatalf("%s ticket should remain", key)
		}
	}
}

func TestRealtimeClientEnqueueDropsOldestMessageWhenQueueIsFull(t *testing.T) {
	client := &realtimeClient{
		send: make(chan realtimeMessage, realtimeClientQueueSize),
		done: make(chan struct{}),
	}
	for i := 0; i < realtimeClientQueueSize; i++ {
		if !client.enqueue(realtimeMessage{Type: "old", Seq: uint64(i)}) {
			t.Fatalf("enqueue old message %d failed", i)
		}
	}

	if !client.enqueue(realtimeMessage{Type: "new", Seq: 999}) {
		t.Fatalf("enqueue should keep new message when queue is full")
	}
	if len(client.send) != realtimeClientQueueSize {
		t.Fatalf("queue length should remain capped, got %d", len(client.send))
	}
	var messages []realtimeMessage
	for len(client.send) > 0 {
		messages = append(messages, <-client.send)
	}
	if messages[0].Seq != 1 || messages[len(messages)-1].Seq != 999 {
		t.Fatalf("queue should drop one old message and keep new message: %#v", messages)
	}
}

func TestRealtimeClientEnqueueReturnsFalseAfterClose(t *testing.T) {
	client := &realtimeClient{
		send: make(chan realtimeMessage, realtimeClientQueueSize),
		done: make(chan struct{}),
	}
	client.close()
	client.close()

	if client.enqueue(realtimeMessage{Type: "after-close"}) {
		t.Fatalf("closed client should reject enqueue")
	}
}

func TestBroadcastSendsOnlyMessagesAllowedByClientSubscription(t *testing.T) {
	dashboardClient := &realtimeClient{
		send:   make(chan realtimeMessage, realtimeClientQueueSize),
		done:   make(chan struct{}),
		topics: map[string]struct{}{realtimeTopicDashboard: {}},
	}
	auditClient := &realtimeClient{
		send:   make(chan realtimeMessage, realtimeClientQueueSize),
		done:   make(chan struct{}),
		topics: map[string]struct{}{realtimeTopicAudit: {}},
	}
	allClient := &realtimeClient{
		send: make(chan realtimeMessage, realtimeClientQueueSize),
		done: make(chan struct{}),
	}
	closedClient := &realtimeClient{
		send:   make(chan realtimeMessage, realtimeClientQueueSize),
		done:   make(chan struct{}),
		topics: map[string]struct{}{realtimeTopicDashboard: {}},
	}
	closedClient.close()
	hub := &RealtimeHub{
		clients: map[*realtimeClient]struct{}{
			dashboardClient: {},
			auditClient:     {},
			allClient:       {},
			closedClient:    {},
		},
	}

	hub.broadcast(realtimeTopicDashboard, realtimeMessage{Type: "dashboard_snapshot"})

	if len(dashboardClient.send) != 1 {
		t.Fatalf("dashboard client should receive dashboard message")
	}
	if len(auditClient.send) != 0 {
		t.Fatalf("audit-only client should not receive dashboard message")
	}
	if len(allClient.send) != 1 {
		t.Fatalf("client without explicit topics should receive dashboard message")
	}
	if _, ok := hub.clients[closedClient]; ok {
		t.Fatalf("closed client should be removed after enqueue failure")
	}
}

func TestWebSocketHandlerRejectsInvalidTicket(t *testing.T) {
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)
	addr := startRealtimeTestServer(t, hub)
	c, err := client.NewClient(client.WithDialer(standard.NewDialer()))
	if err != nil {
		t.Fatalf("create realtime http client: %v", err)
	}
	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()
	defer protocol.ReleaseRequest(req)
	defer protocol.ReleaseResponse(resp)
	req.SetRequestURI(realtimeTestURL(addr, url.Values{"ticket": {"missing"}}))
	req.SetMethod("GET")
	if err := c.Do(context.Background(), req, resp); err != nil {
		t.Fatalf("request realtime websocket with invalid ticket: %v", err)
	}
	if resp.StatusCode() != 401 {
		t.Fatalf("invalid ticket status = %d, want 401", resp.StatusCode())
	}
	if got := jsonStringValue(resp.Body(), "error"); got != "invalid realtime ticket" {
		t.Fatalf("invalid ticket error = %q, want invalid realtime ticket", got)
	}
}

func TestWebSocketHandlerHelloIncludesParsedTopics(t *testing.T) {
	ticket := "ticket-with-topics"
	hub := newRealtimeTestHubWithTicket(t, ticket)
	addr := startRealtimeTestServer(t, hub)
	conn := dialRealtimeTestWebSocket(t, addr, url.Values{
		"ticket": {ticket},
		"topics": {"audit,unknown,fingerprints"},
	})
	payload := readRealtimeHello(t, conn)
	assertRealtimeHelloTopics(t, payload,
		realtimeTopicAudit,
		realtimeTopicFingerprints,
		realtimeTopicHeartbeat,
		realtimeTopicRuntime,
		realtimeTopicUpstreams,
	)
	if hub.consumeTicket(ticket) {
		t.Fatalf("websocket handler should consume ticket once")
	}
}

func TestWebSocketHandlerHelloTopicsAllDisablesFiltering(t *testing.T) {
	ticket := "ticket-all-topics"
	hub := newRealtimeTestHubWithTicket(t, ticket)
	addr := startRealtimeTestServer(t, hub)
	conn := dialRealtimeTestWebSocket(t, addr, url.Values{
		"ticket": {ticket},
		"topics": {realtimeTopicAll},
	})
	payload := readRealtimeHello(t, conn)
	assertRealtimeHelloTopics(t, payload, realtimeTopicAll)
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.clients) != 1 {
		t.Fatalf("expected one realtime client, got %d", len(hub.clients))
	}
	for client := range hub.clients {
		if len(client.topics) != 0 {
			t.Fatalf("all topic should disable filtering, got %#v", realtimeTopicList(client.topics))
		}
	}
}

func TestWebSocketHandlerHelloUsesRuntimeDefaultsWhenTopicsOmitted(t *testing.T) {
	ticket := "ticket-default-topics"
	hub := newRealtimeTestHubWithTicket(t, ticket)
	addr := startRealtimeTestServer(t, hub)
	conn := dialRealtimeTestWebSocket(t, addr, url.Values{"ticket": {ticket}})
	payload := readRealtimeHello(t, conn)
	assertRealtimeHelloTopics(t, payload,
		realtimeTopicHeartbeat,
		realtimeTopicRuntime,
		realtimeTopicUpstreams,
	)
}

func TestRealtimeTopicParsingKeepsRuntimeDefaultsAndFiltersUnknownValues(t *testing.T) {
	topics := parseRealtimeTopics("audit,unknown,fingerprints")
	for _, topic := range []string{
		realtimeTopicRuntime,
		realtimeTopicUpstreams,
		realtimeTopicHeartbeat,
		realtimeTopicAudit,
		realtimeTopicFingerprints,
	} {
		if _, ok := topics[topic]; !ok {
			t.Fatalf("expected topic %s in parsed set %#v", topic, realtimeTopicList(topics))
		}
	}
	if _, ok := topics["unknown"]; ok {
		t.Fatalf("unknown topic should be ignored")
	}
}

func TestRealtimeTopicParsingAllDisablesFiltering(t *testing.T) {
	topics := parseRealtimeTopics("audit,all")
	if len(topics) != 0 {
		t.Fatalf("all topic should return empty set for compatibility, got %#v", realtimeTopicList(topics))
	}
}

func jsonContainsKey(raw []byte, key string) bool {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	_, ok := value[key]
	return ok
}

func jsonStringValue(raw []byte, key string) string {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	text, _ := value[key].(string)
	return text
}
