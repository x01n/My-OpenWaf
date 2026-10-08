package realtime

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

/*
本文件的两条用例原先位于 internal/admin/system/system_misc_test.go，
随 realtime 文件组迁出后一并移入本包，断言内容未改。
*/

func TestRealtimeTicketHandlerIssuesUniqueTickets(t *testing.T) {
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)

	seen := make(map[string]struct{}, 3)
	for i := 0; i < 3; i++ {
		ctx := invokeRealtimeHandler(t, hub.TicketHandler(), "POST", "/api/v1/realtime/ticket", nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("ticket status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp struct {
			Ticket    string `json:"ticket"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode ticket response: %v", err)
		}
		if len(resp.Ticket) != 64 {
			t.Fatalf("ticket length = %d, want 64 hex chars", len(resp.Ticket))
		}
		if resp.ExpiresAt == "" {
			t.Fatalf("ticket response must carry an expiry")
		}
		if _, dup := seen[resp.Ticket]; dup {
			t.Fatalf("ticket %q was issued twice", resp.Ticket)
		}
		seen[resp.Ticket] = struct{}{}
	}

	// 签发的票据必须可被一次性消费。
	for ticket := range seen {
		if !hub.consumeTicket(ticket) {
			t.Fatalf("issued ticket %q could not be consumed", ticket)
		}
		if hub.consumeTicket(ticket) {
			t.Fatalf("ticket %q must not be consumable twice", ticket)
		}
	}
}

func TestRandomTicketProducesDistinctHexStrings(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		ticket := randomTicket()
		if len(ticket) != 64 {
			t.Fatalf("ticket length = %d, want 64", len(ticket))
		}
		if strings.Trim(ticket, "0123456789abcdef") != "" {
			t.Fatalf("ticket %q is not lowercase hex", ticket)
		}
		if _, dup := seen[ticket]; dup {
			t.Fatalf("randomTicket produced a duplicate: %q", ticket)
		}
		seen[ticket] = struct{}{}
	}
}

func TestRealtimeHubHasSubscribersWithoutClients(t *testing.T) {
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)
	for _, topic := range []string{"dashboard", "access_logs", "security_events"} {
		if hub.hasSubscribers(topic) {
			t.Fatalf("topic %q reports subscribers on a fresh hub", topic)
		}
	}
}
