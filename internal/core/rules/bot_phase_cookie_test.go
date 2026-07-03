package rules

import (
	"net"
	"testing"
	"time"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/challenge"
)

func TestBotPhaseSkipsChallengeWhenCookieHeaderStoredLowercase(t *testing.T) {
	now := time.Now()
	clientIP := net.ParseIP("203.0.113.10")
	cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{
		Host:      "example.com",
		ClientIP:  clientIP,
		UserAgent: "Mozilla/5.0",
		SiteID:    7,
		Bind:      ":443",
	}, true, now, time.Hour)

	phase := &botPhase{threshold: 80}
	ctx := &pipeline.RequestCtx{
		Bind:      ":443",
		ClientIP:  clientIP,
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		SiteID:    7,
		Headers: map[string]string{
			"cookie": cookie,
		},
	}

	got, stop := phase.Execute(ctx)
	if stop {
		t.Fatalf("bot phase should bypass challenge-pass cookie without stopping, got %#v", got)
	}
	if got.Matched {
		t.Fatalf("bot phase should bypass challenge-pass cookie, got %#v", got)
	}
}
