package rules

import (
	"reflect"
	"testing"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot"
)

func TestBotPhaseStoreBotScoreDetailsOnlyForHighRisk(t *testing.T) {
	phase := &botPhase{threshold: 80}
	ctx := &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "suspicious", Score: 50}, bot.BotScore{Total: 50, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil {
		t.Fatal("expected bot score result")
	}
	if ctx.BotScoreResult.Details != "" {
		t.Fatalf("non-high-risk bot score should skip JSON details, got %q", ctx.BotScoreResult.Details)
	}

	ctx = &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "malicious", Score: 90}, bot.BotScore{Total: 90, IsHighRisk: true, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil || ctx.BotScoreResult.Details == "" {
		t.Fatalf("high-risk bot score should keep details: %#v", ctx.BotScoreResult)
	}
}

func TestCtxFromPipelineAddsTLSSNIHeader(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Headers: map[string]string{"User-Agent": "Mozilla/5.0"},
		TLS: bot.TLSClientFingerprint{
			SNI: "login.example.com",
		},
	}

	mc := ctxFromPipeline(ctx)
	if mc.Headers["X-OWAF-TLS-SNI"] != "login.example.com" {
		t.Fatalf("expected uppercase TLS SNI header, got %#v", mc.Headers)
	}
	if mc.Headers["x-owaf-tls-sni"] != "login.example.com" {
		t.Fatalf("expected lowercase TLS SNI header, got %#v", mc.Headers)
	}
	if mc.Headers["User-Agent"] != "Mozilla/5.0" {
		t.Fatalf("expected original headers to be preserved, got %#v", mc.Headers)
	}
}

func TestExtractBodyTargetsSkipsCleanOpaqueBody(t *testing.T) {
	body := []byte("\x10\x14\x10\x17\x18\x02\x22\x76\x0a\x74https://www.baidu.com/link?url=v9rmp7zwgcafttycljbacgyvpcdxksjlxwd0etm4fgm&wd=&eqid=b3bd902700001c8f0000000464a293cd")

	targets := extractBodyTargets(body, "application/x-protobuf")

	if len(targets) != 0 {
		t.Fatalf("clean opaque body targets = %#v, want none", targets)
	}
}

func TestExtractBodyTargetsKeepsSuspiciousOpaqueBody(t *testing.T) {
	body := []byte("\x10\x14\x22\x20<script>alert(1)</script>")

	targets := extractBodyTargets(body, "application/x-protobuf")

	if len(targets) != 1 {
		t.Fatalf("suspicious opaque body targets length = %d, want 1: %#v", len(targets), targets)
	}
	if targets[0] == "" {
		t.Fatal("suspicious opaque body target should not be empty")
	}
}

func TestExtractBodyTargetsRawFallbackForInvalidJSON(t *testing.T) {
	body := []byte("d2hvYW1p\x00whoami")

	targets := extractBodyTargets(body, "application/json")

	if len(targets) != 1 {
		t.Fatalf("invalid JSON raw fallback targets length = %d, want 1: %#v", len(targets), targets)
	}
	if targets[0] != string(body) {
		t.Fatalf("invalid JSON raw fallback target = %#v, want %#v", targets[0], string(body))
	}
}

func TestExtractBodyTargetsDedupesRepeatedFormValues(t *testing.T) {
	body := []byte("first=false&second=false&third=true&fourth=false")

	targets := extractBodyTargets(body, "application/x-www-form-urlencoded")

	want := []string{"false", "first", "second", "true", "third", "fourth"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("form body targets = %#v, want %#v", targets, want)
	}
}

func TestDedupeBodyTargetsPreservesFirstOccurrenceOrder(t *testing.T) {
	targets := []string{"a", "b", "a", "c", "b"}

	got := dedupeBodyTargets(targets)

	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deduped body targets = %#v, want %#v", got, want)
	}
}
