package rules

import (
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
