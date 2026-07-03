package engine

import (
	"testing"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
)

func newTestHolder(prot store.ProtectionConfig, rules []snapshot.CompiledRule) *snapshot.Holder {
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "example.com"): {
				Site:     store.Site{ID: 1, Host: "example.com", Bind: ":80"},
				Bind:     ":80",
				PolicyID: 1,
				Rules:    rules,
			},
		},
		Protection: prot,
	})
	return holder
}

func TestProcessChecksACLBlacklistBeforeBuiltinDetectors(t *testing.T) {
	prot := store.DefaultProtectionConfig()
	prot.OWASPEnabled = true
	prot.OWASPAction = "drop"
	holder := newTestHolder(prot, []snapshot.CompiledRule{
		{ID: 10, Phase: store.PhaseACL, Kind: "block_path", Arg: "/admin", Action: store.ActionRateLimit, Priority: 1},
	})

	eng := New(holder, nil, nil, nil)
	result := eng.Process(&pipeline.RequestCtx{
		Bind:     ":80",
		Host:     "example.com",
		Path:     "/admin",
		RawQuery: "q=union select password from users",
		Headers:  map[string]string{},
	})

	if result.Action.Type != action.RateLimit {
		t.Fatalf("expected ACL action to run before OWASP, got %q", result.Action.Type)
	}
	if result.Action.ResponseStatusCode() != 429 {
		t.Fatalf("expected ACL rate_limit status 429, got %d", result.Action.ResponseStatusCode())
	}
}

func TestProcessHonorsACLPriorityBeforeAllow(t *testing.T) {
	prot := store.DefaultProtectionConfig()
	holder := newTestHolder(prot, []snapshot.CompiledRule{
		{ID: 10, Phase: store.PhaseACL, Kind: "block_path", Arg: "/admin", Action: store.ActionIntercept, Priority: 1},
		{ID: 20, Phase: store.PhaseACL, Kind: "allow_ip", Arg: "1.2.3.4", Action: store.ActionAllow, Priority: 100},
	})

	eng := New(holder, nil, nil, nil)
	result := eng.Process(&pipeline.RequestCtx{
		Bind:     ":80",
		Host:     "example.com",
		Path:     "/admin",
		ClientIP: []byte{1, 2, 3, 4},
		Headers:  map[string]string{},
	})

	if result.Action.Type != action.Intercept {
		t.Fatalf("expected higher-priority ACL intercept to win, got %q", result.Action.Type)
	}
	if result.Action.RuleID != 10 {
		t.Fatalf("expected intercept rule id 10, got %d", result.Action.RuleID)
	}
}

func TestProcessKeepsHigherPriorityCustomObserveAuditBeforeLaterIntercept(t *testing.T) {
	prot := store.DefaultProtectionConfig()
	holder := newTestHolder(prot, []snapshot.CompiledRule{
		{ID: 10, Phase: store.PhaseCustom, Kind: "block_path", Arg: "/admin", Action: store.ActionObserve, Priority: 1},
		{ID: 20, Phase: store.PhaseCustom, Kind: "block_path", Arg: "/admin", Action: store.ActionIntercept, Priority: 2},
	})

	eng := New(holder, nil, nil, nil)
	result := eng.Process(&pipeline.RequestCtx{
		Bind:    ":80",
		Host:    "example.com",
		Path:    "/admin",
		Headers: map[string]string{},
	})

	if result.Action.Type != action.Intercept {
		t.Fatalf("later terminal custom rule should win, got %#v", result.Action)
	}
	if result.Action.RuleID != 20 {
		t.Fatalf("terminal rule id = %d, want 20", result.Action.RuleID)
	}
	if len(result.ObserveHits) != 1 {
		t.Fatalf("observe hits length = %d, want 1", len(result.ObserveHits))
	}
	if result.ObserveHits[0].Type != action.Observe {
		t.Fatalf("observe hit type = %q, want %q", result.ObserveHits[0].Type, action.Observe)
	}
	if result.ObserveHits[0].RuleID != 10 {
		t.Fatalf("observe hit rule id = %d, want 10", result.ObserveHits[0].RuleID)
	}
}

func TestProcessDoesNotReuseAntiReplayPhaseAcrossSitesWithSamePolicy(t *testing.T) {
	prot := store.DefaultProtectionConfig()
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "disabled.example.com"): {
				Site:              store.Site{ID: 1, Host: "disabled.example.com", Bind: ":80"},
				Bind:              ":80",
				PolicyID:          1,
				AntiReplayEnabled: false,
			},
			snapshot.SiteMapKey(":80", "enabled.example.com"): {
				Site:              store.Site{ID: 2, Host: "enabled.example.com", Bind: ":80"},
				Bind:              ":80",
				PolicyID:          1,
				AntiReplayEnabled: true,
			},
		},
		Protection: prot,
	})

	newEngine := func() *Engine {
		eng := New(holder, nil, nil, nil)
		eng.SetAntiReplayManager(antireplay.NewAntiReplayManager("phase-cache-test", nil, time.Minute))
		return eng
	}

	t.Run("disabled_then_enabled", func(t *testing.T) {
		eng := newEngine()

		disabled := eng.Process(&pipeline.RequestCtx{
			Bind:    ":80",
			Host:    "disabled.example.com",
			Path:    "/",
			Headers: map[string]string{"X-Nonce": "invalid"},
		})
		if disabled.Action.Matched {
			t.Fatalf("disabled site should not run anti-replay phase, got %#v", disabled.Action)
		}

		enabled := eng.Process(&pipeline.RequestCtx{
			Bind:    ":80",
			Host:    "enabled.example.com",
			Path:    "/",
			Headers: map[string]string{"X-Nonce": "invalid"},
		})
		if enabled.Action.Type != action.Intercept {
			t.Fatalf("enabled site should run anti-replay phase, got %#v", enabled.Action)
		}
		if enabled.Action.Phase != "anti_replay" {
			t.Fatalf("enabled site phase = %q, want %q", enabled.Action.Phase, "anti_replay")
		}
	})

	t.Run("enabled_then_disabled", func(t *testing.T) {
		eng := newEngine()

		enabled := eng.Process(&pipeline.RequestCtx{
			Bind:    ":80",
			Host:    "enabled.example.com",
			Path:    "/",
			Headers: map[string]string{"X-Nonce": "invalid"},
		})
		if enabled.Action.Type != action.Intercept {
			t.Fatalf("enabled site should run anti-replay phase, got %#v", enabled.Action)
		}

		disabled := eng.Process(&pipeline.RequestCtx{
			Bind:    ":80",
			Host:    "disabled.example.com",
			Path:    "/",
			Headers: map[string]string{"X-Nonce": "invalid"},
		})
		if disabled.Action.Matched {
			t.Fatalf("disabled site should not inherit anti-replay phase, got %#v", disabled.Action)
		}
	})
}

func BenchmarkProcessManyACLRules(b *testing.B) {
	prot := store.DefaultProtectionConfig()
	rules := make([]snapshot.CompiledRule, 0, 257)
	for i := 0; i < 256; i++ {
		rules = append(rules, snapshot.CompiledRule{
			ID:       uint(i + 1),
			Phase:    store.PhaseACL,
			Kind:     "allow_ip",
			Arg:      "10.0.0.0/8",
			Action:   store.ActionAllow,
			Priority: i + 1,
		})
	}
	rules = append(rules, snapshot.CompiledRule{
		ID:       1000,
		Phase:    store.PhaseACL,
		Kind:     "block_path",
		Arg:      "/admin",
		Action:   store.ActionIntercept,
		Priority: 300,
	})

	holder := newTestHolder(prot, rules)
	eng := New(holder, nil, nil, nil)
	ctx := &pipeline.RequestCtx{
		Bind:     ":80",
		Host:     "example.com",
		Path:     "/admin",
		ClientIP: []byte{192, 168, 1, 50},
		Headers:  map[string]string{},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Process(ctx)
	}
}

func BenchmarkProcessResolvedManyACLRules(b *testing.B) {
	prot := store.DefaultProtectionConfig()
	rules := make([]snapshot.CompiledRule, 0, 257)
	for i := 0; i < 256; i++ {
		rules = append(rules, snapshot.CompiledRule{
			ID:       uint(i + 1),
			Phase:    store.PhaseACL,
			Kind:     "allow_ip",
			Arg:      "10.0.0.0/8",
			Action:   store.ActionAllow,
			Priority: i + 1,
		})
	}
	rules = append(rules, snapshot.CompiledRule{
		ID:       1000,
		Phase:    store.PhaseACL,
		Kind:     "block_path",
		Arg:      "/admin",
		Action:   store.ActionIntercept,
		Priority: 300,
	})

	holder := newTestHolder(prot, rules)
	eng := New(holder, nil, nil, nil)
	ctx := &pipeline.RequestCtx{
		Bind:     ":80",
		Host:     "example.com",
		Path:     "/admin",
		ClientIP: []byte{192, 168, 1, 50},
		Headers:  map[string]string{},
	}
	sn := holder.Load()
	rt, ok := sn.MatchSite(":80", "example.com")
	if !ok {
		b.Fatal("expected benchmark site to resolve")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.ProcessResolved(sn, &rt, ctx)
	}
}
