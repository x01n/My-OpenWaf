package engine

import (
	"reflect"
	"testing"
	"time"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/ratelimit"
)

const skipByPathPhaseTypeName = "*rules.skipByPathPhase"

func TestGetOrBuildPhasesWrapsOnlyPromisedPhases(t *testing.T) {
	promised := []string{
		"acl",
		"anti_replay",
		"bot_detection",
		"browser_sign",
		"cve_detection",
		"ip_reputation",
		"lua_pre",
		"owasp_default",
		"rate_limit",
	}
	if got := store.SkipPathPhaseKeys(); !reflect.DeepEqual(got, promised) {
		t.Fatalf("skip phase contract = %v, want %v", got, promised)
	}

	prot := store.DefaultProtectionConfig()
	prot.OWASPEnabled = true
	prot.CVEEnabled = true
	prot.BotDetectionEnabled = true
	prot.BrowserSignEnabled = true
	prot.RequestRateLimitEnabled = true
	configured := make(map[string][]string, len(promised))
	for _, name := range promised {
		configured[name] = []string{"/skip/*"}
	}
	prot.SetSkipPathByPhase(configured)

	compileOne := func(id uint, phase store.RulePhase) []snapshot.CompiledRule {
		return []snapshot.CompiledRule{{
			ID: id, Phase: phase, Kind: "block_path", Arg: "/never", Action: store.ActionIntercept,
		}}
	}
	cr := &compiledRules{
		ACL:       convertAndCompile(compileOne(1, store.PhaseACL)),
		Signature: convertAndCompile(compileOne(2, store.PhaseSignature)),
		Custom:    convertAndCompile(compileOne(3, store.PhaseCustom)),
	}
	if len(cr.ACL) != 1 || len(cr.Signature) != 1 || len(cr.Custom) != 1 {
		t.Fatalf("compiled fixture sizes = acl:%d signature:%d custom:%d, want 1 each", len(cr.ACL), len(cr.Signature), len(cr.Custom))
	}

	reqLimiter := ratelimit.NewRateLimiter(60, 300, true)
	eng := New(&snapshot.Holder{}, reqLimiter, nil, iprep.NewIPReputation())
	eng.SetAntiReplayManager(antireplay.NewAntiReplayManager("phase-skip-test", nil, time.Minute))
	eng.SetLuaPlugins(luaEngineWith(t, luaplugin.StagePre, `function handle(ctx) return nil end`))
	sn := &snapshot.Snapshot{Revision: 41}
	rt := &snapshot.SiteRuntime{
		Site:              store.Site{ID: 7},
		PolicyID:          9,
		AntiReplayEnabled: true,
	}

	phases := eng.getOrBuildPhases(sn, rt, cr, &prot)
	seen := make(map[string]int, len(phases))
	for _, phase := range phases {
		name := phase.Name()
		seen[name]++
		gotType := reflect.TypeOf(phase).String()
		switch name {
		case "signature", "custom":
			if gotType == skipByPathPhaseTypeName {
				t.Fatalf("phase %q must not be wrapped", name)
			}
		default:
			if gotType != skipByPathPhaseTypeName {
				t.Fatalf("promised phase %q type = %q, want %q", name, gotType, skipByPathPhaseTypeName)
			}
		}
	}
	for _, name := range promised {
		if seen[name] != 1 {
			t.Fatalf("promised phase %q assembled %d times, want 1", name, seen[name])
		}
	}
	if seen["signature"] != 1 || seen["custom"] != 1 {
		t.Fatalf("unwrapped user-rule phases = signature:%d custom:%d, want 1 each", seen["signature"], seen["custom"])
	}
}

func TestProcessResolvedUsesInheritedAndExplicitlyClearedSkipConfig(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.OWASPEnabled = true
	global.CVEEnabled = false
	global.BotDetectionEnabled = false
	global.BrowserSignEnabled = false
	global.RequestRateLimitEnabled = false
	global.SetSkipPathByPhase(map[string][]string{"owasp_default": {"/skip/*"}})

	eng := New(&snapshot.Holder{}, nil, nil, nil)
	sn := &snapshot.Snapshot{Revision: 51, Protection: global}
	rt := &snapshot.SiteRuntime{Site: store.Site{ID: 8}, PolicyID: 10}
	key := phasesCacheKey{policyID: rt.PolicyID, siteID: rt.Site.ID}

	eng.processResolved(sn, rt, &pipeline.RequestCtx{Path: "/skip/probe"})
	inherited := eng.phasesPtr.Load().cache[key]
	if inherited == nil || inherited.prot != &sn.Protection || len(inherited.phases) != 1 {
		t.Fatalf("inherited cache entry = %#v, want one phase using snapshot protection", inherited)
	}
	if got := reflect.TypeOf(inherited.phases[0]).String(); got != skipByPathPhaseTypeName {
		t.Fatalf("inherited global phase type = %q, want %q", got, skipByPathPhaseTypeName)
	}

	cleared := global
	cleared.SkipPathByPhase = "{}"
	rt.EffectiveProtection = &cleared
	eng.processResolved(sn, rt, &pipeline.RequestCtx{Path: "/skip/probe"})
	overridden := eng.phasesPtr.Load().cache[key]
	if overridden == nil || overridden.prot != &cleared || len(overridden.phases) != 1 {
		t.Fatalf("site override cache entry = %#v, want one phase using effective protection", overridden)
	}
	if got := reflect.TypeOf(overridden.phases[0]).String(); got == skipByPathPhaseTypeName {
		t.Fatalf("explicit empty site override left phase wrapped as %q", got)
	}
}

func TestGetOrBuildPhasesInvalidatesSkipWrapperCacheOnRevision(t *testing.T) {
	prot := store.DefaultProtectionConfig()
	prot.OWASPEnabled = true
	prot.CVEEnabled = false
	prot.BotDetectionEnabled = false
	prot.BrowserSignEnabled = false
	prot.RequestRateLimitEnabled = false
	prot.SetSkipPathByPhase(map[string][]string{"owasp_default": {"/skip/*"}})

	eng := New(&snapshot.Holder{}, nil, nil, nil)
	rt := &snapshot.SiteRuntime{Site: store.Site{ID: 9}, PolicyID: 11}
	cr := &compiledRules{}
	firstSnapshot := &snapshot.Snapshot{Revision: 61}
	first := eng.getOrBuildPhases(firstSnapshot, rt, cr, &prot)
	again := eng.getOrBuildPhases(firstSnapshot, rt, cr, &prot)
	if len(first) != 1 || first[0] != again[0] {
		t.Fatal("same revision and config did not reuse cached skip wrapper")
	}

	secondSnapshot := &snapshot.Snapshot{Revision: 62}
	second := eng.getOrBuildPhases(secondSnapshot, rt, cr, &prot)
	if len(second) != 1 || first[0] == second[0] {
		t.Fatal("new revision reused the previous skip wrapper")
	}
	if got := eng.phasesPtr.Load().revision; got != secondSnapshot.Revision {
		t.Fatalf("phase cache revision = %d, want %d", got, secondSnapshot.Revision)
	}
}

func TestGetOrBuildPhasesInvalidatesRuntimeDepsCacheOnSetterChange(t *testing.T) {
	t.Run("bot threshold", func(t *testing.T) {
		prot := store.DefaultProtectionConfig()
		prot.BotDetectionEnabled = true
		prot.CVEEnabled = false
		prot.BrowserSignEnabled = false
		prot.RequestRateLimitEnabled = false
		prot.OWASPEnabled = false

		eng := New(&snapshot.Holder{}, nil, nil, nil)
		rt := &snapshot.SiteRuntime{Site: store.Site{ID: 19}, PolicyID: 29}
		cr := &compiledRules{}
		sn := &snapshot.Snapshot{Revision: 71}

		first := eng.getOrBuildPhases(sn, rt, cr, &prot)
		if len(first) != 1 {
			t.Fatalf("bot phase count = %d, want 1", len(first))
		}

		eng.SetGeoResolver(nil, 91)
		second := eng.getOrBuildPhases(sn, rt, cr, &prot)
		if len(second) != 1 {
			t.Fatalf("bot phase count after threshold change = %d, want 1", len(second))
		}
		if first[0] == second[0] {
			t.Fatal("bot phase cache reused after SetGeoResolver changed the runtime threshold")
		}
	})

	t.Run("anti replay manager", func(t *testing.T) {
		prot := store.DefaultProtectionConfig()
		prot.BotDetectionEnabled = false
		prot.CVEEnabled = false
		prot.BrowserSignEnabled = false
		prot.RequestRateLimitEnabled = false
		prot.OWASPEnabled = false

		eng := New(&snapshot.Holder{}, nil, nil, nil)
		eng.SetAntiReplayManager(antireplay.NewAntiReplayManager("phase-deps-a", nil, time.Minute))
		rt := &snapshot.SiteRuntime{Site: store.Site{ID: 20}, PolicyID: 30, AntiReplayEnabled: true}
		cr := &compiledRules{}
		sn := &snapshot.Snapshot{Revision: 72}

		first := eng.getOrBuildPhases(sn, rt, cr, &prot)
		if len(first) != 1 {
			t.Fatalf("anti replay phase count = %d, want 1", len(first))
		}

		eng.SetAntiReplayManager(antireplay.NewAntiReplayManager("phase-deps-b", nil, time.Minute))
		second := eng.getOrBuildPhases(sn, rt, cr, &prot)
		if len(second) != 1 {
			t.Fatalf("anti replay phase count after manager change = %d, want 1", len(second))
		}
		if first[0] == second[0] {
			t.Fatal("anti replay phase cache reused after SetAntiReplayManager changed the manager")
		}
	})
}
