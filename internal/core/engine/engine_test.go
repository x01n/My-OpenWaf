package engine

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func TestProcessChecksACLBlacklistBeforeBuiltinDetectors(t *testing.T) {
	holder := &snapshot.Holder{}
	prot := store.DefaultProtectionConfig()
	prot.OWASPEnabled = true
	prot.OWASPAction = "drop"
	holder.Store(&snapshot.Snapshot{
		Revision: 1,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "example.com"): {
				Site:     store.Site{ID: 1, Host: "example.com", Bind: ":80"},
				Bind:     ":80",
				PolicyID: 1,
				Rules: []snapshot.CompiledRule{
					{ID: 10, Phase: store.PhaseACL, Kind: "block_path", Arg: "/admin", Action: store.ActionRateLimit, Priority: 1},
				},
			},
		},
		Protection: prot,
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
