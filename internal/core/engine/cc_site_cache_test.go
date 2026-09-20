package engine

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func TestProcessDoesNotReuseCustomRulesAcrossSitesWithSamePolicy(t *testing.T) {
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "first.example.com"): {
				Site:     store.Site{ID: 1, Host: "first.example.com", Bind: ":80"},
				Bind:     ":80",
				PolicyID: 1,
				Rules: []snapshot.CompiledRule{{
					ID: 1, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/first", Action: store.ActionIntercept,
				}},
			},
			snapshot.SiteMapKey(":80", "second.example.com"): {
				Site:     store.Site{ID: 2, Host: "second.example.com", Bind: ":80"},
				Bind:     ":80",
				PolicyID: 1,
				Rules: []snapshot.CompiledRule{{
					ID: 2, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/second", Action: store.ActionChallenge,
				}},
			},
		},
		Protection: store.DefaultProtectionConfig(),
	})

	for _, order := range [][]string{{"first.example.com", "second.example.com"}, {"second.example.com", "first.example.com"}} {
		t.Run(order[0]+"_then_"+order[1], func(t *testing.T) {
			engine := New(holder, nil, nil, nil)
			for _, host := range order {
				path := "/first"
				want := action.Intercept
				if host == "second.example.com" {
					path = "/second"
					want = action.Challenge
				}
				result := engine.Process(&pipeline.RequestCtx{Bind: ":80", Host: host, Path: path, Headers: map[string]string{}})
				if result.Action.Type != want {
					t.Fatalf("%s action = %q, want %q", host, result.Action.Type, want)
				}
			}
		})
	}
}
