package snapshot

import (
	"reflect"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestMergeProtectionSkipPathByPhaseInheritanceAndExplicitClear(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.SetSkipPathByPhase(map[string][]string{"owasp_default": {"/global/*"}})

	inherited := mergeProtection(global, store.Site{})
	if inherited.SkipPathByPhase != global.SkipPathByPhase {
		t.Fatalf("nil site override = %q, want inherited %q", inherited.SkipPathByPhase, global.SkipPathByPhase)
	}
	if got := inherited.GetSkipPathByPhase(); !reflect.DeepEqual(got, map[string][]string{"owasp_default": {"/global/*"}}) {
		t.Fatalf("inherited skip map = %#v", got)
	}

	empty := "{}"
	cleared := mergeProtection(global, store.Site{SkipPathByPhase: &empty})
	if cleared.SkipPathByPhase != "{}" {
		t.Fatalf("explicit empty override = %q, want %q", cleared.SkipPathByPhase, "{}")
	}
	if got := cleared.GetSkipPathByPhase(); got != nil {
		t.Fatalf("explicit empty override parsed as %#v, want nil", got)
	}

	siteRaw := `{"cve_detection":["/site/*"]}`
	siteOnly := mergeProtection(global, store.Site{SkipPathByPhase: &siteRaw})
	wantSiteOnly := map[string][]string{"cve_detection": {"/site/*"}}
	if got := siteOnly.GetSkipPathByPhase(); !reflect.DeepEqual(got, wantSiteOnly) {
		t.Fatalf("site replacement skip map = %#v, want %#v", got, wantSiteOnly)
	}
}
