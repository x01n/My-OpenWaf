package app

import (
	"testing"

	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func TestListenerRuntimesByBindDeduplicatesBindAndPrefersTLS(t *testing.T) {
	sn := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {Bind: ":443", Site: store.Site{ID: 1, Bind: ":443", TLSEnabled: false}},
		"b": {Bind: ":443", Site: store.Site{ID: 2, Bind: ":443", TLSEnabled: true}},
		"c": {Bind: ":80", Site: store.Site{ID: 3, Bind: ":80", TLSEnabled: false}},
	}}

	got := listenerRuntimesByBind(sn)
	if len(got) != 2 {
		t.Fatalf("expected one listener per bind, got %d", len(got))
	}

	byBind := make(map[string]snapshotpkg.SiteRuntime)
	for _, rt := range got {
		byBind[rt.Bind] = rt
	}
	if !byBind[":443"].Site.TLSEnabled || byBind[":443"].Site.ID != 2 {
		t.Fatalf("expected TLS runtime to represent :443 listener, got %+v", byBind[":443"].Site)
	}
	if byBind[":80"].Site.ID != 3 {
		t.Fatalf("expected :80 runtime to remain available, got %+v", byBind[":80"].Site)
	}
}
