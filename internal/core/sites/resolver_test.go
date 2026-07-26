package sites

import (
	"testing"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func makeHolder(sn *snapshot.Snapshot) *snapshot.Holder {
	h := &snapshot.Holder{}
	if sn != nil {
		h.Store(sn)
	}
	return h
}

func siteRuntime(id uint, bind, host string) *snapshot.SiteRuntime {
	return &snapshot.SiteRuntime{
		Site: store.Site{ID: id},
		Bind: bind,
	}
}

func TestNewResolverReturnNonNil(t *testing.T) {
	h := makeHolder(nil)
	r := NewResolver(h)
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
}

func TestMatchNilSnapshotReturnsFalse(t *testing.T) {
	r := NewResolver(makeHolder(nil))
	_, ok := r.Match(":443", "example.com")
	if ok {
		t.Error("Match with nil snapshot should return false")
	}
}

func TestMatchPtrNilSnapshotReturnsFalse(t *testing.T) {
	r := NewResolver(makeHolder(nil))
	_, ok := r.MatchPtr(":443", "example.com")
	if ok {
		t.Error("MatchPtr with nil snapshot should return false")
	}
}

func TestSnapshotReturnsNilWhenEmpty(t *testing.T) {
	r := NewResolver(makeHolder(nil))
	if r.Snapshot() != nil {
		t.Error("Snapshot() should return nil before any snapshot is stored")
	}
}

func TestMatchFindsExactHost(t *testing.T) {
	sn := &snapshot.Snapshot{
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "app.example.com"): siteRuntime(1, ":80", "app.example.com"),
		},
	}
	r := NewResolver(makeHolder(sn))
	got, ok := r.Match(":80", "app.example.com")
	if !ok {
		t.Fatal("Match should find exact host")
	}
	if got.Site.ID != 1 {
		t.Errorf("Match returned site ID %d, want 1", got.Site.ID)
	}
}

func TestMatchMissReturnsFalse(t *testing.T) {
	sn := &snapshot.Snapshot{
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "app.example.com"): siteRuntime(1, ":80", "app.example.com"),
		},
	}
	r := NewResolver(makeHolder(sn))
	_, ok := r.Match(":80", "other.example.com")
	if ok {
		t.Error("Match should return false for unknown host")
	}
}

func TestMatchPtrFindsExactHost(t *testing.T) {
	sn := &snapshot.Snapshot{
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "secure.example.com"): siteRuntime(2, ":443", "secure.example.com"),
		},
	}
	r := NewResolver(makeHolder(sn))
	ptr, ok := r.MatchPtr(":443", "secure.example.com")
	if !ok || ptr == nil {
		t.Fatal("MatchPtr should find exact host and return non-nil pointer")
	}
	if ptr.Site.ID != 2 {
		t.Errorf("MatchPtr returned site ID %d, want 2", ptr.Site.ID)
	}
}

func TestSnapshotReturnsStoredSnapshot(t *testing.T) {
	sn := &snapshot.Snapshot{Revision: 7}
	r := NewResolver(makeHolder(sn))
	got := r.Snapshot()
	if got == nil {
		t.Fatal("Snapshot() returned nil after storing a snapshot")
	}
	if got.Revision != 7 {
		t.Errorf("Snapshot().Revision = %d, want 7", got.Revision)
	}
}
