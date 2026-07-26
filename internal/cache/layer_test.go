package cache

import (
	"testing"

	"My-OpenWaf/internal/snapshot"
)

func TestNewLayerReturnNonNil(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}
	if l == nil {
		t.Fatal("NewLayer() returned nil")
	}
}

func TestSetAndGetSnapshotRoundTrip(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}

	sn := &snapshot.Snapshot{Revision: 1}
	l.SetSnapshot(1, sn)

	got, ok := l.GetSnapshot(1)
	if !ok {
		t.Fatal("GetSnapshot(1) should return ok after SetSnapshot")
	}
	if got != sn {
		t.Error("GetSnapshot should return the same pointer set by SetSnapshot")
	}
}

func TestGetSnapshotMissReturnsFalse(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}

	got, ok := l.GetSnapshot(999)
	if ok || got != nil {
		t.Error("GetSnapshot on empty cache should return nil, false")
	}
}

func TestGetSnapshotWrongRevisionMisses(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}

	l.SetSnapshot(5, &snapshot.Snapshot{Revision: 5})

	_, ok := l.GetSnapshot(6)
	if ok {
		t.Error("GetSnapshot(6) should miss when only revision 5 is cached")
	}
}

func TestMultipleRevisionsCoexist(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}

	sn1 := &snapshot.Snapshot{Revision: 10}
	sn2 := &snapshot.Snapshot{Revision: 20}
	l.SetSnapshot(10, sn1)
	l.SetSnapshot(20, sn2)

	got1, ok1 := l.GetSnapshot(10)
	got2, ok2 := l.GetSnapshot(20)

	if !ok1 || got1 != sn1 {
		t.Errorf("revision 10 should be cached; ok=%v", ok1)
	}
	if !ok2 || got2 != sn2 {
		t.Errorf("revision 20 should be cached; ok=%v", ok2)
	}
}

func TestInvalidateAllClearsCache(t *testing.T) {
	l, err := NewLayer()
	if err != nil {
		t.Fatalf("NewLayer() error: %v", err)
	}

	l.SetSnapshot(1, &snapshot.Snapshot{Revision: 1})
	l.InvalidateAll()

	_, ok := l.GetSnapshot(1)
	if ok {
		t.Error("GetSnapshot should miss after InvalidateAll")
	}
}
