package health

import (
	"context"
	"testing"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openMemDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory DB: %v", err)
	}
	return db
}

func TestAlwaysAlive(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	if !c.Alive() {
		t.Error("Alive() should always return true")
	}
}

func TestReadyFalseWhenNoSnapshot(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	if c.Ready() {
		t.Error("Ready() should return false when snapshot is nil")
	}
}

func TestReadyTrueWhenSnapshotLoaded(t *testing.T) {
	h := &snapshot.Holder{}
	h.Store(&snapshot.Snapshot{Revision: 1})
	c := New(openMemDB(t), h)
	if !c.Ready() {
		t.Error("Ready() should return true when snapshot is loaded and DB is reachable")
	}
}

func TestStatusSnapshotNilSnapshot(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	status := c.StatusSnapshot()

	if status["alive"] != true {
		t.Error("StatusSnapshot alive should be true")
	}
	if status["revision"] != uint64(0) {
		t.Errorf("StatusSnapshot revision = %v, want 0", status["revision"])
	}
	if status["sites"] != 0 {
		t.Errorf("StatusSnapshot sites = %v, want 0", status["sites"])
	}
	if status["listeners"] != 0 {
		t.Errorf("StatusSnapshot listeners = %v, want 0", status["listeners"])
	}
}

func TestStatusSnapshotWithRevision(t *testing.T) {
	h := &snapshot.Holder{}
	h.Store(&snapshot.Snapshot{Revision: 42})
	c := New(openMemDB(t), h)
	status := c.StatusSnapshot()

	if status["revision"] != uint64(42) {
		t.Errorf("StatusSnapshot revision = %v, want 42", status["revision"])
	}
}

func TestStatusSnapshotContainsRuntimeFields(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	status := c.StatusSnapshot()

	for _, key := range []string{"goroutines", "heap_alloc", "go_version", "num_cpu"} {
		if _, ok := status[key]; !ok {
			t.Errorf("StatusSnapshot missing field %q", key)
		}
	}
	if goroutines, ok := status["goroutines"].(int); !ok || goroutines <= 0 {
		t.Errorf("StatusSnapshot goroutines should be positive int, got %v", status["goroutines"])
	}
}

func TestNewCheckerReturnNonNil(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	if c == nil {
		t.Fatal("New() returned nil")
	}
}

func TestStatusSnapshotWithSitesAndListeners(t *testing.T) {
	h := &snapshot.Holder{}
	h.Store(&snapshot.Snapshot{
		Revision: 5,
		Sites: map[string]*snapshot.SiteRuntime{
			":80|a":  {Bind: ":80", Site: store.Site{ID: 1}},
			":80|b":  {Bind: ":80", Site: store.Site{ID: 2}},
			":443|a": {Bind: ":443", Site: store.Site{ID: 3}},
		},
	})
	c := New(openMemDB(t), h)
	status := c.StatusSnapshot()

	if status["sites"] != 3 {
		t.Errorf("sites = %v, want 3", status["sites"])
	}
	if status["listeners"] != 2 {
		t.Errorf("listeners = %v, want 2", status["listeners"])
	}
	if status["revision"] != uint64(5) {
		t.Errorf("revision = %v, want 5", status["revision"])
	}
}

func TestLivenessHandlerReturns200(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	fn := c.LivenessHandler()
	var rc app.RequestContext
	fn(context.Background(), &rc)
	if rc.Response.StatusCode() != 200 {
		t.Errorf("LivenessHandler status = %d, want 200", rc.Response.StatusCode())
	}
}

func TestReadinessHandlerNotReadyReturns503(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	fn := c.ReadinessHandler()
	var rc app.RequestContext
	fn(context.Background(), &rc)
	if rc.Response.StatusCode() != 503 {
		t.Errorf("ReadinessHandler (not ready) status = %d, want 503", rc.Response.StatusCode())
	}
}

func TestReadinessHandlerReadyReturns200(t *testing.T) {
	h := &snapshot.Holder{}
	h.Store(&snapshot.Snapshot{Revision: 1})
	c := New(openMemDB(t), h)
	fn := c.ReadinessHandler()
	var rc app.RequestContext
	fn(context.Background(), &rc)
	if rc.Response.StatusCode() != 200 {
		t.Errorf("ReadinessHandler (ready) status = %d, want 200", rc.Response.StatusCode())
	}
}

func TestStatusHandlerReturns200(t *testing.T) {
	c := New(openMemDB(t), &snapshot.Holder{})
	fn := c.StatusHandler()
	var rc app.RequestContext
	fn(context.Background(), &rc)
	if rc.Response.StatusCode() != 200 {
		t.Errorf("StatusHandler status = %d, want 200", rc.Response.StatusCode())
	}
}
