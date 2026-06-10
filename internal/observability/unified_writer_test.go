package observability

import "testing"

func TestDrainChanEmpty(t *testing.T) {
	ch := make(chan int)

	drained := drainChan(ch)

	if drained != nil {
		t.Fatalf("drainChan() = %v, want nil", drained)
	}
}

func TestDrainChanDrainsBelowLimit(t *testing.T) {
	ch := make(chan int, 3)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch)

	if got := len(drained); got != 3 {
		t.Fatalf("len(drainChan()) = %d, want 3", got)
	}
	if got := len(ch); got != 0 {
		t.Fatalf("len(ch) after drainChan() = %d, want 0", got)
	}
	for i, v := range drained {
		if v != i {
			t.Fatalf("drained[%d] = %d, want %d", i, v, i)
		}
	}
}

func TestDrainChanRespectsDrainLimit(t *testing.T) {
	extra := 10
	ch := make(chan int, unifiedWriterDrainLimit+extra)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch)

	if got := len(drained); got != unifiedWriterDrainLimit {
		t.Fatalf("len(drainChan()) = %d, want %d", got, unifiedWriterDrainLimit)
	}
	if got := len(ch); got != extra {
		t.Fatalf("len(ch) after drainChan() = %d, want %d", got, extra)
	}
	for i, v := range drained {
		if v != i {
			t.Fatalf("drained[%d] = %d, want %d", i, v, i)
		}
	}
}
