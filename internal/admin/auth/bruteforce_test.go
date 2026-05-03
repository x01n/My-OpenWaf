package auth

import (
	"testing"
	"time"
)

func TestBruteForceReconfigureUpdatesLimit(t *testing.T) {
	bf := NewBruteForceDetector(5, time.Minute)
	bf.RecordFailure("1.2.3.4", "admin")
	bf.RecordFailure("1.2.3.4", "admin")
	if bf.IsLocked("1.2.3.4", "admin") {
		t.Fatal("detector locked before reaching original threshold")
	}

	bf.Reconfigure(2, time.Minute)
	if !bf.IsLocked("1.2.3.4", "admin") {
		t.Fatal("detector did not apply lower threshold")
	}
}
