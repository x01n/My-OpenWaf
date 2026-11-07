package app

import (
	"os"
	"testing"

	snapshotpkg "My-OpenWaf/internal/snapshot"
)

// TestH3Allow0RTTReadsEnvForListenerDecision 确认监听决策真的读进程环境。
//
// 既有 TestH3Allow0RTTEnvGate 用 t.Setenv 覆盖，等价于「读 OR 不读 env」都能过；
// 这里直接改 os.Environ，把「读了 env」这一环单独钉住。
func TestH3Allow0RTTReadsEnvForListenerDecision(t *testing.T) {
	defaults := snapshotpkg.DefaultTLSDefaults()
	defaults.SessionTicketsEnabled = true
	defaults.Allow0RTT = true
	defaults.HasExplicitAllow0RTT = true
	sn := &snapshotpkg.Snapshot{TLSDefaults: defaults}

	original, hadOriginal := os.LookupEnv(snapshotpkg.H3Allow0RTTEnvKey)
	t.Cleanup(func() {
		if hadOriginal {
			_ = os.Setenv(snapshotpkg.H3Allow0RTTEnvKey, original)
			return
		}
		_ = os.Unsetenv(snapshotpkg.H3Allow0RTTEnvKey)
	})

	if err := os.Setenv(snapshotpkg.H3Allow0RTTEnvKey, "0"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if got := h3Allow0RTT(sn); got {
		t.Fatalf("h3Allow0RTT with %s=0 = true, want false even though allow_0rtt is explicitly on", snapshotpkg.H3Allow0RTTEnvKey)
	}

	if err := os.Setenv(snapshotpkg.H3Allow0RTTEnvKey, "1"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if got := h3Allow0RTT(sn); !got {
		t.Fatalf("h3Allow0RTT with %s=1 = false, want true when session tickets are on", snapshotpkg.H3Allow0RTTEnvKey)
	}

	if err := os.Unsetenv(snapshotpkg.H3Allow0RTTEnvKey); err != nil {
		t.Fatalf("unset env: %v", err)
	}
	if got := h3Allow0RTT(sn); !got {
		t.Fatalf("h3Allow0RTT with %s unset = false, want the explicit allow_0rtt=true to pass through", snapshotpkg.H3Allow0RTTEnvKey)
	}
}

// TestH3Allow0RTTNilSnapshotStaysClosed 确认 nil 快照的兜底不受 env 影响。
func TestH3Allow0RTTNilSnapshotStaysClosed(t *testing.T) {
	t.Setenv(snapshotpkg.H3Allow0RTTEnvKey, "1")
	if h3Allow0RTT(nil) {
		t.Fatal("h3Allow0RTT(nil) must stay false regardless of the env override")
	}
}
