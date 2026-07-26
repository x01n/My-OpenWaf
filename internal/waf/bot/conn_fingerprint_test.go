package bot

import (
	"net"
	"testing"
)

// mockConn 最小化 net.Conn 实现，仅用于测试包装逻辑。
type mockConn struct{ net.Conn }

func TestHasValueReturnsFalseForEmpty(t *testing.T) {
	fp := TLSClientFingerprint{}
	if fp.HasValue() {
		t.Error("empty TLSClientFingerprint.HasValue() should be false")
	}
}

func TestHasValueReturnsTrueWhenJA3Set(t *testing.T) {
	fp := TLSClientFingerprint{JA3: "aabbcc"}
	if !fp.HasValue() {
		t.Error("TLSClientFingerprint with JA3 should HasValue()")
	}
}

func TestHasValueReturnsTrueWhenJA4Set(t *testing.T) {
	fp := TLSClientFingerprint{JA4: "t13d12h2_abc"}
	if !fp.HasValue() {
		t.Error("TLSClientFingerprint with JA4 should HasValue()")
	}
}

func TestHasValueReturnsTrueWhenALPNSet(t *testing.T) {
	fp := TLSClientFingerprint{ALPN: []string{"h2"}}
	if !fp.HasValue() {
		t.Error("TLSClientFingerprint with ALPN should HasValue()")
	}
}

// TestWrapFingerprintConnReturnsSameConnWhenNoFingerprint 验证无指纹时直接返回原连接。
func TestWrapFingerprintConnReturnsSameConnWhenNoFingerprint(t *testing.T) {
	base := &mockConn{}
	got := WrapFingerprintConn(base, TLSClientFingerprint{})
	if got != base {
		t.Error("WrapFingerprintConn with empty fingerprint should return original conn")
	}
}

// TestWrapFingerprintConnWrapsWhenFingerprintHasValue 验证有指纹时返回包装连接。
func TestWrapFingerprintConnWrapsWhenFingerprintHasValue(t *testing.T) {
	base := &mockConn{}
	fp := TLSClientFingerprint{JA3: "aabbcc"}
	got := WrapFingerprintConn(base, fp)
	if got == base {
		t.Error("WrapFingerprintConn with fingerprint should return a wrapped conn, not original")
	}
	if _, ok := got.(FingerprintCarrier); !ok {
		t.Error("wrapped conn should implement FingerprintCarrier")
	}
}

// TestWrapFingerprintConnPreservesExistingCarrier 验证若原连接已实现 FingerprintCarrier 则直接包装。
func TestWrapFingerprintConnPreservesExistingCarrier(t *testing.T) {
	base := &mockConn{}
	fp := TLSClientFingerprint{JA3: "aabbcc"}
	wrapped := WrapFingerprintConn(base, fp) // 创建 FingerprintConn

	// 再次包装 — 内部会走 FingerprintCarrier 分支
	rewrapped := WrapFingerprintConn(wrapped, TLSClientFingerprint{JA4: "other"})
	if _, ok := rewrapped.(FingerprintCarrier); !ok {
		t.Error("re-wrapped conn should still implement FingerprintCarrier")
	}
}

// TestTLSFingerprintFromConnReturnsFalseForPlainConn 验证普通连接无法提取指纹。
func TestTLSFingerprintFromConnReturnsFalseForPlainConn(t *testing.T) {
	base := &mockConn{}
	_, ok := TLSFingerprintFromConn(base)
	if ok {
		t.Error("plain conn should not yield a fingerprint")
	}
}

// TestTLSFingerprintFromConnExtractsFingerprintFromWrapped 验证包装连接可提取指纹。
func TestTLSFingerprintFromConnExtractsFingerprintFromWrapped(t *testing.T) {
	base := &mockConn{}
	fp := TLSClientFingerprint{JA3: "aabbcc", JA4: "t13d12h2"}
	wrapped := WrapFingerprintConn(base, fp)

	got, ok := TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected fingerprint to be found")
	}
	if got.JA3 != fp.JA3 || got.JA4 != fp.JA4 {
		t.Errorf("fingerprint mismatch: got %+v, want %+v", got, fp)
	}
}
