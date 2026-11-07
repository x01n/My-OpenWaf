package app

import (
	"crypto/tls"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

/**
 * TestLoadOrCreateSessionTicketKeyPrefersEnv 锁定 key 来源优先级。
 *
 * 跨主机多实例部署只能靠显式配置共享同一个 key，因此环境变量的优先级
 * 必须高于本地文件与随机生成；否则文件里残留的旧 key 会悄悄覆盖运维配置，
 * 表现为「配置了也没生效」。
 */
func TestLoadOrCreateSessionTicketKeyPrefersEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MY_OPENWAF_DATA", dir)

	fileKey := make([]byte, 32)
	for i := range fileKey {
		fileKey[i] = byte(i)
	}
	writeSessionTicketKeyFile(filepath.Join(dir, sessionTicketKeyFileName), toKey32(fileKey))

	envKey := make([]byte, 32)
	for i := range envKey {
		envKey[i] = byte(0xA0 + i)
	}
	t.Setenv(sessionTicketKeyEnv, hex.EncodeToString(envKey))

	if got := loadOrCreateSessionTicketKey(); got != toKey32(envKey) {
		t.Fatalf("key from env not used: got %x", got)
	}
}

/**
 * TestLoadOrCreateSessionTicketKeyPersistsAndReloads 锁定文件持久化与复用。
 *
 * 进程重启后必须能读回同一 key，否则客户端持有的 ticket 全部失效，
 * 会话恢复与 0-RTT 都要重新握手。
 */
func TestLoadOrCreateSessionTicketKeyPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MY_OPENWAF_DATA", dir)
	t.Setenv(sessionTicketKeyEnv, "")

	first := loadOrCreateSessionTicketKey()
	second := loadOrCreateSessionTicketKey()
	if first != second {
		t.Fatalf("key changed across loads: %x != %x", first, second)
	}
	raw, err := os.ReadFile(filepath.Join(dir, sessionTicketKeyFileName))
	if err != nil {
		t.Fatalf("ticket key file not persisted: %v", err)
	}
	decoded, err := hex.DecodeString(string(trimSpaceBytes(raw)))
	if err != nil || len(decoded) != 32 {
		t.Fatalf("persisted key is malformed: %q (%v)", raw, err)
	}
	if toKey32(decoded) != first {
		t.Fatalf("persisted key does not match runtime key")
	}
}

/**
 * TestLoadOrCreateSessionTicketKeyIgnoresMalformedEnv 锁定非法配置的降级行为。
 *
 * 非法 key 不能让进程启动失败：记录告警后退回文件/随机生成，功能仍可用，
 * 只是不再具备跨实例共享能力。
 */
func TestLoadOrCreateSessionTicketKeyIgnoresMalformedEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MY_OPENWAF_DATA", dir)
	t.Setenv(sessionTicketKeyEnv, "not-a-hex-key")

	key := loadOrCreateSessionTicketKey()
	if key == ([32]byte{}) {
		t.Fatal("malformed env key must fall back to a generated key, not an all-zero key")
	}
}

/**
 * TestApplySharedSessionTicketKeySkipsDisabled 锁定关闭票据时不注入 key。
 *
 * SessionTicketsDisabled 为 true 时 SetSessionTicketKeys 无意义；更重要的是
 * 不能让「配置关闭」的语义被静默覆盖成「有 key 可用」。
 */
func TestApplySharedSessionTicketKeySkipsDisabled(t *testing.T) {
	cfg := &tls.Config{SessionTicketsDisabled: true}
	applySharedSessionTicketKey(cfg)
	if !cfg.SessionTicketsDisabled {
		t.Fatal("applySharedSessionTicketKey must not re-enable tickets")
	}
	applySharedSessionTicketKey(nil)
}

func toKey32(b []byte) [32]byte {
	var key [32]byte
	copy(key[:], b)
	return key
}

func trimSpaceBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
