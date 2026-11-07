package app

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"My-OpenWaf/internal/core"
)

const (
	// sessionTicketKeyEnv 允许显式指定 session ticket key（64 位十六进制，
	// 即 32 字节）。多实例跨主机部署必须配置同一个 key，否则一个实例签发的
	// ticket 到另一个实例无法解密，0-RTT 与会话恢复都会退化成完整握手。
	sessionTicketKeyEnv = "MY_OPENWAF_TLS_TICKET_KEY"

	// sessionTicketKeyFileName 是未显式配置环境变量时的持久化文件名，
	// 位于数据目录下。进程重启后复用同一 key，客户端可用已有 ticket 做
	// 0-RTT / 会话恢复，而不是每次重启都强制完整握手。
	sessionTicketKeyFileName = "tls_session_ticket.key"
)

var sharedSessionTicketKeys struct {
	once sync.Once
	keys [][32]byte
}

/**
 * sharedTicketKeys 返回进程内所有 TLS 监听共用的 ticket key 列表。
 *
 * 只初始化一次：h1/h2 与 h3 必须使用同一份 key。若各自随机生成，客户端用
 * h2 得到的 ticket 在切换到 h3 时无法解密，Alt-Svc 升级会白白多一次完整握手。
 *
 * @return 至少包含一个 key 的列表，满足 tls.Config.SetSessionTicketKeys 的约束。
 */
func sharedTicketKeys() [][32]byte {
	sharedSessionTicketKeys.once.Do(func() {
		sharedSessionTicketKeys.keys = [][32]byte{loadOrCreateSessionTicketKey()}
	})
	return sharedSessionTicketKeys.keys
}

/**
 * applySharedSessionTicketKey 给 TLS 配置装上进程级共享 ticket key。
 *
 * 必须在配置开始握手之前调用（即构造期），否则会与并发握手竞争。
 * SessionTicketsDisabled 为 true 时直接跳过：此时 key 不会被使用。
 *
 * @param cfg 待配置的 TLS 配置，可为 nil。
 */
func applySharedSessionTicketKey(cfg *tls.Config) {
	if cfg == nil || cfg.SessionTicketsDisabled {
		return
	}
	cfg.SetSessionTicketKeys(sharedTicketKeys())
}

/**
 * loadOrCreateSessionTicketKey 按「环境变量 → 文件 → 新生成」的顺序取 key。
 *
 * 优先级刻意如此：显式配置最可靠（跨主机共享必须走它）；文件持久化覆盖
 * 单机重启；都没有时才生成随机 key 并尽力落盘。
 *
 * 读盘/写盘失败不阻断启动：ticket 退化为进程内有效，功能仍正确，只是重启后
 * 客户端需要完整握手。日志只记录路径与错误，绝不打印 key 本身。
 *
 * @return 32 字节 ticket key。
 */
func loadOrCreateSessionTicketKey() [32]byte {
	if key, ok := sessionTicketKeyFromEnv(); ok {
		return key
	}
	path := sessionTicketKeyPath()
	if key, ok := readSessionTicketKeyFile(path); ok {
		return key
	}
	key := generateSessionTicketKey()
	if path != "" {
		writeSessionTicketKeyFile(path, key)
	}
	return key
}

func sessionTicketKeyFromEnv() ([32]byte, bool) {
	raw := strings.TrimSpace(os.Getenv(sessionTicketKeyEnv))
	if raw == "" {
		return [32]byte{}, false
	}
	var key [32]byte
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != len(key) {
		slog.Warn("ignoring invalid TLS session ticket key: want 64 hex characters",
			slog.String("env", sessionTicketKeyEnv))
		return [32]byte{}, false
	}
	copy(key[:], decoded)
	return key, true
}

func sessionTicketKeyPath() string {
	dir := strings.TrimSpace(core.LoadConfigFromEnv().DataDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sessionTicketKeyFileName)
}

func readSessionTicketKeyFile(path string) ([32]byte, bool) {
	if path == "" {
		return [32]byte{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, false
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != 32 {
		slog.Warn("ignoring malformed TLS session ticket key file",
			slog.String("path", path))
		return [32]byte{}, false
	}
	var key [32]byte
	copy(key[:], decoded)
	return key, true
}

func generateSessionTicketKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		// crypto/rand 失败时进程已处于不可信状态，但这里仍不能 panic：
		// TLS 层会用零 key，至少保持「同进程内可恢复」的语义。
		slog.Error("failed to generate TLS session ticket key", slog.Any("err", err))
	}
	return key
}

func writeSessionTicketKeyFile(path string, key [32]byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("failed to create TLS session ticket key directory",
			slog.String("path", path), slog.Any("err", err))
		return
	}
	encoded := hex.EncodeToString(key[:])
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		slog.Warn("failed to persist TLS session ticket key",
			slog.String("path", path), slog.Any("err", err))
	}
}
