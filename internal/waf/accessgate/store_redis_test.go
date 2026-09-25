package accessgate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type miniRedis struct {
	ln net.Listener

	mu sync.Mutex
	kv map[string]string // key -> 原始 JSON 值
	tt map[string]int64  // key -> 过期 Unix 毫秒（0 表示不过期）

	failCmd  string // 非空时命中该命令即返回错误
	failOnce bool   // 错误只触发一次
	failed   bool
}

func startMiniRedis(t *testing.T, failCmd string) *miniRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock redis: %v", err)
	}
	m := &miniRedis{
		ln:       ln,
		kv:       make(map[string]string),
		tt:       make(map[string]int64),
		failCmd:  failCmd,
		failOnce: true,
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	t.Cleanup(m.Close)
	return m
}

func (m *miniRedis) Addr() string {
	return m.ln.Addr().String()
}

func (m *miniRedis) Close() {
	_ = m.ln.Close()
}

// serve 处理单连接上的命令流。
func (m *miniRedis) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		resp := m.dispatch(args)
		if resp == "" {
			return
		}
		if _, werr := io.WriteString(conn, resp); werr != nil {
			return
		}
	}
}

// dispatch 按命令名分发。
func (m *miniRedis) dispatch(args []string) string {
	cmd := strings.ToUpper(args[0])
	m.mu.Lock()
	shouldFail := m.failCmd != "" && cmd == m.failCmd && (!m.failOnce || !m.failed)
	if shouldFail {
		m.failed = true
	}
	m.mu.Unlock()
	if shouldFail {
		return "-ERR injected failure\r\n"
	}
	switch cmd {
	case "HELLO":
		return "-ERR unknown command 'hello'\r\n"
	case "CLIENT":
		// go-redis 握手阶段的 client setinfo / setname：置 OK 即可。
		return "+OK\r\n"
	case "PING":
		return "+PONG\r\n"
	case "SET":
		return m.cmdSet(args)
	case "GET":
		return m.cmdGet(args)
	case "DEL":
		return m.cmdDel(args)
	case "EXISTS":
		return m.cmdExists(args)
	case "SCAN":
		return m.cmdScan(args)
	case "EVAL", "EVALSHA":
		return m.cmdEval(args)
	default:
		return "-ERR unknown command\r\n"
	}
}

func (m *miniRedis) cmdSet(args []string) string {
	if len(args) < 5 {
		return "-ERR wrong number of arguments for 'set' command\r\n"
	}
	key, value := args[1], args[2]
	// 只支持 EX/PX 相对 TTL（与生产写入形态一致），换算成绝对 Unix 毫秒。
	var expireMS int64
	ttl, perr := strconv.ParseInt(args[4], 10, 64)
	if perr != nil {
		return "-ERR value is not an integer\r\n"
	}
	now := time.Now().UnixMilli()
	switch strings.ToUpper(args[3]) {
	case "EX":
		expireMS = now + ttl*1000
	case "PX":
		expireMS = now + ttl
	default:
		return "-ERR invalid expire option\r\n"
	}
	m.mu.Lock()
	m.kv[key] = value
	m.tt[key] = expireMS
	m.mu.Unlock()
	return "+OK\r\n"
}

func (m *miniRedis) cmdGet(args []string) string {
	if len(args) != 2 {
		return "-ERR wrong number of arguments for 'get' command\r\n"
	}
	now := time.Now().UnixMilli()
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.kv[args[1]]
	if !ok {
		return "$-1\r\n"
	}
	// TTL 过期的懒删除。
	if expire := m.tt[args[1]]; expire > 0 && now >= expire {
		delete(m.kv, args[1])
		delete(m.tt, args[1])
		return "$-1\r\n"
	}
	return respBulk(value)
}

func (m *miniRedis) cmdDel(args []string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, key := range args[1:] {
		if _, ok := m.kv[key]; ok {
			delete(m.kv, key)
			delete(m.tt, key)
			n++
		}
	}
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

// cmdExists 返回现存键数量（含 TTL 懒过期）。
func (m *miniRedis) cmdExists(args []string) string {
	if len(args) < 2 {
		return "-ERR wrong number of arguments for 'exists' command\r\n"
	}
	now := time.Now().UnixMilli()
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, key := range args[1:] {
		if _, ok := m.kv[key]; !ok {
			continue
		}
		if expire := m.tt[key]; expire > 0 && now >= expire {
			delete(m.kv, key)
			delete(m.tt, key)
			continue
		}
		n++
	}
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

// cmdScan 返回游标 0 与一批匹配键，单次扫描走完。
func (m *miniRedis) cmdScan(args []string) string {
	match := "*"
	for i := 1; i+1 < len(args); i += 2 {
		if strings.EqualFold(args[i], "MATCH") {
			match = args[i+1]
		}
	}
	now := time.Now().UnixMilli()
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for key := range m.kv {
		if expire := m.tt[key]; expire > 0 && now >= expire {
			delete(m.kv, key)
			delete(m.tt, key)
			continue
		}
		if globMatch(match, key) {
			keys = append(keys, key)
		}
	}
	resp := "*2\r\n:0\r\n*" + strconv.Itoa(len(keys)) + "\r\n"
	for _, key := range keys {
		resp += respBulk(key)
	}
	return resp
}

// cmdEval 按参数形态区分 accessCleanupScript 与 accessTakeScript。
func (m *miniRedis) cmdEval(args []string) string {
	if len(args) < 3 {
		return "-ERR wrong number of arguments for 'eval' command\r\n"
	}
	numKeys, err := strconv.Atoi(args[2])
	if err != nil {
		return "-ERR value is not an integer\r\n"
	}
	if numKeys <= 0 || len(args) < 3+numKeys {
		return "-ERR wrong number of keys\r\n"
	}
	keys := args[3 : 3+numKeys]
	argvs := args[3+numKeys:]

	// take 脚本：恰好一个键且无 ARGV。
	if len(keys) == 1 && len(argvs) == 0 {
		return m.cmdEvalTake(keys[0])
	}
	// cleanup 脚本：一批键 + 一个毫秒 ARGV。
	return m.cmdEvalCleanup(keys, argvs)
}

// cmdEvalTake GET+DEL 原子取出。
func (m *miniRedis) cmdEvalTake(key string) string {
	m.mu.Lock()
	raw, ok := m.kv[key]
	if ok {
		delete(m.kv, key)
		delete(m.tt, key)
	}
	m.mu.Unlock()
	if !ok {
		// Lua 脚本对 miss 返回 nil，映射为 RESP nil bulk。
		return "$-1\r\n"
	}
	return respBulk(raw)
}

// cmdEvalCleanup 按值内 expires_at 批量删除过期键。
func (m *miniRedis) cmdEvalCleanup(keys []string, argvs []string) string {
	now := time.Now().UnixMilli()
	if len(argvs) >= 1 {
		if v, err := strconv.ParseInt(argvs[0], 10, 64); err == nil {
			now = v
		}
	}
	m.mu.Lock()
	var removed int64
	for _, key := range keys {
		raw, ok := m.kv[key]
		if !ok {
			continue
		}
		var decoded struct {
			ExpiresAt int64 `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			continue
		}
		if decoded.ExpiresAt <= now {
			delete(m.kv, key)
			delete(m.tt, key)
			removed++
		}
	}
	m.mu.Unlock()
	return ":" + strconv.FormatInt(removed, 10) + "\r\n"
}

// respBulk 组装 bulk string 回复。
func respBulk(value string) string {
	return "$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
}

// globMatch 实现测试所需的通配：仅支持前缀 "*" 与整体 "*"。
func globMatch(pattern, key string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(key, pattern[1:])
	}
	return false
}

// readRESPArgs 读取一条 RESP 数组命令。
func readRESPArgs(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		if line != "" {
			return nil, fmt.Errorf("expected RESP array, got %q", line)
		}
		return nil, io.EOF
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 {
		return nil, fmt.Errorf("invalid RESP array count %q", line)
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimRight(header, "\r\n")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", header)
		}
		valueLen, err := strconv.Atoi(header[1:])
		if err != nil || valueLen < 0 {
			return nil, fmt.Errorf("invalid bulk string length %q", header)
		}
		body := make([]byte, valueLen+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		args = append(args, string(body[:valueLen]))
	}
	return args, nil
}

// newMiniRedisClient 构造指向测试替身的 go-redis 客户端。
func newMiniRedisClient(m *miniRedis) *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: m.Addr()})
}

/**
 * TestRedisSessionStoreSharedAcrossInstances 验证两个独立 store 实例
 * （模拟多实例部署的两个节点）共享同一 Redis 中的会话。
 */
func TestRedisSessionStoreSharedAcrossInstances(t *testing.T) {
	m := startMiniRedis(t, "")
	clientA := newMiniRedisClient(m)
	defer clientA.Close()

	storeA := NewRedisSessionStore(clientA)
	storeB := NewRedisSessionStore(newMiniRedisClient(m))

	token, err := storeA.Create(7, "alice", "shared_password", 3600)
	if err != nil || token == "" {
		t.Fatalf("Create: token=%q err=%v", token, err)
	}

	info, err := storeB.Validate(token)
	if err != nil {
		t.Fatalf("Validate across instance: %v", err)
	}
	if info == nil {
		t.Fatal("Validate across instance: session missing")
	}
	if info.SiteID != 7 || info.Identity != "alice" || info.Provider != "shared_password" {
		t.Fatalf("Validate across instance: unexpected session %+v", info)
	}
	if info.Token != token {
		t.Fatalf("Validate: token mismatch got %q want %q", info.Token, token)
	}
	if n, _ := clientA.Exists(context.Background(), accessSessionKey(token)).Result(); n != 1 {
		t.Fatalf("session should exist in Redis, exists=%d", n)
	}
}

/**
 * TestRedisSessionStoreRevokeAcrossInstances 验证 Revoke 的跨实例可见性。
 */
func TestRedisSessionStoreRevokeAcrossInstances(t *testing.T) {
	m := startMiniRedis(t, "")
	storeA := NewRedisSessionStore(newMiniRedisClient(m))
	storeB := NewRedisSessionStore(newMiniRedisClient(m))

	token, err := storeA.Create(9, "bob", "user_password", 3600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := storeB.Revoke(token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	info, err := storeA.Validate(token)
	if err != nil {
		t.Fatalf("Validate after revoke: %v", err)
	}
	if info != nil {
		t.Fatalf("Validate after revoke: session should be gone, got %+v", info)
	}
}

/**
 * TestRedisSessionStoreTTLExpiry 验证会话 TTL 自然过期。
 */
func TestRedisSessionStoreTTLExpiry(t *testing.T) {
	m := startMiniRedis(t, "")
	store := NewRedisSessionStore(newMiniRedisClient(m))

	token, err := store.Create(1, "exp", "shared_password", 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := store.Validate(token)
	if err != nil || info == nil {
		t.Fatalf("Validate before expiry: info=%v err=%v", info, err)
	}

	time.Sleep(1500 * time.Millisecond)
	info, err = store.Validate(token)
	if err != nil {
		t.Fatalf("Validate after expiry: %v", err)
	}
	if info != nil {
		t.Fatalf("Validate after expiry: session should be gone, got %+v", info)
	}
	if err := store.CleanExpired(); err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}
}

/**
 * TestRedisOAuthStateStoreOneTimeConsume 验证 OAuth state 的一次性语义
 * 与跨实例共享（Get 可见、第二次 Consume 为空）。
 */
func TestRedisOAuthStateStoreOneTimeConsume(t *testing.T) {
	m := startMiniRedis(t, "")
	storeA := NewRedisOAuthStateStore(newMiniRedisClient(m))
	storeB := NewRedisOAuthStateStore(newMiniRedisClient(m))

	st := &OAuthState{
		State:        "abc123",
		CodeVerifier: "v1",
		SiteID:       3,
		ProviderID:   11,
		ReturnURL:    "/dashboard",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}
	if err := storeA.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := storeB.Get("abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.ReturnURL != "/dashboard" || got.CodeVerifier != "v1" {
		t.Fatalf("Get across instance: unexpected state %+v", got)
	}

	// Consume 一次性：任意实例第二次取不到。
	got, err = storeA.Consume("abc123")
	if err != nil || got == nil {
		t.Fatalf("Consume first: state=%v err=%v", got, err)
	}
	got, err = storeB.Consume("abc123")
	if err != nil {
		t.Fatalf("Consume second: %v", err)
	}
	if got != nil {
		t.Fatalf("Consume second: state reused, got %+v", got)
	}
}

/**
 * TestRedisOAuthStateStoreDelete 验证 Delete 幂等与 Get 一致性。
 */
func TestRedisOAuthStateStoreDelete(t *testing.T) {
	m := startMiniRedis(t, "")
	store := NewRedisOAuthStateStore(newMiniRedisClient(m))

	st := &OAuthState{
		State:     "del-state",
		SiteID:    2,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete("del-state"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := store.Get("del-state")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("Get after delete: should be nil, got %+v", got)
	}
	// 幂等：再删一次不报错。
	if err := store.Delete("del-state"); err != nil {
		t.Fatalf("Delete second: %v", err)
	}
}

/**
 * TestRedisSessionStoreFallbackOnCreateFailure 验证瞬时 SET 失败时降级到内存，
 * 会话对同一 store 仍然有效（本机登录不被 Redis 抖动打断）。
 */
func TestRedisSessionStoreFallbackOnCreateFailure(t *testing.T) {
	m := startMiniRedis(t, "SET")
	client := newMiniRedisClient(m)
	defer client.Close()
	store := NewRedisSessionStore(client)

	token, err := store.Create(4, "dave", "shared_password", 3600)
	if err != nil {
		t.Fatalf("Create with failing Redis: %v", err)
	}
	info, err := store.Validate(token)
	if err != nil {
		t.Fatalf("Validate fallback: %v", err)
	}
	if info == nil {
		t.Fatal("fallback validation lost session")
	}
	// Redis 未落库（SET 被注入错误），会话应来自内存回退。
	if n, _ := client.Exists(context.Background(), accessSessionKey(token)).Result(); n != 0 {
		t.Fatalf("session should not exist in Redis after injected SET failure, exists=%d", n)
	}
}

/**
 * TestRedisOAuthStateStoreFallbackOnSaveFailure 验证 OAuth state 保存失败的降级。
 */
func TestRedisOAuthStateStoreFallbackOnSaveFailure(t *testing.T) {
	m := startMiniRedis(t, "SET")
	store := NewRedisOAuthStateStore(newMiniRedisClient(m))

	st := &OAuthState{
		State:     "fb-state",
		SiteID:    6,
		ReturnURL: "/x",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save with failing Redis: %v", err)
	}
	got, err := store.Get("fb-state")
	if err != nil || got == nil {
		t.Fatalf("Get fallback: state=%v err=%v", got, err)
	}
	// 降级 state 同样可被 Consume 一次性取走（callback 路径）。
	got, err = store.Consume("fb-state")
	if err != nil || got == nil {
		t.Fatalf("Consume fallback: state=%v err=%v", got, err)
	}
	got, err = store.Get("fb-state")
	if err != nil || got != nil {
		t.Fatalf("Get after fallback consume: state=%v err=%v", got, err)
	}
}

/**
 * TestRedisSessionStoreNilRedis 验证 redis=nil 时行为等价内存实现。
 */
func TestRedisSessionStoreNilRedis(t *testing.T) {
	store := NewRedisSessionStore(nil)
	token, err := store.Create(5, "eve", "shared_password", 3600)
	if err != nil {
		t.Fatalf("Create with nil redis: %v", err)
	}
	info, err := store.Validate(token)
	if err != nil || info == nil {
		t.Fatalf("Validate with nil redis: info=%v err=%v", info, err)
	}
	if err := store.Revoke(token); err != nil {
		t.Fatalf("Revoke with nil redis: %v", err)
	}
	info, _ = store.Validate(token)
	if info != nil {
		t.Fatalf("Validate after revoke with nil redis: got %+v", info)
	}
	if err := store.CleanExpired(); err != nil {
		t.Fatalf("CleanExpired with nil redis: %v", err)
	}
}

/**
 * TestRedisSessionStoreExpiredValueFallback 验证值内 expires_at 过期但 TTL
 * 尚未触发时的惰性删除与 CleanExpired 清理。
 */
func TestRedisSessionStoreExpiredValueFallback(t *testing.T) {
	m := startMiniRedis(t, "")
	client := newMiniRedisClient(m)
	defer client.Close()
	store := NewRedisSessionStore(client)

	// 直接向 Redis 注入一条已到 Go 侧过期时刻、但保留了 TTL 的会话，
	// 覆盖 validateInRedis 与 cleanup 脚本按字段判定过期的分支。
	token, _ := GenerateToken()
	expired := &redisSessionInfo{
		SiteID:    8,
		Token:     token,
		Identity:  "zoe",
		Provider:  "shared_password",
		ExpiresAt: time.Now().Add(-time.Second).UnixMilli(),
	}
	payload, err := json.Marshal(expired)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// TTL 保持有效，绕开 Redis 层过期，走应用层字段过期路径。
	if err := client.Set(context.Background(), accessSessionKey(token), payload, time.Hour).Err(); err != nil {
		t.Fatalf("seed expired session: %v", err)
	}

	info, err := store.Validate(token)
	if err != nil {
		t.Fatalf("Validate expired-value session: %v", err)
	}
	if info != nil {
		t.Fatalf("Validate expired-value session: should be nil, got %+v", info)
	}

	// 注入未过期条目，验证 CleanExpired 只清过期键。
	liveToken, _ := GenerateToken()
	live := &redisSessionInfo{
		SiteID:    8,
		Token:     liveToken,
		Identity:  "live",
		Provider:  "shared_password",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	livePayload, err := json.Marshal(live)
	if err != nil {
		t.Fatalf("marshal live: %v", err)
	}
	if err := client.Set(context.Background(), accessSessionKey(liveToken), livePayload, time.Hour).Err(); err != nil {
		t.Fatalf("seed live session: %v", err)
	}

	if err := store.CleanExpired(); err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}
	if n, _ := client.Exists(context.Background(), accessSessionKey(liveToken)).Result(); n != 1 {
		t.Fatalf("live session should survive CleanExpired, exists=%d", n)
	}
}
