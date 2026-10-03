package cache

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// kvMiniRedis 是本包测试专用的 RESP3 内存 Redis 替身（不依赖 redis-server）。
//
// 迁移 to rueidis 前，本包的真实行为基线跑本机 redis-server 子进程
// （exec.LookPath + 端口预留 + PING 轮询）。rueidis 恒定 HELLO 3 握手且需要
// 完整 RESP3 会话语义，为消除 CI 对 redis-server 的隐式依赖，改为纯协议层
// mock：HELLO 3 以 RESP3 map 应答（proto=3），后续接 SETINFO 应答按 push 帧
// 聚合为 push 通知后才会被 rueidis 忽略。
//
// 只实现 redis_kv.go 命令面所需的最小命令集：
// SET/GET/DEL/EXISTS/PTTL/INCR/SETNX/EXPIRE/PEXPIRE 以及三个固定 Lua 脚本的
// EVAL/EVALSHA 定点应答。
type kvMiniRedis struct {
	ln      net.Listener
	cmdLog  []string
	failAll bool // 为 true 时除握手外所有命令返回注入错误

	mu     sync.Mutex
	kv     map[string]string // key -> 原始值
	expire map[string]int64  // key -> 过期 Unix 毫秒（0 表示不过期）
	nowFn  func() int64      // 可注入时钟，默认 time.Now().UnixMilli
}

func startKVMiniRedisFailAll(t *testing.T) *kvMiniRedis {
	t.Helper()
	m := startKVMiniRedis(t)
	m.failAll = true
	return m
}

func startKVMiniRedis(t *testing.T) *kvMiniRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock redis: %v", err)
	}
	m := &kvMiniRedis{
		ln:     ln,
		kv:     make(map[string]string),
		expire: make(map[string]int64),
		nowFn:  func() int64 { return time.Now().UnixMilli() },
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
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *kvMiniRedis) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readKVMockRESPArgs(reader)
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

func (m *kvMiniRedis) dispatch(args []string) string {
	cmd := strings.ToUpper(args[0])
	m.mu.Lock()
	m.cmdLog = append(m.cmdLog, strings.Join(args, " "))
	failAll := m.failAll
	m.mu.Unlock()
	// 故障注入模式：握手与 SETINFO 必须正常，否则连接无法建立。
	if failAll && cmd != "HELLO" && cmd != "CLIENT" {
		return "-ERR injected failure\r\n"
	}
	switch cmd {
	case "HELLO":
		// rueidis 按批发送 [HELLO 3, CLIENT SETINFO..., CLIENT SETINFO...]，
		// 回复逐条对应：HELLO 回 RESP3 map（proto=3），CLIENT 各自回 +OK。
		// DisableCache:true 时握手后续不再有 CLIENT TRACKING。
		return kvHelloMapReply()
	case "CLIENT":
		return "+OK\r\n"
	case "PING":
		return "+PONG\r\n"
	case "SET":
		return m.cmdKVSet(args)
	case "GET":
		return m.cmdKVGet(args)
	case "DEL", "UNLINK":
		return m.cmdKVDel(args)
	case "EXISTS":
		return m.cmdKVExists(args)
	case "PTTL":
		return m.cmdKVPTTL(args)
	case "INCR":
		return m.cmdKVIncr(args)
	case "SETNX":
		return m.cmdKVSetNX(args)
	case "EXPIRE", "PEXPIRE":
		return ":1\r\n"
	case "EVAL":
		// 定期执行脚本内容后进入独立的 EVAL 分支。
		return m.cmdKVEval(args, false)
	case "EVALSHA":
		// EVAL 更新时先尝试 sha1；把脚本 sha 从 EVAL 复制到 shas，
		// 使同一个 shas 缓存中相同执行逻辑。当真 sha 未命中时使用 EVAL。
		if resp, ok := m.cmdKVEvalSha(args); ok {
			return resp
		}
		return "-NOSCRIPT No matching script. Please use EVAL.\r\n"
	default:
		return "+OK\r\n"
	}
}

// kvHelloMapReply 生成 RESP3 map 应答：proto 必须为 RESP3 整数（:3）——若编码成
// bulk string，rueidis 会读成 proto<3 并回退 RESP2/HELLO 2 二次握手。
// version=7.2.5 使集群探测走 CLUSTER SLOTS；mock 对该命令回 +OK，
// parseShards 失败且错误文本含 "CLUSTER"，NewClient 单地址时据此回退单机客户端。
// kvBulk 组装 bulk string 回复。
func kvBulk(v string) string {
	return "$" + strconv.Itoa(len(v)) + "\r\n" + v + "\r\n"
}

func kvHelloMapReply() string {
	return "%7\r\n" +
		"$6\r\nserver\r\n$5\r\nredis\r\n" +
		"$7\r\nversion\r\n$5\r\n7.2.5\r\n" +
		"$5\r\nproto\r\n:3\r\n" +
		"$2\r\nid\r\n:1\r\n" +
		"$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n" +
		"$7\r\nmodules\r\n$0\r\n\r\n"
}

func (m *kvMiniRedis) cmdKVSet(args []string) string {
	// SET key value [PX ms | EX s] [NX]
	if len(args) < 3 {
		return "-ERR wrong number of arguments for 'set' command\r\n"
	}
	key, value := args[1], args[2]
	var expireMS int64
	for i := 3; i+1 < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "PX":
			ms, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				return "-ERR value is not an integer\r\n"
			}
			expireMS = m.nowFn() + ms
		case "EX":
			sec, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				return "-ERR value is not an integer\r\n"
			}
			expireMS = m.nowFn() + sec*1000
		case "NX":
			m.mu.Lock()
			_, exists := m.kv[key]
			m.mu.Unlock()
			if exists {
				return "$-1\r\n"
			}
		}
	}
	m.mu.Lock()
	m.kv[key] = value
	if expireMS > 0 {
		m.expire[key] = expireMS
	} else {
		delete(m.expire, key)
	}
	m.mu.Unlock()
	return "+OK\r\n"
}

func (m *kvMiniRedis) cmdKVGet(args []string) string {
	if len(args) != 2 {
		return "-ERR wrong number of arguments for 'get' command\r\n"
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.kv[args[1]]
	if !ok {
		return "$-1\r\n"
	}
	if exp := m.expire[args[1]]; exp > 0 && now >= exp {
		delete(m.kv, args[1])
		delete(m.expire, args[1])
		return "$-1\r\n"
	}
	return kvBulk(value)
}

func (m *kvMiniRedis) cmdKVDel(args []string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, key := range args[1:] {
		if _, ok := m.kv[key]; ok {
			delete(m.kv, key)
			delete(m.expire, key)
			n++
		}
	}
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

func (m *kvMiniRedis) cmdKVExists(args []string) string {
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, key := range args[1:] {
		value, ok := m.kv[key]
		if !ok {
			continue
		}
		if exp := m.expire[key]; exp > 0 && now >= exp {
			delete(m.kv, key)
			delete(m.expire, key)
			continue
		}
		_ = value
		n++
	}
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

func (m *kvMiniRedis) cmdKVPTTL(args []string) string {
	if len(args) != 2 {
		return "-ERR wrong number of arguments for 'pttl' command\r\n"
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.kv[args[1]]
	if !ok {
		return ":-2\r\n"
	}

	_ = value
	exp := m.expire[args[1]]
	if exp == 0 {
		return ":-1\r\n"
	}
	if now >= exp {
		delete(m.kv, args[1])
		delete(m.expire, args[1])
		return ":-2\r\n"
	}
	return ":" + strconv.FormatInt(exp-now, 10) + "\r\n"
}

func (m *kvMiniRedis) cmdKVIncr(args []string) string {
	if len(args) != 2 {
		return "-ERR wrong number of arguments for 'incr' command\r\n"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, _ := strconv.ParseInt(m.kv[args[1]], 10, 64)
	n++
	m.kv[args[1]] = strconv.FormatInt(n, 10)
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

func (m *kvMiniRedis) cmdKVSetNX(args []string) string {
	// SETNX key value — 无 TTL 形态保留给未来用例。
	if len(args) != 3 {
		return "-ERR wrong number of arguments for 'setnx' command\r\n"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kv[args[1]]; ok {
		return ":0\r\n"
	}
	m.kv[args[1]] = args[2]
	return ":1\r\n"
}

// kvLuaHandler 按脚本内容分派三个固定脚本；evalsha 复用同一处理器。
func (m *kvMiniRedis) cmdKVEval(args []string, _ bool) string {
	// EVAL script numkeys key... argv...
	if len(args) < 4 {
		return "-ERR wrong number of arguments for 'eval' command\r\n"
	}
	script := args[1]
	switch {
	case strings.Contains(script, "HGETALL"):
		return m.evalDrainHashPair(args)
	case strings.Contains(script, "redis.call('GET'"):
		return m.evalReleaseLock(args)
	default:
		return m.evalFixedWindow(args)
	}
}

func (m *kvMiniRedis) cmdKVEvalSha(args []string) (string, bool) {
	if len(args) < 4 {
		return "", false
	}
	sha := strings.ToLower(args[1])
	switch sha {
	case kvLuaSHA(incrFixedWindowScript):
		return m.evalFixedWindow(args), true
	case kvLuaSHA(drainHashPairScript):
		return m.evalDrainHashPair(args), true
	case kvLuaSHA(releaseLockScript):
		return m.evalReleaseLock(args), true
	}
	return "", false
}

func kvLuaSHA(script string) string {
	sum := sha1.Sum([]byte(script))
	return hex.EncodeToString(sum[:])
}

// evalFixedWindow 复刻 incrFixedWindowScript：首次 INCR 设 PEXPIRE，之后不动 TTL。
func (m *kvMiniRedis) evalFixedWindow(args []string) string {
	// args: [EVAL|EVALSHA, script|sha, numkeys, key, ttlMS]
	if len(args) != 5 {
		return "-ERR wrong EVAL args for fixed window\r\n"
	}
	key := args[3]
	ttlMS, err := strconv.ParseInt(args[4], 10, 64)
	if err != nil {
		return "-ERR ttl is not an integer\r\n"
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	n, _ := strconv.ParseInt(m.kv[key], 10, 64)
	n++
	m.kv[key] = strconv.FormatInt(n, 10)
	if n == 1 {
		m.expire[key] = now + ttlMS
	}
	return ":" + strconv.FormatInt(n, 10) + "\r\n"
}

// evalDrainHashPair 复刻 drainHashPairScript：HGETALL 两键并 DEL。
// mock 的 hash 以 h:<key>:f 前缀平铺于 kv 中，字段名再编码一层太复杂，
// 测试无用例断言字段内容，返回空数组即可保证长度契约（2 元素数组）。
func (m *kvMiniRedis) evalDrainHashPair(args []string) string {
	if len(args) < 5 {
		return "-ERR wrong EVAL args for drain hash pair\r\n"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range []string{args[3], args[4]} {
		delete(m.kv, key)
		delete(m.expire, key)
	}
	return "*2\r\n*0\r\n*0\r\n"
}

// evalReleaseLock 复刻 releaseLockScript：值匹配才 DEL。
func (m *kvMiniRedis) evalReleaseLock(args []string) string {
	if len(args) < 6 {
		return "-ERR wrong EVAL args for release lock\r\n"
	}
	key, want := args[3], args[5]
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kv[key] != want {
		return ":0\r\n"
	}
	delete(m.kv, key)
	delete(m.expire, key)
	return ":1\r\n"
}

// readKVMockRESPArgs 读取一条 RESP 数组命令（与既有 mock 解码器同构）。
func readKVMockRESPArgs(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array, got %q", line)
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
		length, err := strconv.Atoi(header[1:])
		if err != nil || length < 0 {
			return nil, fmt.Errorf("invalid bulk length %q", header)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		if _, err := reader.Discard(2); err != nil {
			return nil, err
		}
		args = append(args, string(body))
	}
	return args, nil
}
