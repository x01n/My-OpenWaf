package antireplay

import (
	"bufio"
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

func newTestManager() *AntiReplayManager {
	return NewAntiReplayManager("test-secret-key-for-unit-tests", nil, 5*time.Minute)
}

// TestGenerateNonceDecodesValidLength 验证生成的 nonce 可以被解码且长度正确。
func TestGenerateNonceDecodesValidLength(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	if nonce == "" {
		t.Fatal("generated nonce is empty")
	}
	import_base64 := false
	_ = import_base64
	// 直接通过 ValidateAndRotate 验证结构合法性
	valid, isReplay, newNonce := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid {
		t.Fatal("freshly generated nonce should be valid")
	}
	if isReplay {
		t.Fatal("fresh nonce should not be marked as replay")
	}
	if newNonce == "" {
		t.Fatal("rotated nonce should not be empty")
	}
}

// TestValidateAndRotateRejectsWrongIP 验证 IP 不匹配时签名无效。
func TestValidateAndRotateRejectsWrongIP(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	valid, _, _ := m.ValidateAndRotate(nonce, "9.9.9.9", 5*time.Minute)
	if valid {
		t.Fatal("nonce from different IP should be rejected")
	}
}

// TestValidateAndRotateRejectsMalformedNonce 验证格式错误的 nonce 被拒绝。
func TestValidateAndRotateRejectsMalformedNonce(t *testing.T) {
	m := newTestManager()
	for _, bad := range []string{"", "notbase64!!!", "aGVsbG8="} {
		valid, _, _ := m.ValidateAndRotate(bad, "1.2.3.4", 5*time.Minute)
		if valid {
			t.Errorf("malformed nonce %q should be rejected", bad)
		}
	}
}

// TestValidateAndRotateRejectsReplay 验证同一 nonce 在幂等窗口过期后再次提交时被标记为重放。
// 幂等窗口（8秒）内重试是合法的（幂等语义），8秒后提交同一 nonce 才是真正的重放。
// 本测试直接调用 validateAndRotateLocal 模拟跳过 idem 窗口的重放场景。
func TestValidateAndRotateRejectsReplay(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	freshNonce := m.GenerateNonce("1.2.3.4")

	// 第一次使用：合法
	valid1, isReplay1, _ := m.validateAndRotateLocal(nonce, freshNonce, 5*time.Minute)
	if !valid1 || isReplay1 {
		t.Fatalf("first use should succeed: valid=%v isReplay=%v", valid1, isReplay1)
	}

	// 模拟幂等窗口过期：直接删除 idemRotated 中的条目
	m.localMu.Lock()
	delete(m.idemRotated, nonce)
	m.localMu.Unlock()

	// 幂等窗口过期后，nonce 仍在 spentUntil 中 → 应被拒绝为重放
	valid2, isReplay2, _ := m.validateAndRotateLocal(nonce, freshNonce, 5*time.Minute)
	if valid2 {
		t.Fatal("nonce after idem window should be rejected as replay")
	}
	if !isReplay2 {
		t.Fatal("nonce after idem window should be flagged as replay")
	}
}

// TestValidateAndRotateIdempotentRetry 验证幂等重试（同一 nonce 在 idem 窗口内）返回相同的新 nonce。
func TestValidateAndRotateIdempotentRetry(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	valid1, _, newNonce1 := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid1 {
		t.Fatal("first use should succeed")
	}
	// 直接调用内部幂等旋转（模拟幂等重试：nonce 已在 idemRotated 中）
	valid2, isReplay2, newNonce2 := m.validateAndRotateLocal(nonce, "different-new-nonce", 5*time.Minute)
	if !valid2 {
		t.Fatal("idempotent retry should be valid")
	}
	if isReplay2 {
		t.Fatal("idempotent retry should not be flagged as replay")
	}
	// 幂等语义：返回第一次旋转时生成的新 nonce
	if newNonce2 != newNonce1 {
		t.Fatalf("idempotent retry should return same rotated nonce: got %q, want %q", newNonce2, newNonce1)
	}
}

// TestSetRedisNilAndNonNil 验证 SetRedis 可以设置和清除 redis 客户端。
func TestSetRedisNilAndNonNil(t *testing.T) {
	m := newTestManager()
	if m.redisClient() != nil {
		t.Fatal("initial redis client should be nil")
	}
	fakeClient := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer fakeClient.Close()
	m.SetRedis(fakeClient)
	if m.redisClient() == nil {
		t.Fatal("redis client should be non-nil after SetRedis")
	}
	m.SetRedis(nil)
	if m.redisClient() != nil {
		t.Fatal("redis client should be nil after SetRedis(nil)")
	}
}

// TestValidateAndRotateLocalEvictsExpiredSpentUntil 验证 spentUntil 超过 20000 时清理已过期条目。
func TestValidateAndRotateLocalEvictsExpiredSpentUntil(t *testing.T) {
	m := newTestManager()
	m.localMu.Lock()
	for i := 0; i < 20001; i++ {
		m.spentUntil[fmt.Sprintf("expired-nonce-%d", i)] = time.Now().Add(-1 * time.Second)
	}
	m.localMu.Unlock()

	nonce := m.GenerateNonce("1.2.3.4")
	m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)

	m.localMu.Lock()
	count := len(m.spentUntil)
	m.localMu.Unlock()
	if count >= 20000 {
		t.Errorf("expected eviction to reduce spentUntil below 20000, got %d", count)
	}
}

// TestValidateAndRotateLocalEvictsExpiredIdemRotated 验证 idemRotated 超过 5000 时清理已过期条目。
func TestValidateAndRotateLocalEvictsExpiredIdemRotated(t *testing.T) {
	m := newTestManager()
	m.localMu.Lock()
	for i := 0; i < 5001; i++ {
		m.idemRotated[fmt.Sprintf("idem-key-%d", i)] = idemEntry{newNonce: "x", expires: time.Now().Add(-1 * time.Second)}
	}
	m.localMu.Unlock()

	nonce := m.GenerateNonce("1.2.3.4")
	m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)

	m.localMu.Lock()
	count := len(m.idemRotated)
	m.localMu.Unlock()
	if count >= 5000 {
		t.Errorf("expected eviction to reduce idemRotated below 5000, got %d", count)
	}
}

// TestNewAntiReplayManagerDefaultTTL 验证 ttl<=0 时默认为 5 分钟。
func TestNewAntiReplayManagerDefaultTTL(t *testing.T) {
	m := NewAntiReplayManager("", nil, 0)
	if m.ttl != 5*time.Minute {
		t.Fatalf("expected default ttl=5m, got %v", m.ttl)
	}
	if len(m.secret) == 0 {
		t.Fatal("expected auto-generated secret when empty")
	}
}

type antiReplayRedisStep struct {
	response  string
	fail      bool
	loseReply bool
}

type antiReplayRedisServer struct {
	ln net.Listener

	mu    sync.Mutex
	steps []antiReplayRedisStep
	spent map[string]struct{}
	idems map[string]string
}

func startAntiReplayRedisServer(t *testing.T, steps ...antiReplayRedisStep) *antiReplayRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock Redis: %v", err)
	}
	srv := &antiReplayRedisServer{
		ln:    ln,
		steps: append([]antiReplayRedisStep(nil), steps...),
		spent: make(map[string]struct{}),
		idems: make(map[string]string),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()
	return srv
}

func (s *antiReplayRedisServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *antiReplayRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *antiReplayRedisServer) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readAntiReplayRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = io.WriteString(conn, "-ERR unknown command 'hello'\r\n")
		case "EVAL":
			response, closeAfter := s.eval(args)
			if closeAfter {
				return
			}
			_, _ = io.WriteString(conn, response)
		case "PING":
			_, _ = io.WriteString(conn, "+PONG\r\n")
		default:
			_, _ = io.WriteString(conn, "+OK\r\n")
		}
	}
}

func (s *antiReplayRedisServer) eval(args []string) (string, bool) {
	s.mu.Lock()
	var step antiReplayRedisStep
	if len(s.steps) > 0 {
		step = s.steps[0]
		s.steps = s.steps[1:]
	}
	s.mu.Unlock()

	if step.response != "" {
		return step.response, false
	}
	if len(args) != 8 {
		return "-ERR unexpected EVAL arguments\r\n", false
	}
	spentKey, idemKey, freshNonce := args[3], args[4], args[7]
	if step.fail {
		return "-ERR injected EVAL failure\r\n", false
	}
	if step.loseReply {
		s.consume(spentKey, idemKey, freshNonce)
		return "", true
	}
	code, value := s.consume(spentKey, idemKey, freshNonce)
	if code == 0 {
		return ":0\r\n", false
	}
	return antiReplayRedisArrayReply(code, value), false
}

func (s *antiReplayRedisServer) consume(spentKey, idemKey, freshNonce string) (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.spent[spentKey]; !ok {
		s.spent[spentKey] = struct{}{}
		s.idems[idemKey] = freshNonce
		return 1, freshNonce
	}
	if value, ok := s.idems[idemKey]; ok {
		return 2, value
	}
	return 0, ""
}

func antiReplayRedisArrayReply(code int64, value string) string {
	return "*2\r\n:" + strconv.FormatInt(code, 10) + "\r\n$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
}

func readAntiReplayRESPArgs(reader *bufio.Reader) ([]string, error) {
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
	for range count {
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
			return nil, fmt.Errorf("invalid bulk string length %q", header)
		}
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		if _, err := reader.Discard(2); err != nil {
			return nil, err
		}
		args = append(args, string(value))
	}
	return args, nil
}

func newAntiReplayRedisClient(addr string) *goredis.Client {
	return goredis.NewClient(&goredis.Options{
		Addr:       addr,
		MaxRetries: -1,
	})
}

func assertRedisFailure(t *testing.T, m *AntiReplayManager, nonce string) {
	t.Helper()
	valid, isReplay, rotated := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if valid || !isReplay || rotated != "" {
		t.Fatalf("Redis failure should trigger interception semantics: valid=%v isReplay=%v rotated=%q", valid, isReplay, rotated)
	}
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if len(m.spentUntil) != 0 || len(m.idemRotated) != 0 {
		t.Fatalf("Redis failure must not write local ledger: spent=%d idem=%d", len(m.spentUntil), len(m.idemRotated))
	}
}

// TestValidateAndRotateRedisMalformedResponsesFailClosed 验证 Redis 响应异常时不回退本地账本，并返回调用方的拦截语义。
func TestValidateAndRotateRedisMalformedResponsesFailClosed(t *testing.T) {
	cases := []struct {
		name string
		step antiReplayRedisStep
	}{
		{name: "eval error", step: antiReplayRedisStep{fail: true}},
		{name: "empty array", step: antiReplayRedisStep{response: "*0\r\n"}},
		{name: "non array", step: antiReplayRedisStep{response: "+OK\r\n"}},
		{name: "first element type error", step: antiReplayRedisStep{response: "*2\r\n$1\r\n1\r\n$3\r\nnew\r\n"}},
		{name: "second element type error", step: antiReplayRedisStep{response: "*2\r\n:1\r\n:2\r\n"}},
		{name: "unknown value", step: antiReplayRedisStep{response: "*1\r\n:9\r\n"}},
		{name: "missing element", step: antiReplayRedisStep{response: "*1\r\n:1\r\n"}},
		{name: "extra element", step: antiReplayRedisStep{response: "*3\r\n:1\r\n$3\r\nnew\r\n$5\r\nextra\r\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startAntiReplayRedisServer(t, tc.step)
			t.Cleanup(srv.Close)
			client := newAntiReplayRedisClient(srv.Addr())
			t.Cleanup(func() { _ = client.Close() })

			m := NewAntiReplayManager("test-secret-key-for-unit-tests", client, 5*time.Minute)
			assertRedisFailure(t, m, m.GenerateNonce("1.2.3.4"))
		})
	}
}

// TestValidateAndRotateRedisConsumedThenFailureDoesNotUseLocalLedger 验证 Redis 已消费后故障不会回退本地账本。
func TestValidateAndRotateRedisConsumedThenFailureDoesNotUseLocalLedger(t *testing.T) {
	srv := startAntiReplayRedisServer(t, antiReplayRedisStep{}, antiReplayRedisStep{fail: true})
	t.Cleanup(srv.Close)
	client := newAntiReplayRedisClient(srv.Addr())
	t.Cleanup(func() { _ = client.Close() })

	m := NewAntiReplayManager("test-secret-key-for-unit-tests", client, 5*time.Minute)
	nonce := m.GenerateNonce("1.2.3.4")
	valid, isReplay, rotated := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid || isReplay || rotated == "" {
		t.Fatalf("first Redis consumption failed: valid=%v isReplay=%v rotated=%q", valid, isReplay, rotated)
	}
	assertRedisFailure(t, m, nonce)
}

// TestValidateAndRotateRedisRecoversAfterInitialFailure 验证首次 Redis 错误后恢复时可以重新执行 Redis 原子操作。
func TestValidateAndRotateRedisRecoversAfterInitialFailure(t *testing.T) {
	srv := startAntiReplayRedisServer(t, antiReplayRedisStep{fail: true}, antiReplayRedisStep{})
	t.Cleanup(srv.Close)
	client := newAntiReplayRedisClient(srv.Addr())
	t.Cleanup(func() { _ = client.Close() })

	m := NewAntiReplayManager("test-secret-key-for-unit-tests", client, 5*time.Minute)
	nonce := m.GenerateNonce("1.2.3.4")
	assertRedisFailure(t, m, nonce)

	valid, isReplay, rotated := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid || isReplay || rotated == "" {
		t.Fatalf("Redis recovery should allow the first successful consumption: valid=%v isReplay=%v rotated=%q", valid, isReplay, rotated)
	}
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if len(m.spentUntil) != 0 || len(m.idemRotated) != 0 {
		t.Fatalf("Redis-backed recovery must not write local ledger: spent=%d idem=%d", len(m.spentUntil), len(m.idemRotated))
	}
}

// TestValidateAndRotateRedisLostReplyAfterSetNX 验证 SET NX 已执行但响应丢失时先拦截，恢复后使用 Redis 幂等结果。
func TestValidateAndRotateRedisLostReplyAfterSetNX(t *testing.T) {
	srv := startAntiReplayRedisServer(t, antiReplayRedisStep{loseReply: true}, antiReplayRedisStep{})
	t.Cleanup(srv.Close)
	client := newAntiReplayRedisClient(srv.Addr())
	t.Cleanup(func() { _ = client.Close() })

	m := NewAntiReplayManager("test-secret-key-for-unit-tests", client, 5*time.Minute)
	nonce := m.GenerateNonce("1.2.3.4")
	assertRedisFailure(t, m, nonce)

	valid, isReplay, rotated := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid || isReplay || rotated == "" {
		t.Fatalf("Redis idempotent retry after lost reply should succeed: valid=%v isReplay=%v rotated=%q", valid, isReplay, rotated)
	}
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if len(m.spentUntil) != 0 || len(m.idemRotated) != 0 {
		t.Fatalf("lost Redis reply must not write local ledger: spent=%d idem=%d", len(m.spentUntil), len(m.idemRotated))
	}
}
