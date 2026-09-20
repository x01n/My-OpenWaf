package dataplane

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
)

/*
本文件补齐 antireplay_handler_test.go 明确列为"无法覆盖"的第 1 项：
**Redis 成功路径**在 handler 层的语义。

对该"无法覆盖"结论的更正：原文称"ValidateAndRotate 只接受 *goredis.Client
具体类型，无法注入内存假实现；redisNonceLua 依赖服务端 Lua 求值，也无法用
协议层打桩伪造"。这一结论不成立 —— internal/waf/antireplay/antireplay_test.go:199
已经用一个协议层 RESP mock（startAntiReplayRedisServer）覆盖了 Redis 分支。
*goredis.Client 是具体类型不构成障碍：它连的是 TCP 地址，因此在测试里监听一个
本地端口、按 RESP 协议应答即可，无需接口抽象。

本文件把同一手法搬到 dataplane 层，覆盖 handler 视角的 Redis 语义。
antireplay 包内的 mock 是包内未导出标识符，跨包不可复用，故此处重新实现一份
最小版本，只支持本用例所需的 HELLO/PING/EVAL 三条命令。

被模拟的服务端逻辑是 redisNonceLua（antireplay.go:34-45）：
  - spentKey 用 SET NX EX 抢占；抢到则写入 idemKey=newNonce 并返回 {1, newNonce}
  - 未抢到但 idemKey 存在则返回 {2, 已缓存的 nonce}（幂等命中）
  - 两者皆不满足则返回 {0}（判定重放）
*/

/**
 * antiReplayRedisMock 是仅供本文件使用的最小 RESP 服务端，
 * 在内存中复刻 redisNonceLua 的三分支语义。
 */
type antiReplayRedisMock struct {
	ln net.Listener

	mu    sync.Mutex
	spent map[string]struct{}
	idems map[string]string
	evals int
}

/**
 * startAntiReplayRedisMock 启动 mock 并在测试结束时关闭。
 *
 * @param t 测试上下文
 * @returns 已监听的 mock 实例
 */
func startAntiReplayRedisMock(t *testing.T) *antiReplayRedisMock {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock Redis: %v", err)
	}
	m := &antiReplayRedisMock{
		ln:    ln,
		spent: make(map[string]struct{}),
		idems: make(map[string]string),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

/**
 * addr 返回 mock 的监听地址。
 */
func (m *antiReplayRedisMock) addr() string { return m.ln.Addr().String() }

/**
 * evalCount 返回累计收到的 EVAL 次数，用于证明请求确实走了 Redis 分支
 * 而非本地回退。
 */
func (m *antiReplayRedisMock) evalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evals
}

func (m *antiReplayRedisMock) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readMockRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			// 拒绝 HELLO 使 go-redis 退回 RESP2，避免实现握手协商。
			_, _ = io.WriteString(conn, "-ERR unknown command 'hello'\r\n")
		case "PING":
			_, _ = io.WriteString(conn, "+PONG\r\n")
		case "EVAL":
			_, _ = io.WriteString(conn, m.eval(args))
		default:
			_, _ = io.WriteString(conn, "+OK\r\n")
		}
	}
}

/**
 * eval 复刻 redisNonceLua。EVAL 的实参布局由 antireplay.go:141 决定：
 * [EVAL, script, "2", spentKey, idemKey, spentTTL, idemSeconds, newNonce]。
 *
 * @param args 完整 EVAL 实参
 * @returns RESP 编码的应答
 */
func (m *antiReplayRedisMock) eval(args []string) string {
	m.mu.Lock()
	m.evals++
	m.mu.Unlock()

	if len(args) != 8 {
		return "-ERR unexpected EVAL arguments\r\n"
	}
	spentKey, idemKey, freshNonce := args[3], args[4], args[7]

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.spent[spentKey]; !ok {
		m.spent[spentKey] = struct{}{}
		m.idems[idemKey] = freshNonce
		return mockRESPArray(1, freshNonce)
	}
	if cached, ok := m.idems[idemKey]; ok {
		return mockRESPArray(2, cached)
	}
	return ":0\r\n"
}

/**
 * mockRESPArray 编码 {code, value} 两元素数组。
 */
func mockRESPArray(code int, value string) string {
	return "*2\r\n:" + strconv.Itoa(code) + "\r\n$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
}

/**
 * readMockRESPArgs 解析一条 RESP 数组形式的命令。
 */
func readMockRESPArgs(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" || line[0] != '*' {
		return nil, nil
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 {
		return nil, nil
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimRight(header, "\r\n")
		if header == "" || header[0] != '$' {
			return nil, nil
		}
		length, err := strconv.Atoi(header[1:])
		if err != nil || length < 0 {
			return nil, nil
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:length]))
	}
	return args, nil
}

/**
 * newAntiReplayRedisEnv 构造一个开启 AntiReplay 且以 mock Redis 为后端的站点。
 *
 * @param t 测试上下文
 * @param mock 已启动的 mock Redis
 * @returns handler、manager 与上游命中计数
 */
func newAntiReplayRedisEnv(t *testing.T, mock *antiReplayRedisMock) antiReplayConfigEnv {
	t.Helper()

	var mu sync.Mutex
	upstreamHits := 0
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstreamServer.Close)

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:                1,
			Host:              antiReplayConfigHost,
			Bind:              ":80",
			AntiReplayEnabled: antiReplayEnabledPtr(true),
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamServer.URL},
		EffectiveProtection: &protection,
		AntiReplayEnabled:   true,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", antiReplayConfigHost): &rt,
		},
	})

	client := goredis.NewClient(&goredis.Options{Addr: mock.addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("antireplay-redis-test-secret", client, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	return antiReplayConfigEnv{
		handler: Handler(Options{
			Holder: holder,
			Engine: eng,
			Log:    slog.Default(),
			Bind:   ":80",
		}),
		manager: mgr,
		upstreamRequests: func() int {
			mu.Lock()
			defer mu.Unlock()
			return upstreamHits
		},
	}
}

/**
 * TestAntiReplayHandlerRedisSuccessRotatesCookie 固化 Redis 成功路径在 Cookie 入口
 * 的语义：首次消费走 redisNonceLua 的 code=1 分支，请求放行且 Cookie 轮换为
 * 脚本返回的新值。
 *
 * 断言 evalCount 从 0 变为 1，用于排除"其实走了本地回退"这一可能：
 * 本地回退只在 m.redisClient() == nil 时可达（antireplay.go:170）。
 */
func TestAntiReplayHandlerRedisSuccessRotatesCookie(t *testing.T) {
	mock := startAntiReplayRedisMock(t)
	env := newAntiReplayRedisEnv(t, mock)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	c := doAntiReplayConfigRequest(env.handler, original, "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("Redis 成功路径 status = %d, want %d", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("应下发 1 个轮换 nonce, got %v", issued)
	}
	if issued[0] == original {
		t.Fatal("Redis 成功路径未发生轮换")
	}
	if got := mock.evalCount(); got != 1 {
		t.Fatalf("EVAL 次数 = %d, want 1（证明确实走 Redis 分支而非本地回退）", got)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
}

/**
 * TestAntiReplayHandlerRedisIdempotentReplayReturnsSameRotation 固化 Redis 幂等分支：
 * 同一 nonce 第二次提交命中脚本的 code=2 分支，仍然**放行**，
 * 且返回与首次完全相同的轮换值。
 *
 * 这与本地回退的行为一致（antireplay.go:192-194），说明"同一 nonce 只能成功一次"
 * 在幂等窗口内于两种后端下都**不成立**。
 * 本 mock 不实现 EX 过期，因此只覆盖窗口内语义；窗口过期后的拦截由
 * antireplay_handler_test.go 的本地路径用例覆盖。
 */
func TestAntiReplayHandlerRedisIdempotentReplayReturnsSameRotation(t *testing.T) {
	mock := startAntiReplayRedisMock(t)
	env := newAntiReplayRedisEnv(t, mock)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	first := doAntiReplayConfigRequest(env.handler, original, "")
	second := doAntiReplayConfigRequest(env.handler, original, "")

	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次提交 status = %d, want %d", got, http.StatusOK)
	}
	if got := second.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("幂等重复提交 status = %d, want %d（现状为放行）", got, http.StatusOK)
	}

	firstIssued := issuedNonceCookies(first)
	secondIssued := issuedNonceCookies(second)
	if len(firstIssued) != 1 || len(secondIssued) != 1 {
		t.Fatalf("下发数量异常: first=%v second=%v", firstIssued, secondIssued)
	}
	if firstIssued[0] != secondIssued[0] {
		t.Fatalf("幂等分支应返回同一轮换值: first=%q second=%q", firstIssued[0], secondIssued[0])
	}
	if got := mock.evalCount(); got != 2 {
		t.Fatalf("EVAL 次数 = %d, want 2", got)
	}
}

/**
 * TestAntiReplayHandlerRedisExhaustedIdemIsIntercepted 固化 Redis 的 code=0 分支：
 * spentKey 已存在但 idemKey 已过期（幂等窗口结束）时脚本返回 {0}，
 * ValidateAndRotate 返回 (false, true, "")（antireplay.go:150-155），
 * handler 以 403 拦截且不下发新 nonce。
 *
 * 构造方式：先正常消费一次，然后直接从 mock 中删除 idem 记录以模拟其 EX 过期，
 * 无需真实等待。
 */
func TestAntiReplayHandlerRedisExhaustedIdemIsIntercepted(t *testing.T) {
	mock := startAntiReplayRedisMock(t)
	env := newAntiReplayRedisEnv(t, mock)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	first := doAntiReplayConfigRequest(env.handler, original, "")
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次提交 status = %d, want %d", got, http.StatusOK)
	}

	// 模拟 idemKey 的 EX 到期：保留 spent 记录，清空幂等缓存。
	mock.mu.Lock()
	mock.idems = make(map[string]string)
	mock.mu.Unlock()

	second := doAntiReplayConfigRequest(env.handler, original, "")
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("幂等窗口结束后重放 status = %d, want %d", got, http.StatusForbidden)
	}
	if issued := issuedNonceCookies(second); len(issued) != 0 {
		t.Fatalf("nonce_reuse 拦截分支不应下发新 nonce, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（重放未到达上游）", got)
	}
}
