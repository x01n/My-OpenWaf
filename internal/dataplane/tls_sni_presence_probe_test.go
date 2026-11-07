package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/tracer"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/protocol/http1"
	"github.com/cloudwego/hertz/pkg/protocol/suite"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/acme"
	dptlsfp "My-OpenWaf/internal/dataplane/tlsfp"
	"My-OpenWaf/internal/dataplane/tlsfp/tlsfptest"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/tlsmeta"
	"My-OpenWaf/internal/waf/bot/tlsfp"
)

/**
 * 本文件覆盖「访问日志里的 tls_sni 为空」的两义消歧，以及它所依赖的握手回填链。
 *
 * 断言的是机制而不是字段存在性：真实 TLS 客户端握手驱动真实入站包装链
 * （tls.Conn → FixURIConn → fixURIHertzConn），真实 Hertz HTTP/1 服务循环读出请求，
 * 再由数据面记录函数按生产口径落库，最后用 GORM 从库里读回并断言。
 *
 * 三种状态的构造成本：
 *   - present：客户端 ServerName 是域名，ClientHello 携带 server_name 扩展；
 *   - absent：客户端 ServerName 是 IP 字面量。Go 的 crypto/tls 在
 *     handshake_client.go 的 hostnameInSNI 中对 IP 显式返回空串，该扩展不发出；
 *   - unknown：明文连接，根本没有 ClientHello。
 *
 * 两种 TLS 情形都不启用 ClientHello 前缀窃读，因此 JA4 均为空——这恰好把
 * 「JA4 缺失」与「JA4 第 4 位为 i」两条判定路径分开覆盖。
 */

const tlsSNIProbePath = "/tls-sni-probe"

/**
 * TestTLSSNIPresenceDistinguishesAbsentFromUnknown 是本次交付的核心机制断言。
 *
 * 同一个入站栈、同一套记录函数，只改客户端 ServerName 形态：域名请求必须落库为
 * present，IP 字面量请求必须落库为 absent，两者都与「明文/未采集」的 unknown 可区分。
 */
func TestTLSSNIPresenceDistinguishesAbsentFromUnknown(t *testing.T) {
	db := openTLSSNILogDB(t)
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { writer.Close() })

	cases := []struct {
		name          string
		clientTLS     *tls.Config
		wantSNI       string
		wantPresence  string
		wantExtension bool
	}{
		{
			name:          "domain_client_sends_server_name_extension",
			clientTLS:     tlsSNIClientConfig("tls-sni-present.example"),
			wantSNI:       "tls-sni-present.example",
			wantPresence:  tlsfp.SNIPresencePresent,
			wantExtension: true,
		},
		{
			name:          "ip_literal_client_sends_no_server_name_extension",
			clientTLS:     tlsSNIClientConfig("127.0.0.1"),
			wantSNI:       "",
			wantPresence:  tlsfp.SNIPresenceAbsent,
			wantExtension: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requestID := "req-" + tc.name
			observation := runTLSSNIProbeRequest(t, tc.clientTLS, "probe.example:443", tlsSNIProbePath, writer, accessLogInfo{
				SiteID:       1,
				RequestID:    requestID,
				ClientIP:     "127.0.0.1",
				Host:         "probe.example:443",
				Path:         tlsSNIProbePath,
				Method:       http.MethodGet,
				UserAgent:    "tls-sni-presence-probe",
				StatusCode:   http.StatusOK,
				WAFAction:    "none",
				CacheState:   "bypass",
				HTTPProtocol: "http/1.1",
			})

			// 前提核对：absent 情形必须真的是客户端没发扩展，而不是服务端丢了。
			if got := hasServerNameExtension(observation.clientHelloExtensions); got != tc.wantExtension {
				t.Fatalf("probe premise broken: client hello server_name extension present = %v, want %v (extensions=%v)",
					got, tc.wantExtension, observation.clientHelloExtensions)
			}
			if observation.handshakeState.ServerName != tc.wantSNI {
				t.Fatalf("handshake ServerName = %q, want %q", observation.handshakeState.ServerName, tc.wantSNI)
			}

			entry := waitTLSSNIAccessLog(t, db, requestID)
			if entry.TLSSNI != tc.wantSNI {
				t.Fatalf("stored tls_sni = %q, want %q", entry.TLSSNI, tc.wantSNI)
			}
			if entry.TLSSNIPresence != tc.wantPresence {
				t.Fatalf("stored tls_sni_presence = %q, want %q", entry.TLSSNIPresence, tc.wantPresence)
			}
			// 该夹具不开 ClientHello 窃读，JA4 必然为空：判定此时只能来自握手回填，
			// 这条断言防止把 absent 退化成「因为没跑指纹解析所以是空的」。
			if entry.TLSJA4 != "" {
				t.Fatalf("probe expects no client hello peeking, got tls_ja4 = %q", entry.TLSJA4)
			}
			if entry.TLSVersion == "" {
				t.Fatal("handshake backfill did not reach the log entry: tls_version is empty")
			}
		})
	}

	t.Run("plaintext_is_unknown_not_absent", func(t *testing.T) {
		requestID := "req-plaintext"
		_ = runPlaintextSNIProbeRequest(t, "probe.example:80", tlsSNIProbePath, writer, accessLogInfo{
			SiteID:       1,
			RequestID:    requestID,
			ClientIP:     "127.0.0.1",
			Host:         "probe.example:80",
			Path:         tlsSNIProbePath,
			Method:       http.MethodGet,
			UserAgent:    "tls-sni-presence-probe",
			StatusCode:   http.StatusOK,
			WAFAction:    "none",
			CacheState:   "bypass",
			HTTPProtocol: "http/1.1",
		})

		entry := waitTLSSNIAccessLog(t, db, requestID)
		if entry.TLSSNI != "" {
			t.Fatalf("plaintext tls_sni = %q, want empty", entry.TLSSNI)
		}
		if entry.TLSSNIPresence != tlsfp.SNIPresenceUnknown {
			t.Fatalf("plaintext tls_sni_presence = %q, want unknown——明文请求没有 ClientHello，不得上报 absent", entry.TLSSNIPresence)
		}
		if entry.TLSJA4 != "" || entry.TLSVersion != "" {
			t.Fatalf("plaintext request must not carry TLS metadata: ja4=%q version=%q", entry.TLSJA4, entry.TLSVersion)
		}
	})
}

/**
 * TestTLSSNIPresencePropagatesToRedisMirror 断言镜像到 Redis 的访问日志同样携带判定。
 *
 * 镜像路径序列化的是内存里的读侧模型，与落库列无关；若不在镜像前补齐，
 * 下游消费方会拿到「空 tls_sni 且无 presence」的不可消歧形态。
 * 这里不依赖真实 Redis：直接把镜像使用的派生规则作用在同一份读侧模型上，
 * 断言它与 buildAccessLogEntry 的产物一致。
 */
func TestTLSSNIPresencePropagatesToRedisMirror(t *testing.T) {
	cases := []struct {
		name     string
		fp       tlsfp.TLSClientFingerprint
		wantSNI  string
		wantPres string
	}{
		{
			name:     "domain_client",
			fp:       tlsfp.TLSClientFingerprint{TLSVersion: "TLS13", JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", SNI: "app.example"},
			wantSNI:  "app.example",
			wantPres: tlsfp.SNIPresencePresent,
		},
		{
			name:     "ip_literal_client",
			fp:       tlsfp.TLSClientFingerprint{TLSVersion: "TLS13", JA4: "t13i1515h2_aaaaaaaaaaaa_bbbbbbbbbbbb"},
			wantSNI:  "",
			wantPres: tlsfp.SNIPresenceAbsent,
		},
		{
			name:     "plaintext_client",
			fp:       tlsfp.TLSClientFingerprint{},
			wantSNI:  "",
			wantPres: tlsfp.SNIPresenceUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetRequestURI("/redis-mirror")
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.Header.Set("Host", "app.example")

			entry := buildAccessLogEntry(ctx, accessLogInfo{
				SiteID:         1,
				RequestID:      "req-redis-" + tc.name,
				ClientIP:       "127.0.0.1",
				Host:           "app.example",
				Path:           "/redis-mirror",
				Method:         http.MethodGet,
				StatusCode:     http.StatusOK,
				WAFAction:      "none",
				CacheState:     "bypass",
				TLSFingerprint: tc.fp,
			})
			if entry.TLSSNI != tc.wantSNI || entry.TLSSNIPresence != tc.wantPres {
				t.Fatalf("built entry sni=%q presence=%q, want %q/%q",
					entry.TLSSNI, entry.TLSSNIPresence, tc.wantSNI, tc.wantPres)
			}

			// Redis 镜像对的正是这条读侧模型：按同一规则补齐后必须与原值一致。
			mirrored := entry
			mirrored.TLSSNIPresence = tlsfp.SNIPresenceFromValues(mirrored.TLSSNI, mirrored.TLSJA4, mirrored.TLSVersion != "" || mirrored.TLSJA4 != "")
			if mirrored.TLSSNIPresence != tc.wantPres {
				t.Fatalf("redis mirror presence = %q, want %q", mirrored.TLSSNIPresence, tc.wantPres)
			}
		})
	}
}

/**
 * TestTLSSNIPresenceDerivedOnReadFromStoredColumns 断言读侧派生覆盖「从库里读回」这条出口。
 *
 * tls_sni_presence 不是落库列；无论走哪条读取路径，读出的行都必须带上由同行
 * tls_sni / tls_ja4 得出的判定，因此这里直接写入三种已落库形态再读回。
 */
func TestTLSSNIPresenceDerivedOnReadFromStoredColumns(t *testing.T) {
	db := openTLSSNILogDB(t)

	seeds := []store.AccessLog{
		{RequestID: "req-stored-no-sni", TLSSNI: "", TLSJA4: "t13i1515h2_8daaf6152771_b79b8b93dec7", TLSVersion: "TLS13"},
		{RequestID: "req-stored-with-sni", TLSSNI: "app.example", TLSJA4: "t13d1516h2_8daaf6152771_02713d6af862", TLSVersion: "TLS13"},
		// 握手成功但 JA4 缺位（未开 ClientHello 窃读）：连接级 ServerName 是空的，
		// 这仍是权威的「客户端没发 SNI」，因为该字段由 TLS 栈自己从 ClientHello 得出。
		{RequestID: "req-stored-handshake-only", TLSSNI: "", TLSJA4: "", TLSVersion: "TLS13"},
		// 明文请求：没有任何握手证据，判定必须留在 unknown。
		{RequestID: "req-stored-plaintext", TLSSNI: "", TLSJA4: "", TLSVersion: ""},
	}
	for i := range seeds {
		seeds[i].Host = "probe.example"
		seeds[i].Path = tlsSNIProbePath
		seeds[i].Method = http.MethodGet
		if err := db.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed access log %q: %v", seeds[i].RequestID, err)
		}
	}

	want := map[string]string{
		"req-stored-no-sni":         tlsfp.SNIPresenceAbsent,
		"req-stored-with-sni":       tlsfp.SNIPresencePresent,
		"req-stored-handshake-only": tlsfp.SNIPresenceAbsent,
		"req-stored-plaintext":      tlsfp.SNIPresenceUnknown,
	}
	for requestID, wantPresence := range want {
		var entry store.AccessLog
		if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
			t.Fatalf("read access log %q: %v", requestID, err)
		}
		if entry.TLSSNIPresence != wantPresence {
			t.Fatalf("%s: read tls_sni_presence = %q, want %q", requestID, entry.TLSSNIPresence, wantPresence)
		}
	}
}

// tlsSNIProbeObservation 是一次真实入站请求可观测到的全部中介状态。
type tlsSNIProbeObservation struct {
	requestContext        *app.RequestContext
	fingerprint           tlsfp.TLSClientFingerprint
	handshakeState        tls.ConnectionState
	clientHelloExtensions []uint16
}

/**
 * runTLSSNIProbeRequest 用真实 TLS 客户端驱动真实入站包装链与 Hertz HTTP/1 服务循环。
 *
 * @param clientTLSConfig 客户端 TLS 配置，其 ServerName 决定是否发出 server_name 扩展。
 * @param host 请求行中的 Host 头。
 * @param path 请求路径。
 * @param writer 访问日志写入器。
 * @param info 访问日志模板；RequestID 与 TLSFingerprint 在 handler 内补齐。
 * @return 该次请求的上下文、指纹、握手状态与 ClientHello 扩展清单。
 */
func runTLSSNIProbeRequest(t *testing.T, clientTLSConfig *tls.Config, host string, path string, writer accessLogRecorder, info accessLogInfo) tlsSNIProbeObservation {
	t.Helper()

	cert, err := acme.GenerateSelfSigned("localhost")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tls probe: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	observationCh := make(chan tlsSNIProbeObservation, 1)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = serveTLSSNIProbeConnection(conn, serverTLS, info, writer, observationCh)
	}()

	rawConn, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("dial tls probe: %v", dialErr)
	}
	t.Cleanup(func() { _ = rawConn.Close() })

	client := tls.Client(rawConn, clientTLSConfig.Clone())
	// 握手在测试 goroutine 内同步完成：服务端握手在独立 goroutine 中进行，不会互相阻塞。
	if err := client.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	go func() {
		request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
		_, _ = client.Write([]byte(request))
		_, _ = io.ReadAll(client)
	}()

	select {
	case observation := <-observationCh:
		observation.clientHelloExtensions = clientHelloExtensionsForTLSSNITest(t, clientTLSConfig)
		return observation
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the inbound TLS request to be served")
		return tlsSNIProbeObservation{}
	}
}

/**
 * runPlaintextSNIProbeRequest 用明文连接驱动同一套记录路径。
 *
 * @return 该次请求的上下文与指纹（明文下必然为空指纹）。
 */
func runPlaintextSNIProbeRequest(t *testing.T, host string, path string, writer accessLogRecorder, info accessLogInfo) tlsSNIProbeObservation {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen plaintext probe: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	observationCh := make(chan tlsSNIProbeObservation, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = serveTLSSNIProbeConnection(conn, nil, info, writer, observationCh)
	}()

	go func() {
		conn, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", ln.Addr().String())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
		_, _ = conn.Write([]byte(request))
		_, _ = io.ReadAll(conn)
	}()

	select {
	case observation := <-observationCh:
		return observation
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the inbound plaintext request to be served")
		return tlsSNIProbeObservation{}
	}
}

/**
 * serveTLSSNIProbeConnection 在一条入站连接上跑一次真实的 Hertz HTTP/1 服务循环。
 *
 * 记录动作发生在真实的 handler 内部：此时请求上下文与生产一致（尚未被
 * http1.Server 的 putRequestContext 复位），指纹也按生产接线从连接上下文取。
 *
 * @param rawConn 入站 TCP 连接。
 * @param serverTLS 非 nil 时先做 TLS 终止，并包装成与生产同构的连接栈。
 * @param info 记录用的访问日志模板（RequestID/TLSFingerprint 由本函数补齐）。
 * @param writer 访问日志写入器。
 * @param observationCh 请求处理完成后回传可观测状态。
 */
func serveTLSSNIProbeConnection(rawConn net.Conn, serverTLS *tls.Config, info accessLogInfo, writer accessLogRecorder, observationCh chan<- tlsSNIProbeObservation) error {
	ctx := context.Background()
	var hertzConn net.Conn
	if serverTLS != nil {
		tlsConn := tls.Server(rawConn, serverTLS)
		hertzConn = newFixURIHertzConn(NewFixURIConn(tlsConn))
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
	} else {
		hertzConn = newFixURIHertzConn(rawConn)
	}

	// 与 internal/app 的生产接线同构：先按握手结果回填整条连接包装链，
	// 再把整条指纹放进请求上下文。
	if stateProvider, ok := hertzConn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		state := stateProvider.ConnectionState()
		dptlsfp.SetTLSHandshakeInfoOnConn(hertzConn, tlsmeta.CanonicalVersionName(state.Version), state.ServerName, state.NegotiatedProtocol)
	}
	if fp, ok := tlsfp.TLSFingerprintFromConn(hertzConn); ok {
		ctx = ContextWithTLSFingerprint(ctx, fp)
	}
	handshakeState := tls.ConnectionState{}
	if stateProvider, ok := hertzConn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		handshakeState = stateProvider.ConnectionState()
	}
	core := &tlsSNIProbeCore{ctx: app.NewContext(0)}
	core.onRequest = func(handlerCtx context.Context, c *app.RequestContext) {
		// 生产 handler 入口同样把连接级指纹写进请求上下文；日志构造器从那里读。
		fingerprint := tlsfp.TLSClientFingerprint{}
		if fp, ok := tlsFingerprintFromContext(handlerCtx); ok {
			fingerprint = fp
			c.Set(tlsFingerprintContextKey, fp)
		}
		entry := info
		entry.HTTPProtocol = "http/1.1"
		entry.TLSFingerprint = fingerprint
		// 走与生产完全相同的落库构造路径（buildAccessLogEntry → 写入器），
		// 因此断言的是「日志行本身」，而不是测试自建的字段拼装。
		enqueueAccessLog(writer, buildAccessLogEntry(c, entry))

		c.Response.SetStatusCode(http.StatusOK)
		c.Response.SetBodyString("probe")
		observationCh <- tlsSNIProbeObservation{
			requestContext: c,
			fingerprint:    fingerprint,
			handshakeState: handshakeState,
		}
	}

	networkConn, ok := hertzConn.(network.Conn)
	if !ok {
		return errors.New("probe connection does not satisfy network.Conn")
	}
	server := http1.NewServer()
	server.Core = core
	return server.Serve(ctx, networkConn)
}

// tlsSNIClientConfig 构造握手客户端配置；ServerName 为 IP 字面量时 Go 不发
// server_name 扩展，这正是 absent 情形的成因。
func tlsSNIClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	}
}

/**
 * clientHelloExtensionsForTLSSNITest 用同一份客户端配置抓取 ClientHello，
 * 供调用方核对「客户端到底发没发 server_name 扩展」这一前提。
 */
func clientHelloExtensionsForTLSSNITest(t *testing.T, clientTLSConfig *tls.Config) []uint16 {
	t.Helper()
	record := tlsfptest.BuildClientHelloRecord(t, clientTLSConfig)
	fp, err := tlsfp.ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("parse captured client hello: %v", err)
	}
	return fp.Extensions
}

// hasServerNameExtension 判定扩展清单里是否包含 server_name（扩展号 0）。
func hasServerNameExtension(extensions []uint16) bool {
	for _, id := range extensions {
		if id == 0 {
			return true
		}
	}
	return false
}

var _ suite.Core = (*tlsSNIProbeCore)(nil)
var _ tracer.Controller = (*tlsSNINoOpTracer)(nil)

// tlsSNIProbeCore 是测试用的 Core：把 Hertz HTTP/1 服务循环交出来的请求上下文
// 转给 onRequest，其余接口项按关闭遥测时的生产形态给出空实现。
type tlsSNIProbeCore struct {
	ctx       *app.RequestContext
	onRequest func(context.Context, *app.RequestContext)
	ctxPool   sync.Pool
	tracer    tlsSNINoOpTracer
}

func (c *tlsSNIProbeCore) IsRunning() bool { return true }

// GetCtxPool 复用一个固定上下文：Serve 会在结束时 Reset 并归还它，
// 测试只关心 handler 执行期间的取值。
func (c *tlsSNIProbeCore) GetCtxPool() *sync.Pool {
	c.ctxPool.New = func() any { return c.ctx }
	return &c.ctxPool
}

func (c *tlsSNIProbeCore) ServeHTTP(ctx context.Context, rc *app.RequestContext) {
	if c.onRequest != nil {
		c.onRequest(ctx, rc)
	}
}

func (c *tlsSNIProbeCore) GetTracer() tracer.Controller { return &c.tracer }

// tlsSNINoOpTracer 是未注册 Tracer 时的空控制器。
type tlsSNINoOpTracer struct{}

func (t *tlsSNINoOpTracer) Append(tracer.Tracer) {}

func (t *tlsSNINoOpTracer) DoStart(ctx context.Context, _ *app.RequestContext) context.Context {
	return ctx
}

func (t *tlsSNINoOpTracer) DoFinish(context.Context, *app.RequestContext, error) {}

func (t *tlsSNINoOpTracer) HasTracer() bool { return false }

/**
 * openTLSSNILogDB 打开一个日志库并完成日志表迁移。
 *
 * 用文件而不是 ":memory:"：写入经 UnifiedWriter 的独立 goroutine + 连接池，
 * 内存库的「每连接各自一个私有库」会让写连接建的表在读连接上消失
 * （测试表现为间歇性的 "no such table: access_logs"）。
 *
 * @param t 测试上下文。
 * @return 已完成日志表迁移的数据库句柄。
 */
func openTLSSNILogDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "waf_logs.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	return db
}

// waitTLSSNIAccessLog 轮询等待异步写入的访问日志落库。
func waitTLSSNIAccessLog(t *testing.T, db *gorm.DB, requestID string) store.AccessLog {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		var entry store.AccessLog
		if err := db.Where("request_id = ?", requestID).First(&entry).Error; err == nil {
			return entry
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("access log %q did not appear: %v", requestID, lastErr)
	return store.AccessLog{}
}
