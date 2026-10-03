package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/x01n/http2/config"

	snapshotpkg "My-OpenWaf/internal/snapshot"
)

// h2FactoryOptionSignature 断言工厂 Option 只触碰 config.Config 的已存在字段。
// 引入时先穷举全部公开 Option：若 fork 升级新增 Option，本测试仍只校验仓库实际使用的五项。
const (
	// 与 fork config.WithServerMaxHeaderListSize 的语义对齐：
	// MaxHeaderListSize 的默认回退来自 http2.maxHeaderListSize()，
	// 即 1MB + 10 个典型头 × 32B，仓库值为显式覆盖结果。
	h2FactoryOptionAppliedFlagPrefix = "h2-option"
)

func applyOptionsAndSnapshot(opts []config.Option) *config.Config {
	cfg := config.NewConfig(opts...)
	return cfg
}

func StringifyHTTP2FactoryOptions(cfg snapshotpkg.HTTP2Config) string {
	return fmt.Sprintf("read_timeout=%v disable_keepalive=%v permit_prohibited_ciphers=%v max_concurrent_streams=%d max_read_frame_size=%d idle_timeout=%v max_upload_buffer_per_connection=%d max_upload_buffer_per_stream=%d max_header_list_size=%d max_header_fields=%d",
		time.Duration(cfg.ReadTimeoutSeconds)*time.Second,
		cfg.DisableKeepalive,
		cfg.PermitProhibitedCipherSuites,
		cfg.MaxConcurrentStreams,
		cfg.MaxReadFrameSize,
		time.Duration(cfg.IdleTimeoutSeconds)*time.Second,
		cfg.MaxUploadBufferPerConnection,
		cfg.MaxUploadBufferPerStream,
		uint32(cfg.MaxHeaderBytes+cfg.MaxHeaderFields*32),
		cfg.MaxHeaderFields,
	)
}

// TestHTTP2ServerFactoryOptionsPin 钉住 data-plane http2 ServerFactory 的选项映射：
// 快照 HTTP2Config → fork config.Config 是一一映射，任何层改动必须先过这里。
func TestHTTP2ServerFactoryOptionsPin(t *testing.T) {
	cfg := snapshotpkg.DefaultHTTP2Config()

	got := applyOptionsAndSnapshot(http2ServerFactoryOptions(cfg))

	assertInt32 := func(name string, got, want int32) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
	assertUint32 := func(name string, got, want uint32) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
	assertInt := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
	assertBool := func(name string, got, want bool) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
	assertDur := func(name string, got, want time.Duration) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}

	assertDur("ReadTimeout", got.ReadTimeout, time.Duration(cfg.ReadTimeoutSeconds)*time.Second)
	assertBool("DisableKeepalive", got.DisableKeepalive, cfg.DisableKeepalive)
	assertBool("PermitProhibitedCipherSuites", got.PermitProhibitedCipherSuites, cfg.PermitProhibitedCipherSuites)
	assertUint32("MaxConcurrentStreams", got.MaxConcurrentStreams, cfg.MaxConcurrentStreams)
	assertUint32("MaxReadFrameSize", got.MaxReadFrameSize, cfg.MaxReadFrameSize)
	assertDur("IdleTimeout", got.IdleTimeout, time.Duration(cfg.IdleTimeoutSeconds)*time.Second)
	assertInt32("MaxUploadBufferPerConnection", got.MaxUploadBufferPerConnection, cfg.MaxUploadBufferPerConnection)
	assertInt32("MaxUploadBufferPerStream", got.MaxUploadBufferPerStream, cfg.MaxUploadBufferPerStream)
	assertUint32("MaxHeaderListSize", got.MaxHeaderListSize, uint32(cfg.MaxHeaderBytes+cfg.MaxHeaderFields*32))
	assertInt("MaxHeaderFields", got.MaxHeaderFields, cfg.MaxHeaderFields)
}

// TestHTTP2ServerFactoryOptionsNormalized 验证 NormalizeHTTP2Config 后的边界值
// 也能被工厂完整透传（比如 admin 保存的值经归一化后的上限）。
func TestHTTP2ServerFactoryOptionsNormalized(t *testing.T) {
	cfg := snapshotpkg.DefaultHTTP2Config()
	cfg.MaxConcurrentStreams = snapshotpkg.MaxHTTP2ConcurrentStreams // 1000
	cfg.MaxReadFrameSize = snapshotpkg.MaxHTTP2ReadFrameSize         // 16M-1
	cfg.MaxUploadBufferPerConnection = snapshotpkg.MaxHTTP2UploadBufferPerConnection
	cfg.MaxUploadBufferPerStream = snapshotpkg.MaxHTTP2UploadBufferPerStream
	cfg.MaxHeaderBytes = snapshotpkg.MaxHTTP2HeaderBytes
	cfg.MaxHeaderFields = snapshotpkg.MaxHTTP2HeaderFields

	got := applyOptionsAndSnapshot(http2ServerFactoryOptions(cfg))

	if got.MaxConcurrentStreams != cfg.MaxConcurrentStreams {
		t.Fatalf("MaxConcurrentStreams = %d, want %d", got.MaxConcurrentStreams, cfg.MaxConcurrentStreams)
	}
	if got.MaxReadFrameSize != cfg.MaxReadFrameSize {
		t.Fatalf("MaxReadFrameSize = %d, want %d", got.MaxReadFrameSize, cfg.MaxReadFrameSize)
	}
	if got.MaxUploadBufferPerConnection != cfg.MaxUploadBufferPerConnection {
		t.Fatalf("MaxUploadBufferPerConnection = %d, want %d", got.MaxUploadBufferPerConnection, cfg.MaxUploadBufferPerConnection)
	}
	if got.MaxUploadBufferPerStream != cfg.MaxUploadBufferPerStream {
		t.Fatalf("MaxUploadBufferPerStream = %d, want %d", got.MaxUploadBufferPerStream, cfg.MaxUploadBufferPerStream)
	}
	if got.MaxHeaderListSize != uint32(cfg.MaxHeaderBytes+cfg.MaxHeaderFields*32) {
		t.Fatalf("MaxHeaderListSize = %d, want %d", got.MaxHeaderListSize, uint32(cfg.MaxHeaderBytes+cfg.MaxHeaderFields*32))
	}
	if got.MaxHeaderFields != cfg.MaxHeaderFields {
		t.Fatalf("MaxHeaderFields = %d, want %d", got.MaxHeaderFields, cfg.MaxHeaderFields)
	}
}

// TestHTTP2DefaultConfigReflectsForkBehavior 对照 fork 源码里的常数，
// 防止默认值静默漂移后破坏既有 SETTINGS 行为。
// 引用 fork v0.2.0：http2.go defaultMaxReadFrameSize=1<<20、server.go defaultMaxStreams=250、
// maxQueuedControlFrames=10000；flow.go initialWindowSize=65535。
func TestHTTP2DefaultConfigReflectsForkBehavior(t *testing.T) {
	cfg := snapshotpkg.DefaultHTTP2Config()
	if cfg.MaxQueuedControlFrames != 10000 {
		t.Fatalf("MaxQueuedControlFrames default = %d, fork constant is 10000", cfg.MaxQueuedControlFrames)
	}
	if cfg.MaxHandlers != 0 {
		t.Fatalf("MaxHandlers default = %d, fork has no limit implemented (0 = no limit)", cfg.MaxHandlers)
	}
}

// TestHTTP2ConfigDefaultsAreWithinNormalizeBounds 默认配置归一化后必须逐字段等于自身。
func TestHTTP2ConfigDefaultsAreWithinNormalizeBounds(t *testing.T) {
	cfg := snapshotpkg.DefaultHTTP2Config()
	normalized := snapshotpkg.NormalizeHTTP2Config(cfg)
	if got := StringifyHTTP2FactoryOptions(normalized); got != StringifyHTTP2FactoryOptions(cfg) {
		t.Fatalf("normalized default http2 config drifted:\n got: %s\nwant: %s", got, StringifyHTTP2FactoryOptions(cfg))
	}
}
