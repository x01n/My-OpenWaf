package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// appGRPCFrame 构造标准 gRPC 帧：1 字节压缩标志(0) + 4 字节大端长度 + 消息体。
func appGRPCFrame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	copy(out[5:], msg)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	return out
}

// waitGRPCNoCacheHit 等待该路径最近的访问日志全部为 miss（不得出现 hit）。
func waitGRPCNoCacheHit(t *testing.T, h *appProcessHarness, siteID uint, path string) {
	t.Helper()
	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var resp accessLogListResponse
		h.getJSON(t, fmt.Sprintf("/api/v1/sites/%d/access-logs?page=1&page_size=50&path=%s", siteID, path), &resp)
		if len(resp.Items) >= 2 {
			allMiss := true
			for _, item := range resp.Items {
				if item.CacheState == "hit" {
					allMiss = false
					break
				}
			}
			if allMiss {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("gRPC path access logs still contain cache hits for path=%q\n%s", path, h.output.String())
}

// TestGRPCUnaryCacheBoundaryInSeparateProcess 在独立进程数据面钉住 gRPC
// 响应的两级缓存边界：
//  1. 真实 gRPC 是 POST：SiteCacheEligibleWithStale 的 isCacheableRequestMethod
//     只认 GET/HEAD，POST 天然到不了 ShouldCacheHTTPResponse，两次调用都必须回源；
//  2. GET 形态（gRPC-Web unary 的 GET 编码、或误把 RPC 路径配进缓存规则的站点）：
//     修复前 ShouldCacheHTTPResponse 接受 application/grpc 家族，第二次 GET 命中
//     共享缓存（2026-09-19 21:54 实测 upstream 计数停在 1，缺陷成立，见
//     temp/grpc-proxy-e2e-report.md）；修复后（排除 application/grpc 前缀）
//     第二次 GET 必须回源。
func TestGRPCUnaryCacheBoundaryInSeparateProcess(t *testing.T) {
	const requestPath = "/grpc.CachedEcho/Unary"
	wantFrame := appGRPCFrame([]byte("cached-grpc-reply"))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != requestPath {
			http.NotFound(w, r)
			return
		}
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Trailer", "grpc-status, grpc-message")
		_, _ = w.Write(wantFrame)
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	const siteHost = "grpc-edge-cache.example.test"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/grpc.CachedEcho", TTL: 60},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}
		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			CacheEnabled:    true,
			CacheDefaultTTL: 60,
			CacheRules:      string(cacheRulesBytes),
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	requireGRPCFrame := func(label string, resp *http.Response, body []byte) {
		t.Helper()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", label, resp.StatusCode, http.StatusOK)
		}
		if !bytes.Equal(body, wantFrame) {
			t.Fatalf("%s body len = %d, want frame len = %d", label, len(body), len(wantFrame))
		}
	}

	// GET 异常形态第一次：回源填充尝试（修复后 Nothing 入库）。
	respGet1, bodyGet1 := appProc.waitHTTPResponse(t, tcpBind, siteHost, requestPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK && strings.TrimSpace(resp.Header.Get("X-Request-ID")) != ""
	})
	requireGRPCFrame("GET#1", respGet1, bodyGet1)
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream request count after GET#1 = %d, want 1", got)
	}
	t.Logf("GET#1 grpc-status: header=%q trailer=%q", strings.TrimSpace(respGet1.Header.Get("Grpc-Status")), strings.TrimSpace(respGet1.Trailer.Get("grpc-status")))

	// GET 异常形态第二次：修复后必须回源（修复前此处命中缓存、计数停在 1）。
	respGet2, bodyGet2 := appProc.waitHTTPResponse(t, tcpBind, siteHost, requestPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK && strings.TrimSpace(resp.Header.Get("X-Request-ID")) != ""
	})
	requireGRPCFrame("GET#2", respGet2, bodyGet2)
	if got := upstreamRequests.Load(); got != 2 {
		t.Fatalf("upstream request count after GET#2 = %d, want 2 (gRPC response must not be stored in edge cache)", got)
	}

	// POST 真实 gRPC 形态：天然不具备缓存资格，两次都必须回源。
	postGRPC := func(label string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+tcpBind+requestPath, bytes.NewReader(appGRPCFrame([]byte("ping"))))
		if err != nil {
			t.Fatalf("build %s post request: %v", label, err)
		}
		req.Host = siteHost
		req.Header.Set("Content-Type", "application/grpc")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s post request: %v", label, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("%s read body: %v", label, readErr)
		}
		requireGRPCFrame(label, resp, body)
	}

	postGRPC("POST#1")
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("upstream request count after POST#1 = %d, want 3", got)
	}
	postGRPC("POST#2")
	if got := upstreamRequests.Load(); got != 4 {
		t.Fatalf("upstream request count after POST#2 = %d, want 4 (POST gRPC must never be cached)", got)
	}

	waitGRPCNoCacheHit(t, appProc, siteID, requestPath)
}
