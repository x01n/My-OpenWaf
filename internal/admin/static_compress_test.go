package admin

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

/**
 * TestAdminStaticAssetsServeCompressed 验证管理端静态构建产物（_next/static 下的
 * JS）在客户端声明 gzip 时返回压缩字节，并携带 immutable 缓存与 Vary 协商头。
 *
 * 断言解压后与不压缩请求得到的原文严格一致，避免只验证头而漏掉内容损坏。
 */
func TestAdminStaticAssetsServeCompressed(t *testing.T) {
	srv := newAdminRouteTestServer(t)

	index := srv.getJSON(t, "/dashboard")
	if index.StatusCode() != 200 {
		t.Fatalf("GET /dashboard status = %d, want 200", index.StatusCode())
	}
	assetPath := firstStaticAssetPath(t, index.Body())
	if assetPath == "" {
		t.Skip("embedded dist has no _next/static JS asset to verify")
	}

	plain := srv.getJSON(t, assetPath)
	if plain.StatusCode() != 200 {
		t.Fatalf("GET %s status = %d, want 200", assetPath, plain.StatusCode())
	}
	if got := string(plain.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("plain request Content-Encoding = %q, want empty", got)
	}

	packed := srv.getJSONWithHeaders(t, assetPath, map[string]string{"Accept-Encoding": "gzip, deflate"})
	if got := string(packed.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("compressed request Content-Encoding = %q, want gzip", got)
	}
	if got := string(packed.Header.Peek("Vary")); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	if got := string(packed.Header.Peek("Cache-Control")); got != "public,max-age=31536000,immutable" {
		t.Fatalf("Cache-Control = %q, want immutable policy", got)
	}

	gz, err := gzip.NewReader(bytes.NewReader(packed.Body()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	roundTrip, err := io.ReadAll(gz)
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(roundTrip, plain.Body()) {
		t.Fatal("decompressed asset differs from plain response body")
	}
	if len(packed.Body()) >= len(plain.Body()) {
		t.Fatalf("compressed size %d not smaller than plain %d", len(packed.Body()), len(plain.Body()))
	}
}

/**
 * TestAdminStaticHTMLIsNotImmutable 验证页面 HTML 不使用 immutable 缓存，
 * 保证发版后浏览器能立即拿到新文档。
 */
func TestAdminStaticHTMLIsNotImmutable(t *testing.T) {
	srv := newAdminRouteTestServer(t)

	resp := srv.getJSON(t, "/dashboard")
	if got := string(resp.Header.Peek("Cache-Control")); got == "public,max-age=31536000,immutable" {
		t.Fatal("route HTML must not be served with immutable cache policy")
	}
}

/** firstStaticAssetPath 从导出的 HTML 中提取首个 _next/static 下的 JS 资源路径。 */
func firstStaticAssetPath(t *testing.T, body []byte) string {
	t.Helper()
	const marker = "/_next/static/"
	idx := bytes.Index(body, []byte(marker))
	if idx < 0 {
		return ""
	}
	rest := body[idx:]
	end := bytes.IndexAny(rest, "\"'")
	if end <= 0 {
		return ""
	}
	return string(rest[:end])
}
