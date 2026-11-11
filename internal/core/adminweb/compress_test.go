package adminweb

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

/**
 * TestCompressedBodyGzipTextAssets 验证文本资源返回 gzip 字节；
 * 小于阈值或不可压缩类型按原文返回。
 */
func TestCompressedBodyGzipTextAssets(t *testing.T) {
	bigJS := bytes.Repeat([]byte("console.log('x');\n"), 200) // ~3.4KB

	body, encoding := CompressedBody("_next/static/chunks/app.js", bigJS)
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip", encoding)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
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
	if !bytes.Equal(roundTrip, bigJS) {
		t.Fatal("round-trip content differs from source bytes")
	}
}

/**
 * TestCompressedBodyFallbacks 验证阈值以下、不可压缩类型与缓存命中三种回退路径。
 */
func TestCompressedBodyFallbacks(t *testing.T) {
	small := []byte("x")

	if _, enc := CompressedBody("_next/static/tiny.js", small); enc != "" {
		t.Fatalf("small file encoding = %q, want empty", enc)
	}
	png := bytes.Repeat([]byte{0x89, 0x50}, 2048)
	if _, enc := CompressedBody("_next/static/img.png", png); enc != "" {
		t.Fatalf("png encoding = %q, want empty", enc)
	}
	big := bytes.Repeat([]byte("body{color:#fff}\n"), 200)
	if _, enc := CompressedBody("_next/static/app.css", big); enc != "gzip" {
		t.Fatalf("css first call encoding = %q, want gzip", enc)
	}
	if _, enc := CompressedBody("_next/static/app.css", big); enc != "gzip" {
		t.Fatalf("css cached call encoding = %q, want gzip", enc)
	}
}

/**
 * TestCacheControlPolicy 验证内容哈希资产用 immutable，页面 HTML 每次回源校验。
 */
func TestCacheControlPolicy(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"_next/static/chunks/app.js", "public,max-age=31536000,immutable"},
		{"_next/static/media/font.woff2", "public,max-age=31536000,immutable"},
		{"index.html", "no-cache"},
		{"dashboard/index.html", "no-cache"},
	}
	for _, tc := range cases {
		if got := CacheControl(tc.name); got != tc.want {
			t.Errorf("CacheControl(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
