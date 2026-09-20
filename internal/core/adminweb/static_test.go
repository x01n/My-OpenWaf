package adminweb

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadRouteFileResolvesExportedIndexHTML(t *testing.T) {
	webFS := fstest.MapFS{
		"dashboard/index.html": &fstest.MapFile{Data: []byte("dashboard")},
		"index.html":           &fstest.MapFile{Data: []byte("root")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/dashboard/")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error: %v", err)
	}
	if resolved != "dashboard/index.html" {
		t.Fatalf("expected dashboard/index.html, got %s", resolved)
	}
	if string(data) != "dashboard" {
		t.Fatalf("expected dashboard page, got %q", string(data))
	}
}

func TestReadRouteFileKeepsStaticAssetPath(t *testing.T) {
	webFS := fstest.MapFS{
		"_next/static/app.js": &fstest.MapFile{Data: []byte("console.log('ok')")},
		"index.html":          &fstest.MapFile{Data: []byte("root")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/_next/static/app.js")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error: %v", err)
	}
	if resolved != "_next/static/app.js" {
		t.Fatalf("expected asset path, got %s", resolved)
	}
	if string(data) != "console.log('ok')" {
		t.Fatalf("expected asset contents, got %q", string(data))
	}
}

func TestReadRouteFileFallsBackToSPAIndexForRoutePath(t *testing.T) {
	webFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("root")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/unknown/deep/link")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error: %v", err)
	}
	if resolved != "index.html" {
		t.Fatalf("expected index.html, got %s", resolved)
	}
	if string(data) != "root" {
		t.Fatalf("expected root page, got %q", string(data))
	}
}

func TestReadRouteFileDoesNotFallbackForMissingAssetPath(t *testing.T) {
	webFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("root")},
	}

	_, _, err := ReadRouteFile(webFS, "/missing/app.js")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestReadRouteFileResolvesDynamicExportPlaceholder(t *testing.T) {
	webFS := fstest.MapFS{
		"sites/_/index.html": &fstest.MapFile{Data: []byte("site-detail")},
		"sites/_/index.txt":  &fstest.MapFile{Data: []byte("site-detail-data")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/sites/123")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error: %v", err)
	}
	if resolved != "sites/_/index.html" {
		t.Fatalf("expected sites/_/index.html, got %s", resolved)
	}
	if string(data) != "site-detail" {
		t.Fatalf("expected site-detail page, got %q", string(data))
	}

	data, resolved, err = ReadRouteFile(webFS, "/sites/123/index.txt")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error for index.txt: %v", err)
	}
	if resolved != "sites/_/index.txt" {
		t.Fatalf("expected sites/_/index.txt, got %s", resolved)
	}
	if string(data) != "site-detail-data" {
		t.Fatalf("expected site-detail-data, got %q", string(data))
	}
}

func TestReadRouteFileResolvesNextRSCPageData(t *testing.T) {
	webFS := fstest.MapFS{
		"security/__next.!KGRhc2hib2FyZCk/security/__PAGE__.txt": &fstest.MapFile{Data: []byte("security-rsc")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/security/__next.!KGRhc2hib2FyZCk.security.__PAGE__.txt")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error for RSC page data: %v", err)
	}
	if resolved != "security/__next.!KGRhc2hib2FyZCk/security/__PAGE__.txt" {
		t.Fatalf("expected security RSC page data path, got %s", resolved)
	}
	if string(data) != "security-rsc" {
		t.Fatalf("expected security-rsc, got %q", string(data))
	}
}

func TestReadRouteFileResolvesNextRSCSegmentData(t *testing.T) {
	webFS := fstest.MapFS{
		"ip-lists/__next.!KGRhc2hib2FyZCk/ip-lists.txt": &fstest.MapFile{Data: []byte("ip-lists-rsc")},
	}

	data, resolved, err := ReadRouteFile(webFS, "/ip-lists/__next.!KGRhc2hib2FyZCk.ip-lists.txt")
	if err != nil {
		t.Fatalf("ReadRouteFile returned error for RSC segment data: %v", err)
	}
	if resolved != "ip-lists/__next.!KGRhc2hib2FyZCk/ip-lists.txt" {
		t.Fatalf("expected ip-lists RSC segment data path, got %s", resolved)
	}
	if string(data) != "ip-lists-rsc" {
		t.Fatalf("expected ip-lists-rsc, got %q", string(data))
	}
}

func TestContentTypeAllSuffixes(t *testing.T) {
	cases := []struct {
		name     string
		expected string
	}{
		{"page.html", "text/html; charset=utf-8"},
		{"app.js", "application/javascript"},
		{"style.css", "text/css"},
		{"data.json", "application/json"},
		{"icon.svg", "image/svg+xml"},
		{"logo.png", "image/png"},
		{"favicon.ico", "image/x-icon"},
		{"font.woff2", "font/woff2"},
		{"binary.bin", "application/octet-stream"},
		{"noextension", "application/octet-stream"},
	}
	for _, tc := range cases {
		got := ContentType(tc.name)
		if got != tc.expected {
			t.Errorf("ContentType(%q) = %q, want %q", tc.name, got, tc.expected)
		}
	}
}

func TestResolveFSDiskDirReturnsOsDir(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.html")
	if err := os.WriteFile(testFile, []byte("<html></html>"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fsys, err := ResolveFS(dir)
	if err != nil {
		t.Fatalf("ResolveFS(%q) error: %v", dir, err)
	}
	data, err := fs.ReadFile(fsys, "test.html")
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if string(data) != "<html></html>" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestResolveFSWhitespaceDiskDirIsTrimmed(t *testing.T) {
	dir := t.TempDir()
	fsys, err := ResolveFS("  " + dir + "  ")
	if err != nil {
		t.Fatalf("ResolveFS with whitespace error: %v", err)
	}
	if fsys == nil {
		t.Fatal("expected non-nil fs.FS")
	}
}

func TestRouteCandidatesEmptyAndRoot(t *testing.T) {
	for _, p := range []string{"", "/", "   "} {
		got := routeCandidates(p)
		if len(got) == 0 || got[0] != "index.html" {
			t.Errorf("routeCandidates(%q) = %v, want [index.html ...]", p, got)
		}
	}
}

func TestRouteCandidatesTrailingSlashGeneratesIndexHTML(t *testing.T) {
	got := routeCandidates("/dashboard/")
	found := false
	for _, c := range got {
		if c == "dashboard/index.html" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dashboard/index.html in candidates, got %v", got)
	}
}

// 单段路径带扩展名时不产生 .html 候选（无动态变体）。
func TestRouteCandidatesSingleSegmentWithExtensionSkipsHTMLVariants(t *testing.T) {
	got := routeCandidates("/data.json")
	for _, c := range got {
		if strings.HasSuffix(c, ".html") {
			t.Errorf("single-segment path with extension should not produce .html candidates, got %v", got)
		}
	}
}

func TestUniqueStringsDeduplicatesAndPreservesOrder(t *testing.T) {
	input := []string{"a", "b", "a", "", "c", "b"}
	got := uniqueStrings(input)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings = %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("uniqueStrings[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDynamicRouteVariantsReplacesSegments(t *testing.T) {
	variants := dynamicRouteVariants("sites/123")
	found := false
	for _, v := range variants {
		if v == "sites/_" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected sites/_ in variants, got %v", variants)
	}
}

func TestDynamicRouteVariantsSingleSegmentReturnsNil(t *testing.T) {
	got := dynamicRouteVariants("index")
	if len(got) != 0 {
		t.Errorf("expected no variants for single segment, got %v", got)
	}
}

func TestOsDirOpenMissingFileReturnsError(t *testing.T) {
	dir := osDir(t.TempDir())
	_, err := dir.Open("nonexistent.html")
	if err == nil {
		t.Fatal("expected error opening nonexistent file, got nil")
	}
}
