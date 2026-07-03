package adminweb

import (
	"errors"
	"io/fs"
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
