package adminweb

import (
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
