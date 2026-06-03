package admin

import (
	"os"
	"regexp"
	"testing"
)

func TestRegisterRoutesUsesOnlyGetAndPost(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}

	forbidden := regexp.MustCompile(`\.(PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(`)
	if match := forbidden.Find(src); match != nil {
		t.Fatalf("admin routes must use only GET and POST, found %s", match)
	}
}
