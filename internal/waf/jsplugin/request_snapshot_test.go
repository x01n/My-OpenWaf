package jsplugin

import (
	"strings"
	"testing"
)

func TestNormalizeRequestSnapshotEnforcesFieldBudgets(t *testing.T) {
	tests := []struct {
		name string
		req  RequestSnapshot
		want string
	}{
		{
			name: "body",
			req:  RequestSnapshot{Body: strings.Repeat("b", MaxRequestSnapshotBodyBytes+1)},
			want: "body exceeds",
		},
		{
			name: "scalar",
			req:  RequestSnapshot{Path: strings.Repeat("p", MaxRequestSnapshotStringBytes+1)},
			want: "path exceeds",
		},
		{
			name: "headers count",
			req:  RequestSnapshot{Headers: requestSnapshotMap(MaxRequestSnapshotHeaders + 1)},
			want: "headers exceed",
		},
		{
			name: "query count",
			req:  RequestSnapshot{QueryParams: requestSnapshotMap(MaxRequestSnapshotQueryParams + 1)},
			want: "query params exceed",
		},
		{
			name: "header item",
			req:  RequestSnapshot{Headers: map[string]string{"X-Test": strings.Repeat("v", MaxRequestSnapshotStringBytes+1)}},
			want: "header exceeds size limit",
		},
		{
			name: "query item",
			req:  RequestSnapshot{QueryParams: map[string]string{"q": strings.Repeat("v", MaxRequestSnapshotStringBytes+1)}},
			want: "query parameter exceeds size limit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeRequestSnapshot(tt.req); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalize error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestNormalizeRequestSnapshotEnforcesSerializedBudget(t *testing.T) {
	req := RequestSnapshot{Headers: make(map[string]string, MaxRequestSnapshotHeaders)}
	for i := 0; i < MaxRequestSnapshotHeaders; i++ {
		req.Headers[strings.Repeat("h", 8)+string(rune('A'+i%26))+string(rune('a'+i/26))] = strings.Repeat("v", 1000)
	}
	if _, err := normalizeRequestSnapshot(req); err == nil || !strings.Contains(err.Error(), "request snapshot exceeds") {
		t.Fatalf("normalize error = %v, want serialized size error", err)
	}
}

func requestSnapshotMap(size int) map[string]string {
	result := make(map[string]string, size)
	for i := 0; i < size; i++ {
		result[string(rune('a'+i%26))+string(rune('A'+i/26))] = "v"
	}
	return result
}
