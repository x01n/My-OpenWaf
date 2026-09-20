package snapshot

import (
	"reflect"
	"testing"
)

func TestParseUpstreamURLs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "comma", raw: "http://a:80, https://b:443", want: []string{"http://a:80", "https://b:443"}},
		{
			name: "json",
			raw:  `["http://a:80","https://b:443"]`,
			want: []string{"http://a:80", "https://b:443"},
		},
		{
			name: "rpc_aliases",
			raw:  "grpc://a:9000,grpcs://b:443",
			want: []string{"h2c://a:9000", "https://b:443"},
		},
		{
			name: "rpc_aliases_json",
			raw:  `["grpc://a:9000","tls://b:443"]`,
			want: []string{"h2c://a:9000", "https://b:443"},
		},
		{
			name: "mixed_case_alias",
			raw:  "GRPCS://b:443",
			want: []string{"https://b:443"},
		},
		// 旧四前缀原样保留（仅 RPC 别名展开）。
		{
			name: "legacy_unchanged",
			raw:  "h2c://a:9000,h3://b:443",
			want: []string{"h2c://a:9000", "h3://b:443"},
		},
		{name: "empty", raw: "", want: nil},
		{name: "blank_items", raw: " , http://a:80 , ", want: []string{"http://a:80"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseUpstreamURLs(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseUpstreamURLs(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
