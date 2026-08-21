package rules

import "testing"

func TestValidatePatternEmptyPatternReturnsError(t *testing.T) {
	kind, _, errs := ValidatePattern("")
	if kind != "" {
		t.Errorf("empty pattern should return empty kind, got %q", kind)
	}
	if len(errs) == 0 {
		t.Error("empty pattern should return at least one error")
	}
}

func TestValidatePatternIPMatchers(t *testing.T) {
	cases := []struct {
		pattern string
		wantOK  bool
	}{
		{"allow_ip:1.2.3.4", true},
		{"block_ip:10.0.0.0/8", true},
		{"allow_ip:not-an-ip", false},
		{"block_ip:999.999.999.999", false},
	}
	for _, tc := range cases {
		_, _, errs := ValidatePattern(tc.pattern)
		if tc.wantOK && len(errs) != 0 {
			t.Errorf("ValidatePattern(%q) unexpected errors: %v", tc.pattern, errs)
		}
		if !tc.wantOK && len(errs) == 0 {
			t.Errorf("ValidatePattern(%q) expected error, got none", tc.pattern)
		}
	}
}

func TestValidatePatternRegexMatchers(t *testing.T) {
	validPattern := "block_path_regex:/admin"
	if _, _, errs := ValidatePattern(validPattern); len(errs) != 0 {
		t.Errorf("ValidatePattern(%q) unexpected errors: %v", validPattern, errs)
	}
	invalid := "block_path_regex:(?invalid"
	if _, _, errs := ValidatePattern(invalid); len(errs) == 0 {
		t.Error("invalid regex should produce error")
	}
}

func TestValidatePatternHostAddressForms(t *testing.T) {
	tests := []string{
		"host:2001:db8::1",
		"host_full:[2001:db8::1]:443",
		"host:api.example.com:8443",
		"host_full:*.example.com:8443",
	}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			kind, arg, errs := ValidatePattern(pattern)
			if kind == "" || arg == "" {
				t.Fatalf("ValidatePattern(%q) = kind %q, arg %q", pattern, kind, arg)
			}
			if len(errs) != 0 {
				t.Fatalf("ValidatePattern(%q) errors = %v, want none", pattern, errs)
			}
		})
	}
}

func TestValidatePatternRejectsInvalidHostRegex(t *testing.T) {
	pattern := "host_regex:(?invalid"
	if _, _, errs := ValidatePattern(pattern); len(errs) == 0 {
		t.Fatalf("ValidatePattern(%q) should reject invalid regular expression", pattern)
	}
}

func TestValidatePatternQueryParamRegexMissingColon(t *testing.T) {
	pattern := "query_param_regex:nocolon"
	_, _, errs := ValidatePattern(pattern)
	if len(errs) == 0 {
		t.Error("query_param_regex without param:regex format should produce error")
	}
}

func TestValidatePatternQueryParamRegexInvalid(t *testing.T) {
	pattern := "query_param_regex:param:(?invalid"
	_, _, errs := ValidatePattern(pattern)
	if len(errs) == 0 {
		t.Error("query_param_regex with invalid regex should produce error")
	}
}

func TestValidatePatternBodyRegexValid(t *testing.T) {
	if _, _, errs := ValidatePattern("block_body_regex:evil"); len(errs) != 0 {
		t.Errorf("block_body_regex: unexpected errors: %v", errs)
	}
	if _, _, errs := ValidatePattern("body_regex:evil"); len(errs) != 0 {
		t.Errorf("body_regex: unexpected errors: %v", errs)
	}
}

func TestValidatePatternCompoundNotRequiresChild(t *testing.T) {
	pattern := `{"op":"not","children":[]}`
	kind, _, errs := ValidatePattern(pattern)
	if kind != "compound" {
		t.Fatalf("expected compound kind, got %q", kind)
	}
	if len(errs) == 0 {
		t.Error("not with no children should produce error")
	}
}

func TestValidatePatternCompoundAndRequiresChild(t *testing.T) {
	pattern := `{"op":"and","children":[]}`
	_, _, errs := ValidatePattern(pattern)
	if len(errs) == 0 {
		t.Error("and with no children should produce error")
	}
}

func TestValidatePatternCompoundIfRequiresBranches(t *testing.T) {
	pattern := `{"op":"if","if":{"kind":"block_path","arg":"/x"}}`
	_, _, errs := ValidatePattern(pattern)
	if len(errs) == 0 {
		t.Error("if without then should produce error")
	}
}

func TestValidatePatternCompoundInvalidJSON(t *testing.T) {
	pattern := `{"op":"and", "children": [not-json]}`
	kind, _, errs := ValidatePattern(pattern)
	if kind != "compound" {
		t.Fatalf("expected compound kind, got %q", kind)
	}
	if len(errs) == 0 {
		t.Error("invalid JSON compound should produce error")
	}
}

func TestValidatePatternCompoundCCRateRequiresChild(t *testing.T) {
	pattern := `{"op":"cc_rate","window":60,"threshold":100,"duration":3600,"children":[]}`
	_, _, errs := ValidatePattern(pattern)
	if len(errs) == 0 {
		t.Error("cc_rate with no children should produce error")
	}
}

func TestValidatePatternBlockMultipartValidRegex(t *testing.T) {
	if _, _, errs := ValidatePattern("block_multipart:.+\\.php$"); len(errs) != 0 {
		t.Errorf("block_multipart with valid regex: unexpected errors: %v", errs)
	}
}

func TestValidatePatternBlockMultipartInvalidRegex(t *testing.T) {
	if _, _, errs := ValidatePattern("block_multipart:(?bad"); len(errs) == 0 {
		t.Error("block_multipart with invalid regex should produce error")
	}
}

func TestValidatePatternRejectsInvalidTLSLeaf(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{
			name:    "invalid tls version",
			pattern: "tls_version:TLS 1.9",
			wantErr: "tls_version 需要合法的 TLS 版本标识",
		},
		{
			name:    "unsupported ssl3 tls version",
			pattern: "tls_version:SSL3",
			wantErr: "tls_version 需要合法的 TLS 版本标识",
		},
		{
			name:    "invalid tls cipher suites",
			pattern: "tls_cipher_suites: , ",
			wantErr: "tls_cipher_suites 至少需要一个合法的密码套件标识",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, _, errs := ValidatePattern(tt.pattern)
			if kind == "" {
				t.Fatalf("ValidatePattern(%q) returned empty kind", tt.pattern)
			}
			if len(errs) != 1 || errs[0] != tt.wantErr {
				t.Fatalf("ValidatePattern(%q) errors = %#v, want %q", tt.pattern, errs, tt.wantErr)
			}
		})
	}
}

func TestValidatePatternRejectsInvalidCompoundTLSLeaf(t *testing.T) {
	pattern := `{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"tls_version","arg":"TLS 1.9"}]}`

	kind, _, errs := ValidatePattern(pattern)
	if kind != "compound" {
		t.Fatalf("ValidatePattern() kind = %q, want compound", kind)
	}
	if len(errs) != 1 || errs[0] != "tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("ValidatePattern() errors = %#v", errs)
	}
}

func TestValidatePatternAcceptsCompoundTLSAliases(t *testing.T) {
	pattern := `{"op":"and","children":[{"kind":"tls_version","arg":"TLS 1.3"},{"kind":"tls_cipher_suites","arg":"4865"}]}`

	kind, arg, errs := ValidatePattern(pattern)
	if kind != "compound" {
		t.Fatalf("ValidatePattern() kind = %q, want compound", kind)
	}
	if arg != pattern {
		t.Fatalf("ValidatePattern() arg = %q, want %q", arg, pattern)
	}
	if len(errs) != 0 {
		t.Fatalf("ValidatePattern() errors = %#v, want none", errs)
	}
}

func TestValidatePatternCompoundSemanticBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "unknown leaf kind",
			input: `{"op":"and","children":[{"kind":"unknown_kind","arg":"x"}]}`,
		},
		{
			name:  "unknown operator leaf",
			input: `{"op":"unknown","kind":"block_path","arg":"/admin"}`,
		},
		{
			name:  "unknown operator branches",
			input: `{"op":"unknown","if":{"kind":"block_path","arg":"/admin"},"then":{"kind":"block_method","arg":"POST"}}`,
		},
		{
			name:  "not requires one child",
			input: `{"op":"not","children":[{"kind":"block_path","arg":"/a"},{"kind":"block_path","arg":"/b"}]}`,
		},
		{
			name:  "cc rate requires one child",
			input: `{"op":"cc_rate","window":60,"threshold":3,"children":[{"kind":"block_path","arg":"/a"},{"kind":"block_path","arg":"/b"}]}`,
		},
		{
			name:  "cc rate window must be positive",
			input: `{"op":"cc_rate","window":0,"threshold":3,"children":[{"kind":"block_path","arg":"/a"}]}`,
		},
		{
			name:  "cc rate threshold must be positive",
			input: `{"op":"cc_rate","window":60,"threshold":0,"children":[{"kind":"block_path","arg":"/a"}]}`,
		},
		{
			name:  "cc rate duration cannot be negative",
			input: `{"op":"cc_rate","window":60,"threshold":3,"duration":-1,"children":[{"kind":"block_path","arg":"/a"}]}`,
		},
		{
			name:  "cc rate duration seconds cannot be negative",
			input: `{"op":"cc_rate","window":60,"threshold":3,"duration_seconds":-1,"children":[{"kind":"block_path","arg":"/a"}]}`,
		},
		{
			name:  "zero duration retains window semantics",
			input: `{"op":"cc_rate","window":60,"threshold":3,"duration":0,"children":[{"kind":"block_path","arg":"/a"}]}`,
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, errs := ValidatePattern(tt.input)
			if tt.valid && len(errs) != 0 {
				t.Fatalf("ValidatePattern(%q) errors = %#v, want none", tt.input, errs)
			}
			if !tt.valid && len(errs) == 0 {
				t.Fatalf("ValidatePattern(%q) unexpectedly succeeded", tt.input)
			}
		})
	}
}

func TestValidatePatternRejectsEmptyBroadMatchers(t *testing.T) {
	patterns := []string{
		"block_query_contains:",
		"block_path_exact:",
		"block_method:",
		"block_content_type:",
		"block_user_agent:",
		"header_order_contains:",
		"body_contains:",
		"block_body_contains:",
		"path_contains:",
		"path_not_contains:",
		"host:",
		"host_full:",
		"full_url_contains:",
		"host_contains:",
		"host_not_contains:",
		"cookie_contains:",
		"referer_contains:",
		"tls_ja3:",
		"tls_ja3_hash:",
		"tls_ja4:",
		"tls_sni:",
		"tls_alpn:",
		"geo_block:",
	}

	for _, pattern := range patterns {
		if _, _, errs := ValidatePattern(pattern); len(errs) == 0 {
			t.Errorf("ValidatePattern(%q) should reject an empty argument", pattern)
		}
	}
}

func TestValidatePatternRejectsEmptyNameValueComponents(t *testing.T) {
	patterns := []string{
		"block_header::value",
		"block_header:name:",
		"block_header_exact::value",
		"block_header_exact:name:",
		"query_param::value",
		"query_param:name:",
	}

	for _, pattern := range patterns {
		if _, _, errs := ValidatePattern(pattern); len(errs) == 0 {
			t.Errorf("ValidatePattern(%q) should reject an empty component", pattern)
		}
	}
}

func TestValidatePatternAllowsDefaultMultipartPattern(t *testing.T) {
	if _, _, errs := ValidatePattern("block_multipart:"); len(errs) != 0 {
		t.Fatalf("block_multipart without a custom pattern should remain valid: %v", errs)
	}
}
