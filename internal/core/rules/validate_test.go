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
			wantErr: "tls_version requires a supported TLS version token",
		},
		{
			name:    "unsupported ssl3 tls version",
			pattern: "tls_version:SSL3",
			wantErr: "tls_version requires a supported TLS version token",
		},
		{
			name:    "invalid tls cipher suites",
			pattern: "tls_cipher_suites: , ",
			wantErr: "tls_cipher_suites requires at least one valid cipher suite token",
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
	if len(errs) != 1 || errs[0] != "tls_version requires a supported TLS version token" {
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
