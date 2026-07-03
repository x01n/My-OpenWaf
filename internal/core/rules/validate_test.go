package rules

import "testing"

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
