package appresource

import (
	"net"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

func TestBuildMaterialKeepsMatchFieldsRawAndRecordedFieldsRedacted(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/submit?page=1&token=query-secret")
	ctx.Request.Header.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "material-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Authorization", "Bearer req-secret")
	ctx.Request.SetBody([]byte(`{"username":"alice","password":"secret"}`))
	ctx.Response.SetStatusCode(201)
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Response.Header.Set("Set-Cookie", "sid=resp-secret")

	mat := BuildMaterial(ctx, net.ParseIP("203.0.113.10"), TLSMetadata{
		TLSVersion: "TLS13",
		TLSSNI:     "client.example",
		TLSALPN:    "h3",
		JA3Hash:    "ja3-match-value",
		JA4:        "ja4-match-value",
	}, []byte(`{"token":"resp-secret","status":"ok"}`), nil)
	if mat == nil {
		t.Fatal("BuildMaterial() returned nil")
	}
	if mat.TLSVersion != "TLS13" || mat.TLSSNI != "client.example" || mat.TLSALPN != "h3" {
		t.Fatalf("TLS metadata = %#v", mat)
	}
	if mat.JA4 != "ja4-match-value" {
		t.Fatalf("JA4 = %q, want %q", mat.JA4, "ja4-match-value")
	}
	if mat.QueryString != "page=1&token=%5Bredacted%5D" {
		t.Fatalf("QueryString = %q, want sanitized query", mat.QueryString)
	}
	if !strings.Contains(mat.RequestBody, `"password":"secret"`) {
		t.Fatalf("RequestBody should keep raw value, got %q", mat.RequestBody)
	}
	if strings.Contains(mat.RequestBodySnippet, "secret") || !strings.Contains(mat.RequestBodySnippet, `[redacted]`) {
		t.Fatalf("RequestBodySnippet should redact secrets, got %q", mat.RequestBodySnippet)
	}
	if !strings.Contains(mat.ResponseBody, `"token":"resp-secret"`) {
		t.Fatalf("ResponseBody should keep raw value, got %q", mat.ResponseBody)
	}
	if strings.Contains(mat.ResponseBodySnippet, "resp-secret") || !strings.Contains(mat.ResponseBodySnippet, `[redacted]`) {
		t.Fatalf("ResponseBodySnippet should redact secrets, got %q", mat.ResponseBodySnippet)
	}
	if !strings.Contains(mat.RequestHeadersFull, "Authorization: Bearer req-secret") {
		t.Fatalf("RequestHeadersFull should keep raw header, got %q", mat.RequestHeadersFull)
	}
	if strings.Contains(mat.RequestHeadersJSON, "req-secret") || !strings.Contains(mat.RequestHeadersJSON, `[redacted]`) {
		t.Fatalf("RequestHeadersJSON should redact secrets, got %q", mat.RequestHeadersJSON)
	}
	if !strings.Contains(mat.ResponseHeadersFull, "Set-Cookie: sid=resp-secret") {
		t.Fatalf("ResponseHeadersFull should keep raw response header, got %q", mat.ResponseHeadersFull)
	}
	if strings.Contains(mat.ResponseHeadersJSON, "resp-secret") || !strings.Contains(mat.ResponseHeadersJSON, `[redacted]`) {
		t.Fatalf("ResponseHeadersJSON should redact secrets, got %q", mat.ResponseHeadersJSON)
	}

	fullReq := Subject(CompiledRule{Target: "full_http_request"}, mat, nil)
	if !strings.Contains(fullReq, `"password":"secret"`) {
		t.Fatalf("full_http_request should match raw request payload, got %q", fullReq)
	}
	fullResp := Subject(CompiledRule{Target: "full_http_response"}, mat, nil)
	if !strings.Contains(fullResp, `"token":"resp-secret"`) {
		t.Fatalf("full_http_response should match raw response payload, got %q", fullResp)
	}
	fp := Subject(CompiledRule{Target: "fingerprint"}, mat, nil)
	if fp != "ja3-match-value\tmaterial-test" {
		t.Fatalf("fingerprint subject = %q, want %q", fp, "ja3-match-value\tmaterial-test")
	}
}

func TestBuildMaterialFromRequestBodySkipsFullResponseCaptureWhenNotNeeded(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/upload")
	ctx.Request.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "material-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"username":"alice","password":"secret"}`))
	ctx.Response.SetStatusCode(201)
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Response.Header.Set("Set-Cookie", "sid=resp-secret")

	mat := BuildMaterialFromRequestBody(ctx, net.ParseIP("203.0.113.10"), TLSMetadata{
		TLSVersion: "TLS13",
		TLSSNI:     "client.example",
		TLSALPN:    "h3",
		JA3Hash:    "ja3-match-value",
		JA4:        "ja4-match-value",
	}, nil, []byte(`{"token":"resp-secret","status":"ok"}`), nil, false)
	if mat == nil {
		t.Fatal("BuildMaterialFromRequestBody() returned nil")
	}
	if mat.ResponseBody != "" {
		t.Fatalf("ResponseBody should be omitted when response capture is disabled, got %q", mat.ResponseBody)
	}
	if mat.ResponseHeadersFull != "" {
		t.Fatalf("ResponseHeadersFull should be omitted when response capture is disabled, got %q", mat.ResponseHeadersFull)
	}
	if mat.ResponseBodySnippet == "" || !strings.Contains(mat.ResponseBodySnippet, `[redacted]`) {
		t.Fatalf("ResponseBodySnippet should still be recorded and redacted, got %q", mat.ResponseBodySnippet)
	}
	if !strings.Contains(mat.ResponseHeadersJSON, `[redacted]`) {
		t.Fatalf("ResponseHeadersJSON should still be recorded, got %q", mat.ResponseHeadersJSON)
	}
}

func TestRequestHeaderLookupJoinsRepeatedValuesAndIgnoresCase(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Add("X-Test", "one")
	ctx.Request.Header.Add("x-test", "two")
	ctx.Request.Header.Add("X-Other", "value")

	lookup := RequestHeaderLookup(ctx)

	if got := lookup("X-Test"); got != "one, two" {
		t.Fatalf("lookup(X-Test) = %q, want %q", got, "one, two")
	}
	if got := lookup("x-test"); got != "one, two" {
		t.Fatalf("lookup(x-test) = %q, want %q", got, "one, two")
	}
	if got := lookup("missing"); got != "" {
		t.Fatalf("lookup(missing) = %q, want empty string", got)
	}
}
