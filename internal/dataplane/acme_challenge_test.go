package dataplane

import (
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

func TestHandleACMEChallengeReturnsResponse(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI("/.well-known/acme-challenge/token-1")

	handled := handleACMEChallenge(ctx, func(token string) (string, bool) {
		if token != "token-1" {
			t.Fatalf("token = %q, want token-1", token)
		}
		return "token-response", true
	})

	if !handled {
		t.Fatal("ACME challenge was not handled")
	}
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d, want 200", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Body()); got != "token-response" {
		t.Fatalf("body = %q, want token-response", got)
	}
	if got := string(ctx.Response.Header.ContentType()); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content type = %q, want text/plain", got)
	}
}

func TestHandleACMEChallengeReturns404ForMissingToken(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI("/.well-known/acme-challenge/missing")

	handled := handleACMEChallenge(ctx, func(token string) (string, bool) {
		return "", false
	})

	if !handled {
		t.Fatal("ACME challenge path was not handled")
	}
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("status = %d, want 404", ctx.Response.StatusCode())
	}
}

func TestHandleACMEChallengeIgnoresOtherPaths(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI("/healthz")

	handled := handleACMEChallenge(ctx, func(token string) (string, bool) {
		t.Fatalf("lookup should not run for non-ACME path")
		return "", false
	})

	if handled {
		t.Fatal("non-ACME path should not be handled")
	}
}
