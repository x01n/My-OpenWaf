package dataplane

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/challenge"
)

func TestHandlerEarlyGatesHonorSkipPathByPhase(t *testing.T) {
	tests := []struct {
		name             string
		phase            string
		path             string
		skipPath         string
		method           string
		body             []byte
		nonceCookie      string
		antiReplayEnable bool
	}{
		{
			name:             "anti replay cookie gate",
			phase:            "anti_replay",
			path:             "/phase-skip/anti-replay",
			skipPath:         "/phase-skip/*",
			method:           http.MethodGet,
			nonceCookie:      "invalid-nonce",
			antiReplayEnable: true,
		},
		{
			name:     "Cisco translation table OWASP gate",
			phase:    "owasp_default",
			path:     "/translation-table/+CSCOT+",
			skipPath: "/translation-table/*",
			method:   http.MethodGet,
		},
		{
			name:     "opaque body OWASP gate",
			phase:    "owasp_default",
			path:     "/uc/feedback/api/v1/pc/feedback/add",
			skipPath: "/uc/feedback/api/v1/pc/feedback/*",
			method:   http.MethodPost,
			body:     []byte(strings.Repeat("+", 1024)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, skip := range []struct {
				name       string
				enabled    bool
				wantStatus int
				wantHits   int32
			}{
				{name: "path is not skipped", wantStatus: http.StatusForbidden, wantHits: 0},
				{name: "path is skipped", enabled: true, wantStatus: http.StatusNoContent, wantHits: 1},
			} {
				t.Run(skip.name, func(t *testing.T) {
					var upstreamHits atomic.Int32
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						upstreamHits.Add(1)
						w.WriteHeader(http.StatusNoContent)
					}))
					defer upstream.Close()

					holder := &snapshot.Holder{}
					globalProtection := store.DefaultProtectionConfig()
					globalProtection.OWASPEnabled = false
					globalProtection.BotDetectionEnabled = false
					effectiveProtection := globalProtection
					if skip.enabled {
						effectiveProtection.SetSkipPathByPhase(map[string][]string{
							tt.phase: {tt.skipPath},
						})
					}

					rt := snapshot.SiteRuntime{
						Site: store.Site{
							ID:   1,
							Host: "handler-phase-skip.example.com",
							Bind: ":80",
						},
						Bind:                ":80",
						UpstreamURLs:        []string{upstream.URL},
						AntiReplayEnabled:   tt.antiReplayEnable,
						EffectiveProtection: &effectiveProtection,
					}
					holder.Store(&snapshot.Snapshot{
						Revision:   1,
						Protection: globalProtection,
						Sites: map[string]*snapshot.SiteRuntime{
							snapshot.SiteMapKey(":80", "handler-phase-skip.example.com"): &rt,
						},
					})

					eng := engine.New(holder, nil, nil, nil)
					if tt.antiReplayEnable {
						eng.SetAntiReplayManager(antireplay.NewAntiReplayManager("handler-phase-skip-secret", nil, 0))
					}
					handler := Handler(Options{Holder: holder, Engine: eng, Log: slog.Default(), Bind: ":80"})

					c := app.NewContext(0)
					c.Request.Header.SetMethod(tt.method)
					c.Request.SetRequestURI(tt.path)
					c.Request.Header.SetHost("handler-phase-skip.example.com")
					if len(tt.body) > 0 {
						c.Request.SetBody(tt.body)
					}
					if tt.nonceCookie != "" {
						c.Request.Header.SetCookie(challenge.NonceKey, tt.nonceCookie)
					}

					handler(context.Background(), c)

					if got := c.Response.StatusCode(); got != skip.wantStatus {
						t.Fatalf("status = %d, want %d", got, skip.wantStatus)
					}
					if got := upstreamHits.Load(); got != skip.wantHits {
						t.Fatalf("upstream hits = %d, want %d", got, skip.wantHits)
					}
					if skip.enabled && tt.phase == "anti_replay" && len(c.Response.Header.Peek("Set-Cookie")) != 0 {
						t.Fatal("skipped anti-replay cookie gate must not rotate or replace the nonce")
					}
				})
			}
		})
	}
}
