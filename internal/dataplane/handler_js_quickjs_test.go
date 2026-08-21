//go:build cgo && quickjs

package dataplane

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

func newJSHandler(
	t *testing.T,
	upstreamURL string,
	rules []snapshot.CompiledRule,
	scripts []*jsplugin.Script,
	writers ...*observability.UnifiedWriter,
) app.HandlerFunc {
	t.Helper()

	var writer *observability.UnifiedWriter
	if len(writers) > 0 {
		writer = writers[0]
	}

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "js.example.com",
			Bind: ":80",
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamURL},
		EffectiveProtection: &protection,
		Rules:               rules,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "js.example.com"): &rt,
		},
		JSPlugins: scripts,
	})

	wafEngine := engine.New(holder, nil, nil, nil)
	jsEngine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	wafEngine.SetJSPlugins(jsEngine)
	t.Cleanup(func() { _ = jsEngine.Close() })

	return Handler(Options{
		Holder:                holder,
		Engine:                wafEngine,
		Writer:                writer,
		Log:                   slog.Default(),
		Bind:                  ":80",
		AccessLogSamplingRate: 1,
	})
}

func newJSHandlerWithAccessControl(
	t *testing.T,
	upstreamURL string,
	scripts []*jsplugin.Script,
	accessControl *snapshot.AccessControlConfig,
) app.HandlerFunc {
	t.Helper()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "js.example.com",
			Bind: ":80",
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamURL},
		EffectiveProtection: &protection,
		AccessControl:       accessControl,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "js.example.com"): &rt,
		},
		JSPlugins: scripts,
	})

	wafEngine := engine.New(holder, nil, nil, nil)
	jsEngine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	wafEngine.SetJSPlugins(jsEngine)
	t.Cleanup(func() { _ = jsEngine.Close() })

	return Handler(Options{
		Holder:                holder,
		Engine:                wafEngine,
		Log:                   slog.Default(),
		Bind:                  ":80",
		AccessLogSamplingRate: 1,
	})
}

func TestHandlerJSRequestStageHonorsFailureModes(t *testing.T) {
	tests := []struct {
		name             string
		failureMode      string
		wantStatus       int
		wantUpstreamCall int32
	}{
		{
			name:             "fail open continues to upstream",
			failureMode:      store.JSFailureModeOpen,
			wantStatus:       http.StatusOK,
			wantUpstreamCall: 1,
		},
		{
			name:             "fail closed returns service unavailable",
			failureMode:      store.JSFailureModeClosed,
			wantStatus:       http.StatusServiceUnavailable,
			wantUpstreamCall: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("upstream-ok"))
			}))
			defer upstream.Close()

			script := compileRequestScript(t, "failure-script", `export default {
				fetch() { throw new Error("secret quickjs failure"); }
			}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
				ID: 1, Stage: store.JSStageRequest, Priority: 1, FailureMode: tt.failureMode,
			})
			handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI("/failure")
			ctx.Request.Header.SetHost("js.example.com")

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
			if got := upstreamCalls.Load(); got != tt.wantUpstreamCall {
				t.Fatalf("upstream calls = %d, want %d", got, tt.wantUpstreamCall)
			}
			body := string(ctx.Response.Body())
			if strings.Contains(body, "secret quickjs failure") || strings.Contains(body, "failure-script") {
				t.Fatalf("response leaks plugin failure details: %q", body)
			}
		})
	}
}

func TestHandlerJSRequestStageHonorsInvalidMutationFailureModes(t *testing.T) {
	tests := []struct {
		name             string
		failureMode      string
		wantStatus       int
		wantUpstreamCall int32
	}{
		{
			name:             "fail open ignores invalid mutation",
			failureMode:      store.JSFailureModeOpen,
			wantStatus:       http.StatusOK,
			wantUpstreamCall: 1,
		},
		{
			name:             "fail closed rejects invalid mutation",
			failureMode:      store.JSFailureModeClosed,
			wantStatus:       http.StatusServiceUnavailable,
			wantUpstreamCall: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.URL.Path != "/original" {
					t.Errorf("upstream path = %q, want original path", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			script := compileRequestScript(t, "invalid-mutation", `export default {
				fetch() { return {path: "relative-path"}; }
			}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
				ID: 1, Stage: store.JSStageRequest, Priority: 1, FailureMode: tt.failureMode,
			})
			handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI("/original")
			ctx.Request.Header.SetHost("js.example.com")

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
			if got := upstreamCalls.Load(); got != tt.wantUpstreamCall {
				t.Fatalf("upstream calls = %d, want %d", got, tt.wantUpstreamCall)
			}
		})
	}
}

func TestHandlerJSRequestStageMutationVisibleToWAF(t *testing.T) {
	tests := []struct {
		name   string
		source string
		rule   snapshot.CompiledRule
	}{
		{
			name:   "path",
			source: `export default { fetch() { return {path: "/mutated/path"}; } }`,
			rule: snapshot.CompiledRule{
				ID: 1, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/mutated/path", Action: store.ActionIntercept,
			},
		},
		{
			name:   "query",
			source: `export default { fetch() { return {raw_query: "mutated=yes"}; } }`,
			rule: snapshot.CompiledRule{
				ID: 1, Phase: store.PhaseCustom, Kind: "block_query_contains", Arg: "mutated=yes", Action: store.ActionIntercept,
			},
		},
		{
			name:   "header",
			source: `export default { fetch() { return {set_headers: {"X-JS-Marker": "mutated"}}; } }`,
			rule: snapshot.CompiledRule{
				ID: 1, Phase: store.PhaseCustom, Kind: "block_header_exact", Arg: "X-JS-Marker:mutated", Action: store.ActionIntercept,
			},
		},
		{
			name:   "body",
			source: `export default { fetch() { return {body: "mutated-body"}; } }`,
			rule: snapshot.CompiledRule{
				ID: 1, Phase: store.PhaseCustom, Kind: "body_contains", Arg: "mutated-body", Action: store.ActionIntercept,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			script := compileRequestScript(t, "mutation-"+tt.name, tt.source, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
				ID: 1, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeClosed,
			})
			handler := newJSHandler(t, upstream.URL, []snapshot.CompiledRule{tt.rule}, []*jsplugin.Script{script})

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/original?original=yes")
			ctx.Request.Header.SetHost("js.example.com")
			ctx.Request.Header.Set("Content-Type", "text/plain")
			ctx.Request.SetBodyString("original-body")

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("upstream calls = %d, want 0", got)
			}
		})
	}
}

func TestHandlerJSRequestStageMutationVisibleToUpstream(t *testing.T) {
	const originalBody = "original-body"
	const mutatedBody = "mutated-body-from-js"
	var upstreamCalls atomic.Int32
	received := make(chan struct {
		method        string
		path          string
		rawQuery      string
		userAgent     string
		contentType   string
		marker        string
		deleted       string
		body          []byte
		contentLength int64
	}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		received <- struct {
			method        string
			path          string
			rawQuery      string
			userAgent     string
			contentType   string
			marker        string
			deleted       string
			body          []byte
			contentLength int64
		}{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			userAgent: r.UserAgent(), contentType: r.Header.Get("Content-Type"),
			marker: r.Header.Get("X-JS-Marker"), deleted: r.Header.Get("X-Delete-Me"),
			body: body, contentLength: r.ContentLength,
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())
	t.Cleanup(writer.Close)

	script := compileRequestScript(t, "mutation-upstream", `export default {
		fetch(request) {
			return {
				method: "PUT",
				path: "/mutated/upstream",
				raw_query: "from=js&order=2",
				body: "mutated-body-from-js",
				set_headers: {
					"User-Agent": "mutated-agent",
					"Content-Type": "application/json",
					"X-JS-Marker": "visible",
				},
				delete_headers: ["X-Delete-Me"]
			};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeClosed,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script}, writer)

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/original?original=yes")
	ctx.Request.Header.SetHost("js.example.com")
	ctx.Request.Header.Set("User-Agent", "original-agent")
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.Header.Set("X-Delete-Me", "must-disappear")
	ctx.Request.SetBodyString(originalBody)

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	got := <-received
	if got.method != http.MethodPut {
		t.Fatalf("upstream method = %q, want %q", got.method, http.MethodPut)
	}
	if got.path != "/mutated/upstream" || got.rawQuery != "from=js&order=2" {
		t.Fatalf("upstream URI = %s?%s", got.path, got.rawQuery)
	}
	if got.userAgent != "mutated-agent" || got.contentType != "application/json" {
		t.Fatalf("upstream request metadata = user-agent %q content-type %q", got.userAgent, got.contentType)
	}
	if got.marker != "visible" || got.deleted != "" {
		t.Fatalf("upstream headers = marker %q deleted %q", got.marker, got.deleted)
	}
	if !bytes.Equal(got.body, []byte(mutatedBody)) {
		t.Fatalf("upstream body = %q, want %q", got.body, mutatedBody)
	}
	if got.contentLength != int64(len(mutatedBody)) {
		t.Fatalf("upstream content length = %d, want %d", got.contentLength, len(mutatedBody))
	}

	writer.Close()
	var entry store.AccessLog
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if entry.Method != http.MethodPut || entry.Path != "/mutated/upstream" || entry.QueryString != "from=js&order=2" {
		t.Fatalf("access log request view = method %q path %q query %q", entry.Method, entry.Path, entry.QueryString)
	}
	if entry.UserAgent != "mutated-agent" || entry.StatusCode != http.StatusOK || entry.WAFAction != "none" {
		t.Fatalf("access log metadata = method %q user-agent %q status %d action %q", entry.Method, entry.UserAgent, entry.StatusCode, entry.WAFAction)
	}
}

func TestHandlerJSRequestStageRechecksFinalAccessControlPath(t *testing.T) {
	tests := []struct {
		name         string
		originalPath string
		targetPath   string
		withSession  bool
		wantStatus   int
		wantUpstream int32
	}{
		{
			name:         "public path rewritten to protected path redirects",
			originalPath: "/public/page",
			targetPath:   "/private/page",
			wantStatus:   http.StatusFound,
			wantUpstream: 0,
		},
		{
			name:         "protected original path is checked before script",
			originalPath: "/private/page",
			targetPath:   "/public/page",
			wantStatus:   http.StatusFound,
			wantUpstream: 0,
		},
		{
			name:         "session permits rewritten protected path",
			originalPath: "/public/page",
			targetPath:   "/private/page",
			withSession:  true,
			wantStatus:   http.StatusOK,
			wantUpstream: 1,
		},
		{
			name:         "rewritten deny path is rejected",
			originalPath: "/public/page",
			targetPath:   "/deny/page",
			wantStatus:   http.StatusForbidden,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access login endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   accessLoginPath,
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access verify endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   accessVerifyPath,
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access logout endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   accessLogoutPath,
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access oauth start endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   accessOAuthStartPrefix + "provider",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access oauth callback endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   accessOAuthCallbackPath,
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten access dot segment remains internal",
			originalPath: "/public/page",
			targetPath:   "/__owaf/access/../private",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten internal wasm asset is rejected",
			originalPath: "/public/page",
			targetPath:   "/__owaf/pow.wasm",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten internal root is rejected",
			originalPath: "/public/page",
			targetPath:   "/__owaf",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten encoded internal endpoint is rejected",
			originalPath: "/public/page",
			targetPath:   "/%5f%5fowaf/access/login",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten encoded internal separator is rejected",
			originalPath: "/public/page",
			targetPath:   "/__owaf%2faccess%2flogin",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten dot segment into internal namespace is rejected",
			originalPath: "/public/page",
			targetPath:   "/public/../__owaf/access/login",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
		{
			name:         "rewritten encoded dot segment into internal namespace is rejected",
			originalPath: "/public/page",
			targetPath:   "/public/%2e%2e/__owaf/access/login",
			wantStatus:   http.StatusNotFound,
			wantUpstream: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			script := compileRequestScript(t, "access-path-rewrite", `export default {
				fetch() {
					return {path: "`+tt.targetPath+`"};
				}
			}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
				ID: 1, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeClosed,
			})
			accessControl := &snapshot.AccessControlConfig{
				Enabled:    true,
				SessionTTL: 3600,
				PathRules: []snapshot.AccessControlPathRule{
					{Path: "/public/*", Action: "allow", Priority: 0},
					{Path: "/deny/*", Action: "deny", Priority: 1},
				},
			}
			handler := newJSHandlerWithAccessControl(t, upstream.URL, []*jsplugin.Script{script}, accessControl)

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI(tt.originalPath)
			ctx.Request.Header.SetHost("js.example.com")
			if tt.withSession {
				token, err := globalAccessSessionStore.Create(1, "testuser", "password", 3600)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = globalAccessSessionStore.Revoke(token) })
				ctx.Request.Header.SetCookie("__owaf_access_1", token)
			}

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
			if got := upstreamCalls.Load(); got != tt.wantUpstream {
				t.Fatalf("upstream calls = %d, want %d", got, tt.wantUpstream)
			}
		})
	}
}
