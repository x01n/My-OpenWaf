package dataplane

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/jsplugin"
)

func TestApplyJSMutationPlanSynchronizesRequestAndPipeline(t *testing.T) {
	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/before?tag=old&tag=second")
	c.Request.Header.Set("User-Agent", "before-agent")
	c.Request.Header.Set("Content-Type", "text/plain")
	c.Request.Header.Set("X-Delete", "remove-me")
	c.Request.SetBodyString("before-body")

	reqCtx := &pipeline.RequestCtx{
		Method:      "GET",
		Path:        "/before",
		RawQuery:    "tag=old&tag=second",
		UserAgent:   "before-agent",
		ContentType: "text/plain",
		Body:        []byte("before-body"),
	}
	populateRequestCtxHeaders(reqCtx, c)
	rules.PopulateLuaQueryParams(reqCtx)
	reqCtx.BodyTargets = []string{"stale"}
	reqCtx.BodyTargetsDone = true
	reqCtx.StoreMatcherHeaders(map[string]string{"x-delete": "remove-me"})
	_ = reqCtx.DerivedHeaderOrder(func() string { return "stale-order" })

	method := "POST"
	path := "/after"
	rawQuery := "tag=first&tag=second&blank="
	body := "after-body"
	state, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
		method:      reqCtx.Method,
		path:        reqCtx.Path,
		rawQuery:    reqCtx.RawQuery,
		body:        string(reqCtx.Body),
		userAgent:   reqCtx.UserAgent,
		contentType: reqCtx.ContentType,
	}, jsplugin.MutationPlan{
		Method:        &method,
		Path:          &path,
		RawQuery:      &rawQuery,
		Body:          &body,
		SetHeaders:    map[string]string{"User-Agent": "after-agent", "X-JS": "applied"},
		DeleteHeaders: []string{"X-Delete", "Content-Type"},
	})
	if err != nil {
		t.Fatalf("applyJSMutationPlan() error = %v", err)
	}

	if state.method != "POST" || state.path != "/after" || state.rawQuery != rawQuery || state.body != body || !state.bodyLoaded || !state.bodySet {
		t.Fatalf("state = %#v", state)
	}
	if got := string(c.Request.Method()); got != "POST" {
		t.Fatalf("request method = %q", got)
	}
	if got := string(c.Request.URI().PathOriginal()); got != "/after" {
		t.Fatalf("request path = %q", got)
	}
	if got := string(c.Request.URI().QueryString()); got != rawQuery {
		t.Fatalf("request query = %q", got)
	}
	if got := string(c.Request.Body()); got != body {
		t.Fatalf("request body = %q", got)
	}
	if got := string(c.Request.Header.Peek("X-JS")); got != "applied" {
		t.Fatalf("X-JS = %q", got)
	}
	if got := string(c.Request.Header.Peek("X-Delete")); got != "" {
		t.Fatalf("X-Delete = %q", got)
	}
	if got := string(c.Request.Header.ContentType()); got != "" {
		t.Fatalf("Content-Type = %q", got)
	}
	if reqCtx.Method != "POST" || reqCtx.Path != "/after" || reqCtx.RawQuery != rawQuery || string(reqCtx.Body) != body {
		t.Fatalf("request context = %#v", reqCtx)
	}
	if reqCtx.UserAgent != "after-agent" || reqCtx.ContentType != "" {
		t.Fatalf("request context headers user_agent=%q content_type=%q", reqCtx.UserAgent, reqCtx.ContentType)
	}
	if _, ok := reqCtx.Headers["x-delete"]; ok {
		t.Fatalf("deleted header remained in request context: %#v", reqCtx.Headers)
	}
	if _, ok := reqCtx.Headers["content-type"]; ok {
		t.Fatalf("deleted content type remained in request context: %#v", reqCtx.Headers)
	}
	if reqCtx.Headers["x-js"] != "applied" || reqCtx.Headers["user-agent"] != "after-agent" {
		t.Fatalf("request context headers = %#v", reqCtx.Headers)
	}
	headerCounts := make(map[string]int, len(reqCtx.HeaderKeys))
	for _, key := range reqCtx.HeaderKeys {
		headerCounts[strings.ToLower(key)]++
	}
	if headerCounts["x-delete"] != 0 || headerCounts["content-type"] != 0 ||
		headerCounts["x-js"] != 1 || headerCounts["user-agent"] != 1 {
		t.Fatalf("request context header order = %#v", reqCtx.HeaderKeys)
	}
	if _, ready := reqCtx.CachedMatcherHeaders(); ready {
		t.Fatal("matcher header cache remained ready after mutation")
	}
	if reqCtx.BodyTargetsDone || reqCtx.BodyTargets != nil {
		t.Fatalf("body target cache remained after mutation: done=%v targets=%#v", reqCtx.BodyTargetsDone, reqCtx.BodyTargets)
	}
	if order := reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }); order == "stale-order" {
		t.Fatal("derived header order cache remained after mutation")
	}
	if reqCtx.QueryParams["tag"] != "first" {
		t.Fatalf("QueryParams = %#v", reqCtx.QueryParams)
	}
	if values := reqCtx.QueryValues["tag"]; len(values) != 2 || values[0] != "first" || values[1] != "second" {
		t.Fatalf("QueryValues[tag] = %#v", values)
	}
}

func TestJSMutationCannotChangeChallengePassIdentity(t *testing.T) {
	now := time.Now()
	clientIP := net.ParseIP("203.0.113.10")
	originalCookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{
		Host:      "example.com",
		ClientIP:  clientIP,
		UserAgent: "original-agent",
		SiteID:    7,
		Bind:      ":443",
	}, true, now, time.Hour)

	newContext := func(cookie string) (*app.RequestContext, *pipeline.RequestCtx) {
		c := &app.RequestContext{}
		c.Request.SetMethod("POST")
		c.Request.SetRequestURI("/api/v1/items")
		c.Request.Header.Set("User-Agent", "original-agent")
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("Accept", "application/json")
		if cookie != "" {
			c.Request.Header.Set("Cookie", cookie)
		}
		reqCtx := &pipeline.RequestCtx{
			Bind:                       ":443",
			ClientIP:                   clientIP,
			Method:                     "POST",
			Path:                       "/api/v1/items",
			Host:                       "example.com",
			UserAgent:                  "original-agent",
			ChallengeIdentityCaptured:  true,
			ChallengeIdentityUserAgent: "original-agent",
			ChallengeIdentityCookie:    cookie,
			SiteID:                     7,
			ContentType:                "application/json",
		}
		populateRequestCtxHeaders(reqCtx, c)
		return c, reqCtx
	}

	browser := rules.NewBrowserSignPhase(&store.ProtectionConfig{
		BrowserSignEnabled: true,
		BrowserSignAction:  string(action.Challenge),
	})

	t.Run("原始通行身份不受变更影响", func(t *testing.T) {
		c, reqCtx := newContext(originalCookie)
		mutatedAgent := "mutated-agent"
		if _, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
			method:      reqCtx.Method,
			path:        reqCtx.Path,
			userAgent:   reqCtx.UserAgent,
			contentType: reqCtx.ContentType,
		}, jsplugin.MutationPlan{SetHeaders: map[string]string{
			"User-Agent": mutatedAgent,
			"Cookie":     "__owaf_pass=invalid",
		}}); err != nil {
			t.Fatalf("applyJSMutationPlan() error = %v", err)
		}
		if reqCtx.UserAgent != mutatedAgent {
			t.Fatalf("mutated user agent = %q", reqCtx.UserAgent)
		}
		if result, terminal := browser.Execute(reqCtx); terminal || result.Matched {
			t.Fatalf("pre-mutation pass identity should remain trusted, terminal=%v result=%+v", terminal, result)
		}
	})

	t.Run("原始无通行身份时禁止脚本注入绕过", func(t *testing.T) {
		c, reqCtx := newContext("")
		if _, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
			method:      reqCtx.Method,
			path:        reqCtx.Path,
			userAgent:   reqCtx.UserAgent,
			contentType: reqCtx.ContentType,
		}, jsplugin.MutationPlan{SetHeaders: map[string]string{
			"Cookie": originalCookie,
		}}); err != nil {
			t.Fatalf("applyJSMutationPlan() error = %v", err)
		}
		result, terminal := browser.Execute(reqCtx)
		if !terminal || result.Type != action.Challenge {
			t.Fatalf("injected pass cookie must not bypass browser sign, terminal=%v result=%+v", terminal, result)
		}
	})
}

func TestApplyJSMutationPlanKeepsMutatedBodyAfterStreamCleanup(t *testing.T) {
	c := &app.RequestContext{}
	original := &trackingRequestBodyStream{reader: bytes.NewReader([]byte("original-stream"))}
	c.Request.SetBodyStream(original, len("original-stream"))
	body, _, _ := requestBodySample(c)

	reqCtx := &pipeline.RequestCtx{
		Method: "POST",
		Path:   "/upload",
		Body:   append([]byte(nil), body...),
		Headers: map[string]string{
			"content-length": "15",
		},
		HeadersLowercase: true,
	}
	mutated := "mutated-body"
	_, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
		method: "POST",
		path:   "/upload",
		body:   string(body),
	}, jsplugin.MutationPlan{Body: &mutated})
	if err != nil {
		t.Fatalf("applyJSMutationPlan() error = %v", err)
	}

	restoreOriginalRequestBodyStream(c)
	if got := string(c.Request.Body()); got != mutated {
		t.Fatalf("body after cleanup = %q, want %q", got, mutated)
	}
	if c.Request.IsBodyStream() {
		t.Fatal("mutated request unexpectedly restored the original body stream")
	}
	if !original.closed {
		t.Fatal("replaced original body stream was not closed")
	}
}

func TestExecuteJSRequestStageSkipsBodyCopyWithoutApplicableScript(t *testing.T) {
	body := []byte(strings.Repeat("request-body-", 4096))
	reqCtx := &pipeline.RequestCtx{
		Method:      "POST",
		Path:        "/orders",
		Body:        body,
		UserAgent:   "test-agent",
		ContentType: "application/json",
	}

	state, failed, err := executeJSRequestStage(context.Background(), nil, reqCtx, nil, nil)
	if err != nil || failed != nil {
		t.Fatalf("executeJSRequestStage() error = %v, failed = %v", err, failed)
	}
	if state.bodyLoaded || state.bodySet || state.body != "" {
		t.Fatalf("body state = %#v, want no body copy", state)
	}
	if !bytes.Equal(reqCtx.Body, body) {
		t.Fatalf("request context body changed without an applicable script")
	}
}

func TestApplyJSMutationPlanKeepsBodyWithoutBodyMutation(t *testing.T) {
	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/before")
	c.Request.SetBodyString("original-body")
	reqCtx := &pipeline.RequestCtx{
		Method: "GET",
		Path:   "/before",
		Body:   []byte("original-body"),
	}
	path := "/after"

	state, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
		method: "GET",
		path:   "/before",
	}, jsplugin.MutationPlan{Path: &path})
	if err != nil {
		t.Fatalf("applyJSMutationPlan() error = %v", err)
	}
	if state.bodyLoaded || state.bodySet || state.body != "" {
		t.Fatalf("body state = %#v, want unchanged body", state)
	}
	if got := string(c.Request.Body()); got != "original-body" {
		t.Fatalf("request body = %q, want original-body", got)
	}
	if got := string(reqCtx.Body); got != "original-body" {
		t.Fatalf("request context body = %q, want original-body", got)
	}
}

func BenchmarkExecuteJSRequestStageWithoutApplicableScript(b *testing.B) {
	body := []byte(strings.Repeat("request-body-", 4096))
	reqCtx := &pipeline.RequestCtx{
		Method:      "POST",
		Path:        "/orders",
		Body:        body,
		UserAgent:   "benchmark-agent",
		ContentType: "application/json",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		state, failed, err := executeJSRequestStage(context.Background(), nil, reqCtx, nil, nil)
		if err != nil || failed != nil || state.bodyLoaded || state.bodySet {
			b.Fatalf("executeJSRequestStage() state=%#v failed=%v err=%v", state, failed, err)
		}
	}
}

func TestApplyJSMutationPlanRejectsInvalidChangesAtomically(t *testing.T) {
	cases := []struct {
		name string
		plan jsplugin.MutationPlan
	}{
		{name: "invalid method", plan: jsplugin.MutationPlan{Method: stringPointer("GET /admin")}},
		{name: "absolute path", plan: jsplugin.MutationPlan{Path: stringPointer("https://example.test/admin")}},
		{name: "invalid escaped path", plan: jsplugin.MutationPlan{Path: stringPointer("/%zz")}},
		{name: "invalid query", plan: jsplugin.MutationPlan{RawQuery: stringPointer("token=%zz")}},
		{name: "framing header", plan: jsplugin.MutationPlan{SetHeaders: map[string]string{"Content-Length": "1"}}},
		{name: "header null byte", plan: jsplugin.MutationPlan{SetHeaders: map[string]string{"X-Test": "before\x00after"}}},
		{name: "header delete byte", plan: jsplugin.MutationPlan{SetHeaders: map[string]string{"X-Test": "before\x7fafter"}}},
		{name: "duplicate normalized header", plan: jsplugin.MutationPlan{SetHeaders: map[string]string{"X-Test": "1", "x-test": "2"}}},
		{name: "header conflict", plan: jsplugin.MutationPlan{SetHeaders: map[string]string{"X-Test": "1"}, DeleteHeaders: []string{"x-test"}}},
		{name: "forbidden header deletion", plan: jsplugin.MutationPlan{DeleteHeaders: []string{"CONTENT-LENGTH"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &app.RequestContext{}
			c.Request.SetMethod("GET")
			c.Request.SetRequestURI("/before?q=1")
			c.Request.Header.Set("X-Keep", "yes")
			reqCtx := &pipeline.RequestCtx{
				Method: "GET", Path: "/before", RawQuery: "q=1",
				Headers: map[string]string{"x-keep": "yes"}, HeadersLowercase: true,
			}
			before := jsRequestState{method: "GET", path: "/before", rawQuery: "q=1"}

			got, err := applyJSMutationPlan(c, reqCtx, before, tc.plan)
			if err == nil {
				t.Fatal("applyJSMutationPlan() error = nil")
			}
			if got != before {
				t.Fatalf("state changed on validation failure: got=%#v want=%#v", got, before)
			}
			if string(c.Request.Method()) != "GET" || string(c.Request.URI().RequestURI()) != "/before?q=1" {
				t.Fatalf("request changed on validation failure: method=%q uri=%q", c.Request.Method(), c.Request.URI().RequestURI())
			}
			if reqCtx.Method != "GET" || reqCtx.Path != "/before" || reqCtx.RawQuery != "q=1" {
				t.Fatalf("request context changed on validation failure: %#v", reqCtx)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}
