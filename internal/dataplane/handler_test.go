package dataplane

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/pages"
	"My-OpenWaf/internal/waf/ratelimit"
)

type trackingRequestBodyStream struct {
	reader io.Reader
	closed bool
}

func (s *trackingRequestBodyStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *trackingRequestBodyStream) Close() error {
	s.closed = true
	return nil
}

type closeSensitiveRequestBodyStream struct {
	reader io.Reader
	closed bool
}

func (s *closeSensitiveRequestBodyStream) Read(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("stream closed before replay completed")
	}
	return s.reader.Read(p)
}

func (s *closeSensitiveRequestBodyStream) Close() error {
	s.closed = true
	return nil
}

type unexpectedEOFRequestBodyStream struct {
	reader     io.Reader
	emittedEOF bool
}

type blockingRequestBodyReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingRequestBodyReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (s *unexpectedEOFRequestBodyStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err == io.EOF && !s.emittedEOF {
		s.emittedEOF = true
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (s *unexpectedEOFRequestBodyStream) Close() error {
	return nil
}

func TestNormalizeAntiReplayActionKeepsChallengeActions(t *testing.T) {
	cases := map[string]string{
		"":                  "challenge",
		"shield_challenge":  "shield_challenge",
		"captcha_challenge": "captcha_challenge",
		"chain_challenge":   "chain_challenge",
		"block":             "intercept",
		"drop":              "challenge",
	}
	for input, want := range cases {
		if got := normalizeAntiReplayAction(input); got != want {
			t.Fatalf("normalizeAntiReplayAction(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRequestBodySamplePreservesBodyStreamForForwarding(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))

	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &trackingRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	sample, truncated, size := requestBodySample(ctx)
	if len(sample) != requestInspectionBodyLimit {
		t.Fatalf("sample length = %d, want %d", len(sample), requestInspectionBodyLimit)
	}
	if !truncated {
		t.Fatal("expected truncated sample for oversized stream body")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if !bytes.Equal(sample, body[:requestInspectionBodyLimit]) {
		t.Fatal("sample prefix mismatch")
	}

	replayed, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read replayed body stream: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Fatalf("replayed body mismatch: got %d bytes want %d bytes", len(replayed), len(body))
	}
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("CloseBodyStream returned error: %v", err)
	}
	if stream.closed {
		t.Fatal("forwarding stream close must not close the original Hertz stream")
	}
	restoreOriginalRequestBodyStream(ctx)
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("close restored original stream: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected Hertz cleanup to close the restored original stream")
	}
}

func TestRequestBodySampleDoesNotCloseOriginalStreamDuringRebind(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))

	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &closeSensitiveRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	sample, truncated, size := requestBodySample(ctx)
	if len(sample) != requestInspectionBodyLimit {
		t.Fatalf("sample length = %d, want %d", len(sample), requestInspectionBodyLimit)
	}
	if !truncated {
		t.Fatal("expected truncated sample for oversized stream body")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if stream.closed {
		t.Fatal("original stream must not be closed during request body rebind")
	}

	replayed, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read replayed body stream: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Fatalf("replayed body mismatch: got %d bytes want %d bytes", len(replayed), len(body))
	}
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("CloseBodyStream returned error: %v", err)
	}
	if stream.closed {
		t.Fatal("forwarding stream close must not close the original Hertz stream")
	}
	restoreOriginalRequestBodyStream(ctx)
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("close restored original stream: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected Hertz cleanup to close the restored original stream")
	}
}

func TestPrefetchedRequestBodyStreamCloseWaitsForActiveRead(t *testing.T) {
	reader := &blockingRequestBodyReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	stream := &prefetchedRequestBodyStream{reader: reader}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = stream.Read(make([]byte, 1))
	}()
	<-reader.started

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = stream.Close()
	}()

	select {
	case <-closeDone:
		t.Fatal("Close returned while Read was still active")
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	<-readDone
	<-closeDone

	if n, err := stream.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read after Close = (%d, %v), want (0, EOF)", n, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestRestoreOriginalRequestBodyStreamAfterSnapshot(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))
	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &closeSensitiveRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	requestBodySample(ctx)
	if ctx.Request.BodyStream() == stream {
		t.Fatal("expected prefetched wrapper before restore")
	}

	restoreOriginalRequestBodyStream(ctx)
	if ctx.Request.BodyStream() != stream {
		t.Fatal("original request stream was not restored")
	}
	if stream.closed {
		t.Fatal("original stream must remain open for server cleanup")
	}
}

func TestRequestBodySampleCapturesPrefetchReadError(t *testing.T) {
	body := []byte(strings.Repeat("prefetch-read-error-", 64))

	ctx := app.NewContext(0)
	stream := &unexpectedEOFRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, -1)

	sample, truncated, size := requestBodySample(ctx)
	if truncated {
		t.Fatal("unexpected truncated sample for short stream body")
	}
	if !bytes.Equal(sample, body) {
		t.Fatal("sample body mismatch")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if err := requestBodySnapshotError(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("requestBodySnapshotError() = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestChallengeSubmissionValuesOnlyAcceptsURLEncodedForm(t *testing.T) {
	values := url.Values{
		"__waf_challenge_ts":    {"1700000000"},
		"__waf_challenge_token": {"signed-token"},
		"__waf_challenge_rid":   {"request-id"},
	}

	ts, token, requestID, ok := challengeSubmissionValues([]byte(values.Encode()), "application/x-www-form-urlencoded; charset=UTF-8")
	if !ok {
		t.Fatal("expected complete URL-encoded challenge submission")
	}
	if ts != "1700000000" || token != "signed-token" || requestID != "request-id" {
		t.Fatalf("challenge values = %q, %q, %q", ts, token, requestID)
	}

	if _, _, _, ok := challengeSubmissionValues([]byte(values.Encode()), "multipart/form-data; boundary=test"); ok {
		t.Fatal("multipart body must not be parsed as a challenge submission")
	}
	values.Del("__waf_challenge_token")
	if _, _, _, ok := challengeSubmissionValues([]byte(values.Encode()), "application/x-www-form-urlencoded"); ok {
		t.Fatal("incomplete challenge submission must be rejected")
	}
}

func TestHandlerMultipartBodyLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		bodySize  int
		filename  string
		content   string
		wantBlock bool
	}{
		{name: "forwards 435-byte clean body", bodySize: 435, filename: "report.txt", content: "ordinary report"},
		{name: "forwards 43336-byte clean body", bodySize: 43336, filename: "report.txt", content: "ordinary report"},
		{name: "forwards body above inspection limit", bodySize: 64 * 1024, filename: "report.txt", content: "ordinary report"},
		{name: "blocks 435-byte executable upload", bodySize: 435, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
		{name: "blocks 43336-byte executable upload", bodySize: 43336, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
		{name: "blocks executable upload above inspection limit", bodySize: 64 * 1024, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := fixedLengthMultipartBody(t, tt.bodySize, tt.filename, tt.content)
			var upstreamRequests atomic.Int32
			receivedBody := make(chan []byte, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				got, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				receivedBody <- got
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.OWASPEnabled = true
			protection.OWASPAction = "intercept"
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site:                store.Site{ID: 1, Host: "upload.example.com", Bind: ":80"},
				Bind:                ":80",
				UpstreamURLs:        []string{upstream.URL},
				EffectiveProtection: &protection,
			}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "upload.example.com"): rt,
				},
			})

			handler := Handler(Options{
				Holder: holder,
				Engine: engine.New(holder, nil, nil, nil),
				Log:    slog.Default(),
				Bind:   ":80",
			})
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/upload")
			ctx.Request.Header.SetHost("upload.example.com")
			ctx.Request.Header.Set("Content-Type", contentType)
			ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))

			handler(context.Background(), ctx)

			if tt.wantBlock {
				if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
				}
				if got := upstreamRequests.Load(); got != 0 {
					t.Fatalf("upstream requests = %d, want 0", got)
				}
				return
			}

			if got := ctx.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("status = %d, want %d", got, http.StatusOK)
			}
			if got := upstreamRequests.Load(); got != 1 {
				t.Fatalf("upstream requests = %d, want 1", got)
			}
			got := <-receivedBody
			if !bytes.Equal(got, body) {
				t.Fatalf("upstream body mismatch: got %d bytes want %d", len(got), len(body))
			}
		})
	}
}

func TestHandlerEvaluatesWAFBeforeChallengeRedirect(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantCookie bool
	}{
		{name: "valid challenge redirects after clean WAF result", wantStatus: http.StatusFound, wantCookie: true},
		{name: "dangerous body is blocked before valid challenge redirect", payload: `<script>alert(1)</script>`, wantStatus: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.OWASPEnabled = true
			protection.OWASPAction = "intercept"
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site:                store.Site{ID: 1, Host: "challenge.example.com", Bind: ":80"},
				Bind:                ":80",
				UpstreamURLs:        []string{upstream.URL},
				EffectiveProtection: &protection,
				Rules: []snapshot.CompiledRule{{
					ID:       1,
					Phase:    store.PhaseCustom,
					Action:   store.ActionChallenge,
					Priority: 1,
					Kind:     "always",
				}},
			}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "challenge.example.com"): rt,
				},
			})

			requestID := "challenge-request-id"
			ts, token := challenge.GenerateChallengeTokenPair(requestID)
			values := url.Values{
				"__waf_challenge_ts":    {ts},
				"__waf_challenge_token": {token},
				"__waf_challenge_rid":   {requestID},
			}
			if tt.payload != "" {
				values.Set("payload", tt.payload)
			}
			body := []byte(values.Encode())

			handler := Handler(Options{
				Holder: holder,
				Engine: engine.New(holder, nil, nil, nil),
				Log:    slog.Default(),
				Bind:   ":80",
			})
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/guarded")
			ctx.Request.Header.SetHost("challenge.example.com")
			ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ctx.Request.Header.Set("Referer", "/original")
			ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
			if got := upstreamRequests.Load(); got != 0 {
				t.Fatalf("upstream requests = %d, want 0", got)
			}
			if got := len(ctx.Response.Header.Peek("Set-Cookie")) > 0; got != tt.wantCookie {
				t.Fatalf("challenge cookie present = %v, want %v", got, tt.wantCookie)
			}
		})
	}
}

func fixedLengthMultipartBody(t *testing.T, size int, filename, content string) ([]byte, string) {
	t.Helper()
	const boundary = "owaf-lifecycle-boundary"
	prefix := []byte("--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"document\"; filename=\"" + filename + "\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" + content)
	suffix := []byte("\r\n--" + boundary + "--\r\n")
	paddingSize := size - len(prefix) - len(suffix)
	if paddingSize < 0 {
		t.Fatalf("multipart target size %d is below framing size %d", size, len(prefix)+len(suffix))
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("A"), paddingSize)...)
	body = append(body, suffix...)
	if len(body) != size {
		t.Fatalf("multipart body length = %d, want %d", len(body), size)
	}
	return body, "multipart/form-data; boundary=" + boundary
}

func TestErrorRateLimitActionDefaultsToRateLimit(t *testing.T) {
	got := errorRateLimitAction("")
	if got.Type != action.RateLimit || !got.Matched || got.Phase != "error_rate_limit" || got.StatusCode != 429 {
		t.Fatalf("errorRateLimitAction() = %#v", got)
	}
}

func TestErrorRateLimitActionKeepsConfiguredIntercept(t *testing.T) {
	got := errorRateLimitAction("intercept")
	if got.Type != action.Intercept || got.StatusCode != 0 {
		t.Fatalf("errorRateLimitAction(intercept) = %#v", got)
	}
}

func TestRateLimitActionUsesDefault429Status(t *testing.T) {
	res := action.Result{Type: action.RateLimit, Matched: true}
	if got := res.ResponseStatusCode(); got != 429 {
		t.Fatalf("rate limit response status = %d, want 429", got)
	}
}

func TestAccessLogKeepsSpecificChallengeActions(t *testing.T) {
	for _, actionName := range []string{
		"challenge",
		"captcha_challenge",
		"shield_challenge",
		"chain_challenge",
	} {
		ctx := app.NewContext(0)
		entry := buildAccessLogEntry(ctx, accessLogInfo{WAFAction: actionName, StatusCode: 403})
		if entry.WAFAction != actionName {
			t.Fatalf("access log WAFAction = %q, want %q", entry.WAFAction, actionName)
		}
	}
}

func TestAntiReplayChallengeActionsRenderSpecificChallengePages(t *testing.T) {
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	defer captchaManager.Close()
	shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
	defer shieldManager.Close()
	chainManager := challenge.NewChainChallengeManager(captchaManager, nil)

	baseProtection := store.DefaultProtectionConfig()
	baseProtection.CaptchaEnabled = true
	baseProtection.CaptchaType = "math"
	baseProtection.ShieldEnabled = true
	baseProtection.ChainEnabled = true

	opts := Options{
		CaptchaManager: captchaManager,
		ShieldManager:  shieldManager,
		ChainManager:   chainManager,
	}

	cases := []struct {
		name       string
		actionName action.Type
		wantParts  []string
	}{
		{
			name:       "captcha",
			actionName: action.CaptchaChallenge,
			wantParts: []string{
				`action="/__owaf/captcha/verify"`,
				`name="__waf_captcha_session"`,
				`Security Verification / 安全验证`,
			},
		},
		{
			name:       "shield",
			actionName: action.ShieldChallenge,
			wantParts: []string{
				`action='/__owaf/shield/verify'`,
				`__waf_shield_session`,
				`shield-icon`,
			},
		},
		{
			name:       "chain",
			actionName: action.ChainChallenge,
			wantParts: []string{
				`action='/__owaf/chain/verify'`,
				`__waf_chain_session`,
				`Environment Check / 环境检测`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/guarded?from=anti-replay")

			sn := &snapshot.Snapshot{Protection: baseProtection}
			rt := &snapshot.SiteRuntime{Site: store.Site{ID: 1, Host: "example.com"}}
			result := action.Result{Type: tc.actionName, Matched: true}

			writeAntiReplayActionResponse(ctx, opts, sn, rt, "req-specific-challenge", string(tc.actionName), result, 403)

			if got := ctx.Response.StatusCode(); got != 403 {
				t.Fatalf("status = %d, want 403", got)
			}
			body := string(ctx.Response.Body())
			for _, want := range tc.wantParts {
				if !strings.Contains(body, want) {
					t.Fatalf("response body missing %q", want)
				}
			}
			if strings.Contains(body, "__waf_challenge_token") {
				t.Fatalf("%s response used generic JS challenge token", tc.actionName)
			}
		})
	}
}

func TestHandlerRuleChallengeActionsRenderSpecificChallengePages(t *testing.T) {
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	defer captchaManager.Close()
	shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
	defer shieldManager.Close()
	chainManager := challenge.NewChainChallengeManager(captchaManager, nil)

	cases := []struct {
		name       string
		actionName store.RuleAction
		wantParts  []string
	}{
		{
			name:       "captcha",
			actionName: store.ActionCaptchaChallenge,
			wantParts: []string{
				`action="/__owaf/captcha/verify"`,
				`name="__waf_captcha_session"`,
				`Security Verification / 安全验证`,
			},
		},
		{
			name:       "shield",
			actionName: store.ActionShieldChallenge,
			wantParts: []string{
				`action='/__owaf/shield/verify'`,
				`__waf_shield_session`,
				`shield-icon`,
			},
		},
		{
			name:       "chain",
			actionName: store.ActionChainChallenge,
			wantParts: []string{
				`action='/__owaf/chain/verify'`,
				`__waf_chain_session`,
				`Environment Check / 环境检测`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			protection.CaptchaEnabled = true
			protection.CaptchaType = "math"
			protection.ShieldEnabled = true
			protection.ChainEnabled = true

			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:   1,
					Host: "challenge-rule.example.com",
					Bind: ":80",
				},
				Bind:     ":80",
				PolicyID: 1,
				Rules: []snapshot.CompiledRule{
					{
						ID:       81,
						Phase:    store.PhaseCustom,
						Kind:     "block_path_exact",
						Arg:      "/guarded",
						Action:   tc.actionName,
						Priority: 1,
					},
				},
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "challenge-rule.example.com"): rt,
				},
			}
			holder.Store(sn)

			handler := Handler(Options{
				Holder:         holder,
				Engine:         engine.New(holder, nil, nil, nil),
				Log:            slog.Default(),
				Bind:           ":80",
				CaptchaManager: captchaManager,
				ShieldManager:  shieldManager,
				ChainManager:   chainManager,
			})

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/guarded?from=rule")
			ctx.Request.Header.SetHost("challenge-rule.example.com")

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != 403 {
				t.Fatalf("status = %d, want 403", got)
			}
			body := string(ctx.Response.Body())
			for _, want := range tc.wantParts {
				if !strings.Contains(body, want) {
					t.Fatalf("response body missing %q", want)
				}
			}
			if strings.Contains(body, "__waf_challenge_token") {
				t.Fatalf("%s response used generic JS challenge token", tc.actionName)
			}
		})
	}
}

func TestBuildAccessLogEntryKeepsHTTPProtocol(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:       1,
		StatusCode:   200,
		WAFAction:    "none",
		HTTPProtocol: "h2",
	})
	if entry.HTTPProtocol != "h2" {
		t.Fatalf("HTTPProtocol = %q, want %q", entry.HTTPProtocol, "h2")
	}
}

func TestBuildAccessLogEntryPersistsTLSCipherSuites(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:     1,
		StatusCode: 403,
		WAFAction:  "intercept",
		TLSFingerprint: bot.TLSClientFingerprint{
			CipherSuites: []uint16{4865, 4866},
		},
	})
	if entry.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("TLSCipherSuites = %q, want canonical TLS suite names", entry.TLSCipherSuites)
	}
}

func TestBuildAccessLogEntryPersistsTLSShapeMetadata(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:     1,
		StatusCode: 403,
		WAFAction:  "intercept",
		TLSFingerprint: bot.TLSClientFingerprint{
			Extensions:   []uint16{0, 16, 43},
			Curves:       []uint16{29, 23},
			PointFormats: []uint8{0},
		},
	})
	if entry.TLSExtensions != "0,16,43" {
		t.Fatalf("TLSExtensions = %q, want %q", entry.TLSExtensions, "0,16,43")
	}
	if entry.TLSCurves != "29,23" {
		t.Fatalf("TLSCurves = %q, want %q", entry.TLSCurves, "29,23")
	}
	if entry.TLSPointFormats != "0" {
		t.Fatalf("TLSPointFormats = %q, want %q", entry.TLSPointFormats, "0")
	}
}

func TestRecordSecurityEventAddsTLSMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/tls-security-event?q=1")
	ctx.Request.Header.Set("Host", "127.0.0.1")
	ctx.Request.Header.Set("User-Agent", "tls-security-event-test")
	reqCtx := ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3:          "771,4865-4866,0-11,29,0",
		JA3Hash:      "0123456789abcdef0123456789abcdef",
		JA4:          "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		TLSVersion:   "TLS13",
		SNI:          "security-event.example",
		ALPN:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{4865, 4866},
		Extensions:   []uint16{0, 11, 29},
		Curves:       []uint16{29, 23},
		PointFormats: []uint8{0},
	})
	if fp, ok := tlsFingerprintFromContext(reqCtx); ok {
		ctx.Set(tlsFingerprintContextKey, fp)
	}

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		RequestID:  "req-tls-security",
		ClientIP:   "127.0.0.1",
		Host:       "127.0.0.1",
		Path:       "/tls-security-event",
		Method:     "GET",
		UserAgent:  "tls-security-event-test",
		RuleIDStr:  "owasp:sqli:001",
		Phase:      "owasp_default",
		Action:     "intercept",
		Category:   "sqli",
		MatchDesc:  "SQL injection signals",
		StatusCode: 403,
	})
	writer.Close()

	var got store.SecurityEvent
	if err := db.Where("request_id = ?", "req-tls-security").First(&got).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if got.TLSSNI != "security-event.example" || got.TLSVersion != "TLS13" || got.TLSALPN != "h2,http/1.1" {
		t.Fatalf("security event missed TLS metadata: %#v", got)
	}
	if got.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || got.TLSJA4 == "" || got.TLSJA3 == "" {
		t.Fatalf("security event missed TLS fingerprint: %#v", got)
	}
	if got.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("security event missed TLS cipher suites: %#v", got)
	}
	if got.TLSExtensions != "0,11,29" || got.TLSCurves != "29,23" || got.TLSPointFormats != "0" {
		t.Fatalf("security event missed TLS shape metadata: %#v", got)
	}
	if got.HeaderOrder == "" {
		t.Fatalf("security event missed header order: %#v", got)
	}
}

func TestRecordSecurityEventAddsInternalHTTP3TLSMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-security-event?q=1")
	ctx.Request.Header.Set("Host", "h3.example.com")
	ctx.Request.Header.Set("User-Agent", "h3-security-event-test")
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
	ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
	ctx.Request.Header.Set(InternalHTTP3TLSCipherSuitesHeader, "4865,4866")
	ctx.Request.Header.Set(InternalHTTP3TLSExtensionsHeader, "0,16,43")
	ctx.Request.Header.Set(InternalHTTP3TLSCurvesHeader, "29,23")
	ctx.Request.Header.Set(InternalHTTP3TLSPointFormatsHeader, "0")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		RequestID:  "req-h3-tls-security",
		ClientIP:   "127.0.0.1",
		Host:       "h3.example.com",
		Path:       "/h3-security-event",
		Method:     "GET",
		UserAgent:  "h3-security-event-test",
		RuleIDStr:  "custom:h3:001",
		Phase:      "custom",
		Action:     "intercept",
		Category:   "fingerprint",
		MatchDesc:  "HTTP/3 fingerprint match",
		StatusCode: 403,
	})
	writer.Close()

	var got store.SecurityEvent
	if err := db.Where("request_id = ?", "req-h3-tls-security").First(&got).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if got.TLSVersion != "TLS13" || got.TLSSNI != "client.example" || got.TLSALPN != "h3" {
		t.Fatalf("internal HTTP/3 security event missed TLS metadata: %#v", got)
	}
	if got.TLSJA3 != "771,4865-4866,0-16-43,29,0" || got.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || got.TLSJA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("internal HTTP/3 security event missed JA3/JA4 metadata: %#v", got)
	}
	if got.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("internal HTTP/3 security event missed TLS cipher suites: %#v", got)
	}
	if got.TLSExtensions != "0,16,43" || got.TLSCurves != "29,23" || got.TLSPointFormats != "0" {
		t.Fatalf("internal HTTP/3 security event missed TLS shape metadata: %#v", got)
	}
}

func TestHandlerRecordsTLSSNIWarningForHostMismatch(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "app.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "app.example.com"): rt,
		},
	}
	holder.Store(sn)

	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Writer: writer,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/sni-warning")
	ctx.Request.Header.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "tls-sni-warning-test")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", "other.example.com", "h2"), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}

	var got store.SecurityEvent
	if err := db.Where("site_id = ? AND rule_id_str = ?", 1, "tls:unknown_sni").First(&got).Error; err != nil {
		t.Fatalf("read TLS SNI warning event: %v", err)
	}
	if got.Action != "observe" || got.Phase != "tls" || got.Category != "tls_sni" {
		t.Fatalf("unexpected TLS SNI warning classification: %#v", got)
	}
	if got.Host != "app.example.com" || got.TLSSNI != "other.example.com" || got.TLSVersion != "TLS13" || got.TLSALPN != "h2" {
		t.Fatalf("unexpected TLS SNI warning metadata: %#v", got)
	}
	if got.Path != "/sni-warning" || got.Method != "GET" || got.UserAgent != "tls-sni-warning-test" {
		t.Fatalf("unexpected TLS SNI request metadata: %#v", got)
	}
	if got.MatchDesc != "tls_sni=other.example.com host=app.example.com" {
		t.Fatalf("match_desc = %q", got.MatchDesc)
	}
}

func TestHandlerSkipsTLSSNIWarningWhenHostMatches(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "app.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "app.example.com"): rt,
		},
	}
	holder.Store(sn)

	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Writer: writer,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/sni-ok")
	ctx.Request.Header.SetHost("app.example.com")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", "app.example.com", "h2"), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}

	var count int64
	if err := db.Model(&store.SecurityEvent{}).Where("category = ?", "tls_sni").Count(&count).Error; err != nil {
		t.Fatalf("count TLS SNI warning events: %v", err)
	}
	if count != 0 {
		t.Fatalf("TLS SNI warning event count = %d, want 0", count)
	}
}

func TestHandlerRecordedResourcesKeepMatchFieldsRawButStoreRedactedAudits(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sid=resp-secret")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"resp-secret","status":"ok"}`))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "app.example.com",
			Bind: ":80",
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		AppRouteRules: []appresource.CompiledRule{
			{ID: 11, Target: store.AppRouteTargetRequestBody, Op: store.AppRouteOpContains, Pattern: `"password":"secret"`},
			{ID: 12, Target: store.AppRouteTargetResponseBody, Op: store.AppRouteOpContains, Pattern: `"token":"resp-secret"`},
			{ID: 13, Target: store.AppRouteTargetFingerprint, Op: store.AppRouteOpContains, Pattern: "ja3-match-value"},
		},
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "app.example.com"): rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:               holder,
		Engine:               eng,
		Log:                  slog.Default(),
		Bind:                 ":80",
		RecordedResourceRepo: recordedRepo,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/submit?page=1&token=query-secret")
	ctx.Request.Header.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "handler-recorded-resource-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Authorization", "Bearer req-secret")
	ctx.Request.SetBody([]byte(`{"username":"alice","password":"secret"}`))

	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h3"},
		JA3Hash:    "ja3-match-value",
		JA4:        "ja4-match-value",
	}), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusCreated {
		t.Fatalf("status = %d, want %d", got, http.StatusCreated)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "POST", "app.example.com", "/submit").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.MatchedRuleIDs != "11,12,13" || rec.PrimaryRuleID != 11 {
		t.Fatalf("unexpected matched rule metadata: %#v", rec)
	}
	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "client.example" || rec.TLSALPN != "h3" {
		t.Fatalf("unexpected TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "ja3-match-value" || rec.JA4 != "ja4-match-value" {
		t.Fatalf("unexpected TLS fingerprint metadata: %#v", rec)
	}
	if rec.QueryString != "page=1&token=%5Bredacted%5D" {
		t.Fatalf("QueryString = %q, want sanitized query", rec.QueryString)
	}
	if strings.Contains(rec.RequestHeadersJSON, "req-secret") || !strings.Contains(rec.RequestHeadersJSON, `[redacted]`) {
		t.Fatalf("request_headers_json should redact secrets, got %q", rec.RequestHeadersJSON)
	}
	if strings.Contains(rec.ResponseHeadersJSON, "resp-secret") || !strings.Contains(rec.ResponseHeadersJSON, `[redacted]`) {
		t.Fatalf("response_headers_json should redact secrets, got %q", rec.ResponseHeadersJSON)
	}
	if strings.Contains(rec.RequestBodySnippet, "secret") || !strings.Contains(rec.RequestBodySnippet, `[redacted]`) {
		t.Fatalf("request_body_snippet should redact secrets, got %q", rec.RequestBodySnippet)
	}
	if strings.Contains(rec.ResponseBodySnippet, "resp-secret") || !strings.Contains(rec.ResponseBodySnippet, `[redacted]`) {
		t.Fatalf("response_body_snippet should redact secrets, got %q", rec.ResponseBodySnippet)
	}
}

func TestHandlerRecordedResourcesUseInternalHTTP3TLSMetadata(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources_h3.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "h3-resource.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "h3-resource.example.com"): rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:               holder,
		Engine:               eng,
		Log:                  slog.Default(),
		Bind:                 ":443",
		RecordedResourceRepo: recordedRepo,
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/app.js?v=1")
	ctx.Request.Header.SetHost("h3-resource.example.com")
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
	ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
	ctx.SetConn(&loopbackHertzConn{
		Conn: &testHertzConn{Conn: bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
			TLSVersion: "TLS13",
			SNI:        "proxy.example",
			ALPN:       []string{"h2"},
			JA3Hash:    "proxy-ja3",
			JA4:        "proxy-ja4",
		})},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "GET", "h3-resource.example.com", "/assets/app.js").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "client.example" || rec.TLSALPN != "h3" {
		t.Fatalf("recorded resource missed internal HTTP/3 TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "0123456789abcdef0123456789abcdef" || rec.JA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("recorded resource missed internal HTTP/3 JA3/JA4 metadata: %#v", rec)
	}
	if rec.QueryString != "v=1" {
		t.Fatalf("QueryString = %q, want %q", rec.QueryString, "v=1")
	}
}

func TestHandlerRecordedResourcesIncludeInterceptedRequestsWithoutTreatingLocalBlockPageAsUpstreamResponse(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources_intercept.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "blocked.example.com",
			Bind: ":80",
		},
		Bind:     ":80",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       41,
				Phase:    store.PhaseCustom,
				Kind:     "block_path_exact",
				Arg:      "/blocked",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
		AppRouteRules: []appresource.CompiledRule{
			{ID: 71, Target: store.AppRouteTargetRequestMethod, Op: store.AppRouteOpEq, Pattern: "POST"},
			{ID: 72, Target: store.AppRouteTargetResponseBody, Op: store.AppRouteOpContains, Pattern: "访问被拒绝"},
		},
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "blocked.example.com"): rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:               holder,
		Engine:               eng,
		Log:                  slog.Default(),
		Bind:                 ":80",
		RecordedResourceRepo: recordedRepo,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/blocked?redirect=%2Fconsole&token=req-secret")
	ctx.Request.Header.SetHost("blocked.example.com")
	ctx.Request.Header.Set("User-Agent", "handler-intercept-recorded-resource-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"token":"body-secret","status":"attempt"}`))

	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "blocked.example.com",
		ALPN:       []string{"h2"},
		JA3Hash:    "ja3-intercept-value",
		JA4:        "ja4-intercept-value",
	}), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "POST", "blocked.example.com", "/blocked").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.MatchedRuleIDs != "71" || rec.PrimaryRuleID != 71 {
		t.Fatalf("unexpected matched rule metadata: %#v", rec)
	}
	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "blocked.example.com" || rec.TLSALPN != "h2" {
		t.Fatalf("unexpected TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "ja3-intercept-value" || rec.JA4 != "ja4-intercept-value" {
		t.Fatalf("unexpected TLS fingerprint metadata: %#v", rec)
	}
	if rec.QueryString != "redirect=%2Fconsole&token=%5Bredacted%5D" {
		t.Fatalf("QueryString = %q, want sanitized query", rec.QueryString)
	}
	if strings.Contains(rec.RequestBodySnippet, "body-secret") || !strings.Contains(rec.RequestBodySnippet, `[redacted]`) {
		t.Fatalf("request_body_snippet should redact secrets, got %q", rec.RequestBodySnippet)
	}
	if !strings.Contains(rec.ResponseBodySnippet, "访问被拒绝") {
		t.Fatalf("response_body_snippet should keep local intercept page preview, got %q", rec.ResponseBodySnippet)
	}
}

func TestHandlerRejectsTooManyRequestHeaders(t *testing.T) {
	holder := &snapshot.Holder{}
	sn := &snapshot.Snapshot{
		Revision:    1,
		Protection:  store.DefaultProtectionConfig(),
		HTTP2Config: snapshot.HTTP2Config{MaxHeaderFields: 3},
	}
	holder.Store(sn)
	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("headers.example.com")
	for i := 0; i < 4; i++ {
		ctx.Request.Header.Add("X-Header-"+strconv.Itoa(i), "v")
	}

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != 431 {
		t.Fatalf("status = %d, want 431", got)
	}
	if got := string(ctx.Response.Body()); !strings.Contains(got, "431") || !strings.Contains(got, "Request Header Field(s) Too Large") {
		t.Fatalf("body = %q, want 431 error page", got)
	}
}

func TestScrubResponseHopByHopHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Transfer-Encoding", "chunked")
	ctx.Response.Header.Set("Upgrade", "websocket")

	scrubResponseHopByHopHeaders(ctx)

	for _, key := range []string{"Connection", "Transfer-Encoding", "Upgrade"} {
		if got := string(ctx.Response.Header.Peek(key)); got != "" {
			t.Fatalf("%s header was not scrubbed: %q", key, got)
		}
	}
}

func TestHandlerHEADCacheMissUsesStreamingForwardPath(t *testing.T) {
	payload := []byte(strings.Repeat("head-cache-miss-body-", 128))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("upstream method = %s, want HEAD", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Upstream", "head-cache-miss")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("HEAD")
	ctx.Request.SetRequestURI("/cacheable/head.txt")
	ctx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(payload)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(payload))
	}
	if got := string(ctx.Response.Header.Peek("X-Upstream")); got != "head-cache-miss" {
		t.Fatalf("X-Upstream = %q, want head-cache-miss", got)
	}
	if entries, _ := responseCache.Stats(); entries != 0 {
		t.Fatalf("response cache entries = %d, want 0", entries)
	}
}

func TestHandlerHEADCacheHitWritesMetadataWithoutBody(t *testing.T) {
	payload := []byte(strings.Repeat("head-cache-hit-body-", 128))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("upstream method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	getCtx := app.NewContext(0)
	getCtx.Request.Header.SetMethod("GET")
	getCtx.Request.SetRequestURI("/cacheable/head-hit.txt")
	getCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), getCtx)

	if got := getCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(getCtx.Response.Body(), payload) {
		t.Fatalf("GET body length = %d, want %d", len(getCtx.Response.Body()), len(payload))
	}
	if entries, _ := responseCache.Stats(); entries != 1 {
		t.Fatalf("response cache entries after GET = %d, want 1", entries)
	}

	headCtx := app.NewContext(0)
	headCtx.Request.Header.SetMethod("HEAD")
	headCtx.Request.SetRequestURI("/cacheable/head-hit.txt")
	headCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), headCtx)

	if got := headCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("HEAD status = %d, want %d", got, http.StatusOK)
	}
	if got := len(headCtx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(headCtx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(payload)) {
		t.Fatalf("HEAD Content-Length = %q, want %d", got, len(payload))
	}
	if got := string(headCtx.Response.Header.Peek("Content-Type")); got != "text/plain; charset=utf-8" {
		t.Fatalf("HEAD Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
}

func TestHandlerRecompressesDecodedCachedUpstreamCompressedResponses(t *testing.T) {
	upstreamBody := []byte(strings.Repeat("cached decoded handler gzip response.", 96))
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	if _, err := gzipWriter.Write(upstreamBody); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip body: %v", err)
	}
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(encoded.Len()))
		_, _ = w.Write(encoded.Bytes())
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:                           ":80",
		UpstreamURLs:                   []string{upstream.URL},
		CacheEnabled:                   true,
		ResponseCompressionConfigured:  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1024,
		BrotliEnabled:                  true,
		CacheRules:                     []store.SiteCacheRule{{Type: "prefix", Value: "/cacheable", TTL: 60}},
		EffectiveProtection:            &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	request := func() *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/cacheable/compressed.txt")
		ctx.Request.Header.SetHost("cache.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "br, gzip")
		handler(context.Background(), ctx)
		return ctx
	}

	missCtx := request()
	if got := missCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("miss status = %d, want %d", got, http.StatusOK)
	}
	if got := string(missCtx.Response.Header.Peek("Content-Encoding")); got != "br" {
		t.Fatalf("miss Content-Encoding = %q, want br", got)
	}
	if entries, _ := responseCache.Stats(); entries != 1 {
		t.Fatalf("response cache entries after miss = %d, want 1", entries)
	}

	hitCtx := request()
	if got := hitCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("hit status = %d, want %d", got, http.StatusOK)
	}
	if got := string(hitCtx.Response.Header.Peek("Content-Encoding")); got != "br" {
		t.Fatalf("hit Content-Encoding = %q, want br", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
}

func TestHandlerCacheHitBypassesRangeAndConditionalRequests(t *testing.T) {
	basePayload := []byte("cacheable-full-body")
	tests := []struct {
		name       string
		headerName string
		headerVal  string
		wantStatus int
		wantBody   []byte
	}{
		{
			name:       "range",
			headerName: "Range",
			headerVal:  "bytes=0-4",
			wantStatus: http.StatusPartialContent,
			wantBody:   []byte("cache"),
		},
		{
			name:       "if-none-match",
			headerName: "If-None-Match",
			headerVal:  `"cache-etag"`,
			wantStatus: http.StatusNotModified,
			wantBody:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("ETag", `"cache-etag"`)

				switch {
				case r.Header.Get("Range") != "":
					if got := r.Header.Get("Range"); got != tt.headerVal {
						t.Errorf("Range = %q, want %q", got, tt.headerVal)
					}
					w.Header().Set("Content-Range", "bytes 0-4/19")
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write(tt.wantBody)
				case r.Header.Get("If-None-Match") != "":
					if got := r.Header.Get("If-None-Match"); got != tt.headerVal {
						t.Errorf("If-None-Match = %q, want %q", got, tt.headerVal)
					}
					w.WriteHeader(http.StatusNotModified)
				default:
					_, _ = w.Write(basePayload)
				}
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:   1,
					Host: "cache.example.com",
					Bind: ":80",
				},
				Bind:         ":80",
				UpstreamURLs: []string{upstream.URL},
				CacheEnabled: true,
				CacheRules: []store.SiteCacheRule{
					{Type: "prefix", Value: "/cacheable", TTL: 60},
				},
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "cache.example.com"): rt,
				},
			}
			holder.Store(sn)

			responseCache := cache.NewResponseCache(16, 60)
			defer responseCache.Close()

			eng := engine.New(holder, nil, nil, nil)
			handler := Handler(Options{
				Holder:        holder,
				Engine:        eng,
				Log:           slog.Default(),
				Bind:          ":80",
				ResponseCache: responseCache,
			})

			getCtx := app.NewContext(0)
			getCtx.Request.Header.SetMethod("GET")
			getCtx.Request.SetRequestURI("/cacheable/item.txt")
			getCtx.Request.Header.SetHost("cache.example.com")

			handler(context.Background(), getCtx)

			if got := getCtx.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("GET status = %d, want %d", got, http.StatusOK)
			}
			if !bytes.Equal(getCtx.Response.Body(), basePayload) {
				t.Fatalf("GET body = %q, want %q", getCtx.Response.Body(), basePayload)
			}
			if entries, _ := responseCache.Stats(); entries != 1 {
				t.Fatalf("response cache entries after GET = %d, want 1", entries)
			}

			bypassCtx := app.NewContext(0)
			bypassCtx.Request.Header.SetMethod("GET")
			bypassCtx.Request.SetRequestURI("/cacheable/item.txt")
			bypassCtx.Request.Header.SetHost("cache.example.com")
			bypassCtx.Request.Header.Set(tt.headerName, tt.headerVal)

			handler(context.Background(), bypassCtx)

			if got := bypassCtx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("%s status = %d, want %d", tt.name, got, tt.wantStatus)
			}
			if !bytes.Equal(bypassCtx.Response.Body(), tt.wantBody) {
				t.Fatalf("%s body = %q, want %q", tt.name, bypassCtx.Response.Body(), tt.wantBody)
			}
			if got := upstreamRequests.Load(); got != 2 {
				t.Fatalf("upstream requests = %d, want 2", got)
			}
		})
	}
}

func TestHandlerServesStaleCacheWhenUpstreamFailsAfterCacheExpiry(t *testing.T) {
	staleBody := []byte("stale cached body")
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(staleBody)))
		_, _ = w.Write(staleBody)
	}))

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 1},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	fillCtx := app.NewContext(0)
	fillCtx.Request.Header.SetMethod("GET")
	fillCtx.Request.SetRequestURI("/cacheable/stale.txt")
	fillCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), fillCtx)

	if got := fillCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("fill status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(fillCtx.Response.Body(), staleBody) {
		t.Fatalf("fill body = %q, want %q", fillCtx.Response.Body(), staleBody)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests after fill = %d, want 1", got)
	}

	time.Sleep(2 * time.Second)
	upstream.Close()

	staleCtx := app.NewContext(0)
	staleCtx.Request.Header.SetMethod("GET")
	staleCtx.Request.SetRequestURI("/cacheable/stale.txt")
	staleCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), staleCtx)

	if got := staleCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("stale status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(staleCtx.Response.Body(), staleBody) {
		t.Fatalf("stale body = %q, want %q", staleCtx.Response.Body(), staleBody)
	}
	if got := string(staleCtx.Response.Header.Peek("Content-Type")); got != "text/plain; charset=utf-8" {
		t.Fatalf("stale Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests after stale fallback = %d, want 1", got)
	}
}

func TestHandlerCacheMissLargeResponseStreamsWithoutCaching(t *testing.T) {
	payload := []byte(strings.Repeat("large-cache-miss-body-", 6000))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("upstream method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(1, 60)
	defer responseCache.Close()
	if int64(len(payload)) <= responseCache.MaxEntryBodySize() {
		t.Fatalf("test payload length = %d, want above cache max entry size %d", len(payload), responseCache.MaxEntryBodySize())
	}

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/cacheable/large.txt")
	ctx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(ctx.Response.Body(), payload) {
		t.Fatalf("response body length = %d, want %d", len(ctx.Response.Body()), len(payload))
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "" {
		t.Fatalf("Content-Length = %q, want empty for streamed overflow response", got)
	}
	if entries, _ := responseCache.Stats(); entries != 0 {
		t.Fatalf("response cache entries = %d, want 0", entries)
	}
}

func TestHandlerMatchesTLSHandshakeMetadataRuleWithoutClientHelloFingerprint(t *testing.T) {
	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "tls-rule.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:     ":443",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       11,
				Phase:    store.PhaseCustom,
				Kind:     "tls_sni",
				Arg:      "client.example",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "tls-rule.example.com"): rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("tls-rule.example.com")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", "client.example", "h2"), ctx)

	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
	}
}

func TestHandlerMatchesInternalHTTP3TLSFingerprintRules(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		rules   []snapshot.CompiledRule
	}{
		{
			name: "ja3 hash rule",
			headers: map[string]string{
				InternalHTTP3TLSVersionHeader: "TLS13",
				InternalHTTP3TLSJA3HashHeader: "0123456789abcdef0123456789abcdef",
				InternalHTTP3TLSJA4Header:     "q13d0511h3_fea09b2e4d67_1234567890ab",
			},
			rules: []snapshot.CompiledRule{
				{
					ID:       11,
					Phase:    store.PhaseCustom,
					Kind:     "tls_ja3_hash",
					Arg:      "0123456789abcdef0123456789abcdef",
					Action:   store.ActionIntercept,
					Priority: 1,
				},
			},
		},
		{
			name: "cipher suites rule",
			headers: map[string]string{
				InternalHTTP3TLSVersionHeader:      "TLS13",
				InternalHTTP3TLSCipherSuitesHeader: "4865,4866",
				InternalHTTP3TLSCurvesHeader:       "29,23",
			},
			rules: []snapshot.CompiledRule{
				{
					ID:       12,
					Phase:    store.PhaseCustom,
					Kind:     "tls_cipher_suites",
					Arg:      "TLS_AES_128_GCM_SHA256",
					Action:   store.ActionIntercept,
					Priority: 1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:         1,
					Host:       "h3-rule.example.com",
					Bind:       ":443",
					TLSEnabled: true,
				},
				Bind:                ":443",
				PolicyID:            1,
				Rules:               tt.rules,
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]snapshot.SiteRuntime{
					snapshot.SiteMapKey(":443", "h3-rule.example.com"): rt,
				},
			}
			holder.Store(sn)

			eng := engine.New(holder, nil, nil, nil)
			handler := Handler(Options{
				Holder: holder,
				Engine: eng,
				Log:    slog.Default(),
				Bind:   ":443",
			})

			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/")
			ctx.Request.Header.SetHost("h3-rule.example.com")
			ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
			ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
			for key, value := range tt.headers {
				ctx.Request.Header.Set(key, value)
			}
			ctx.SetConn(&loopbackHertzConn{
				Conn: &testHertzConn{Conn: bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
					TLSVersion: "TLS13",
					JA3Hash:    "proxy-ja3",
					JA4:        "proxy-ja4",
				})},
				localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			handler(context.Background(), ctx)

			if ctx.Response.StatusCode() != 403 {
				t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
			}
		})
	}
}

func TestHandlerAppliesSiteAntiReplayTTLToNonceHeaderPhase(t *testing.T) {
	holder := &snapshot.Holder{}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: store.DefaultProtectionConfig(),
		Sites:      make(map[string]snapshot.SiteRuntime),
	}
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:               1,
			Host:             "ttl.example.com",
			AntiReplayTTL:    1,
			AntiReplayAction: "shield_challenge",
		},
		Bind:              ":80",
		AntiReplayEnabled: true,
	}
	sn.Sites[snapshot.SiteMapKey(":80", "ttl.example.com")] = rt
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("handler-anti-replay-ttl", nil, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	nonce := mgr.GenerateNonce("")
	time.Sleep(1100 * time.Millisecond)

	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":80",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("ttl.example.com")
	ctx.Request.Header.Set("X-Nonce", nonce)

	handler(context.Background(), ctx)

	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
	}
}

func TestShouldApplyErrorRateLimitUsesHistoricalErrors(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"

	rl.Increment(key)
	if shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("rate limit applied at threshold instead of above threshold")
	}
	rl.Increment(key)
	if !shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("rate limit did not apply after historical errors exceeded threshold")
	}
}

func TestIncrementErrorRateLimitStatusHonorsConfiguredBuckets(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	prot := store.ProtectionConfig{ErrorRateLimitCount4xx: true}

	incrementErrorRateLimitStatus(eng, prot, key, 500)
	if shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("5xx response was counted while only 4xx bucket is enabled")
	}
	incrementErrorRateLimitStatus(eng, prot, key, 404)
	incrementErrorRateLimitStatus(eng, prot, key, 401)
	if !shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("4xx responses were not counted")
	}
}

func TestIncrementErrorRateLimitBlockHonorsSwitch(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 0, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"

	incrementErrorRateLimitBlock(eng, store.ProtectionConfig{}, key)
	if shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("block was counted while error_ratelimit_count_block is disabled")
	}
	incrementErrorRateLimitBlock(eng, store.ProtectionConfig{ErrorRateLimitCountBlock: true}, key)
	if !shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("block was not counted while error_ratelimit_count_block is enabled")
	}
}

func TestSiteErrorPageUsesConfiguredHTMLTemplate(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"502":{"status_code":502,"title":"Custom Upstream","html":"<h1>{{.StatusCode}}</h1><p>{{.Message}}</p>","content_type":"text/html"}}`}}

	cfg := siteErrorPage(&rt, 502)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.Title != "Custom Upstream" || cfg.StatusCode != 502 {
		t.Fatalf("siteErrorPage() = %#v", cfg)
	}
	if got, want := string(pages.RenderErrorPage(502, cfg)), "<h1>502</h1><p>Custom Upstream</p>"; got != want {
		t.Fatalf("RenderErrorPage() = %q, want %q", got, want)
	}
	if cfg := siteErrorPage(&rt, 504); cfg != nil {
		t.Fatalf("siteErrorPage() returned %#v for unconfigured status code", cfg)
	}
}

func TestSiteErrorPageFillsMissingStatusCode(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"503":{"title":"Maintenance","html":"maintenance"}}`}}

	cfg := siteErrorPage(&rt, 503)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.StatusCode != 503 {
		t.Fatalf("siteErrorPage().StatusCode = %d, want 503", cfg.StatusCode)
	}
}

func TestSetChallengeCookieSignsValue(t *testing.T) {
	value := challenge.SignChallengePassValue("example.com", nil, time.Unix(100, 0), time.Hour)
	if value == "1" {
		t.Fatal("challenge pass value must not be a forgeable boolean")
	}
	if !challenge.VerifyChallengePassValue(value, "example.com", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value did not verify")
	}
	if challenge.VerifyChallengePassValue(value, "other.example", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value verified for the wrong host")
	}
}

func TestShouldLogDropConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogDropConsoleCount(count); got != want {
			t.Fatalf("shouldLogDropConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestShouldLogNoSiteMatchConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogNoSiteMatchConsoleCount(count); got != want {
			t.Fatalf("shouldLogNoSiteMatchConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}
