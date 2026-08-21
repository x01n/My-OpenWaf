package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func TestValidatePersistedRuleAction(t *testing.T) {
	tests := []struct {
		name  string
		phase store.RulePhase
		in    string
		want  string
		ok    bool
	}{
		{name: "intercept", phase: store.PhaseCustom, in: "intercept", want: "intercept", ok: true},
		{name: "legacy block", phase: store.PhaseCustom, in: "block", want: "intercept", ok: true},
		{name: "legacy log only", phase: store.PhaseCustom, in: "log_only", want: "observe", ok: true},
		{name: "acl allow", phase: store.PhaseACL, in: "allow", want: "allow", ok: true},
		{name: "signature allow rejected", phase: store.PhaseSignature, in: "allow", ok: false},
		{name: "custom allow rejected", phase: store.PhaseCustom, in: "allow", ok: false},
		{name: "tag rejected", phase: store.PhaseACL, in: "tag", ok: false},
		{name: "reject invalid", phase: store.PhaseCustom, in: "destroy", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := validatePersistedRuleAction(tt.phase, store.RuleAction(tt.in))
			if ok != tt.ok || string(got) != tt.want {
				t.Fatalf("validatePersistedRuleAction(%q, %q) = (%q, %v), want (%q, %v)", tt.phase, tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizePersistedRuleConfigRejectsNonACLAllow(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseSignature, store.PhaseCustom} {
		item := store.Rule{
			Phase:   phase,
			Action:  store.ActionAllow,
			Pattern: "block_path:/ok",
		}
		if got := normalizePersistedRuleConfig(&item); got != "invalid action" {
			t.Fatalf("normalizePersistedRuleConfig(%q allow) = %q, want invalid action", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigRequiresRedirectTarget(t *testing.T) {
	item := store.Rule{Phase: store.PhaseACL, Action: store.ActionRedirect, Pattern: "block_path:/blocked"}
	if got := normalizePersistedRuleConfig(&item); got != "redirect_to required" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want redirect_to required", got)
	}

	item.RedirectTo = "/blocked"
	if got := normalizePersistedRuleConfig(&item); got != "" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want empty error", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsUnsupportedPhase(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseRateLimit, store.PhaseOWASP} {
		item := store.Rule{
			Phase:  phase,
			Action: store.ActionIntercept,
		}
		if got := normalizePersistedRuleConfig(&item); got != "unsupported phase: only acl, signature, custom are executable custom rule phases" {
			t.Fatalf("normalizePersistedRuleConfig(%q) = %q", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigAcceptsExecutableRulePhases(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseACL, store.PhaseSignature, store.PhaseCustom} {
		item := store.Rule{
			Phase:   phase,
			Action:  store.ActionObserve,
			Pattern: "block_path:/ok",
		}
		if got := normalizePersistedRuleConfig(&item); got != "" {
			t.Fatalf("normalizePersistedRuleConfig(%q) = %q", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigCaptchaTypeContract(t *testing.T) {
	for _, captchaType := range []string{"math", "click", "slide", "rotate"} {
		item := store.Rule{
			Phase:       store.PhaseCustom,
			Action:      store.ActionCaptchaChallenge,
			Pattern:     "block_path:/guarded",
			CaptchaType: captchaType,
		}
		if got := normalizePersistedRuleConfig(&item); got != "" {
			t.Fatalf("captcha_type=%q should be accepted: %q", captchaType, got)
		}
	}

	for _, captchaType := range []string{"Math", "image", " slide ", "pow"} {
		item := store.Rule{
			Phase:       store.PhaseCustom,
			Action:      store.ActionCaptchaChallenge,
			Pattern:     "block_path:/guarded",
			CaptchaType: captchaType,
		}
		if got := normalizePersistedRuleConfig(&item); got != "invalid captcha_type" {
			t.Fatalf("captcha_type=%q error = %q, want invalid captcha_type", captchaType, got)
		}
	}

	item := store.Rule{
		Phase:       store.PhaseCustom,
		Action:      store.ActionIntercept,
		Pattern:     "block_path:/guarded",
		CaptchaType: "slide",
	}
	if got := normalizePersistedRuleConfig(&item); got != "captcha_type requires captcha_challenge action" {
		t.Fatalf("non-captcha action error = %q", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsInvalidTLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:   store.PhaseCustom,
		Action:  store.ActionObserve,
		Pattern: "tls_version:TLS 1.9",
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsUnsupportedSSL3TLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:   store.PhaseCustom,
		Action:  store.ActionObserve,
		Pattern: "tls_version:SSL3",
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsInvalidCompoundTLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:  store.PhaseCustom,
		Action: store.ActionObserve,
		Pattern: `{"op":"and","children":[` +
			`{"kind":"block_path","arg":"/admin"},` +
			`{"kind":"tls_version","arg":"TLS 1.9"}` +
			`]}`,
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigAcceptsCompoundTLSAliases(t *testing.T) {
	item := store.Rule{
		Phase:  store.PhaseCustom,
		Action: store.ActionObserve,
		Pattern: `{"op":"and","children":[` +
			`{"kind":"tls_version","arg":"TLS 1.3"},` +
			`{"kind":"tls_cipher_suites","arg":"4865"}` +
			`]}`,
	}
	if got := normalizePersistedRuleConfig(&item); got != "" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func invokeTestRuleHandler(t *testing.T, payload []byte) *app.RequestContext {
	t.Helper()

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/rules/test")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	TestRule()(context.Background(), ctx)
	return ctx
}

func TestTestRuleMatchesTLSVersionHeader(t *testing.T) {
	ctx := invokeTestRuleHandler(t, []byte(`{
		"pattern":"tls_version:TLS13",
		"method":"GET",
		"path":"/",
		"headers":{"X-OWAF-TLS-Version":"TLS13"}
	}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Matched bool   `json:"matched"`
		Kind    string `json:"kind"`
		Arg     string `json:"arg"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected tls_version test rule to match, got %#v", resp)
	}
	if resp.Kind != "tls_version" || resp.Arg != "TLS13" {
		t.Fatalf("unexpected tls_version response %#v", resp)
	}
}

func TestTestRuleMatchesTLSCipherSuitesHeader(t *testing.T) {
	ctx := invokeTestRuleHandler(t, []byte(`{
		"pattern":"tls_cipher_suites:TLS_AES_128_GCM_SHA256",
		"method":"GET",
		"path":"/",
		"headers":{"X-OWAF-TLS-Cipher-Suites":"TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"}
	}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Matched bool   `json:"matched"`
		Kind    string `json:"kind"`
		Arg     string `json:"arg"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected tls_cipher_suites test rule to match, got %#v", resp)
	}
	if resp.Kind != "tls_cipher_suites" || resp.Arg != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected tls_cipher_suites response %#v", resp)
	}
}

func newRuleRepoForHandlerTest(t *testing.T) *repository.RuleRepo {
	t.Helper()
	repo, _ := newRuleRepoAndDBForHandlerTest(t)
	return repo
}

func newRuleRepoAndDBForHandlerTest(t *testing.T) (*repository.RuleRepo, *gorm.DB) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Rule{}); err != nil {
		t.Fatalf("migrate rules: %v", err)
	}
	if err := db.Create(&store.Policy{
		Name:        "handler-policy",
		Description: "handler tests",
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return repository.NewRuleRepo(db), db
}

func invokePersistedRuleHandler(
	t *testing.T,
	handler app.HandlerFunc,
	uri string,
	payload []byte,
) *app.RequestContext {
	t.Helper()

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateRuleRejectsInvalidTLSPattern(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	handler := CreateRule(repo, func() error { return nil })

	ctx := invokePersistedRuleHandler(t, handler, "/api/v1/rules", []byte(`{
		"name":"invalid tls version create",
		"policy_id":1,
		"phase":"custom",
		"pattern":"tls_version:TLS 1.9",
		"action":"observe",
		"priority":10,
		"enabled":true
	}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "invalid pattern: tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("error = %q", resp.Error)
	}
}

func TestImportRulesRejectsInvalidCompoundTLSPattern(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	handler := ImportRules(repo, func() error { return nil })

	ctx := invokePersistedRuleHandler(t, handler, "/api/v1/rules/import", []byte(`{
		"rules":[
			{
				"name":"invalid compound tls version import",
				"policy_id":1,
				"phase":"custom",
				"pattern":"{\"op\":\"and\",\"children\":[{\"kind\":\"block_path\",\"arg\":\"/admin\"},{\"kind\":\"tls_version\",\"arg\":\"TLS 1.9\"}]}",
				"action":"observe",
				"priority":11,
				"enabled":true
			}
		]
	}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Error string `json:"error"`
		Index int    `json:"index"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "invalid pattern: tls_version 需要合法的 TLS 版本标识" {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Index != 0 {
		t.Fatalf("index = %d, want 0", resp.Index)
	}
}

func invokeRuleGetHandler(t *testing.T, handler app.HandlerFunc, uri string, ps param.Params) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI(uri)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	if ps != nil {
		ctx.Params = ps
	}
	handler(context.Background(), ctx)
	return ctx
}

func newSiteAndRuleReposForTest(t *testing.T) (*repository.SiteRepo, *repository.RuleRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.Policy{}, &store.Rule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&store.Policy{Name: "p1"}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID := uint(1)
	if err := db.Create(&store.Site{Host: "example.test", Bind: ":80", Network: "tcp", Enabled: true, PolicyID: &policyID}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewRuleRepo(db)
}

func TestListRulesReturns200OnEmptyDB(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	ctx := invokeRuleGetHandler(t, ListRules(repo), "/api/v1/rules", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Items []store.Rule `json:"items"`
		Total int64        `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 0 || len(resp.Items) != 0 {
		t.Fatalf("expected empty list, got total=%d items=%d", resp.Total, len(resp.Items))
	}
}

func TestGetRuleInvalidIDReturns400(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	ctx := invokeRuleGetHandler(t, GetRule(repo), "/api/v1/rules/abc",
		param.Params{{Key: "id", Value: "abc"}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
}

func TestGetRuleNotFoundReturns404(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	ctx := invokeRuleGetHandler(t, GetRule(repo), "/api/v1/rules/9999",
		param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
}

func TestCreateAndGetRuleSuccess(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	reloaded := 0
	createCtx := invokePersistedRuleHandler(t, CreateRule(repo, func() error {
		reloaded++
		return nil
	}), "/api/v1/rules", []byte(`{
		"name":"test-create","policy_id":1,"phase":"custom",
		"pattern":"block_path:/blocked","action":"intercept",
		"priority":5,"enabled":true
	}`))
	if createCtx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", createCtx.Response.StatusCode(), createCtx.Response.Body())
	}
	if reloaded != 1 {
		t.Fatalf("expected 1 reload, got %d", reloaded)
	}
	var created store.Rule
	if err := json.Unmarshal(createCtx.Response.Body(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected non-zero ID after create")
	}

	getCtx := invokeRuleGetHandler(t, GetRule(repo), "/api/v1/rules/1",
		param.Params{{Key: "id", Value: "1"}})
	if getCtx.Response.StatusCode() != 200 {
		t.Fatalf("get status %d: %s", getCtx.Response.StatusCode(), getCtx.Response.Body())
	}
}

func TestUpdateRuleNotFoundReturns404(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	ctx := invokePersistedRuleHandler(t,
		UpdateRule(repo, func() error { return nil }),
		"/api/v1/rules/9999/update",
		[]byte(`{"name":"x","policy_id":1,"phase":"custom","pattern":"block_path:/x","action":"intercept","priority":1,"enabled":true}`),
	)
	ctx.Params = param.Params{{Key: "id", Value: "9999"}}
	UpdateRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
}

func TestUpdateRuleSuccess(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	seed := store.Rule{Name: "orig", PolicyID: 1, Phase: store.PhaseCustom,
		Pattern: "block_path:/orig", Action: store.ActionIntercept, Priority: 3, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	updatePayload := []byte(`{"name":"updated","policy_id":1,"phase":"custom","pattern":"block_path:/updated","action":"observe","priority":3,"enabled":false}`)
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/rules/1/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(updatePayload)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	UpdateRule(repo, func() error { return nil })(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var updated store.Rule
	if err := json.Unmarshal(ctx.Response.Body(), &updated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if updated.Name != "updated" || updated.Enabled {
		t.Fatalf("unexpected updated rule: %+v", updated)
	}
}

func TestDeleteRuleSuccess(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	seed := store.Rule{Name: "to-delete", PolicyID: 1, Phase: store.PhaseACL,
		Pattern: "block_ip:1.2.3.4", Action: store.ActionIntercept, Priority: 1, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/rules/1/delete")
	req.Header.Set("Content-Type", "application/json")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	DeleteRule(repo, func() error { return nil })(context.Background(), ctx)

	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	getCtx := invokeRuleGetHandler(t, GetRule(repo), "/api/v1/rules/1",
		param.Params{{Key: "id", Value: "1"}})
	if getCtx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 after delete, got %d", getCtx.Response.StatusCode())
	}
}

func TestExportRulesEmpty(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	ctx := invokeRuleGetHandler(t, ExportRules(repo), "/api/v1/rules/export", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Rules []store.Rule `json:"rules"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Fatalf("expected empty export, got %d rules", len(resp.Rules))
	}
}

func TestImportRulesSuccess(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	reloaded := 0
	ctx := invokePersistedRuleHandler(t, ImportRules(repo, func() error {
		reloaded++
		return nil
	}), "/api/v1/rules/import", []byte(`{
		"rules":[
			{"name":"r1","policy_id":1,"phase":"acl","pattern":"block_ip:10.0.0.1","action":"intercept","priority":1,"enabled":true},
			{"name":"r2","policy_id":1,"phase":"acl","pattern":"block_ip:10.0.0.2","action":"intercept","priority":2,"enabled":true}
		]
	}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("import status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if reloaded != 1 {
		t.Fatalf("expected 1 reload, got %d", reloaded)
	}
	var resp struct {
		Imported int `json:"imported"`
		Total    int `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Imported != 2 || resp.Total != 2 {
		t.Fatalf("expected imported=2 total=2, got %+v", resp)
	}
}

func TestRuleWritesRejectMissingOrSoftDeletedPolicy(t *testing.T) {
	tests := []struct {
		name       string
		policyID   uint
		softDelete bool
	}{
		{name: "missing", policyID: 999},
		{name: "soft deleted", policyID: 2, softDelete: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, db := newRuleRepoAndDBForHandlerTest(t)
			if tt.softDelete {
				policy := store.Policy{ID: tt.policyID, Name: "deleted policy"}
				if err := db.Create(&policy).Error; err != nil {
					t.Fatalf("seed policy: %v", err)
				}
				if err := db.Delete(&policy).Error; err != nil {
					t.Fatalf("soft delete policy: %v", err)
				}
			}

			reloaded := 0
			createPayload := []byte(fmt.Sprintf(`{"name":"orphan","policy_id":%d,"phase":"custom","pattern":"block_path:/orphan","action":"intercept","priority":1,"enabled":true}`, tt.policyID))
			createCtx := invokePersistedRuleHandler(t, CreateRule(repo, func() error {
				reloaded++
				return nil
			}), "/api/v1/rules", createPayload)
			if createCtx.Response.StatusCode() != 400 {
				t.Fatalf("create status %d: %s", createCtx.Response.StatusCode(), createCtx.Response.Body())
			}

			seed := store.Rule{Name: "existing", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/existing", Action: store.ActionIntercept, Priority: 2, Enabled: true}
			if err := repo.Create(&seed); err != nil {
				t.Fatalf("seed rule: %v", err)
			}
			updateCtx := invokePersistedRuleHandler(t, UpdateRule(repo, func() error {
				reloaded++
				return nil
			}), "/api/v1/rules/1/update", createPayload)
			updateCtx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(seed.ID), 10)}}
			UpdateRule(repo, func() error {
				reloaded++
				return nil
			})(context.Background(), updateCtx)
			if updateCtx.Response.StatusCode() != 400 {
				t.Fatalf("update status %d: %s", updateCtx.Response.StatusCode(), updateCtx.Response.Body())
			}

			importPayload := []byte(fmt.Sprintf(`{"rules":[{"name":"orphan","policy_id":%d,"phase":"custom","pattern":"block_path:/import","action":"intercept","priority":3,"enabled":true}]}`, tt.policyID))
			importCtx := invokePersistedRuleHandler(t, ImportRules(repo, func() error {
				reloaded++
				return nil
			}), "/api/v1/rules/import", importPayload)
			if importCtx.Response.StatusCode() != 400 {
				t.Fatalf("import status %d: %s", importCtx.Response.StatusCode(), importCtx.Response.Body())
			}
			if reloaded != 0 {
				t.Fatalf("reload count = %d, want 0", reloaded)
			}
		})
	}
}

func TestListSiteRulesNoPolicyReturnsEmpty(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.Policy{}, &store.Rule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("seed default policy: %v", err)
	}
	if err := db.Create(&store.Site{Host: "nopolicy.test", Bind: ":8080", Network: "tcp", Enabled: true}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if err := db.Create(&store.Rule{Name: "default rule", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/blocked", Action: store.ActionIntercept, Priority: 1, Enabled: true}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	ruleRepo := repository.NewRuleRepo(db)

	ctx := invokeRuleGetHandler(t, ListSiteRules(siteRepo, ruleRepo), "/api/v1/sites/1/rules",
		param.Params{{Key: "id", Value: "1"}})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Items     []store.Rule `json:"items"`
		Total     int          `json:"total"`
		PolicyID  uint         `json:"policy_id"`
		Inherited bool         `json:"inherited"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.PolicyID != 1 || !resp.Inherited {
		t.Fatalf("expected default policy rules, got %+v", resp)
	}
}

func TestListSiteRulesNotFoundReturns404(t *testing.T) {
	siteRepo, ruleRepo := newSiteAndRuleReposForTest(t)
	ctx := invokeRuleGetHandler(t, ListSiteRules(siteRepo, ruleRepo), "/api/v1/sites/9999/rules",
		param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing site, got %d", ctx.Response.StatusCode())
	}
}
