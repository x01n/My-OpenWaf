package system

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

func invokeSettingsHandler(t *testing.T, handler app.HandlerFunc, method string, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func protectedSettingKeysForTest() []string {
	return []string{
		"protection",
		"bot_settings",
		"drop_policy",
		store.SettingKeyRedisConfig,
		settingKeyNetwork,
		settingKeyLog,
		settingKeyTLSDefault,
		store.SettingKeyACMEConfig,
	}
}

func TestGenericSettingsRejectProtectedCreateUpdateDelete(t *testing.T) {
	for _, key := range protectedSettingKeysForTest() {
		t.Run(key, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			reloadCount := 0
			reload := func() error {
				reloadCount++
				return nil
			}
			createBody, err := json.Marshal(map[string]string{
				"key":   key,
				"value": `{"enabled":true}`,
			})
			if err != nil {
				t.Fatalf("encode create body: %v", err)
			}

			createCtx := invokeSettingsHandler(t, CreateSetting(repo, reload), "POST", "/api/v1/settings", nil, createBody)
			if createCtx.Response.StatusCode() != 400 {
				t.Fatalf("create protected setting status %d: %s", createCtx.Response.StatusCode(), bytes.TrimSpace(createCtx.Response.Body()))
			}
			if _, err := repo.Get(key); err == nil {
				t.Fatalf("protected create should not persist key %q", key)
			}

			if err := repo.Set(key, "old-value"); err != nil {
				t.Fatalf("seed protected setting: %v", err)
			}
			keyParam := param.Params{{Key: "key", Value: key}}
			updateCtx := invokeSettingsHandler(t, SetSetting(repo, reload), "POST", "/api/v1/settings/"+key, keyParam, []byte(`{"value":"new-value"}`))
			if updateCtx.Response.StatusCode() != 400 {
				t.Fatalf("update protected setting status %d: %s", updateCtx.Response.StatusCode(), bytes.TrimSpace(updateCtx.Response.Body()))
			}
			val, err := repo.Get(key)
			if err != nil {
				t.Fatalf("load protected setting after update reject: %v", err)
			}
			if val != "old-value" {
				t.Fatalf("protected update changed %q to %q", key, val)
			}

			deleteCtx := invokeSettingsHandler(t, DeleteSetting(repo, reload), "POST", "/api/v1/settings/"+key+"/delete", keyParam, nil)
			if deleteCtx.Response.StatusCode() != 400 {
				t.Fatalf("delete protected setting status %d: %s", deleteCtx.Response.StatusCode(), bytes.TrimSpace(deleteCtx.Response.Body()))
			}
			val, err = repo.Get(key)
			if err != nil {
				t.Fatalf("load protected setting after delete reject: %v", err)
			}
			if val != "old-value" {
				t.Fatalf("protected delete changed %q to %q", key, val)
			}
			if reloadCount != 0 {
				t.Fatalf("protected setting operation reload count = %d, want 0", reloadCount)
			}
		})
	}
}

func TestGenericSettingsRedactsRedisPasswordOnRead(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	rawRedis := `{"enabled":true,"addr":"127.0.0.1:6379","password":"secret-pass","db":2}`
	if err := repo.Set(store.SettingKeyRedisConfig, rawRedis); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}
	if err := repo.Set("custom_note", "plain-value"); err != nil {
		t.Fatalf("seed custom setting: %v", err)
	}

	keyParam := param.Params{{Key: "key", Value: store.SettingKeyRedisConfig}}
	getCtx := invokeSettingsHandler(t, GetSetting(repo), "GET", "/api/v1/settings/redis_config", keyParam, nil)
	if getCtx.Response.StatusCode() != 200 {
		t.Fatalf("get redis setting status %d: %s", getCtx.Response.StatusCode(), bytes.TrimSpace(getCtx.Response.Body()))
	}
	var getResp struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(getCtx.Response.Body(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if bytes.Contains([]byte(getResp.Value), []byte("secret-pass")) {
		t.Fatalf("redis password leaked in get response: %s", getResp.Value)
	}
	if !bytes.Contains([]byte(getResp.Value), []byte("[redacted]")) {
		t.Fatalf("redis password was not redacted in get response: %s", getResp.Value)
	}

	listCtx := invokeSettingsHandler(t, ListSettings(repo), "GET", "/api/v1/settings", nil, nil)
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("list settings status %d: %s", listCtx.Response.StatusCode(), bytes.TrimSpace(listCtx.Response.Body()))
	}
	if bytes.Contains(listCtx.Response.Body(), []byte("secret-pass")) {
		t.Fatalf("redis password leaked in list response: %s", bytes.TrimSpace(listCtx.Response.Body()))
	}
	if !bytes.Contains(listCtx.Response.Body(), []byte("[redacted]")) {
		t.Fatalf("redis password was not redacted in list response: %s", bytes.TrimSpace(listCtx.Response.Body()))
	}
	if !bytes.Contains(listCtx.Response.Body(), []byte("plain-value")) {
		t.Fatalf("custom setting should remain readable in list response: %s", bytes.TrimSpace(listCtx.Response.Body()))
	}
}
