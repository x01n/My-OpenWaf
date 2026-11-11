"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton } from "@/components/ui/primitives";
import type { ProtectionSettings } from "@/lib/types/protection";
import {
  SectionCard,
  SwitchRow,
  NumberField,
  TextFieldRow,
  SelectRow,
  JsonTextArea,
} from "./field-controls";
import {
  SENSITIVITY_LEVELS,
  GENERIC_ACTIONS,
  CHALLENGE_ACTIONS,
  AUTO_BAN_ACTIONS,
  CAPTCHA_TYPES,
  ANTI_REPLAY_MODES,
  BROWSER_SIGN_ACTIONS,
} from "./protection-model";

/**
 * 综合防护 Tab 的表单状态：blob 字段（cc_rules 等）以后端展开后的
 * JSON 文本形式编辑，保存前 JSON.parse 校验。
 */
type GeneralForm = ProtectionSettings & {
  cc_rules_text: string;
  owasp_modules_text: string;
  owasp_rules_config_text: string;
  cve_rules_config_text: string;
  skip_path_by_phase_text: string;
};

/** blob 字段名与其表单文本键的对应关系 */
const BLOB_TEXT_KEYS = [
  ["cc_rules", "cc_rules_text"],
  ["owasp_modules", "owasp_modules_text"],
  ["owasp_rules_config", "owasp_rules_config_text"],
  ["cve_rules_config", "cve_rules_config_text"],
  ["skip_path_by_phase", "skip_path_by_phase_text"],
] as const;

function blobToText(v: unknown): string {
  return JSON.stringify(v ?? (Array.isArray(v) ? [] : {}), null, 2);
}

function buildForm(cfg: ProtectionSettings): GeneralForm {
  return {
    ...cfg,
    cc_rules_text: blobToText(cfg.cc_rules),
    owasp_modules_text: blobToText(cfg.owasp_modules),
    owasp_rules_config_text: blobToText(cfg.owasp_rules_config),
    cve_rules_config_text: blobToText(cfg.cve_rules_config),
    skip_path_by_phase_text: blobToText(cfg.skip_path_by_phase),
  };
}

/** phase 键白名单，见 internal/store/protection.go skipPathPhaseKeys（L350-360） */
const SKIP_PHASE_KEYS =
  "ip_reputation / anti_replay / acl / lua_pre / owasp_default / cve_detection / bot_detection / browser_sign / rate_limit";

export function GeneralPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<ProtectionSettings>(
    useCallback(() => apiGet<ProtectionSettings>("/protection-settings"), []),
  );
  const [form, setForm] = useState<GeneralForm | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setForm(buildForm(data));
  }, [data]);

  const patch = useCallback(
    <K extends keyof GeneralForm>(key: K, value: GeneralForm[K]) => {
      setForm((f) => (f ? { ...f, [key]: value } : f));
    },
    [],
  );

  async function save() {
    if (!form) return;
    // blob 字段先解析校验，失败立即提示并中止保存
    const blobs: Record<string, unknown> = {};
    for (const [field, textKey] of BLOB_TEXT_KEYS) {
      try {
        blobs[field] = JSON.parse(form[textKey]);
      } catch {
        showError(t("protection.saveFailed"), t("protection.invalidJson", { field }));
        return;
      }
    }
    const { cc_rules_text: _c, owasp_modules_text: _o, owasp_rules_config_text: _r, cve_rules_config_text: _v, skip_path_by_phase_text: _s, ...rest } = form;
    const payload = { ...rest, ...blobs };
    setSaving(true);
    try {
      await apiPost("/protection-settings", payload);
      showSuccess(t("protection.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (loading && !form) return <CardSkeleton height="h-96" />;
  if (!form) return null;

  const sensitivityOptions = localizeOptions(SENSITIVITY_LEVELS, t);
  const genericActions = localizeOptions(GENERIC_ACTIONS, t);
  const challengeActions = localizeOptions(CHALLENGE_ACTIONS, t);
  const autoBanActions = localizeOptions(AUTO_BAN_ACTIONS, t);
  const captchaTypes = localizeOptions(CAPTCHA_TYPES, t);
  const antiReplayModes = localizeOptions(ANTI_REPLAY_MODES, t);
  const browserSignActions = localizeOptions(BROWSER_SIGN_ACTIONS, t);

  return (
    <div className="flex flex-col gap-4">
      {/* 基础开关 */}
      <SectionCard
        title={t("protection.general.base.title")}
        description={t("protection.general.base.description")}
      >
        <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2 xl:grid-cols-3">
          <SwitchRow label={t("protection.general.base.bot")} value={form.bot_detection_enabled} onChange={(v) => patch("bot_detection_enabled", v)} />
          <SwitchRow label={t("protection.general.base.owasp")} value={form.builtin_owasp_enabled} onChange={(v) => patch("builtin_owasp_enabled", v)} />
          <SwitchRow label={t("protection.general.base.cve")} value={form.cve_enabled} onChange={(v) => patch("cve_enabled", v)} />
          <SwitchRow label={t("protection.general.base.captcha")} value={form.captcha_enabled} onChange={(v) => patch("captcha_enabled", v)} />
          <SwitchRow label={t("protection.general.base.antiReplay")} value={form.anti_replay_enabled} onChange={(v) => patch("anti_replay_enabled", v)} />
          <SwitchRow label={t("protection.general.base.shield")} value={form.shield_enabled} onChange={(v) => patch("shield_enabled", v)} />
          <SwitchRow label={t("protection.general.base.chain")} value={form.chain_enabled} onChange={(v) => patch("chain_enabled", v)} />
          <SwitchRow label={t("protection.general.base.escalation")} value={form.escalation_enabled} onChange={(v) => patch("escalation_enabled", v)} />
          <SwitchRow label={t("protection.general.base.waitingRoom")} value={form.waiting_room_enabled} onChange={(v) => patch("waiting_room_enabled", v)} />
          <SwitchRow label={t("protection.general.base.browserSign")} value={form.browser_sign_enabled} onChange={(v) => patch("browser_sign_enabled", v)} />
          <SwitchRow label={t("protection.general.base.autoBan")} value={form.auto_ban_enabled} onChange={(v) => patch("auto_ban_enabled", v)} />
          <SwitchRow label={t("protection.general.base.basicAuth")} value={form.basic_auth_enabled} onChange={(v) => patch("basic_auth_enabled", v)} />
          <SwitchRow label={t("protection.general.base.maintenance")} value={form.maintenance_global_enabled} onChange={(v) => patch("maintenance_global_enabled", v)} />
          <SwitchRow label={t("protection.general.base.ccRules")} value={form.cc_use_custom} onChange={(v) => patch("cc_use_custom", v)} />
        </div>
      </SectionCard>

      {/* 请求限流 */}
      <SectionCard title={t("protection.general.requestRateLimit.title")}>
        <SwitchRow label={t("protection.general.requestRateLimit.enabled")} value={form.request_ratelimit_enabled} onChange={(v) => patch("request_ratelimit_enabled", v)} />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <NumberField label={t("protection.field.window")} value={form.request_ratelimit_window} onChange={(v) => patch("request_ratelimit_window", v)} min={0} />
          <NumberField label={t("protection.general.requestRateLimit.max")} value={form.request_ratelimit_max} onChange={(v) => patch("request_ratelimit_max", v)} min={0} />
          <SelectRow label={t("protection.field.action")} value={form.request_ratelimit_action} onChange={(v) => patch("request_ratelimit_action", v)} options={genericActions} />
        </div>
      </SectionCard>

      {/* 错误限流 */}
      <SectionCard
        title={t("protection.general.errorRateLimit.title")}
        description={t("protection.general.errorRateLimit.description")}
      >
        <SwitchRow label={t("protection.general.errorRateLimit.enabled")} value={form.error_ratelimit_enabled} onChange={(v) => patch("error_ratelimit_enabled", v)} />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <NumberField label={t("protection.field.window")} value={form.error_ratelimit_window} onChange={(v) => patch("error_ratelimit_window", v)} min={0} />
          <NumberField label={t("protection.general.errorRateLimit.max")} value={form.error_ratelimit_max} onChange={(v) => patch("error_ratelimit_max", v)} min={0} />
          <SelectRow label={t("protection.field.action")} value={form.error_ratelimit_action} onChange={(v) => patch("error_ratelimit_action", v)} options={genericActions} />
        </div>
        <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-3">
          <SwitchRow label={t("protection.general.errorRateLimit.count4xx")} value={form.error_ratelimit_count_4xx} onChange={(v) => patch("error_ratelimit_count_4xx", v)} />
          <SwitchRow label={t("protection.general.errorRateLimit.count5xx")} value={form.error_ratelimit_count_5xx} onChange={(v) => patch("error_ratelimit_count_5xx", v)} />
          <SwitchRow label={t("protection.general.errorRateLimit.countBlock")} value={form.error_ratelimit_count_block} onChange={(v) => patch("error_ratelimit_count_block", v)} />
        </div>
      </SectionCard>

      {/* OWASP / CVE */}
      <SectionCard title={t("protection.general.owaspCve.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <SelectRow label={t("protection.general.owaspCve.owaspSensitivity")} value={form.builtin_owasp_sensitivity} onChange={(v) => patch("builtin_owasp_sensitivity", v)} options={sensitivityOptions} />
          <SelectRow label={t("protection.general.owaspCve.owaspAction")} value={form.builtin_owasp_on_hit} onChange={(v) => patch("builtin_owasp_on_hit", v)} options={genericActions} />
          <SelectRow label={t("protection.general.owaspCve.cveAction")} value={form.cve_action} onChange={(v) => patch("cve_action", v)} options={genericActions} />
        </div>
        <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2">
          <SwitchRow label={t("protection.general.owaspCve.autoDropCritical")} value={form.cve_auto_drop_critical} onChange={(v) => patch("cve_auto_drop_critical", v)} />
          <SwitchRow label={t("protection.general.owaspCve.autoDropHigh")} value={form.cve_auto_drop_high} onChange={(v) => patch("cve_auto_drop_high", v)} />
        </div>
      </SectionCard>

      {/* 验证码 / 质询 */}
      <SectionCard title={t("protection.general.challenge.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <SelectRow label={t("protection.general.challenge.captchaType")} value={form.captcha_type} onChange={(v) => patch("captcha_type", v)} options={captchaTypes} />
          <SelectRow label={t("protection.general.challenge.challengeAction")} value={form.challenge_action} onChange={(v) => patch("challenge_action", v)} options={challengeActions} hint={t("protection.general.challenge.challengeActionHint")} />
          <SelectRow label={t("protection.general.challenge.cookieMode")} value={form.anti_replay_cookie_mode || "standard"} onChange={(v) => patch("anti_replay_cookie_mode", v)} options={antiReplayModes} />
          <NumberField label={t("protection.general.challenge.captchaTimeout")} value={form.captcha_timeout} onChange={(v) => patch("captcha_timeout", v)} />
          <NumberField label={t("protection.general.challenge.passTtl")} value={form.captcha_pass_ttl} onChange={(v) => patch("captcha_pass_ttl", v)} />
        </div>
      </SectionCard>

      {/* 5 秒盾参数 */}
      <SectionCard title={t("protection.general.shield.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <NumberField label={t("protection.general.shield.difficulty")} value={form.shield_difficulty} onChange={(v) => patch("shield_difficulty", v)} min={1} />
          <NumberField label={t("protection.general.shield.timeout")} value={form.shield_timeout_secs} onChange={(v) => patch("shield_timeout_secs", v)} />
          <NumberField label={t("protection.general.shield.autoStartDelay")} value={form.shield_auto_start_delay} onChange={(v) => patch("shield_auto_start_delay", v)} />
          <NumberField label={t("protection.general.shield.maxRetries")} value={form.shield_max_retries} onChange={(v) => patch("shield_max_retries", v)} />
          <NumberField label={t("protection.general.shield.envStrictness")} value={form.shield_env_strictness} onChange={(v) => patch("shield_env_strictness", v)} min={0} />
        </div>
        <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2 xl:grid-cols-3">
          <SwitchRow label={t("protection.general.shield.requireHttp2")} value={form.shield_require_http2} onChange={(v) => patch("shield_require_http2", v)} />
          <SwitchRow label={t("protection.general.shield.requireHttp3")} value={form.shield_require_http3} onChange={(v) => patch("shield_require_http3", v)} />
          <SwitchRow label={t("protection.general.shield.allowHttp1")} value={form.shield_allow_http1} onChange={(v) => patch("shield_allow_http1", v)} />
          <SwitchRow label={t("protection.general.shield.jsChallenge")} value={form.shield_enable_js_challenge} onChange={(v) => patch("shield_enable_js_challenge", v)} />
          <SwitchRow label={t("protection.general.shield.envCheck")} value={form.shield_enable_env_check} onChange={(v) => patch("shield_enable_env_check", v)} />
          <SwitchRow label={t("protection.general.shield.devtools")} value={form.shield_enable_devtools} onChange={(v) => patch("shield_enable_devtools", v)} />
        </div>
      </SectionCard>

      {/* 自动封禁 */}
      <SectionCard title={t("protection.general.autoBan.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <NumberField label={t("protection.general.autoBan.threshold")} value={form.auto_ban_threshold} onChange={(v) => patch("auto_ban_threshold", v)} />
          <NumberField label={t("protection.general.autoBan.window")} value={form.auto_ban_window} onChange={(v) => patch("auto_ban_window", v)} />
          <NumberField label={t("protection.general.autoBan.duration")} value={form.auto_ban_duration} onChange={(v) => patch("auto_ban_duration", v)} />
          <SelectRow
            label={t("protection.general.autoBan.action")}
            value={form.auto_ban_action}
            onChange={(v) => patch("auto_ban_action", v)}
            options={autoBanActions}
          />
        </div>
      </SectionCard>

      {/* 浏览器签名 */}
      <SectionCard title={t("protection.general.browserSign.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <NumberField label={t("protection.general.browserSign.ttl")} value={form.browser_sign_ttl} onChange={(v) => patch("browser_sign_ttl", v)} />
          <SelectRow label={t("protection.general.browserSign.action")} value={form.browser_sign_action} onChange={(v) => patch("browser_sign_action", v)} options={browserSignActions} />
        </div>
      </SectionCard>

      {/* Basic Auth / 登录安全 */}
      <SectionCard
        title={t("protection.general.basicAuth.title")}
        description={t("protection.general.basicAuth.description")}
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <TextFieldRow label={t("protection.general.basicAuth.username")} value={form.basic_auth_username} onChange={(v) => patch("basic_auth_username", v)} placeholder={t("protection.general.basicAuth.usernamePlaceholder")} />
          <NumberField label={t("protection.general.basicAuth.minPasswordLength")} value={form.login_min_password_length} onChange={(v) => patch("login_min_password_length", v)} />
          <NumberField label={t("protection.general.basicAuth.maxAttempts")} value={form.login_max_attempts} onChange={(v) => patch("login_max_attempts", v)} />
          <NumberField label={t("protection.general.basicAuth.lockoutMinutes")} value={form.login_lockout_minutes} onChange={(v) => patch("login_lockout_minutes", v)} />
        </div>
      </SectionCard>

      {/* 维护页 */}
      <SectionCard title={t("protection.general.maintenance.title")}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <NumberField label={t("protection.general.maintenance.status")} value={form.maintenance_global_status} onChange={(v) => patch("maintenance_global_status", v)} />
        </div>
        <TextFieldRow label={t("protection.general.maintenance.html")} value={form.maintenance_global_html} onChange={(v) => patch("maintenance_global_html", v)} placeholder={t("protection.general.maintenance.htmlPlaceholder")} />
      </SectionCard>

      {/* CC 规则 */}
      <SectionCard
        title={t("protection.general.cc.title")}
        description={t("protection.general.cc.description")}
      >
        <SwitchRow label={t("protection.general.cc.enabled")} value={form.cc_use_custom} onChange={(v) => patch("cc_use_custom", v)} />
        <JsonTextArea label={t("protection.general.cc.rules")} value={form.cc_rules_text} onChange={(v) => patch("cc_rules_text", v)} />
      </SectionCard>

      {/* OWASP 模块覆盖与规则级配置 */}
      <SectionCard
        title={t("protection.general.owaspModules.title")}
        description={t("protection.general.owaspModules.description")}
      >
        <JsonTextArea
          label={t("protection.general.owaspModules.modules")}
          value={form.owasp_modules_text}
          onChange={(v) => patch("owasp_modules_text", v)}
          hint={t("protection.general.owaspModules.modulesHint", {
            levels: SENSITIVITY_LEVELS.map((l) => l.key).join(" / "),
          })}
        />
        <JsonTextArea label={t("protection.general.owaspModules.rulesConfig")} value={form.owasp_rules_config_text} onChange={(v) => patch("owasp_rules_config_text", v)} />
        <JsonTextArea label={t("protection.general.owaspModules.cveRulesConfig")} value={form.cve_rules_config_text} onChange={(v) => patch("cve_rules_config_text", v)} />
      </SectionCard>

      {/* Pipeline 跳过路径 */}
      <SectionCard
        title={t("protection.general.skipPath.title")}
        description={t("protection.general.skipPath.description")}
      >
        <JsonTextArea
          label={t("protection.general.skipPath.label")}
          value={form.skip_path_by_phase_text}
          onChange={(v) => patch("skip_path_by_phase_text", v)}
          hint={t("protection.general.skipPath.hint", { phases: SKIP_PHASE_KEYS })}
        />
      </SectionCard>

      <div className="flex justify-end">
        <Button variant="primary" isPending={saving} onPress={save}>
          {t("protection.general.save")}
        </Button>
      </div>
    </div>
  );
}
