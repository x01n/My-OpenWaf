"use client";

/**
 * OWASP 单条规则配置抽屉。
 *
 * 写入端点（router.go:326/327）：
 * - POST /api/v1/owasp-rules/:id/update
 * - POST /api/v1/owasp-rules/:id/reset
 * 动作校验在 owasp_rules.go validateOWASPPatch / validateOWASPStoredConfig。
 */

import { useEffect, useState } from "react";
import { Button, Input, TextArea, TextField, Chip } from "@heroui/react";
import { apiPost, ApiError } from "@/lib/api/client";
import type { OWASPRule, OWASPRulePatch } from "@/lib/types/owasp";
import { useI18n } from "@/i18n";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { SimpleSelect, ToggleSwitch} from "@/components/ui/primitives";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { showSuccess, showError } from "@/components/ui/toast-host";
import {
  ACTION_LABELS,
  CAPTCHA_TYPE_OPTIONS,
  CISCO_ASA_OPTIONS,
  OWASP_CATEGORY_LABELS,
  localizeOptions,
  SENSITIVITY_OPTIONS,
  translateLabel,
} from "@/lib/utils/rule-constants";

type FormState = {
  enabled: boolean;
  action: string;
  sensitivity: string;
  status_code: string;
  redirect_to: string;
  captcha_type: string;
  cisco_asa_mode: string;
  note: string;
  whitelist: string;
};

function toInt(value: string): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

function initialForm(rule: OWASPRule): FormState {
  return {
    enabled: rule.enabled,
    action: rule.action || "intercept",
    sensitivity: rule.sensitivity ?? "",
    status_code: rule.status_code ? String(rule.status_code) : "",
    redirect_to: rule.redirect_to ?? "",
    captcha_type: rule.captcha_type ?? "",
    cisco_asa_mode: rule.cisco_asa_mode ?? "",
    note: rule.note ?? "",
    whitelist: (rule.whitelist ?? []).join("\n"),
  };
}

function buildPatch(form: FormState): OWASPRulePatch {
  const statusCode = toInt(form.status_code);
  const whitelist = form.whitelist
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  return {
    enabled: form.enabled,
    action: form.action,
    sensitivity: form.sensitivity,
    status_code: statusCode,
    redirect_to: form.redirect_to.trim(),
    captcha_type: form.captcha_type,
    cisco_asa_mode: form.cisco_asa_mode,
    note: form.note,
    whitelist,
  };
}

export function OWASPRuleDrawer({
  state,
  rule,
  policyId,
  onSaved,
}: {
  state: ReturnType<typeof import("@heroui/react").useOverlayState>;
  rule: OWASPRule | null;
  policyId: number;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<FormState | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (state.isOpen && rule) setForm(initialForm(rule));
  }, [state.isOpen, rule]);

  if (!rule || !form) {
    return (
      <DetailDrawer state={state} title={t("owaspRules.drawer.pickTitle")}>
        <div className="text-muted text-sm">{t("owaspRules.drawer.pickRule")}</div>
      </DetailDrawer>
    );
  }

  // 早退后收窄只在当前作用域有效；嵌套函数统一读取快照，避免 TS 认为可能为 null
  const current = form;

  function validateLocal(): string | null {
    if (current.action === "redirect" && !current.redirect_to.trim()) {
      return t("owaspRules.error.redirectRequired");
    }
    const statusCode = toInt(current.status_code);
    if (statusCode !== 0 && (statusCode < 100 || statusCode > 599)) {
      return t("owaspRules.error.statusCodeRange");
    }
    const whitelist = current.whitelist
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s !== "");
    if (whitelist.length > 64) return t("owaspRules.error.whitelistMax");
    for (const item of whitelist) {
      if (item !== "*" && !item.startsWith("/")) {
        return t("owaspRules.error.whitelistPrefix", { item });
      }
      if (item !== "*" && !item.endsWith("*")) {
        return t("owaspRules.error.whitelistWildcard", { item });
      }
    }
    if (current.note.length > 4096) return t("owaspRules.error.noteMax");
    return null;
  }

  async function handleSave() {
    if (!rule) return;
    const error = validateLocal();
    if (error) {
      showError(t("owaspRules.saveFailed"), error);
      return;
    }
    setSaving(true);
    try {
      // policy_id 同时作为 body 字段提交；后端按 路径 > query > body > 默认策略 解析
      await apiPost(`/owasp-rules/${rule.id}/update`, {
        policy_id: policyId,
        ...buildPatch(current),
      });
      showSuccess(t("owaspRules.drawer.saved"));
      state.close();
      onSaved();
    } catch (err) {
      showError(t("owaspRules.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const effectiveLabel = (rule.default_action ?? rule.action ?? "").length
    ? translateLabel(t, ACTION_LABELS, rule.action)
    : "-";

  return (
    <DetailDrawer
      state={state}
      title={t("owaspRules.drawer.title", { name: rule.name, id: policyId })}
      description={
        rule.overridden
          ? t("owaspRules.drawer.overriddenDesc")
          : t("owaspRules.drawer.defaultDesc")
      }
      width="w-[560px]"
      footer={
        <>
          <ConfirmButton
            variant="danger"
            size="sm"
            title={t("owaspRules.resetTitle")}
            confirmText={t("owaspRules.drawer.resetConfirm", { name: rule.name, id: policyId })}
            successText={t("owaspRules.resetSuccess")}
            isDisabled={!rule.overridden}
            onConfirm={async () => {
              await apiPost(`/owasp-rules/${rule.id}/reset`, { policy_id: policyId });
              state.close();
              onSaved();
            }}
          >
            {t("owaspRules.resetTitle")}
          </ConfirmButton>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" isPending={saving} onPress={handleSave}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <div className="bg-surface rounded-xl border border-separator px-4 py-2">
        <DetailRow label={t("owaspRules.field.id")}>
          <span className="font-mono text-xs break-all">{rule.id}</span>
        </DetailRow>
        <DetailRow label={t("owaspRules.field.category")}>
          <Chip size="sm" variant="soft">
            {translateLabel(t, OWASP_CATEGORY_LABELS, rule.category)}
          </Chip>
        </DetailRow>
        <DetailRow label={t("owaspRules.field.score")}>
          <span className="tabular">{rule.score}</span>
        </DetailRow>
        <DetailRow label={t("owaspRules.field.catalogDefault")}>
          {rule.default_enabled ? (
            <span className="text-success">{t("common.enabled")}</span>
          ) : (
            <span className="text-muted">{t("common.disabled")}</span>
          )}
          <span className="text-muted">
            {" "}
            {t("owaspRules.drawer.catalogMeta", {
              action: rule.default_action,
              sensitivity: rule.default_sensitivity || t("owaspRules.drawer.inheritGlobal"),
            })}
          </span>
        </DetailRow>
        <DetailRow label={t("owaspRules.field.description")}>
          <span className="text-muted">{rule.description || "-"}</span>
        </DetailRow>
        <DetailRow label={t("owaspRules.field.pattern")}>
          <span className="block max-h-24 overflow-auto font-mono text-xs break-all">
            {rule.pattern || "-"}
          </span>
        </DetailRow>
      </div>

      <div className="text-sm font-medium">{t("owaspRules.drawer.sectionTitle")}</div>
      <ToggleSwitch
        isSelected={form.enabled}
        onChange={(enabled) => setForm((f) => (f ? { ...f, enabled } : f))}
      >
        {t("owaspRules.drawer.enableRule")}
      </ToggleSwitch>

      <SimpleSelect<string>
        value={form.action}
        onChange={(action) =>
          setForm((f) =>
            f
              ? {
                  ...f,
                  action,
                  redirect_to: action === "redirect" ? f.redirect_to : "",
                  captcha_type: action === "captcha_challenge" ? f.captcha_type : "",
                }
              : f,
          )
        }
        label={t("owaspRules.drawer.actionLabel")}
        className="w-full"
        options={[
          { key: "", label: t("owaspRules.drawer.actionInherit") },
          { key: "intercept", label: t("action.option.intercept") },
          { key: "drop", label: t("action.option.drop") },
          { key: "challenge", label: t("action.option.challenge") },
          { key: "captcha_challenge", label: t("action.option.captchaChallenge") },
          { key: "shield_challenge", label: t("action.option.shieldChallenge") },
          { key: "chain_challenge", label: t("action.option.chainChallenge") },
          { key: "redirect", label: t("owaspRules.drawer.actionRedirect") },
          { key: "rate_limit", label: t("action.option.rateLimit") },
          { key: "observe", label: t("action.option.observe") },
        ]}
      />

      <SimpleSelect<string>
        value={form.sensitivity}
        onChange={(sensitivity) => setForm((f) => (f ? { ...f, sensitivity } : f))}
        label={t("owaspRules.drawer.sensitivityLabel")}
        className="w-full"
        options={[{ key: "", label: t("owaspRules.drawer.sensitivityUnset") }, ...localizeOptions(SENSITIVITY_OPTIONS, t)]}
      />

      <SimpleSelect<string>
        value={form.cisco_asa_mode}
        onChange={(cisco_asa_mode) => setForm((f) => (f ? { ...f, cisco_asa_mode } : f))}
        label={t("owaspRules.drawer.ciscoLabel")}
        className="w-full"
        options={localizeOptions(CISCO_ASA_OPTIONS, t)}
      />

      <TextField aria-label={t("owaspRules.drawer.statusCodeAria")}>
        <Input
          type="number"
          placeholder={t("owaspRules.drawer.statusCodePlaceholder")}
          value={form.status_code}
          onChange={(e) => setForm((f) => (f ? { ...f, status_code: e.target.value } : f))}
        />
      </TextField>

      {form.action === "redirect" && (
        <TextField aria-label={t("owaspRules.drawer.redirectAria")}>
          <Input
            placeholder={t("owaspRules.drawer.redirectPlaceholder")}
            value={form.redirect_to}
            onChange={(e) => setForm((f) => (f ? { ...f, redirect_to: e.target.value } : f))}
          />
        </TextField>
      )}

      {form.action === "captcha_challenge" && (
        <SimpleSelect<string>
          value={form.captcha_type}
          onChange={(captcha_type) => setForm((f) => (f ? { ...f, captcha_type } : f))}
          label={t("owaspRules.drawer.captchaTypeLabel")}
          className="w-full"
          options={[{ key: "", label: t("owaspRules.drawer.captchaInherit") }, ...localizeOptions(CAPTCHA_TYPE_OPTIONS, t)]}
        />
      )}

      <div className="text-sm font-medium">{t("owaspRules.drawer.whitelistTitle")}</div>
      <TextArea
        aria-label={t("owaspRules.drawer.whitelistAria")}
        placeholder={t("owaspRules.drawer.whitelistPlaceholder")}
        value={form.whitelist}
        onChange={(e) => setForm((f) => (f ? { ...f, whitelist: e.target.value } : f))}
        className="min-h-[88px] font-mono text-xs"
      />

      <TextArea
        aria-label={t("owaspRules.drawer.noteAria")}
        placeholder={t("owaspRules.drawer.notePlaceholder")}
        value={form.note}
        onChange={(e) => setForm((f) => (f ? { ...f, note: e.target.value } : f))}
        className="min-h-[56px]"
      />

      <div className="text-muted text-xs">
        {t("owaspRules.drawer.footerMeta", {
          action: effectiveLabel,
          state: rule.overridden
            ? t("owaspRules.drawer.overriddenYes")
            : t("owaspRules.drawer.overriddenNo"),
        })}
      </div>
    </DetailDrawer>
  );
}
