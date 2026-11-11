"use client";

/**
 * 验证码 Tab：GET/POST /captcha/config 表单 + 「测试验证码」（POST /captcha/test）。
 * 字段取自 internal/admin/protect/captcha/captcha.go captchaConfigResponse（L16-33）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, Modal, useOverlayState } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton } from "@/components/ui/primitives";
import type { CaptchaConfig, CaptchaTestResult } from "@/lib/types/protection";
import { SectionCard, SwitchRow, NumberField, SelectRow } from "./field-controls";
import { CAPTCHA_TYPES } from "./protection-model";

/** 补全 data URI 前缀（后端 ToBase64 输出可能不含前缀，math 类型自带） */
function asDataUri(img: string): string {
  return img.startsWith("data:") ? img : `data:image/png;base64,${img}`;
}

export function CaptchaPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<CaptchaConfig>(
    useCallback(() => apiGet<CaptchaConfig>("/captcha/config"), []),
  );
  const [form, setForm] = useState<CaptchaConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<CaptchaTestResult | null>(null);
  const testState = useOverlayState();

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  const patch = useCallback(
    <K extends keyof CaptchaConfig>(key: K, value: CaptchaConfig[K]) => {
      setForm((f) => (f ? { ...f, [key]: value } : f));
    },
    [],
  );

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      await apiPost("/captcha/config", form);
      showSuccess(t("protection.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  /**
   * 生成一张测试验证码并弹窗预览。
   * 管理端无答案校验端点（/captcha/test 仅生成预览），此处仅做渲染验证。
   */
  async function test() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await apiPost<CaptchaTestResult>("/captcha/test", {});
      setTestResult(result);
      testState.open();
    } catch (err) {
      showError(t("protection.captcha.testFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setTesting(false);
    }
  }

  const captchaTypes = localizeOptions(CAPTCHA_TYPES, t);

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !form ? (
        <CardSkeleton height="h-96" />
      ) : form ? (
        <>
          <SectionCard title={t("protection.captcha.title")}>
            <SwitchRow label={t("protection.captcha.enabled")} value={form.captcha_enabled} onChange={(v) => patch("captcha_enabled", v)} />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <SelectRow label={t("protection.captcha.type")} value={form.captcha_type} onChange={(v) => patch("captcha_type", v)} options={captchaTypes} />
              <NumberField label={t("protection.captcha.timeout")} value={form.captcha_timeout} onChange={(v) => patch("captcha_timeout", v)} />
              <NumberField label={t("protection.captcha.passTtl")} value={form.captcha_pass_ttl} onChange={(v) => patch("captcha_pass_ttl", v)} />
            </div>
          </SectionCard>

          <SectionCard
            title={t("protection.captcha.shieldTitle")}
            description={t("protection.captcha.shieldDescription")}
          >
            <SwitchRow label={t("protection.captcha.shieldEnabled")} value={form.shield_enabled} onChange={(v) => patch("shield_enabled", v)} />
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

          <div className="flex justify-end gap-2">
            <Button variant="outline" isPending={testing} onPress={test}>
              {t("protection.captcha.test")}
            </Button>
            <Button variant="primary" isPending={saving} onPress={save}>
              {t("protection.captcha.save")}
            </Button>
          </div>
        </>
      ) : null}

      {/* 测试验证码预览弹窗 */}
      <Modal state={testState}>
        <Modal.Backdrop>
          <Modal.Container size="lg">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Heading>{t("protection.captcha.testTitle")}</Modal.Heading>
                <Modal.CloseTrigger />
              </Modal.Header>
              <Modal.Body>
                {testResult ? (
                  <div className="flex flex-col items-center gap-3">
                    <img
                      src={asDataUri(testResult.master_img)}
                      alt={t("protection.captcha.previewAlt", { prompt: testResult.prompt })}
                      style={{ width: testResult.width, maxWidth: "100%" }}
                      className="rounded-lg border border-separator"
                    />
                    <div className="text-sm">{testResult.prompt}</div>
                    <div className="text-muted grid w-full grid-cols-2 gap-2 text-xs md:grid-cols-4">
                      <div>{t("protection.captcha.typeLabel", { type: testResult.captcha_type })}</div>
                      <div className="tabular">
                        {t("protection.captcha.sizeLabel", {
                          width: testResult.width,
                          height: testResult.height,
                        })}
                      </div>
                      <div className="tabular">
                        {t("protection.captcha.timeoutLabel", { seconds: testResult.timeout })}
                      </div>
                      <div className="tabular">
                        {t("protection.captcha.passTtlLabel", { seconds: testResult.pass_ttl })}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-muted text-sm">{t("common.loading")}</div>
                )}
              </Modal.Body>
              <Modal.Footer>
                <Button variant="ghost" onPress={testState.close}>
                  {t("common.close")}
                </Button>
              </Modal.Footer>
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </div>
  );
}
