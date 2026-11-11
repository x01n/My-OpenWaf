"use client";

/**
 * 站点高级配置：缓存、维护模式、拦截页、动态保护与自定义 CC 规则。
 *
 * 字段语义见 internal/store/site.go；动态保护三态与 TTL 约束见
 * internal/waf/dynamic（最大 1800 秒）。
 */

import { SimpleSelect, ToggleSwitch } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import {
  DYNAMIC_JS_MODE_OPTIONS,
  localizeOptions,
  type SiteAdvancedDraft,
} from "./site-advanced-model";
import {
  FieldRow,
  Section,
  TextAreaRow,
  TextRow,
  TriStateBool,
} from "./form-primitives";

type SetDraft = (patch: Partial<SiteAdvancedDraft>) => void;

/** 缓存分区 */
export function CacheSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.cache.title")}
      description={t("siteDetail.advanced.cache.description")}
    >
      <ToggleSwitch isSelected={draft.cache_enabled} onChange={(v) => set({ cache_enabled: v })}>
        {t("siteDetail.advanced.cache.enabled")}
      </ToggleSwitch>
      <div className="grid gap-3 md:grid-cols-2">
        <TextRow
          label={t("siteDetail.advanced.cache.ttl")}
          type="number"
          value={String(draft.cache_default_ttl)}
          onChange={(v) => set({ cache_default_ttl: Number(v) || 0 })}
          hint={t("siteDetail.advanced.cache.ttlHint")}
        />
      </div>
      <TextAreaRow
        label={t("siteDetail.advanced.cache.rules")}
        value={draft.cache_rules}
        onChange={(v) => set({ cache_rules: v })}
        placeholder='[{"pattern":"/static/*","ttl":3600}]'
        hint={t("siteDetail.advanced.cache.rulesHint")}
        rows={4}
      />
    </Section>
  );
}

/** 维护模式与拦截页分区 */
export function MaintenanceSection({
  draft,
  set,
}: {
  draft: SiteAdvancedDraft;
  set: SetDraft;
}) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.maintenance.title")}
      description={t("siteDetail.advanced.maintenance.description")}
    >
      <ToggleSwitch
        isSelected={draft.maintenance_enabled}
        onChange={(v) => set({ maintenance_enabled: v })}
      >
        {t("siteDetail.advanced.maintenance.enabled")}
      </ToggleSwitch>
      <div className="grid gap-3 md:grid-cols-2">
        <TextRow
          label={t("siteDetail.advanced.maintenance.status")}
          type="number"
          value={String(draft.maintenance_status)}
          onChange={(v) => set({ maintenance_status: Number(v) || 0 })}
          hint={t("siteDetail.advanced.maintenance.statusHint")}
        />
        <TextRow
          label={t("siteDetail.advanced.maintenance.blockStatus")}
          type="number"
          value={String(draft.block_status)}
          onChange={(v) => set({ block_status: Number(v) || 0 })}
          hint={t("siteDetail.advanced.maintenance.blockStatusHint")}
        />
      </div>
      <TextAreaRow
        label={t("siteDetail.advanced.maintenance.html")}
        value={draft.maintenance_html}
        onChange={(v) => set({ maintenance_html: v })}
        placeholder={t("siteDetail.advanced.maintenance.htmlPlaceholder")}
        hint={t("siteDetail.advanced.maintenance.htmlHint")}
        rows={4}
      />
      <TextAreaRow
        label={t("siteDetail.advanced.maintenance.blockHtml")}
        value={draft.block_html}
        onChange={(v) => set({ block_html: v })}
        placeholder={t("siteDetail.advanced.maintenance.blockHtmlPlaceholder")}
        hint={t("siteDetail.advanced.maintenance.blockHtmlHint")}
        rows={4}
      />
    </Section>
  );
}

/** 动态保护分区 */
export function DynamicProtectionSection({
  draft,
  set,
}: {
  draft: SiteAdvancedDraft;
  set: SetDraft;
}) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.dynamic.title")}
      description={t("siteDetail.advanced.dynamic.description")}
    >
      <div className="grid gap-3 md:grid-cols-2">
        <TriStateBool
          label={t("siteDetail.advanced.dynamic.enabled")}
          value={draft.dynamic_protection_enabled}
          onChange={(v) => set({ dynamic_protection_enabled: v })}
        />
        <TriStateBool
          label={t("siteDetail.advanced.dynamic.html")}
          value={draft.dynamic_html_enabled}
          onChange={(v) => set({ dynamic_html_enabled: v })}
        />
        <TriStateBool
          label={t("siteDetail.advanced.dynamic.js")}
          value={draft.dynamic_js_enabled}
          onChange={(v) => set({ dynamic_js_enabled: v })}
        />
        <FieldRow
          label={t("siteDetail.advanced.dynamic.jsMode")}
          hint={t("siteDetail.advanced.dynamic.jsModeHint")}
        >
          <SimpleSelect<string>
            value={draft.dynamic_js_mode}
            onChange={(v) => set({ dynamic_js_mode: v })}
            label={t("siteDetail.advanced.dynamic.jsMode")}
            className="w-full"
            options={localizeOptions(DYNAMIC_JS_MODE_OPTIONS, t)}
          />
        </FieldRow>
        <TextRow
          label={t("siteDetail.advanced.dynamic.decryptTtl")}
          type="number"
          value={draft.dynamic_decrypt_cache_ttl === null ? "" : String(draft.dynamic_decrypt_cache_ttl)}
          onChange={(v) => set({ dynamic_decrypt_cache_ttl: v.trim() === "" ? null : Number(v) || 0 })}
          hint={t("siteDetail.advanced.dynamic.decryptTtlHint")}
        />
      </div>
      <TextAreaRow
        label={t("siteDetail.advanced.dynamic.jsPaths")}
        value={draft.dynamic_js_paths}
        onChange={(v) => set({ dynamic_js_paths: v })}
        placeholder='["/checkout/*","/login"]'
        hint={t("siteDetail.advanced.dynamic.jsPathsHint")}
        rows={3}
      />
    </Section>
  );
}

/** 自定义 CC 规则分区 */
export function CCRulesSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.cc.title")}
      description={t("siteDetail.advanced.cc.description")}
    >
      <TriStateBool
        label={t("siteDetail.advanced.cc.useCustom")}
        value={draft.cc_use_custom}
        onChange={(v) => set({ cc_use_custom: v })}
      />
      <TextAreaRow
        label={t("siteDetail.advanced.cc.rules")}
        value={draft.cc_rules}
        onChange={(v) => set({ cc_rules: v })}
        placeholder={t("siteDetail.advanced.cc.rulesPlaceholder")}
        hint={t("siteDetail.advanced.cc.rulesHint")}
        rows={5}
      />
    </Section>
  );
}
