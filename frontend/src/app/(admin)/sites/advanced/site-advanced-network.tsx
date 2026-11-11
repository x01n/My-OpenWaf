"use client";

/**
 * 站点高级配置：上游、TLS 运行参数与客户端 IP 识别。
 *
 * 字段语义见 internal/store/site.go 与 internal/admin/shared/site_upstreams.go。
 */

import { SimpleSelect, ToggleSwitch } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import {
  localizeOptions,
  type SiteAdvancedDraft,
} from "./site-advanced-model";
import {
  CLIENT_IP_HEADERS,
  NETWORK_OPTIONS,
  TLS_VERSION_OPTIONS,
  XFF_MODE_OPTIONS,
} from "./site-advanced-model";
import {
  FieldRow,
  Section,
  TextAreaRow,
  TextRow,
  TriStateText,
} from "./form-primitives";

type SetDraft = (patch: Partial<SiteAdvancedDraft>) => void;

/** 上游与请求体分区 */
export function UpstreamSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.upstream.title")}
      description={t("siteDetail.advanced.upstream.description")}
    >
      <div className="grid gap-3 md:grid-cols-2">
        <TextRow
          label={t("siteDetail.advanced.upstream.host")}
          value={draft.upstream_host}
          onChange={(v) => set({ upstream_host: v })}
          placeholder={t("siteDetail.advanced.upstream.hostPlaceholder")}
          hint={t("siteDetail.advanced.upstream.hostHint")}
        />
        <TextRow
          label={t("siteDetail.advanced.upstream.maxBody")}
          type="number"
          value={String(draft.max_body_bytes)}
          onChange={(v) => set({ max_body_bytes: Number(v) || 0 })}
          hint={t("siteDetail.advanced.upstream.maxBodyHint")}
        />
        <TextRow
          label={t("siteDetail.advanced.upstream.tlsServerName")}
          value={draft.upstream_tls_server_name}
          onChange={(v) => set({ upstream_tls_server_name: v })}
          placeholder={t("siteDetail.advanced.upstream.tlsServerNamePlaceholder")}
        />
      </div>
      <div className="flex flex-wrap items-center gap-6">
        <ToggleSwitch
          isSelected={draft.upstream_tls_skip_verify}
          onChange={(v) => set({ upstream_tls_skip_verify: v })}
        >
          {t("siteDetail.advanced.upstream.skipVerify")}
        </ToggleSwitch>
        <ToggleSwitch
          isSelected={draft.preserve_original_host}
          onChange={(v) => set({ preserve_original_host: v })}
        >
          {t("siteDetail.advanced.upstream.preserveHost")}
        </ToggleSwitch>
      </div>
    </Section>
  );
}

/** TLS 运行参数分区 */
export function TlsSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.tls.title")}
      description={t("siteDetail.advanced.tls.description")}
    >
      <div className="grid gap-3 md:grid-cols-2">
        <TriStateTlsVersion
          label={t("siteDetail.advanced.tls.minVersion")}
          value={draft.min_tls_version}
          onChange={(v) => set({ min_tls_version: v })}
        />
        <TriStateTlsVersion
          label={t("siteDetail.advanced.tls.maxVersion")}
          value={draft.max_tls_version}
          onChange={(v) => set({ max_tls_version: v })}
        />
        <FieldRow
          label={t("siteDetail.advanced.tls.network")}
          hint={t("siteDetail.advanced.tls.networkHint")}
        >
          <SimpleSelect<string>
            value={draft.network}
            onChange={(v) => set({ network: v })}
            label={t("siteDetail.advanced.tls.network")}
            className="w-44"
            options={localizeOptions(NETWORK_OPTIONS, t)}
          />
        </FieldRow>
        <TextRow
          label={t("siteDetail.advanced.tls.alpn")}
          value={draft.alpn}
          onChange={(v) => set({ alpn: v })}
          placeholder="h2,http/1.1"
          hint={t("siteDetail.advanced.tls.alpnHint")}
        />
      </div>
      <TextAreaRow
        label={t("siteDetail.advanced.tls.cipherSuites")}
        value={draft.cipher_suites}
        onChange={(v) => set({ cipher_suites: v })}
        placeholder='["TLS_AES_128_GCM_SHA256"]'
        hint={t("siteDetail.advanced.tls.cipherSuitesHint")}
        rows={3}
      />
    </Section>
  );
}

/** TLS 版本三态选择：继承项由 TriStateText 注入，选项去掉了空 key 占位。 */
function TriStateTlsVersion({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const { t } = useI18n();
  return (
    <TriStateText
      label={label}
      value={value}
      onChange={onChange}
      options={localizeOptions(TLS_VERSION_OPTIONS.slice(1), t)}
    />
  );
}

/** 客户端 IP 识别分区 */
export function ClientIPSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.clientIp.title")}
      description={t("siteDetail.advanced.clientIp.description")}
    >
      <div className="grid gap-3 md:grid-cols-2">
        <FieldRow label={t("siteDetail.advanced.clientIp.xffMode")}>
          <SimpleSelect<string>
            value={draft.xff_mode}
            onChange={(v) => set({ xff_mode: v })}
            label={t("siteDetail.advanced.clientIp.xffMode")}
            className="w-full"
            options={localizeOptions(XFF_MODE_OPTIONS, t)}
          />
        </FieldRow>
        <TextRow
          label={t("siteDetail.advanced.clientIp.trustedCidr")}
          value={draft.trusted_cidr}
          onChange={(v) => set({ trusted_cidr: v })}
          placeholder={t("siteDetail.advanced.clientIp.trustedCidrPlaceholder")}
          hint={t("siteDetail.advanced.clientIp.trustedCidrHint")}
        />
      </div>
      <TextAreaRow
        label={t("siteDetail.advanced.clientIp.headerOrder")}
        value={draft.client_ip_header_order}
        onChange={(v) => set({ client_ip_header_order: v })}
        placeholder='["x_forwarded_for","x_real_ip","forwarded"]'
        hint={t("siteDetail.advanced.clientIp.headerOrderHint", {
          values: CLIENT_IP_HEADERS.map((h) => h.key).join(" / "),
        })}
        rows={3}
      />
    </Section>
  );
}
