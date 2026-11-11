"use client";

/**
 * TLS 设置面板：
 * - GET/POST /tls-config（TLSDefaultConfig，network.go）
 * - GET /tls-cipher-suites 只读清单（secure / insecure / curves）
 */

import { useCallback, useState } from "react";
import { Button, TextField, Input, Chip } from "@heroui/react";
import { apiGet } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { SimpleSelect } from "@/components/ui/primitives";
import {
  useConfigForm,
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  ToggleRow,
} from "./form-kit";
import type {
  CipherSuiteInfo,
  CipherSuitesResponse,
  TLSDefaultConfig,
} from "@/lib/types/settings";

const TLS_VERSIONS = ["TLS10", "TLS11", "TLS12", "TLS13"];

export function TLSPanel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<TLSDefaultConfig>("/tls-config");
  const suites = useApi<CipherSuitesResponse>(
    useCallback(() => apiGet<CipherSuitesResponse>("/tls-cipher-suites"), []),
  );

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  return (
    <div className="flex flex-col gap-4">
      <PanelCard
        title={t("settings.tls.title")}
        description={t("settings.tls.description")}
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field label={t("settings.tls.minVersion")}>
            <SimpleSelect
              className="w-full"
              value={form.min_version}
              onChange={(v) => setForm({ ...form, min_version: v })}
              options={TLS_VERSIONS.map((v) => ({ key: v, label: v }))}
            />
          </Field>
          <Field label={t("settings.tls.maxVersion")}>
            <SimpleSelect
              className="w-full"
              value={form.max_version}
              onChange={(v) => setForm({ ...form, max_version: v })}
              options={TLS_VERSIONS.map((v) => ({ key: v, label: v }))}
            />
          </Field>
          <Field label="Cipher Suites" hint={t("settings.tls.cipherSuitesHint")}>
            <TextField aria-label="Cipher Suites">
              <Input
                placeholder={t("settings.tls.cipherSuitesPlaceholder")}
                value={form.cipher_suites}
                onChange={(e) => setForm({ ...form, cipher_suites: e.target.value })}
              />
            </TextField>
          </Field>
          <Field label="Curve Preferences" hint={t("settings.tls.curvePreferencesHint")}>
            <TextField aria-label={t("settings.tls.curvePreferencesAria")}>
              <Input
                value={form.curve_preferences}
                onChange={(e) => setForm({ ...form, curve_preferences: e.target.value })}
              />
            </TextField>
          </Field>
          <Field label={t("settings.tls.defaultAlpn")} hint={t("settings.tls.defaultAlpnHint")}>
            <TextField aria-label={t("settings.tls.defaultAlpn")}>
              <Input
                placeholder="h3,h2,http/1.1"
                value={form.default_alpn}
                onChange={(e) => setForm({ ...form, default_alpn: e.target.value })}
              />
            </TextField>
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <ToggleRow
            label={t("settings.tls.preferServerCiphers")}
            description={t("settings.tls.preferServerCiphersDesc")}
            checked={form.prefer_server_cipher_suites}
            onChange={(v) => setForm({ ...form, prefer_server_cipher_suites: v })}
          />
          <ToggleRow
            label="Session Ticket"
            checked={form.session_tickets_enabled}
            onChange={(v) => setForm({ ...form, session_tickets_enabled: v })}
          />
          <ToggleRow
            label={t("settings.tls.allow0rtt")}
            description={t("settings.tls.allow0rttDesc")}
            checked={form.allow_0rtt}
            onChange={(v) => setForm({ ...form, allow_0rtt: v, has_explicit_allow_0rtt: true })}
          />
          <ToggleRow
            label={t("settings.tls.selfSignedOnIp")}
            checked={form.self_signed_on_ip}
            onChange={(v) => setForm({ ...form, self_signed_on_ip: v })}
          />
        </div>
        <div className="flex justify-end">
          <Button
            variant="primary"
            isPending={saving}
            onPress={() =>
              void save({
                ...form,
                // 未显式配置 0-RTT 时提交 null，保持「继承 session_tickets_enabled」语义
                allow_0rtt: form.has_explicit_allow_0rtt ? form.allow_0rtt : null,
              })
            }
          >
            {t("common.save")}
          </Button>
        </div>
      </PanelCard>

      <CipherSuitesCard suites={suites} />
    </div>
  );
}

function CipherSuitesCard({ suites }: { suites: ReturnType<typeof useApi<CipherSuitesResponse>> }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<"secure" | "insecure">("secure");
  // CipherSuiteInfo 自带数字 id，可直接作为 DataTable 行标识
  const rows: CipherSuiteInfo[] = suites.data?.[tab] ?? [];

  const columns: DataTableColumn<CipherSuiteInfo>[] = [
    { header: t("settings.tls.suites.colName"), render: (r) => <span className="font-mono text-xs">{r.name}</span> },
    { header: "ID", render: (r) => <span className="tabular text-muted text-xs">{r.hex_id}</span> },
    {
      header: t("settings.tls.suites.colTlsVersions"),
      render: (r) => <span className="text-muted text-xs">{r.tls_versions.join(", ")}</span>,
    },
    {
      header: t("settings.tls.suites.colStatus"),
      render: (r) =>
        r.insecure ? (
          <Chip size="sm" variant="soft" color="danger">
            {t("settings.tls.suites.insecure")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="success">
            {t("settings.tls.suites.secure")}
          </Chip>
        ),
    },
  ];

  if (suites.error) return <PanelError message={suites.error} onRetry={suites.reload} />;
  if (suites.loading && !suites.data) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.tls.suites.title")}
      description={t("settings.tls.suites.description")}
    >
      <div className="flex items-center gap-2">
        <SimpleSelect
          value={tab}
          onChange={(v) => setTab(v)}
          options={[
            { key: "secure", label: t("settings.tls.suites.secureTab") },
            { key: "insecure", label: t("settings.tls.suites.insecureTab") },
          ]}
        />
        <div className="flex flex-wrap items-center gap-1.5">
          {(suites.data?.curves ?? []).map((c) => (
            <Chip key={c.id} size="sm" variant="soft" color="default">
              {c.name}
            </Chip>
          ))}
        </div>
      </div>
      <DataTable
        ariaLabel={t("settings.tls.suites.listAria")}
        columns={columns}
        rows={rows}
        loading={suites.loading}
        emptyMessage={t("settings.tls.suites.empty")}
      />
    </PanelCard>
  );
}
