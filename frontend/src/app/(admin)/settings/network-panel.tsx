"use client";

/**
 * 网络配置面板：GET/POST /network-config（internal/admin/system/network.go NetworkConfig）。
 */

import { Button, TextField, Input, Select, ListBox } from "@heroui/react";
import { useI18n, type MessageKey } from "@/i18n";
import {
  useConfigForm,
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  ToggleRow,
} from "./form-kit";
import type { NetworkConfig } from "@/lib/types/settings";

/** 网络类型值 → 语言键映射 */
const NETWORK_LABELS: Record<string, MessageKey> = {
  tcp: "settings.network.tcpDual",
  tcp4: "settings.network.tcp4Only",
  tcp6: "settings.network.tcp6Only",
};

export function NetworkPanel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<NetworkConfig>("/network-config");

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.network.title")}
      description={t("settings.network.description")}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <ToggleRow
          label="IPv6"
          description={t("settings.network.ipv6Desc")}
          checked={form.ipv6_enabled}
          onChange={(v) => setForm({ ...form, ipv6_enabled: v })}
        />
        <ToggleRow
          label="HTTP/2"
          description={t("settings.network.http2Desc")}
          checked={form.http2_enabled}
          onChange={(v) => setForm({ ...form, http2_enabled: v })}
        />
        <ToggleRow
          label="HTTP/3"
          description={t("settings.network.http3Desc")}
          checked={form.http3_enabled}
          onChange={(v) => setForm({ ...form, http3_enabled: v })}
        />
        <ToggleRow
          label={t("settings.network.http3PerPort")}
          description={t("settings.network.http3PerPortDesc")}
          checked={form.http3_per_port_enabled}
          onChange={(v) => setForm({ ...form, http3_per_port_enabled: v })}
        />
        <Field label={t("settings.network.http3Bind")} hint={t("settings.network.http3BindHint")}>
          <TextField aria-label={t("settings.network.http3Bind")}>
            <Input
              placeholder=":443"
              value={form.http3_bind}
              onChange={(e) => setForm({ ...form, http3_bind: e.target.value })}
            />
          </TextField>
        </Field>
        <Field label={t("settings.network.defaultNetwork")} hint="tcp / tcp4 / tcp6">
          <Select
            aria-label={t("settings.network.defaultNetwork")}
            selectedKey={form.default_network || "tcp"}
            onSelectionChange={(key) =>
              setForm({ ...form, default_network: (key as string) ?? "tcp" })
            }
          >
            <ListBox>
              {Object.entries(NETWORK_LABELS).map(([key, labelKey]) => {
                const label = t(labelKey);
                return (
                  <ListBox.Item key={key} id={key} textValue={label}>
                    {label}
                  </ListBox.Item>
                );
              })}
            </ListBox>
          </Select>
        </Field>
        <Field label={t("settings.network.defaultAlpn")} hint={t("settings.network.defaultAlpnHint")}>
          <TextField aria-label={t("settings.network.defaultAlpn")}>
            <Input
              placeholder="h3,h2,http/1.1"
              value={form.default_alpn}
              onChange={(e) => setForm({ ...form, default_alpn: e.target.value })}
            />
          </TextField>
        </Field>
      </div>
      <div className="flex justify-end">
        <Button variant="primary" isPending={saving} onPress={() => void save()}>
          {t("common.save")}
        </Button>
      </div>
    </PanelCard>
  );
}
