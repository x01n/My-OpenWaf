"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useSiteMutation } from "@/hooks/use-api";
import type { Site } from "@/lib/types";

interface AdvancedTabProps {
  site: Site;
}

export function AdvancedTab({ site }: AdvancedTabProps) {
  const { t } = useTranslation();
  const updateSite = useSiteMutation();

  const [antiReplayEnabled, setAntiReplayEnabled] = useState(site.anti_replay_enabled);
  const [antiReplayTtl, setAntiReplayTtl] = useState(site.anti_replay_ttl);
  const [maintenanceEnabled, setMaintenanceEnabled] = useState(site.maintenance_enabled);
  const [maintenanceStatus, setMaintenanceStatus] = useState(site.maintenance_status);
  const [xffMode, setXffMode] = useState(site.xff_mode);
  const [trustedCidr, setTrustedCidr] = useState(site.trusted_cidr || "");
  const [preserveHost, setPreserveHost] = useState(site.preserve_original_host);
  const [saving, setSaving] = useState(false);

  const handleToggleAntiReplay = async (enabled: boolean) => {
    setAntiReplayEnabled(enabled);
    try {
      await updateSite.execute({ id: site.id, data: { anti_replay_enabled: enabled } });
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
      setAntiReplayEnabled(!enabled);
    }
  };

  const handleToggleMaintenance = async (enabled: boolean) => {
    setMaintenanceEnabled(enabled);
    try {
      await updateSite.execute({ id: site.id, data: { maintenance_enabled: enabled } });
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
      setMaintenanceEnabled(!enabled);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          anti_replay_enabled: antiReplayEnabled,
          anti_replay_ttl: antiReplayTtl,
          maintenance_enabled: maintenanceEnabled,
          maintenance_status: maintenanceStatus,
          xff_mode: xffMode,
          trusted_cidr: trustedCidr,
          preserve_original_host: preserveHost,
        },
      });
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* TLS 配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">TLS</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">{t("sites.detail.tls")}</span>
              <p className="font-medium">
                <Badge variant={site.tls_enabled ? "default" : "outline"} className="h-5 text-[10px]">
                  {site.tls_enabled ? "HTTPS" : "HTTP"}
                </Badge>
              </p>
            </div>
            {site.tls_enabled && (
              <>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.minTlsVersion")}</span>
                  <p className="font-medium">{site.min_tls_version || "TLS 1.2"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.maxTlsVersion")}</span>
                  <p className="font-medium">{site.max_tls_version || "TLS 1.3"}</p>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Anti-Replay */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Anti-Replay</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">{t("sites.detail.enableAntiReplay")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.antiReplayDesc")}</p>
            </div>
            <Switch checked={antiReplayEnabled} onCheckedChange={handleToggleAntiReplay} />
          </div>

          {antiReplayEnabled && (
            <div className="space-y-2">
              <Label className="text-sm">TTL</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  className="w-32"
                  value={antiReplayTtl}
                  onChange={(e) => setAntiReplayTtl(Math.max(1, Number(e.target.value) || 60))}
                />
                <span className="text-sm text-muted-foreground">{t("common.seconds")}</span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 维护模式 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.maintenanceMode")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">{t("sites.detail.enableMaintenance")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.maintenanceDesc")}</p>
            </div>
            <Switch checked={maintenanceEnabled} onCheckedChange={handleToggleMaintenance} />
          </div>

          {maintenanceEnabled && (
            <div className="space-y-2">
              <Label className="text-sm">{t("sites.detail.maintenanceStatus")}</Label>
              <Input
                type="number"
                min={100}
                max={599}
                className="w-32"
                value={maintenanceStatus}
                onChange={(e) => setMaintenanceStatus(Number(e.target.value) || 503)}
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* 网络配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.networkConfig")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label className="text-sm">{t("sites.detail.xffMode")}</Label>
            <select
              value={xffMode}
              onChange={(e) => setXffMode(e.target.value)}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="append">append</option>
              <option value="overwrite">overwrite</option>
              <option value="transparent">transparent</option>
            </select>
          </div>

          <div className="space-y-2">
            <Label className="text-sm">{t("sites.detail.trustedCidr")}</Label>
            <Input
              value={trustedCidr}
              onChange={(e) => setTrustedCidr(e.target.value)}
              placeholder="10.0.0.0/8, 172.16.0.0/12"
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">{t("sites.detail.preserveHost")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.preserveHostDesc")}</p>
            </div>
            <Switch checked={preserveHost} onCheckedChange={setPreserveHost} />
          </div>
        </CardContent>
      </Card>

      {/* 保存按钮 */}
      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saving}>
          <IconDeviceFloppy className="mr-1 h-4 w-4" />
          {saving ? t("common.saving") : t("common.save")}
        </Button>
      </div>
    </div>
  );
}
