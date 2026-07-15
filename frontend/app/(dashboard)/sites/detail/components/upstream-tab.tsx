"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { IconPlus, IconTrash, IconDeviceFloppy } from "@tabler/icons-react";
import { useSiteMutation } from "@/hooks/use-api";
import type { Site } from "@/lib/types";

interface UpstreamTabProps {
  site: Site;
}

export function UpstreamTab({ site }: UpstreamTabProps) {
  const { t } = useTranslation();
  const updateSite = useSiteMutation();

  const [upstreamUrls, setUpstreamUrls] = useState(site.upstream_urls || "");
  const [upstreamHost, setUpstreamHost] = useState(site.upstream_host || "");
  const [skipVerify, setSkipVerify] = useState(site.upstream_tls_skip_verify);
  const [serverName, setServerName] = useState(site.upstream_tls_server_name || "");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          upstream_urls: upstreamUrls,
          upstream_host: upstreamHost,
          upstream_tls_skip_verify: skipVerify,
          upstream_tls_server_name: serverName,
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
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.upstreamServer")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t("sites.detail.upstreamServer")}</Label>
            <Input
              value={upstreamUrls}
              onChange={(e) => setUpstreamUrls(e.target.value)}
              placeholder="http://127.0.0.1:8080, http://127.0.0.1:8081"
            />
            <p className="text-xs text-muted-foreground">
              {t("sites.form.upstreamUrlsHint")}
            </p>
          </div>

          <div className="space-y-2">
            <Label>{t("sites.form.upstreamHost")}</Label>
            <Input
              value={upstreamHost}
              onChange={(e) => setUpstreamHost(e.target.value)}
              placeholder={t("sites.form.upstreamHostPlaceholder")}
            />
          </div>

          <div className="space-y-4 rounded-lg border p-4">
            <h4 className="text-sm font-medium">{t("sites.detail.upstreamTls")}</h4>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>{t("sites.form.skipVerify")}</Label>
                <p className="text-xs text-muted-foreground">{t("sites.form.skipVerifyDesc")}</p>
              </div>
              <Switch checked={skipVerify} onCheckedChange={setSkipVerify} />
            </div>

            <div className="space-y-2">
              <Label>{t("sites.form.tlsServerName")}</Label>
              <Input
                value={serverName}
                onChange={(e) => setServerName(e.target.value)}
                placeholder={t("sites.form.tlsServerNamePlaceholder")}
              />
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={handleSave} disabled={saving}>
              <IconDeviceFloppy className="mr-1 h-4 w-4" />
              {saving ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
