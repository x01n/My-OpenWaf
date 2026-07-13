"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useSiteMutation } from "@/hooks/use-api";
import type { Site } from "@/lib/types";

interface CacheTabProps {
  site: Site;
}

export function CacheTab({ site }: CacheTabProps) {
  const { t } = useTranslation();
  const updateSite = useSiteMutation();

  const [cacheEnabled, setCacheEnabled] = useState(site.cache_enabled);
  const [defaultTtl, setDefaultTtl] = useState(site.cache_default_ttl);
  const [saving, setSaving] = useState(false);

  const handleToggleCache = async (enabled: boolean) => {
    setCacheEnabled(enabled);
    try {
      await updateSite.execute({ id: site.id, data: { cache_enabled: enabled } });
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
      setCacheEnabled(!enabled);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          cache_enabled: cacheEnabled,
          cache_default_ttl: defaultTtl,
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
          <CardTitle className="text-base">{t("sites.detail.cacheConfig")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">{t("sites.detail.enableCache")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.cacheDesc")}</p>
            </div>
            <Switch checked={cacheEnabled} onCheckedChange={handleToggleCache} />
          </div>

          <div className="space-y-2">
            <Label className="text-sm">{t("sites.detail.defaultTtl")}</Label>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={0}
                className="w-32"
                value={defaultTtl}
                onChange={(e) => setDefaultTtl(Math.max(0, Number(e.target.value) || 0))}
                disabled={!cacheEnabled}
              />
              <span className="text-sm text-muted-foreground">{t("common.seconds")}</span>
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={handleSave} disabled={saving || !cacheEnabled}>
              <IconDeviceFloppy className="mr-1 h-4 w-4" />
              {saving ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
