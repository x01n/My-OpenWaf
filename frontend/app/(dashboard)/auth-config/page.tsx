"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { IconKey, IconUser, IconRefresh, IconShield } from "@tabler/icons-react";
import { useProtectionSettings, useProtectionSettingsUpdate } from "@/hooks/use-api";
import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";

export default function AuthConfigPage() {
  const { t } = useTranslation();
  const { data: settings, isLoading } = useProtectionSettings();
  const updateSettings = useProtectionSettingsUpdate();

  const [localSettings, setLocalSettings] = useState<Record<string, any>>({}); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (settings?.basic_auth_username) {
      setUsername(settings.basic_auth_username);
    }
  }, [settings?.basic_auth_username]);

  const getValue = (key: string, defaultValue: any = false) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    return localSettings[key] !== undefined ? localSettings[key] : (settings?.[key] ?? defaultValue);
  };

  const handleToggle = (key: string) => {
    setLocalSettings((prev) => ({ ...prev, [key]: !getValue(key) }));
  };

  const handleSave = async () => {
    try {
      const payload: Record<string, any> = { ...settings, ...localSettings }; // eslint-disable-line @typescript-eslint/no-explicit-any
      if (username) payload.basic_auth_username = username;
      if (password) payload.basic_auth_password = password;
      await updateSettings.execute(payload);
      toast.success(t("authConfig.saveSuccess"));
      setPassword("");
    } catch {
      toast.error(t("authConfig.saveFailed"));
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <IconKey className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-semibold">{t("authConfig.title")}</h1>
        </div>
        <Card className="h-64 animate-pulse bg-muted" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconKey className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-semibold">{t("authConfig.title")}</h1>
        </div>
        <Button className="bg-primary hover:bg-primary/90" onClick={handleSave}>
          <IconRefresh className="mr-1 h-4 w-4" />
          {t("authConfig.saveConfig")}
        </Button>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconShield className="h-5 w-5 text-primary" />
            {t("authConfig.basicAuth")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Switch
              checked={getValue("basic_auth_enabled", false)}
              onCheckedChange={() => handleToggle("basic_auth_enabled")}
              id="basic_auth"
            />
            <div>
              <Label htmlFor="basic_auth" className="cursor-pointer">{t("authConfig.enableBasicAuth")}</Label>
              <p className="text-xs text-muted-foreground">{t("authConfig.basicAuthDesc")}</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("common.username")}</Label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t("authConfig.usernamePlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("common.password")}</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("authConfig.passwordPlaceholder")}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconUser className="h-5 w-5 text-primary" />
            {t("authConfig.sessionManagement")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t("authConfig.sessionTimeout")}</Label>
            <Select defaultValue="3600">
              <SelectTrigger className="w-64">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="300">{t("authConfig.minutes5")}</SelectItem>
                <SelectItem value="900">{t("authConfig.minutes15")}</SelectItem>
                <SelectItem value="1800">{t("authConfig.minutes30")}</SelectItem>
                <SelectItem value="3600">{t("authConfig.hour1")}</SelectItem>
                <SelectItem value="7200">{t("authConfig.hours2")}</SelectItem>
                <SelectItem value="86400">{t("authConfig.hours24")}</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">{t("authConfig.sessionTimeoutDesc")}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
