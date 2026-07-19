"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  IconWorld,
  IconNetwork,
  IconRocket,
  IconShieldLock,
  IconTrash,
  IconHelpCircle,
  IconDatabase,
} from "@tabler/icons-react";
import { useNetworkConfig, useTLSConfig, useLogConfig, useRedisConfig } from "@/hooks/use-api";
import { useNetworkConfigUpdate, useTLSConfigUpdate, useLogConfigUpdate, useRedisConfigUpdate } from "@/hooks/use-api";

export default function SettingsPage() {
  const { t } = useTranslation();
  const { data: networkConfig, isLoading: networkLoading } = useNetworkConfig();
  const { data: tlsConfig, isLoading: tlsLoading } = useTLSConfig();
  const { data: logConfig, isLoading: logLoading } = useLogConfig();

  const networkUpdate = useNetworkConfigUpdate();
  const tlsUpdate = useTLSConfigUpdate();
  const logUpdate = useLogConfigUpdate();

  const [localNetwork, setLocalNetwork] = useState<Record<string, any>>({}); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [localTLS, setLocalTLS] = useState<Record<string, any>>({}); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [localLog, setLocalLog] = useState<Record<string, any>>({}); // eslint-disable-line @typescript-eslint/no-explicit-any

  const getNetworkValue = (key: string, defaultValue: any = false) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    return localNetwork[key] !== undefined ? localNetwork[key] : (networkConfig?.[key] ?? defaultValue);
  };

  const getTLSValue = (key: string, defaultValue: any = "") => { // eslint-disable-line @typescript-eslint/no-explicit-any
    return localTLS[key] !== undefined ? localTLS[key] : (tlsConfig?.[key] ?? defaultValue);
  };

  const getLogValue = (key: string, defaultValue: any = "") => { // eslint-disable-line @typescript-eslint/no-explicit-any
    return localLog[key] !== undefined ? localLog[key] : (logConfig?.[key] ?? defaultValue);
  };

  const handleSaveNetwork = async () => {
    try {
      await networkUpdate.execute({ ...networkConfig, ...localNetwork });
      toast.success(t("settings.networkSaveSuccess"));
    } catch {
      toast.error(t("settings.networkSaveFailed"));
    }
  };

  const handleSaveTLS = async () => {
    try {
      await tlsUpdate.execute({ ...tlsConfig, ...localTLS });
      toast.success(t("settings.tlsSaveSuccess"));
    } catch {
      toast.error(t("settings.tlsSaveFailed"));
    }
  };

  const handleSaveLog = async () => {
    try {
      await logUpdate.execute({ ...logConfig, ...localLog });
      toast.success(t("settings.logSaveSuccess"));
    } catch {
      toast.error(t("settings.logSaveFailed"));
    }
  };

  const toggleNetwork = (key: string) => {
    setLocalNetwork((prev) => ({ ...prev, [key]: !getNetworkValue(key) }));
  };

  const switchItems = [
    { key: "listen_ipv6", label: t("settings.listenIpv6"), desc: t("settings.listenIpv6Desc") },
    { key: "enable_http10", label: t("settings.enableHttp10"), desc: t("settings.enableHttp10Desc") },
    { key: "enable_http2", label: t("settings.enableHttp2"), desc: t("settings.enableHttp2Desc") },
    { key: "http_redirect_https", label: t("settings.httpRedirectHttps"), desc: t("settings.httpRedirectHttpsDesc") },
    { key: "enable_hsts", label: t("settings.enableHsts"), desc: t("settings.enableHstsDesc") },
    { key: "proxy_host_header", label: t("settings.proxyHostHeader"), desc: t("settings.proxyHostHeaderDesc") },
    { key: "proxy_x_forwarded", label: t("settings.proxyXForwarded"), desc: t("settings.proxyXForwardedDesc") },
    { key: "enable_gzip", label: t("settings.enableGzip"), desc: t("settings.enableGzipDesc") },
    { key: "enable_brotli", label: t("settings.enableBrotli"), desc: t("settings.enableBrotliDesc") },
    { key: "enable_sse", label: t("settings.enableSse"), desc: t("settings.enableSseDesc") },
    { key: "enable_ntlm", label: t("settings.enableNtlm"), desc: t("settings.enableNtlmDesc") },
    { key: "fallback_cert", label: t("settings.fallbackCert"), desc: t("settings.fallbackCertDesc") },
  ];

  const logRetentionOptions = [
    { value: "0", label: t("settings.noCleanup") },
    { value: "1", label: t("settings.days", { count: 1 }) },
    { value: "3", label: t("settings.days", { count: 3 }) },
    { value: "7", label: t("settings.days", { count: 7 }) },
    { value: "15", label: t("settings.days", { count: 15 }) },
    { value: "30", label: t("settings.days", { count: 30 }) },
  ];

  const tlsVersions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv2", "SSLv3"];

  const isLoading = networkLoading || tlsLoading || logLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-64 mt-1" />
        </div>
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-64 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("settings.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("settings.description")}</p>
        </div>
      </div>

      {/* Source IP */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconWorld className="h-5 w-5 text-primary" />
            {t("settings.sourceIp")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t("settings.ipMode")}</Label>
            <Select
              value={getNetworkValue("xff_mode", "xff")}
              onValueChange={(v) => setLocalNetwork((prev) => ({ ...prev, xff_mode: v }))}
              disabled={networkLoading}
            >
              <SelectTrigger className="w-64">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="xff">X-Forwarded-For</SelectItem>
                <SelectItem value="real_ip">X-Real-IP</SelectItem>
                <SelectItem value="direct">{t("settings.directConnect")}</SelectItem>
                <SelectItem value="custom">{t("settings.customHeader")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>{t("settings.trustedCidr")}</Label>
            <Input
              className="w-96"
              placeholder={t("settings.trustedIpsPlaceholder")}
              value={getNetworkValue("trusted_cidr", "")}
              onChange={(e) => setLocalNetwork((prev) => ({ ...prev, trusted_cidr: e.target.value }))}
              disabled={networkLoading}
            />
            <p className="text-xs text-muted-foreground">
              {t("settings.trustedCidrDesc")}
            </p>
          </div>
          <div className="flex justify-end">
            <Button
              onClick={handleSaveNetwork}
              disabled={networkLoading || networkUpdate.loading}

            >
              {networkUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Advanced */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconNetwork className="h-5 w-5 text-primary" />
            {t("settings.advanced")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {switchItems.map((item) => (
              <div
                key={item.key}
                className="flex items-start gap-3 rounded-lg border p-3"
              >
                <Switch
                  checked={getNetworkValue(item.key)}
                  onCheckedChange={() => toggleNetwork(item.key)}
                  id={item.key}
                  disabled={networkLoading}
                />
                <div className="space-y-0.5">
                  <Label htmlFor={item.key} className="cursor-pointer text-sm">
                    {item.label}
                  </Label>
                  <p className="text-xs text-muted-foreground">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex justify-end">
            <Button
              onClick={handleSaveNetwork}
              disabled={networkLoading || networkUpdate.loading}

            >
              {networkUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* HTTP/3 (QUIC) */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconRocket className="h-5 w-5 text-primary" />
            {t("settings.http3.title")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <Switch
              checked={getNetworkValue("http3_enabled")}
              onCheckedChange={() => toggleNetwork("http3_enabled")}
              id="http3_enabled"
              disabled={networkLoading}
            />
            <div className="space-y-0.5">
              <Label htmlFor="http3_enabled" className="cursor-pointer text-sm">
                {t("settings.http3.enableLabel")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("settings.http3.description")}
              </p>
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t("settings.http3.bindLabel")}</Label>
            <Input
              className="w-96"
              placeholder={t("settings.http3.bindPlaceholder")}
              value={getNetworkValue("http3_bind", "")}
              onChange={(e) =>
                setLocalNetwork((prev) => ({ ...prev, http3_bind: e.target.value }))
              }
              disabled={networkLoading || !getNetworkValue("http3_enabled")}
            />
            <p className="text-xs text-muted-foreground">
              {t("settings.http3.bindDescription")}
            </p>
          </div>
          <div className="flex justify-end">
            <Button
              onClick={handleSaveNetwork}
              disabled={networkLoading || networkUpdate.loading}

            >
              {networkUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* SSL Compliance */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconShieldLock className="h-5 w-5 text-primary" />
            {t("settings.sslCompliance")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center gap-1">
              <Label>{t("settings.sslVersion")}</Label>
              <IconHelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="flex flex-wrap gap-2">
              {tlsVersions.map((v) => {
                const selected = (getTLSValue("min_version", "TLSv1.2") === v) ||
                  (getTLSValue("max_version", "TLSv1.3") === v) ||
                  (tlsConfig?.cipher_suites || []).includes(v);
                return (
                  <Button
                    key={v}
                    variant={selected ? "default" : "outline"}
                    size="sm"
                    className="h-8 text-xs"
                    onClick={() => {
                      setLocalTLS((prev) => ({ ...prev, min_version: v }));
                    }}
                    disabled={tlsLoading}
                  >
                    {v}
                  </Button>
                );
              })}
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t("settings.cipherSuites")}</Label>
            <div className="flex items-center gap-2">
              <Input
                className="flex-1"
                placeholder={t("settings.tlsCipherPlaceholder")}
                value={getTLSValue("cipher_suites", "")}
                onChange={(e) => setLocalTLS((prev) => ({ ...prev, cipher_suites: e.target.value }))}
                disabled={tlsLoading}
              />
              <Button
                variant="outline"
                size="sm"
                className="h-9 shrink-0 text-xs"
                onClick={() => toast.info(t("settings.helpDev"))}
              >
                {t("settings.helpDocs")}
              </Button>
            </div>
          </div>
          <div className="flex justify-end">
            <Button
              onClick={handleSaveTLS}
              disabled={tlsLoading || tlsUpdate.loading}

            >
              {tlsUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Data Cleanup */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconTrash className="h-5 w-5 text-primary" />
            {t("settings.dataCleanup")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t("settings.logRetention")}</Label>
            <RadioGroup
              value={getLogValue("max_age", "7")}
              onValueChange={(v) => setLocalLog((prev) => ({ ...prev, max_age: v }))}
              className="flex flex-wrap gap-4"
              disabled={logLoading}
            >
              {logRetentionOptions.map((opt) => (
                <div key={opt.value} className="flex items-center gap-2">
                  <RadioGroupItem value={opt.value} id={`log-${opt.value}`} />
                  <Label htmlFor={`log-${opt.value}`} className="cursor-pointer text-sm">
                    {opt.label}
                  </Label>
                </div>
              ))}
            </RadioGroup>
            <p className="text-xs text-muted-foreground">
              {t("settings.logRetentionDesc")}
            </p>
          </div>
          <div className="flex justify-end">
            <Button
              onClick={handleSaveLog}
              disabled={logLoading || logUpdate.loading}

            >
              {logUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Redis Configuration */}
      <RedisConfigCard />
    </div>
  );
}

function RedisConfigCard() {
  const { t } = useTranslation();
  const { data: redisConfig, isLoading } = useRedisConfig();
  const redisUpdate = useRedisConfigUpdate();

  const [addr, setAddr] = useState("");
  const [password, setPassword] = useState("");
  const [db, setDb] = useState("0");
  const [initialized, setInitialized] = useState(false);

  if (!initialized && redisConfig) {
    setAddr(redisConfig.redis_addr ?? "");
    setPassword(redisConfig.redis_password ?? "");
    setDb(String(redisConfig.redis_db ?? 0));
    setInitialized(true);
  }

  const handleSave = async () => {
    try {
      await redisUpdate.execute({
        redis_addr: addr,
        redis_password: password || undefined,
        redis_db: parseInt(db, 10) || 0,
      });
      toast.success(t("settings.redisSaveSuccess"));
    } catch {
      toast.error(t("settings.redisSaveFailed"));
    }
  };

  if (isLoading) {
    return <Skeleton className="h-48 w-full" />;
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconDatabase className="h-5 w-5 text-primary" />
          {t("settings.redis")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>{t("settings.redisAddr")}</Label>
            <Input
              value={addr}
              onChange={(e) => setAddr(e.target.value)}
              placeholder="127.0.0.1:6379"
            />
            <p className="text-xs text-muted-foreground">{t("settings.redisAddrDesc")}</p>
          </div>
          <div className="space-y-2">
            <Label>{t("settings.redisPassword")}</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t("settings.redisPasswordPlaceholder")}
            />
          </div>
        </div>
        <div className="space-y-2">
          <Label>{t("settings.redisDb")}</Label>
          <Input
            type="number"
            min={0}
            max={15}
            value={db}
            onChange={(e) => setDb(e.target.value)}
            className="w-32"
          />
          <p className="text-xs text-muted-foreground">{t("settings.redisDbDesc")}</p>
        </div>
        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={redisUpdate.loading}>
            {redisUpdate.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
