"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  IconShield,
  IconBolt,
  IconAlertTriangle,
  IconLoader2,
} from "@tabler/icons-react";
import {
  useProtectionSettings,
  useProtectionSettingsUpdate,
} from "@/hooks/use-api";
import {
  CCRulesEditor,
  CC_ACTION_OPTIONS,
  type CCRule,
} from "@/components/cc-rules-editor";

/**
 * 防护设置数据类型（已就绪，非空）。
 */
type ProtectionSettingsData = NonNullable<
  ReturnType<typeof useProtectionSettings>["data"]
>;

interface CCProtectionFormProps {
  settings: ProtectionSettingsData;
  /** 请求父组件重挂载本表单以还原为服务端初值 */
  onReset: () => void;
}

/**
 * CC 防护配置表单。
 *
 * 表单本地状态在挂载时通过 lazy 初始化从 settings 派生（不在 effect 中同步），
 * 因此取消操作由父组件通过 bump key 重挂载来还原初值，避免 effect 内 setState 的级联渲染。
 */
function CCProtectionForm({ settings, onReset }: CCProtectionFormProps) {
  const { t } = useTranslation();
  const updateSettings = useProtectionSettingsUpdate();

  const [requestRateLimitEnabled, setRequestRateLimitEnabled] = useState(
    () => settings.request_ratelimit_enabled ?? false
  );
  const [requestRateLimitWindow, setRequestRateLimitWindow] = useState(
    () => settings.request_ratelimit_window ?? 60
  );
  const [requestRateLimitMax, setRequestRateLimitMax] = useState(
    () => settings.request_ratelimit_max ?? 300
  );
  const [requestRateLimitAction, setRequestRateLimitAction] = useState(
    () => settings.request_ratelimit_action ?? "rate_limit"
  );

  const [errorRateLimitEnabled, setErrorRateLimitEnabled] = useState(
    () => settings.error_ratelimit_enabled ?? false
  );
  const [errorRateLimitWindow, setErrorRateLimitWindow] = useState(
    () => settings.error_ratelimit_window ?? 300
  );
  const [errorRateLimitMax, setErrorRateLimitMax] = useState(
    () => settings.error_ratelimit_max ?? 30
  );
  const [errorRateLimitCount4xx, setErrorRateLimitCount4xx] = useState(
    () => settings.error_ratelimit_count_4xx ?? true
  );
  const [errorRateLimitCount5xx, setErrorRateLimitCount5xx] = useState(
    () => settings.error_ratelimit_count_5xx ?? true
  );
  const [errorRateLimitCountBlock, setErrorRateLimitCountBlock] = useState(
    () => settings.error_ratelimit_count_block ?? false
  );
  const [errorRateLimitAction, setErrorRateLimitAction] = useState(
    () => settings.error_ratelimit_action ?? "rate_limit"
  );

  const [ccUseCustom, setCCUseCustom] = useState(() => settings.cc_use_custom ?? false);
  const [ccRules, setCCRules] = useState<CCRule[]>(() =>
    Array.isArray(settings.cc_rules) ? settings.cc_rules : []
  );

  const handleSave = async () => {
    try {
      await updateSettings.execute({
        request_ratelimit_enabled: requestRateLimitEnabled,
        request_ratelimit_window: requestRateLimitWindow,
        request_ratelimit_max: requestRateLimitMax,
        request_ratelimit_action: requestRateLimitAction,
        error_ratelimit_enabled: errorRateLimitEnabled,
        error_ratelimit_window: errorRateLimitWindow,
        error_ratelimit_max: errorRateLimitMax,
        error_ratelimit_count_4xx: errorRateLimitCount4xx,
        error_ratelimit_count_5xx: errorRateLimitCount5xx,
        error_ratelimit_count_block: errorRateLimitCountBlock,
        error_ratelimit_action: errorRateLimitAction,
        cc_use_custom: ccUseCustom,
        cc_rules: ccRules,
      });
      toast.success(t("ccProtection.saveSuccess"));
    } catch {
      toast.error(t("common.saveFailed"));
    }
  };

  const handleCancel = () => {
    toast.info(t("ccProtection.resetSuccess"));
    onReset();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <IconShield className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">{t("ccProtection.title")}</h1>
      </div>

      <Tabs defaultValue="rate-limit">
        <TabsList>
          <TabsTrigger value="rate-limit">
            <IconBolt className="mr-1.5 h-4 w-4" />
            {t("ccProtection.rateLimit")}
          </TabsTrigger>
          <TabsTrigger value="custom-rules">
            <IconAlertTriangle className="mr-1.5 h-4 w-4" />
            {t("ccProtection.customRules")}
          </TabsTrigger>
        </TabsList>

        {/* ==================== 频率限制 ==================== */}
        <TabsContent value="rate-limit" className="space-y-4">
          {/* 请求频率限制 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <IconBolt className="h-5 w-5 text-primary" />
                {t("ccProtection.requestRateLimit")}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <Switch
                  checked={requestRateLimitEnabled}
                  onCheckedChange={setRequestRateLimitEnabled}
                  id="req-rate-limit"
                />
                <Label htmlFor="req-rate-limit" className="cursor-pointer">
                  {t("ccProtection.enableRequestRateLimit")}
                </Label>
              </div>
              {requestRateLimitEnabled && (
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <div className="space-y-1.5">
                    <Label>{t("ccProtection.window")}</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        type="number"
                        min={1}
                        value={requestRateLimitWindow}
                        onChange={(e) =>
                          setRequestRateLimitWindow(Number(e.target.value))
                        }
                      />
                      <span className="text-sm text-muted-foreground">{t("ccProtection.seconds")}</span>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t("ccProtection.maxRequests")}</Label>
                    <Input
                      type="number"
                      min={1}
                      value={requestRateLimitMax}
                      onChange={(e) =>
                        setRequestRateLimitMax(Number(e.target.value))
                      }
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t("ccProtection.action")}</Label>
                    <Select
                      value={requestRateLimitAction}
                      onValueChange={setRequestRateLimitAction}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {CC_ACTION_OPTIONS.map((action) => (
                          <SelectItem key={action} value={action}>
                            {t(`ccProtection.action_${action}`)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 错误频率限制 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <IconAlertTriangle className="h-5 w-5 text-primary" />
                {t("ccProtection.errorRateLimit")}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <Switch
                  checked={errorRateLimitEnabled}
                  onCheckedChange={setErrorRateLimitEnabled}
                  id="err-rate-limit"
                />
                <Label htmlFor="err-rate-limit" className="cursor-pointer">
                  {t("ccProtection.enableErrorRateLimit")}
                </Label>
              </div>
              {errorRateLimitEnabled && (
                <>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    <div className="space-y-1.5">
                      <Label>{t("ccProtection.window")}</Label>
                      <div className="flex items-center gap-2">
                        <Input
                          type="number"
                          min={1}
                          value={errorRateLimitWindow}
                          onChange={(e) =>
                            setErrorRateLimitWindow(Number(e.target.value))
                          }
                        />
                        <span className="text-sm text-muted-foreground">{t("ccProtection.seconds")}</span>
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label>{t("ccProtection.maxErrors")}</Label>
                      <Input
                        type="number"
                        min={1}
                        value={errorRateLimitMax}
                        onChange={(e) =>
                          setErrorRateLimitMax(Number(e.target.value))
                        }
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>{t("ccProtection.action")}</Label>
                      <Select
                        value={errorRateLimitAction}
                        onValueChange={setErrorRateLimitAction}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {CC_ACTION_OPTIONS.map((action) => (
                            <SelectItem key={action} value={action}>
                              {t(`ccProtection.action_${action}`)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-6">
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={errorRateLimitCount4xx}
                        onCheckedChange={setErrorRateLimitCount4xx}
                        id="count-4xx"
                      />
                      <Label htmlFor="count-4xx" className="cursor-pointer text-sm">
                        {t("ccProtection.count4xx")}
                      </Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={errorRateLimitCount5xx}
                        onCheckedChange={setErrorRateLimitCount5xx}
                        id="count-5xx"
                      />
                      <Label htmlFor="count-5xx" className="cursor-pointer text-sm">
                        {t("ccProtection.count5xx")}
                      </Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={errorRateLimitCountBlock}
                        onCheckedChange={setErrorRateLimitCountBlock}
                        id="count-block"
                      />
                      <Label htmlFor="count-block" className="cursor-pointer text-sm">
                        {t("ccProtection.countBlock")}
                      </Label>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ==================== 自定义 CC 规则 ==================== */}
        <TabsContent value="custom-rules">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center justify-between text-base">
                <div className="flex items-center gap-2">
                  <IconAlertTriangle className="h-5 w-5 text-primary" />
                  {t("ccProtection.customRules")}
                </div>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={ccUseCustom}
                    onCheckedChange={setCCUseCustom}
                    id="cc-use-custom"
                  />
                  <Label htmlFor="cc-use-custom" className="cursor-pointer text-sm font-normal">
                    {t("ccProtection.enableCustomRules")}
                  </Label>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {!ccUseCustom && (
                <p className="text-sm text-muted-foreground">
                  {t("ccProtection.customRulesDisabledHint")}
                </p>
              )}

              {ccUseCustom && (
                <CCRulesEditor rules={ccRules} onChange={setCCRules} />
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* 底部操作按钮 */}
      <div className="flex justify-end gap-3">
        <Button variant="outline" onClick={handleCancel}>
          {t("common.cancel")}
        </Button>
        <Button
          onClick={handleSave}
          disabled={updateSettings.loading}
          className="bg-primary hover:bg-primary/90"
        >
          {updateSettings.loading && (
            <IconLoader2 className="mr-1.5 h-4 w-4 animate-spin" />
          )}
          {updateSettings.loading ? t("common.saving") : t("common.save")}
        </Button>
      </div>
    </div>
  );
}

export default function CCProtectionPage() {
  const { t } = useTranslation();
  const { data: settings, isLoading } = useProtectionSettings();
  // 用于“取消”时重挂载表单以还原为服务端初值
  const [formKey, setFormKey] = useState(0);

  if (isLoading || !settings) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <IconShield className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-semibold">{t("ccProtection.title")}</h1>
        </div>
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  return (
    <CCProtectionForm
      key={formKey}
      settings={settings}
      onReset={() => setFormKey((k) => k + 1)}
    />
  );
}
