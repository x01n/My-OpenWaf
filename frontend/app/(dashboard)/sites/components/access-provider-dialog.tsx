"use client";

import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { NumberField } from "@/components/ui/number-field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import { IconDeviceFloppy } from "@tabler/icons-react";
import {
  useAccessProviderCreate,
  useAccessProviderUpdate,
} from "@/hooks/use-api";
import type { AccessProvider, OAuthProviderConfig } from "@/lib/types";

interface AccessProviderDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteId: number;
  /** 编辑目标提供方，为 null 时表示新建。 */
  provider?: AccessProvider | null;
}

/** OAuth/OIDC 配置表单字段。 */
interface OAuthForm {
  client_id: string;
  client_secret: string;
  auth_url: string;
  token_url: string;
  userinfo_url: string;
  issuer: string;
  scopes: string;
  redirect_path: string;
  use_pkce: boolean;
}

/**
 * 认证提供方添加/编辑对话框。
 * 支持 password / oauth2 / oidc 三种类型；OAuth/oidc 类型需填写 OAuthProviderConfig 字段。
 * 编辑时 client_secret 留空表示保持原密钥不变。
 */
export function AccessProviderDialog({
  open,
  onOpenChange,
  siteId,
  provider,
}: AccessProviderDialogProps) {
  const { t } = useTranslation();
  const isEdit = !!provider;

  // 表单初值用 useState 懒初始化从 props 同步；父组件以 key 重挂载触发刷新，避免 effect 内 setState。
  const [type, setType] = useState<AccessProvider["type"]>(() => provider?.type ?? "password");
  const [name, setName] = useState(() => provider?.name ?? "");
  const [priority, setPriority] = useState(() => provider?.priority ?? 100);
  const [enabled, setEnabled] = useState(() => provider?.enabled ?? true);
  const [oauth, setOauth] = useState<OAuthForm>(() => {
    const cfg = provider?.config;
    return {
      client_id: cfg?.client_id ?? "",
      client_secret: "",
      auth_url: cfg?.auth_url ?? "",
      token_url: cfg?.token_url ?? "",
      userinfo_url: cfg?.userinfo_url ?? "",
      issuer: cfg?.issuer ?? "",
      scopes: (cfg?.scopes ?? []).join(" "),
      redirect_path: cfg?.redirect_path ?? "",
      use_pkce: cfg?.use_pkce ?? false,
    };
  });

  const createMutation = useAccessProviderCreate();
  const updateMutation = useAccessProviderUpdate();
  const loading = createMutation.loading || updateMutation.loading;

  const isOAuth = type === "oauth2" || type === "oidc";

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!name.trim()) {
        toast.error(t("common.operationFailed"));
        return;
      }
      const cfg: OAuthProviderConfig | undefined = isOAuth
        ? {
            client_id: oauth.client_id,
            client_secret: oauth.client_secret.trim() || undefined,
            auth_url: oauth.auth_url || undefined,
            token_url: oauth.token_url || undefined,
            userinfo_url: oauth.userinfo_url || undefined,
            issuer: oauth.issuer || undefined,
            scopes: oauth.scopes
              .split(/\s+/)
              .map((s) => s.trim())
              .filter((s) => s.length > 0),
            redirect_path: oauth.redirect_path || undefined,
            use_pkce: oauth.use_pkce,
          }
        : undefined;
      try {
        if (isEdit && provider) {
          await updateMutation.execute({
            siteId,
            pid: provider.id,
            data: {
              name: name.trim(),
              priority,
              enabled,
              type,
              config: cfg,
            },
          });
          toast.success(t("sites.detail.providerUpdated"));
        } else {
          await createMutation.execute({
            siteId,
            data: {
              name: name.trim(),
              priority,
              enabled,
              type,
              config: cfg,
            },
          });
          toast.success(t("sites.detail.providerCreated"));
        }
        onOpenChange(false);
      } catch {
        toast.error(t("common.operationFailed"));
      }
    },
    [isEdit, provider, type, name, priority, enabled, isOAuth, oauth, siteId, createMutation, updateMutation, onOpenChange, t]
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? t("sites.detail.editProvider") : t("sites.detail.addProvider")}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label>{t("sites.detail.providerType")}</Label>
            <Select
              value={type}
              onValueChange={(v) => setType(v as AccessProvider["type"])}
              disabled={isEdit}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="password">{t("sites.detail.typePassword")}</SelectItem>
                <SelectItem value="oauth2">{t("sites.detail.typeOauth2")}</SelectItem>
                <SelectItem value="oidc">{t("sites.detail.typeOidc")}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.providerName")}</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.providerPriority")}</Label>
            <NumberField.Root
              value={priority}
              onValueChange={(v) => setPriority(v ?? 100)}
              min={0}
              className="w-32"
            >
              <NumberField.Group>
                <NumberField.Decrement />
                <NumberField.Input />
                <NumberField.Increment />
              </NumberField.Group>
            </NumberField.Root>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("common.enabled")}</Label>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>

          {isOAuth && (
            <>
              <Separator />
              <div className="space-y-3">
                <Label className="text-sm font-medium">
                  {t("sites.detail.oauthConfig")}
                </Label>
                <div className="space-y-2">
                  <Label>{t("sites.detail.clientId")}</Label>
                  <Input
                    value={oauth.client_id}
                    onChange={(e) => setOauth({ ...oauth, client_id: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t("sites.detail.clientSecret")}</Label>
                  <Input
                    type="password"
                    value={oauth.client_secret}
                    onChange={(e) => setOauth({ ...oauth, client_secret: e.target.value })}
                    placeholder={t("sites.detail.clientSecretPlaceholder")}
                  />
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>{t("sites.detail.authUrl")}</Label>
                    <Input
                      value={oauth.auth_url}
                      onChange={(e) => setOauth({ ...oauth, auth_url: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>{t("sites.detail.tokenUrl")}</Label>
                    <Input
                      value={oauth.token_url}
                      onChange={(e) => setOauth({ ...oauth, token_url: e.target.value })}
                    />
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>{t("sites.detail.userinfoUrl")}</Label>
                    <Input
                      value={oauth.userinfo_url}
                      onChange={(e) => setOauth({ ...oauth, userinfo_url: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>{t("sites.detail.issuer")}</Label>
                    <Input
                      value={oauth.issuer}
                      onChange={(e) => setOauth({ ...oauth, issuer: e.target.value })}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>{t("sites.detail.scopes")}</Label>
                  <Input
                    value={oauth.scopes}
                    onChange={(e) => setOauth({ ...oauth, scopes: e.target.value })}
                    placeholder={t("sites.detail.scopesPlaceholder")}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t("sites.detail.redirectPath")}</Label>
                  <Input
                    value={oauth.redirect_path}
                    onChange={(e) => setOauth({ ...oauth, redirect_path: e.target.value })}
                    placeholder="/__owaf/oauth/callback"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="use-pkce"
                    checked={oauth.use_pkce}
                    onCheckedChange={(v) => setOauth({ ...oauth, use_pkce: v === true })}
                  />
                  <Label htmlFor="use-pkce" className="cursor-pointer text-sm">
                    {t("sites.detail.usePkce")}
                  </Label>
                </div>
              </div>
            </>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={loading}>
              <IconDeviceFloppy className="mr-1 h-4 w-4" />
              {loading ? t("common.saving") : t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
