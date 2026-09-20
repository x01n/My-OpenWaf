"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { toast } from "sonner"
import { IconDeviceFloppy } from "@tabler/icons-react"
import { useSiteMutation } from "@/hooks/use-api"
import type { Site } from "@/lib/types"

interface UpstreamTabProps {
  site: Site
  canManage: boolean
}

export function UpstreamTab({ site, canManage }: UpstreamTabProps) {
  const { t } = useTranslation()
  const updateSite = useSiteMutation()

  const [upstreamUrls, setUpstreamUrls] = useState(site.upstream_urls || "")
  const [upstreamHost, setUpstreamHost] = useState(site.upstream_host || "")
  const [skipVerify, setSkipVerify] = useState(site.upstream_tls_skip_verify)
  const [serverName, setServerName] = useState(
    site.upstream_tls_server_name || ""
  )
  const [clientCert, setClientCert] = useState(
    site.upstream_tls_client_cert_pem || ""
  )
  const [clientKey, setClientKey] = useState("")
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (!canManage) return
    setSaving(true)
    try {
      const data: Record<string, unknown> = {
        upstream_urls: upstreamUrls,
        upstream_host: upstreamHost,
        upstream_tls_skip_verify: skipVerify,
        upstream_tls_server_name: serverName,
      }
      // 私钥只写不读：仅在用户重新粘贴时提交；接口不回传明文，因此回显留空。
      if (clientKey.trim() !== "") {
        data.upstream_tls_client_cert_pem = clientCert
        data.upstream_tls_client_key_pem = clientKey
      } else if (clientCert === "") {
        // 用户清空证书输入框 = 显式移除客户端证书配置。
        data.upstream_tls_client_cert_pem = ""
        data.upstream_tls_client_key_pem = ""
      }
      await updateSite.execute({
        id: site.id,
        data,
      })
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
    } finally {
      setSaving(false)
    }
  }

  return (
    <fieldset
      disabled={!canManage}
      className="m-0 min-w-0 space-y-4 border-0 p-0"
    >
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.upstreamServer")}
          </CardTitle>
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
            <h4 className="text-sm font-medium">
              {t("sites.detail.upstreamTls")}
            </h4>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>{t("sites.form.skipVerify")}</Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.form.skipVerifyDesc")}
                </p>
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

            <div className="space-y-2">
              <Label>{t("sites.form.clientCert")}</Label>
              <Textarea
                value={clientCert}
                onChange={(e) => setClientCert(e.target.value)}
                placeholder={t("sites.form.clientCertPlaceholder")}
                className="min-h-[88px] font-mono text-xs"
              />
            </div>

            <div className="space-y-2">
              <Label>{t("sites.form.clientKey")}</Label>
              <Textarea
                value={clientKey}
                onChange={(e) => setClientKey(e.target.value)}
                placeholder={t("sites.form.clientKeyPlaceholder")}
                className="min-h-[88px] font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                {t("sites.form.clientCertHint")}
              </p>
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
    </fieldset>
  )
}
