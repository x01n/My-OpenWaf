/**
 * 证书解析信息面板
 *
 * 展示 POST /api/v1/certificates/parse 返回的证书公开信息与命中站点，
 * 不涉及私钥。后端契约见 internal/admin/system/certificate.go 的
 * certificateParseResponse。
 */
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Badge } from "@/components/ui/badge"
import { IconFileSearch } from "@tabler/icons-react"
import { formatDate } from "@/lib/utils"
import type { CertificateParseResult } from "@/lib/types"

interface CertificateParsePanelProps {
  result: CertificateParseResult
}

export function CertificateParsePanel({ result }: CertificateParsePanelProps) {
  const { t } = useTranslation()
  const dnsNames = result.dns_names ?? []
  const ipAddresses = result.ip_addresses ?? []
  const matchedSites = result.matched_sites ?? []

  // 渲染期读 Date.now() 违反 React 纯度约束（react-hooks/purity），且静态导出预渲染
  // 与客户端水合会得到不同的值。用惰性初始化把“现在”固定为面板挂载时刻：证书到期是
  // 天粒度信息，面板生命周期内不重算不会影响判断。
  const [nowMs] = useState(() => Date.now())
  const expiresAt = result.expires_at
  const daysUntilExpiry = expiresAt ? Math.ceil((new Date(expiresAt).getTime() - nowMs) / (1000 * 60 * 60 * 24)) : null

  const expiryStatus = daysUntilExpiry !== null ?
    (daysUntilExpiry <= 0 ? "expired" : daysUntilExpiry <= 30 ? "expiring" : "valid") : "unknown"

  return (
    <div className="space-y-3 rounded-xl border bg-muted/20 p-4">
      <div className="flex items-center gap-2">
        <IconFileSearch className="h-4 w-4 text-primary" />
        <p className="text-sm font-medium">{t("certificates.parseResultTitle")}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">
            {t("certificates.commonName")}
          </p>
          <p className="break-all">{result.common_name || "-"}</p>
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">
            {t("certificates.expiresAt")}
          </p>
          <div className="flex items-center gap-2">
            <p>{formatDate(result.expires_at)}</p>
            {expiryStatus === "expiring" && (
              <Badge variant="destructive" className="flex items-center gap-1">
                <span>{t("certificates.expiringDays", { days: daysUntilExpiry })}</span>
              </Badge>
            )}
            {expiryStatus === "expired" && (
              <Badge variant="destructive">{t("certificates.expired")}</Badge>
            )}
            {expiryStatus === "valid" && (
              <Badge variant="default">{t("certificates.valid")}</Badge>
            )}
          </div>
        </div>
        {expiryStatus === "unknown" && (
          <div className="min-w-0 sm:col-span-2">
            <p className="text-xs text-muted-foreground">
              {t("certificates.expiresAt")}
            </p>
            <p className="text-destructive">{t("certificates.unknownExpiry")}</p>
          </div>
        )}
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">
            {t("certificates.dnsNames")}
          </p>
          {dnsNames.length > 0 ? (
            <div className="mt-1 flex flex-wrap gap-1.5">
              {dnsNames.map((name) => (
                <Badge
              key={name}
              variant="outline"
              className="h-auto min-w-0 max-w-full whitespace-normal break-all text-xs"
            >
                  {name}
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">-</p>
          )}
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">
            {t("certificates.ipAddresses")}
          </p>
          {ipAddresses.length > 0 ? (
            <div className="mt-1 flex flex-wrap gap-1.5">
              {ipAddresses.map((ip) => (
                <Badge
              key={ip}
              variant="outline"
              className="h-auto min-w-0 max-w-full whitespace-normal break-all text-xs"
            >
                  {ip}
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">-</p>
          )}
        </div>
      </div>
      <div className="pt-3 border-t">
        <p className="text-xs font-medium text-muted-foreground mb-2">{t("certificates.matchedSites")}</p>
        {matchedSites.length > 0 ? (
          <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
            {matchedSites.map((site) => (
              <div key={site.id} className="flex items-start justify-between gap-2 text-sm">
                <div className="min-w-0">
                  <p className="break-all">{site.host}</p>
                  {site.matched_name ? (
                    <p className="text-xs text-muted-foreground break-all">
                      {t("certificates.matchedBy")}: {site.matched_name}
                    </p>
                  ) : null}
                </div>
                <Badge variant={site.tls_enabled ? "default" : "secondary"} className="shrink-0">
                  {site.tls_enabled ? t("common.enabled") : t("common.disabled")}
                </Badge>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">{t("certificates.noMatchedSites")}</p>
        )}
      </div>
    </div>
  )
}
