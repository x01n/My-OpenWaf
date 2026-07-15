"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

const routeKeyMap: Record<string, string> = {
  dashboard: "nav.dashboard",
  sites: "nav.sites",
  detail: "common.detail",
  "security-events": "nav.securityEvents",
  "access-logs": "nav.accessLogs",
  "drop-events": "nav.dropEvents",
  attacks: "nav.attacks",
  "false-positives": "nav.falsePositives",
  rules: "nav.rules",
  "cc-protection": "nav.ccProtection",
  captcha: "nav.captcha",
  "auth-config": "nav.authConfig",
  certificates: "nav.certificates",
  "ip-lists": "nav.ipLists",
  "threat-intel": "nav.threatIntel",
  "upstream-status": "nav.upstreamStatus",
  "api-keys": "nav.apiKeys",
  "admin-users": "nav.adminUsers",
  backup: "nav.backup",
  "request-trace": "nav.requestTrace",
  settings: "nav.settings",
};

export function BreadcrumbNav() {
  const pathname = usePathname();
  const { t } = useTranslation();

  const segments = pathname.split("/").filter(Boolean);
  if (segments.length === 0) return null;

  const crumbs = segments.map((segment, index) => {
    const href = "/" + segments.slice(0, index + 1).join("/");
    const label = routeKeyMap[segment]
      ? t(routeKeyMap[segment])
      : decodeURIComponent(segment);
    return { href, label };
  });

  return (
    <Breadcrumb className="mb-4">
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href="/dashboard">{t("common.home")}</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        {crumbs.map((crumb, index) => (
          <span key={crumb.href} className="contents">
            <BreadcrumbSeparator />
            <BreadcrumbItem>
              {index === crumbs.length - 1 ? (
                <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
              ) : (
                <BreadcrumbLink asChild>
                  <Link href={crumb.href}>{crumb.label}</Link>
                </BreadcrumbLink>
              )}
            </BreadcrumbItem>
          </span>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
