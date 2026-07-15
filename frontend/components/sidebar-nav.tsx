/**
 * 侧边栏导航组件
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  IconChartBar,
  IconShield,
  IconAlertTriangle,
  IconAlertCircle,
  IconFileText,
  IconBan,
  IconFlame,
  IconListCheck,
  IconGauge,
  IconUserCheck,
  IconKey,
  IconSettings,
  IconShieldCheck,
  IconChevronRight,
  IconAlertHexagon,
  IconMenu2,
  IconCertificate,
  IconNetwork,
  IconUsers,
  IconApi,
  IconWorldBolt,
  IconDatabaseExport,
  IconRoute,
  IconServer,
} from "@tabler/icons-react";
import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  children?: NavItem[];
}

function isChildActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.href || pathname.startsWith(item.href + "/")) {
    return true;
  }
  if (item.children) {
    return item.children.some((child) => isChildActive(child, pathname));
  }
  return false;
}

function NavLink({ item, depth = 0 }: { item: NavItem; depth?: number }) {
  const pathname = usePathname();
  const isActive =
    pathname === item.href || pathname.startsWith(item.href + "/");
  const hasChildren = item.children && item.children.length > 0;
  const childActive =
    hasChildren &&
    item.children!.some((child) => isChildActive(child, pathname));
  const [expanded, setExpanded] = useState(isActive || childActive);
  const Icon = item.icon;
  const active = isActive && !childActive;

  const handleChevronClick = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setExpanded((prev) => !prev);
    },
    []
  );

  return (
    <div>
      <Link
        href={item.href}
        className={cn(
          "relative flex items-center gap-3 overflow-hidden rounded-lg px-3 py-2 text-sm font-medium transition-all",
          depth > 0 && "py-1.5 pl-10 text-[13px]",
          active
            ? "bg-primary text-primary-foreground shadow-sm"
            : childActive
              ? "text-foreground"
              : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        )}
      >
        {active && (
          <span className="absolute inset-y-1 left-0 w-[3px] rounded-r-full bg-primary-foreground/80" />
        )}
        <Icon
          className={cn("shrink-0", depth > 0 ? "h-4 w-4" : "h-[18px] w-[18px]")}
        />
        <span className="flex-1 truncate">{item.label}</span>
        {hasChildren && (
          <span
            role="button"
            tabIndex={0}
            onClick={handleChevronClick}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ")
                handleChevronClick(e as unknown as React.MouseEvent);
            }}
            className={cn(
              "inline-flex items-center justify-center rounded p-0.5",
              active
                ? "hover:bg-primary-foreground/20"
                : "hover:bg-muted"
            )}
          >
            <IconChevronRight
              className={cn(
                "h-4 w-4 shrink-0 transition-transform",
                expanded && "rotate-90"
              )}
            />
          </span>
        )}
      </Link>
      {hasChildren && expanded && (
        <div className="mt-0.5 space-y-0.5">
          {item.children!.map((child) => (
            <NavLink key={child.href} item={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function SidebarContent() {
  const { t } = useTranslation();

  const navGroups: NavItem[][] = [
    [{ label: t("nav.dashboard"), href: "/dashboard", icon: IconChartBar }],
    [{ label: t("nav.sites"), href: "/sites", icon: IconShield }],
    [
      {
        label: t("nav.security"),
        href: "/security-events",
        icon: IconAlertTriangle,
        children: [
          {
            label: t("nav.securityEvents"),
            href: "/security-events",
            icon: IconAlertCircle,
          },
          {
            label: t("nav.accessLogs"),
            href: "/access-logs",
            icon: IconFileText,
          },
          {
            label: t("nav.requestTrace"),
            href: "/request-trace",
            icon: IconRoute,
          },
          {
            label: t("nav.dropEvents"),
            href: "/drop-events",
            icon: IconBan,
          },
          {
            label: t("nav.attacks"),
            href: "/attacks",
            icon: IconFlame,
          },
          {
            label: t("nav.falsePositives"),
            href: "/false-positives",
            icon: IconAlertHexagon,
          },
          {
            label: t("nav.upstreamStatus"),
            href: "/upstream-status",
            icon: IconServer,
          },
        ],
      },
    ],
    [
      { label: t("nav.rules"), href: "/rules", icon: IconListCheck },
      {
        label: t("nav.ccProtection"),
        href: "/cc-protection",
        icon: IconGauge,
      },
      { label: t("nav.captcha"), href: "/captcha", icon: IconUserCheck },
      { label: t("nav.authConfig"), href: "/auth-config", icon: IconKey },
    ],
    [
      {
        label: t("nav.certificates"),
        href: "/certificates",
        icon: IconCertificate,
      },
      { label: t("nav.ipLists"), href: "/ip-lists", icon: IconNetwork },
      {
        label: t("nav.threatIntel"),
        href: "/threat-intel",
        icon: IconWorldBolt,
      },
    ],
    [
      { label: t("nav.apiKeys"), href: "/api-keys", icon: IconApi },
      { label: t("nav.adminUsers"), href: "/admin-users", icon: IconUsers },
      {
        label: t("nav.backup"),
        href: "/backup",
        icon: IconDatabaseExport,
      },
      { label: t("nav.settings"), href: "/settings", icon: IconSettings },
    ],
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-14 items-center border-b px-4">
        <div className="flex items-center gap-2.5 font-semibold text-primary">
          <IconShieldCheck className="h-6 w-6" />
          <span className="text-lg tracking-tight">OpenWAF</span>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-2.5 py-3">
        {navGroups.map((group, idx) => (
          <div key={idx}>
            {idx > 0 && (
              <div className="mx-1 my-2 border-t border-border/40" />
            )}
            <div className="space-y-0.5">
              {group.map((item) => (
                <NavLink key={item.href} item={item} />
              ))}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t px-4 py-3">
        <p className="text-xs text-muted-foreground">v1.0.0</p>
      </div>
    </div>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden w-56 border-r bg-card lg:block">
      <SidebarContent />
    </aside>
  );
}

export function MobileSidebar() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="icon" className="lg:hidden">
          <IconMenu2 className="h-5 w-5" />
          <span className="sr-only">{t("common.openMenu")}</span>
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-56 p-0">
        <SidebarContent />
      </SheetContent>
    </Sheet>
  );
}
