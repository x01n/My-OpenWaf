/**
 * 侧边栏导航组件
 * 参考截图中的左侧导航栏设计
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  IconChartBar,
  IconShield,
  IconAlertTriangle,
  IconListCheck,
  IconGauge,
  IconUserCheck,
  IconKey,
  IconSettings,
  IconShieldCheck,
  IconFileText,
  IconBan,
  IconChevronRight,
  IconMenu2,
  IconX,
} from "@tabler/icons-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  children?: NavItem[];
}

function NavLink({ item, depth = 0 }: { item: NavItem; depth?: number }) {
  const pathname = usePathname();
  const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
  const [expanded, setExpanded] = useState(false);
  const hasChildren = item.children && item.children.length > 0;
  const Icon = item.icon;

  return (
    <div>
      <Link
        href={item.href}
        onClick={(e) => {
          if (hasChildren) {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
        className={cn(
          "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
          "hover:bg-accent hover:text-accent-foreground",
          isActive
            ? "bg-primary text-primary-foreground"
            : "text-muted-foreground",
          depth > 0 && "pl-10"
        )}
      >
        <Icon className="h-5 w-5 shrink-0" />
        <span className="flex-1">{item.label}</span>
        {hasChildren && (
          <IconChevronRight
            className={cn(
              "h-4 w-4 shrink-0 transition-transform",
              expanded && "rotate-90"
            )}
          />
        )}
      </Link>
      {hasChildren && expanded && (
        <div className="mt-1 space-y-1">
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

  const navItems: NavItem[] = [
    { label: t("nav.dashboard"), href: "/dashboard", icon: IconChartBar },
    { label: t("nav.sites"), href: "/sites", icon: IconShield },
    { label: t("nav.attacks"), href: "/attacks", icon: IconAlertTriangle },
    { label: t("nav.rules"), href: "/rules", icon: IconListCheck },
    {
      label: t("nav.ccProtection"),
      href: "/cc-protection",
      icon: IconGauge,
      children: [
        { label: t("nav.waitingRoom"), href: "/cc-protection/waiting-room", icon: IconGauge },
        { label: t("nav.rateLimit"), href: "/cc-protection/rate-limit", icon: IconGauge },
      ],
    },
    { label: t("nav.captcha"), href: "/captcha", icon: IconUserCheck },
    { label: t("nav.authConfig"), href: "/auth-config", icon: IconKey },
    { label: t("nav.settings"), href: "/settings", icon: IconSettings },
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-14 items-center border-b px-4">
        <div className="flex items-center gap-2 font-semibold text-primary">
          <IconShieldCheck className="h-6 w-6" />
          <span className="text-lg">OpenWAF</span>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map((item) => (
          <NavLink key={item.href} item={item} />
        ))}
      </nav>
    </div>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden w-60 border-r bg-card lg:block">
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
      <SheetContent side="left" className="w-60 p-0">
        <SidebarContent />
      </SheetContent>
    </Sheet>
  );
}
