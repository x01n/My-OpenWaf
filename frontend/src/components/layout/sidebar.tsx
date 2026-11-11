"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldHalf, Menu } from "lucide-react";
import { Button, Drawer } from "@heroui/react";
import { useOverlayState } from "@heroui/react";
import { NAV_GROUPS, findNavItem } from "@/config/nav";
import { NavIcon } from "@/config/nav-icon";
import { LanguageToggle } from "@/components/layout/language-toggle";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { useI18n, type MessageKey } from "@/i18n";

/** 角色标识到 i18n 键的映射，未知角色原样展示。 */
const ROLE_KEYS: Record<string, MessageKey> = {
  admin: "topbar.role.admin",
  operator: "topbar.role.operator",
  readonly: "topbar.role.readonly",
};

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { t } = useI18n();
  const activeHref = findNavItem(pathname)?.href;
  return (
    <nav className="flex flex-col gap-5 px-3 py-4">
      {NAV_GROUPS.map((group) => (
        <div key={group.titleKey}>
          <div className="text-muted px-2 pb-1.5 text-[11px] font-medium tracking-wider uppercase">
            {t(group.titleKey)}
          </div>
          <ul className="flex flex-col gap-0.5">
            {group.items.map((item) => {
              const active = activeHref === item.href;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    className={`nav-link ${active ? "nav-link--active" : ""}`}
                  >
                    <NavIcon name={item.icon} className="size-4 shrink-0" />
                    {t(item.labelKey)}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function Sidebar() {
  const { t } = useI18n();
  return (
    <aside className="sidebar-rail hidden w-56 shrink-0 flex-col lg:flex">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <span className="brand-badge" aria-hidden="true">
          <ShieldHalf className="size-4" />
        </span>
        <span className="text-[0.9375rem] font-semibold tracking-tight">{t("brand.name")}</span>
      </div>
      <div className="scrollbar-thin flex-1 overflow-y-auto">
        <NavList />
      </div>
    </aside>
  );
}

export function Topbar({ username, role }: { username?: string; role?: string }) {
  const mobileNav = useOverlayState();
  const { t } = useI18n();
  const initial = (username ?? "U").charAt(0).toUpperCase();
  const roleLabel = role ? (ROLE_KEYS[role] ? t(ROLE_KEYS[role]) : role) : null;
  return (
    <header className="topbar-glass flex items-center gap-3 px-4">
      <Button
        variant="ghost"
        size="sm"
        className="lg:hidden"
        onPress={mobileNav.open}
        aria-label={t("topbar.openMenu")}
      >
        <Menu className="size-4" />
      </Button>
      <div className="flex-1" />
      <LanguageToggle />
      <ThemeToggle />
      {username && (
        <div className="flex items-center gap-2.5 text-sm">
          <span className="user-avatar" aria-hidden="true">
            {initial}
          </span>
          <span className="hidden font-medium md:inline">{username}</span>
          {roleLabel && (
            <span className="bg-accent-soft text-accent-soft-foreground hidden rounded-full border border-accent/20 px-2.5 py-0.5 text-xs font-medium sm:inline">
              {roleLabel}
            </span>
          )}
        </div>
      )}
      <Drawer state={mobileNav}>
        <Drawer.Backdrop />
        <Drawer.Content placement="left" className="w-64">
          <Drawer.Dialog>
            <Drawer.Header>
              <div className="flex items-center gap-2">
                <ShieldHalf className="text-accent size-5" />
                <span className="font-semibold">{t("brand.name")}</span>
              </div>
              <Drawer.CloseTrigger aria-label={t("common.close")} />
            </Drawer.Header>
            <Drawer.Body className="p-0">
              <NavList onNavigate={mobileNav.close} />
            </Drawer.Body>
          </Drawer.Dialog>
        </Drawer.Content>
      </Drawer>
    </header>
  );
}
