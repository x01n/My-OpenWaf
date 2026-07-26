/**
 * 侧边栏导航组件
 * 基于 shadcn ui/sidebar 重建：支持整栏 icon 折叠、cookie 持久化、移动端 Sheet。
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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
  IconCertificate,
  IconNetwork,
  IconUsers,
  IconApi,
  IconWorldBolt,
  IconDatabaseExport,
  IconRoute,
  IconServer,
  IconTemplate,
  IconCode,
} from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar";

/**
 * 活动项样式。
 *
 * shadcn 的 SidebarMenuButton 默认活动态是 `data-active:bg-sidebar-accent`，
 * 与 `hover:bg-sidebar-accent` 完全相同 —— 鼠标划过时无法分辨哪个才是当前页。
 * 这里叠加主色文字与左侧指示条，让活动态在悬停时依然可辨认。
 */
const ACTIVE_ITEM_CLASS =
  "relative data-[active=true]:bg-primary/10 data-[active=true]:text-primary data-[active=true]:before:absolute data-[active=true]:before:inset-y-1.5 data-[active=true]:before:start-0 data-[active=true]:before:w-[3px] data-[active=true]:before:rounded-full data-[active=true]:before:bg-primary";

/** 子项活动态：同一套语义，指示条更细 */
const ACTIVE_SUB_ITEM_CLASS =
  "relative data-[active=true]:bg-primary/10 data-[active=true]:text-primary data-[active=true]:font-medium data-[active=true]:before:absolute data-[active=true]:before:inset-y-1 data-[active=true]:before:start-0 data-[active=true]:before:w-0.5 data-[active=true]:before:rounded-full data-[active=true]:before:bg-primary [&>svg]:transition-colors data-[active=true]:[&>svg]:text-primary";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  children?: NavItem[];
}

interface NavGroup {
  /** 分组标题的 i18n key，为空则不显示标题 */
  labelKey?: string;
  items: NavItem[];
}

/** 判断某导航项（含子项）是否命中当前路径（前缀匹配） */
function isChildActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.href || pathname.startsWith(item.href + "/")) {
    return true;
  }
  if (item.children) {
    return item.children.some((child) => isChildActive(child, pathname));
  }
  return false;
}

/** 单个可展开的导航项（带 children） */
function CollapsibleNavItem({ item }: { item: NavItem }) {
  const pathname = usePathname();
  const Icon = item.icon;
  const groupActive = item.children!.some((child) =>
    isChildActive(child, pathname)
  );

  return (
    <Collapsible defaultOpen={groupActive} className="group/collapsible">
      <SidebarMenuItem>
        <CollapsibleTrigger asChild>
          <SidebarMenuButton
            tooltip={item.label}
            isActive={groupActive}
            className={ACTIVE_ITEM_CLASS}
          >
            <Icon />
            <span>{item.label}</span>
            <IconChevronRight className="ms-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
          </SidebarMenuButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {item.children!.map((child) => {
              const childActive =
                pathname === child.href ||
                pathname.startsWith(child.href + "/");
              const ChildIcon = child.icon;
              return (
                <SidebarMenuSubItem key={child.href}>
                  <SidebarMenuSubButton
                    asChild
                    isActive={childActive}
                    className={ACTIVE_SUB_ITEM_CLASS}
                  >
                    <Link href={child.href}>
                      <ChildIcon />
                      <span>{child.label}</span>
                    </Link>
                  </SidebarMenuSubButton>
                </SidebarMenuSubItem>
              );
            })}
          </SidebarMenuSub>
        </CollapsibleContent>
      </SidebarMenuItem>
    </Collapsible>
  );
}

/** 单个普通导航项（无 children） */
function SimpleNavItem({ item }: { item: NavItem }) {
  const pathname = usePathname();
  const Icon = item.icon;
  const active =
    pathname === item.href || pathname.startsWith(item.href + "/");

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        tooltip={item.label}
        isActive={active}
        className={ACTIVE_ITEM_CLASS}
      >
        <Link href={item.href}>
          <Icon />
          <span>{item.label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

/** 构造导航分组数据（保留原 navGroups 全部条目/图标/href/children） */
function useNavGroups(): NavGroup[] {
  const { t } = useTranslation();

  return [
    {
      items: [
        { label: t("nav.dashboard"), href: "/dashboard", icon: IconChartBar },
      ],
    },
    {
      items: [{ label: t("nav.sites"), href: "/sites", icon: IconShield }],
    },
    {
      labelKey: "nav.security",
      items: [
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
    },
    {
      labelKey: "nav.groupProtection",
      items: [
        { label: t("nav.rules"), href: "/rules", icon: IconListCheck },
        {
          label: t("nav.ccProtection"),
          href: "/cc-protection",
          icon: IconGauge,
        },
        { label: t("nav.captcha"), href: "/captcha", icon: IconUserCheck },
        { label: t("nav.authConfig"), href: "/auth-config", icon: IconKey },
        {
          label: t("nav.luaPlugins"),
          href: "/lua-plugins",
          icon: IconCode,
        },
      ],
    },
    {
      labelKey: "nav.groupNetwork",
      items: [
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
    },
    {
      labelKey: "nav.groupSystem",
      items: [
        { label: t("nav.apiKeys"), href: "/api-keys", icon: IconApi },
        { label: t("nav.adminUsers"), href: "/admin-users", icon: IconUsers },
        {
          label: t("nav.pageTemplates"),
          href: "/page-templates",
          icon: IconTemplate,
        },
        {
          label: t("nav.backup"),
          href: "/backup",
          icon: IconDatabaseExport,
        },
        { label: t("nav.settings"), href: "/settings", icon: IconSettings },
      ],
    },
  ];
}

/**
 * 应用侧边栏。桌面端支持 icon 折叠，移动端自动切换为内置 Sheet。
 */
export function AppSidebar() {
  const { t } = useTranslation();
  const { state } = useSidebar();
  const navGroups = useNavGroups();
  const collapsed = state === "collapsed";

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex h-10 items-center gap-2.5 px-2 font-semibold text-primary">
          <IconShieldCheck className="h-6 w-6 shrink-0" />
          {!collapsed && (
            <span className="text-lg tracking-tight">OpenWAF</span>
          )}
        </div>
      </SidebarHeader>
      <SidebarContent>
        {navGroups.map((group, idx) => (
          <SidebarGroup key={group.labelKey ?? `group-${idx}`}>
            {group.labelKey && (
              <SidebarGroupLabel>{t(group.labelKey)}</SidebarGroupLabel>
            )}
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) =>
                  item.children && item.children.length > 0 ? (
                    <CollapsibleNavItem key={item.href} item={item} />
                  ) : (
                    <SimpleNavItem key={item.href} item={item} />
                  )
                )}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter>
        {!collapsed && (
          <p className="px-2 text-xs text-muted-foreground">v1.0.0</p>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}
