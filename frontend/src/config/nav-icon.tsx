"use client";

import {
  LayoutDashboard,
  Globe,
  ShieldCheck,
  Shield,
  FileKey,
  ListFilter,
  ScrollText,
  Radar,
  BookOpen,
  Bug,
  Siren,
  FileText,
  Puzzle,
  Braces,
  Settings,
  Users,
  type LucideIcon,
} from "lucide-react";

const ICONS: Record<string, LucideIcon> = {
  dashboard: LayoutDashboard,
  sites: Globe,
  certificate: FileKey,
  shield: ShieldCheck,
  ip: ListFilter,
  intel: Radar,
  rules: ScrollText,
  policy: BookOpen,
  cve: Bug,
  owasp: Shield,
  events: Siren,
  logs: FileText,
  plugin: Puzzle,
  settings: Settings,
  users: Users,
};

/** nav.ts 中 icon 键名的专用映射（Braces 等） */
const EXTRA_ICONS: Record<string, LucideIcon> = {
  ...ICONS,
};

export function NavIcon({ name, className }: { name: string; className?: string }) {
  const Icon = EXTRA_ICONS[name] ?? Settings;
  return <Icon className={className} />;
}
