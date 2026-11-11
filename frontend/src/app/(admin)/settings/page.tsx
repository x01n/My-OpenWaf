import type { Metadata } from "next";
import SettingsClient from "./settings-client";

export const metadata: Metadata = { title: "系统设置 - My-OpenWaf" };

export default function SettingsPage() {
  return <SettingsClient />;
}
