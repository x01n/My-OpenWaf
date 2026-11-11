import type { Metadata } from "next";
import DashboardClient from "./dashboard-client";

export const metadata: Metadata = {
  title: "仪表盘 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 DashboardClient 运行时拉取 */
export default function DashboardPage() {
  return <DashboardClient />;
}
