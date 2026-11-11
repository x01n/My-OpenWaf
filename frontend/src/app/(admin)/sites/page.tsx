import type { Metadata } from "next";
import SitesClient from "./sites-client";

export const metadata: Metadata = {
  title: "站点管理 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 SitesClient 运行时拉取 */
export default function SitesPage() {
  return <SitesClient />;
}
