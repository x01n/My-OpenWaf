import type { Metadata } from "next"
import SiteDetailClient from "./client"

export const dynamic = "force-static"
export const dynamicParams = false

export const metadata: Metadata = {
  title: "站点详情 · My-OpenWAF",
  description: "管理单个防护应用的监听、上游、缓存、规则与防护覆盖配置。",
}

export function generateStaticParams() {
  return [{ id: "_" }]
}

export default function SiteDetailPage() {
  return <SiteDetailClient />
}
