import { PublicStatusPage } from "@/components/public-status-page"

export const metadata = {
  title: "服务维护中 | My-OpenWAF",
}

export default function MaintenancePage() {
  return (
    <PublicStatusPage
      tone="maintenance"
      statusCode={503}
      eyebrow="维护模式"
      title="站点当前处于维护窗口"
      description="维护模式开启后，当前站点的所有请求都会直接返回维护页面，不会继续连接上游服务。WebSocket 不会升级，SSE 也会返回同一维护内容。"
      facts={[
        { label: "请求标识", value: "__WAF_REQUEST_ID__" },
        { label: "处理模式", value: "maintenance" },
      ]}
    />
  )
}
