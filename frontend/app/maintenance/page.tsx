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
      description="当前站点处于维护模式中"
      facts={[
        { label: "请求标识", value: "__WAF_REQUEST_ID__" },
        { label: "处理模式", value: "maintenance" },
      ]}
    />
  )
}
