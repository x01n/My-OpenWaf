import { PublicStatusPage } from "@/components/public-status-page"

export const metadata = {
  title: "请求已阻断 | My-OpenWAF",
}

export default function BlockedPage() {
  return (
    <PublicStatusPage
      tone="blocked"
      statusCode={403}
      eyebrow="安全策略已生效"
      title="当前请求已被 WAF 阻断"
      description="该请求命中了站点防护策略，系统已在转发到上游之前完成熔断并停止继续处理，以避免敏感流量穿透防护链路。"
      facts={[
        { label: "请求标识", value: "__WAF_REQUEST_ID__" },
        { label: "规则标识", value: "__WAF_RULE_ID__" },
      ]}
    />
  )
}
