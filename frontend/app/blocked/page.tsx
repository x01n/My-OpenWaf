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
      description="该请求命中了站点防护策略，如果对该处理存在异议请携带请求id并保存请求日志询问管理员。"
      facts={[
        { label: "请求标识", value: "__WAF_REQUEST_ID__" },
        { label: "规则标识", value: "__WAF_RULE_ID__" },
      ]}
    />
  )
}
