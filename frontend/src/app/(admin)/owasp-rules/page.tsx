import type { Metadata } from "next";
import OWASPRulesClient from "./owasp-rules-client";

export const metadata: Metadata = {
  title: "OWASP 规则 - My-OpenWaf",
};

/** RSC 静态骨架：构建期预渲染页面壳，策略级规则数据由 OWASPRulesClient 运行时拉取 */
export default function OWASPRulesPage() {
  return <OWASPRulesClient />;
}
