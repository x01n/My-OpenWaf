import type { Metadata } from "next";
import SecurityEventsClient from "./security-events-client";

export const metadata: Metadata = {
  title: "安全事件 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 SecurityEventsClient 运行时拉取 */
export default function SecurityEventsPage() {
  return <SecurityEventsClient />;
}
