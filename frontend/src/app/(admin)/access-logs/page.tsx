import type { Metadata } from "next";
import AccessLogsClient from "./access-logs-client";

export const metadata: Metadata = {
  title: "访问日志 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 AccessLogsClient 运行时拉取 */
export default function AccessLogsPage() {
  return <AccessLogsClient />;
}
