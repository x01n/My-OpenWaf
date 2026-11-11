import type { Metadata } from "next";
import ProtectionClient from "./protection-client";

export const metadata: Metadata = {
  title: "防护设置 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 ProtectionClient 运行时拉取 */
export default function ProtectionPage() {
  return <ProtectionClient />;
}
