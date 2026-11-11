import type { Metadata } from "next";
import CertificatesClient from "./certificates-client";

export const metadata: Metadata = {
  title: "证书管理 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 CertificatesClient 运行时拉取 */
export default function CertificatesPage() {
  return <CertificatesClient />;
}
