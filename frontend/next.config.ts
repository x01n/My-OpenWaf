import type { NextConfig } from "next";

/**
 * Next.js 配置：静态导出模式。
 * 构建产物为纯静态文件（out/），由后端 Hertz 直接托管；
 * 页面骨架通过 RSC 在构建期预渲染，动态数据由客户端组件运行时拉取。
 */
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
