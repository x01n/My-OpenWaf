import type { Metadata } from "next";
import JsPluginsClient from "./js-plugins-client";

export const metadata: Metadata = {
  title: "JS 插件 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 JsPluginsClient 运行时拉取 */
export default function JsPluginsPage() {
  return <JsPluginsClient />;
}
