import type { Metadata } from "next";
import LuaPluginsClient from "./lua-plugins-client";

export const metadata: Metadata = {
  title: "Lua 插件 - My-OpenWaf",
};

/** RSC 静态骨架：页面壳在构建期预渲染，动态数据由 LuaPluginsClient 运行时拉取 */
export default function LuaPluginsPage() {
  return <LuaPluginsClient />;
}
