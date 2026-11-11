import type { Metadata } from "next";
import RulesClient from "./rules-client";

export const metadata: Metadata = { title: "自定义规则 - My-OpenWaf" };

export default function RulesPage() {
  return <RulesClient />;
}
