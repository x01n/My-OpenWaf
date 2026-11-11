import type { Metadata } from "next";
import PoliciesClient from "./policies-client";

export const metadata: Metadata = { title: "策略管理 - My-OpenWaf" };

export default function PoliciesPage() {
  return <PoliciesClient />;
}
