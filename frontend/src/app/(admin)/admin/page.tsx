import type { Metadata } from "next";
import AdminClient from "./admin-client";

export const metadata: Metadata = { title: "账户与密钥 - My-OpenWaf" };

export default function AdminPage() {
  return <AdminClient />;
}
