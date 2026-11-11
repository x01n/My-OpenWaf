import type { Metadata } from "next";
import IPListsClient from "./ip-lists-client";

export const metadata: Metadata = { title: "IP 名单 - My-OpenWaf" };

export default function IPListsPage() {
  return <IPListsClient />;
}
