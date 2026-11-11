import type { Metadata } from "next";
import ThreatIntelClient from "./threat-intel-client";

export const metadata: Metadata = { title: "威胁情报 - My-OpenWaf" };

export default function ThreatIntelPage() {
  return <ThreatIntelClient />;
}
