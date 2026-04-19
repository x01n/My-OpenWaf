import SiteDetailClient from "./client";

export const dynamicParams = false;

export async function generateStaticParams() {
  return [{ id: "0" }];
}

export default function SiteDetailPage() {
  return <SiteDetailClient />;
}
