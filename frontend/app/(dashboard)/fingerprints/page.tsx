"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * 指纹分析功能已移除，访问此路由自动重定向至仪表盘。
 */
export default function FingerprintsPage() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/dashboard/");
  }, [router]);
  return null;
}
