"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    if (process.env.NODE_ENV === "development") {
      console.error("[Error Boundary]", error);
    }
  }, [error]);

  return (
    <div className="flex min-h-[50vh] items-center justify-center p-4">
      <div className="mx-auto max-w-md space-y-4 text-center">
        <h2 className="text-xl font-semibold text-destructive">页面加载失败</h2>
        <p className="text-sm text-muted-foreground">
          该页面出现异常，请尝试重新加载。
        </p>
        <Button onClick={reset} variant="outline" size="sm">
          重新加载
        </Button>
      </div>
    </div>
  );
}
