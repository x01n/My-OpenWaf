"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    if (process.env.NODE_ENV === "development") {
      console.error("[GlobalError]", error);
    }
  }, [error]);

  return (
    <html lang="zh-CN">
      <body className="flex min-h-screen items-center justify-center bg-background p-4">
        <div className="mx-auto max-w-md space-y-4 text-center">
          <h1 className="text-2xl font-bold text-destructive">应用异常</h1>
          <p className="text-muted-foreground">
            发生了意外错误，请尝试刷新页面。
          </p>
          <Button onClick={reset} variant="outline">
            重试
          </Button>
        </div>
      </body>
    </html>
  );
}
