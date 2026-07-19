"use client";

import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const { t } = useTranslation();

  useEffect(() => {
    if (process.env.NODE_ENV === "development") {
      console.error("[Dashboard Error]", error);
    }
  }, [error]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6">
      <div className="mx-auto max-w-sm space-y-4 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
          <IconAlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <h2 className="text-lg font-semibold">{t("error.pageLoadFailed")}</h2>
        <p className="text-sm text-muted-foreground">
          {error.message || t("error.unexpectedError")}
        </p>
        <Button onClick={reset} variant="outline" size="sm">
          <IconRefresh className="mr-1.5 h-4 w-4" />
          {t("error.retry")}
        </Button>
      </div>
    </div>
  );
}
