"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getAccessToken, refreshAccess } from "@/lib/api";

function AuthGuardInner({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [ok, setOk] = useState(() => !!getAccessToken());

  const message = useMemo(() => {
    const reason = searchParams.get("reason");
    if (reason === "session_expired") return "Your session has expired. Please log in again.";
    if (reason === "forbidden") return "You do not have permission to access that resource.";
    return null;
  }, [searchParams]);

  useEffect(() => {
    if (ok) return;
    refreshAccess().then((refreshed) => {
      if (refreshed) {
        setOk(true);
      } else {
        router.replace("/login/");
      }
    });
  }, [ok, router]);

  if (!ok) {
    if (message) {
      return (
        <div className="flex min-h-screen items-center justify-center">
          <p className="text-sm text-muted-foreground">{message}</p>
        </div>
      );
    }
    return null;
  }

  return <>{children}</>;
}

export function AuthGuard({ children }: { children: React.ReactNode }) {
  return (
    <Suspense>
      <AuthGuardInner>{children}</AuthGuardInner>
    </Suspense>
  );
}
