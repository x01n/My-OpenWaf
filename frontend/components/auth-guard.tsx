"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getAccessToken } from "@/lib/api";

function AuthGuardInner({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [ok, setOk] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const reason = searchParams.get("reason");
    if (reason === "session_expired") {
      setMessage("Your session has expired. Please log in again.");
    } else if (reason === "forbidden") {
      setMessage("You do not have permission to access that resource.");
    }

    if (!getAccessToken()) {
      router.replace("/login/");
    } else {
      setOk(true);
    }
  }, [router, searchParams]);

  if (!ok) {
    if (message) {
      return (
        <div className="flex items-center justify-center min-h-screen">
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
