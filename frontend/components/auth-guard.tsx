"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getAccessToken, refreshAccess, setAccessToken } from "@/lib/api";

/**
 * Check if a JWT access token is likely expired by decoding its payload.
 * Returns true if the token is missing, malformed, or within 60s of expiry.
 */
function isTokenExpiredOrSoon(token: string | null): boolean {
  if (!token) return true;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return true;
    const payload = JSON.parse(atob(parts[1]));
    if (!payload.exp) return true;
    // Consider expired if within 60 seconds of expiry.
    return payload.exp * 1000 <= Date.now() + 60_000;
  } catch {
    return true;
  }
}

function AuthGuardInner({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [ok, setOk] = useState(false);
  const [checking, setChecking] = useState(true);

  const message = useMemo(() => {
    const reason = searchParams.get("reason");
    if (reason === "session_expired")
      return "Your session has expired. Please log in again.";
    if (reason === "forbidden")
      return "You do not have permission to access that resource.";
    return null;
  }, [searchParams]);

  useEffect(() => {
    let cancelled = false;

    async function validateSession() {
      const token = getAccessToken();

      // If token exists and not expired/about-to-expire, we're good.
      if (token && !isTokenExpiredOrSoon(token)) {
        if (!cancelled) {
          setOk(true);
          setChecking(false);
        }
        return;
      }

      // Token is missing or expired — attempt refresh via cookie.
      const refreshed = await refreshAccess();
      if (cancelled) return;

      if (refreshed) {
        setOk(true);
        setChecking(false);
      } else {
        // Refresh failed — clear stale token and redirect to login.
        setAccessToken(null);
        setChecking(false);
        router.replace("/login/");
      }
    }

    validateSession();
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (checking) {
    // Show nothing while validating (prevents flash of content or login redirect).
    return null;
  }

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
