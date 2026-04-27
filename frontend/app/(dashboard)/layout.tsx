"use client";

import { useState } from "react";
import { AuthGuard } from "@/components/auth-guard";
import { DashboardTopbar } from "@/components/dashboard-topbar";
import { SidebarNav } from "@/components/sidebar-nav";
import { Toaster } from "@/components/ui/sonner";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <AuthGuard>
      <div className="console-app-shell flex min-h-svh bg-slate-100/80 text-slate-950">
        <SidebarNav
          collapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed((value) => !value)}
        />
        <div className="flex min-w-0 flex-1 flex-col">
          <DashboardTopbar />
          <main className="min-w-0 flex-1 overflow-y-auto">
            <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-6 px-5 py-6 md:px-7">
              {children}
            </div>
          </main>
        </div>
      </div>
      <Toaster richColors />
    </AuthGuard>
  );
}
