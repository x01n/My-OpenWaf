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
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <AuthGuard>
      <div className="console-app-shell flex min-h-svh bg-slate-100/80 text-slate-950">
        {/* Mobile sidebar overlay */}
        {mobileOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
            onClick={() => setMobileOpen(false)}
          />
        )}
        <div
          className={
            mobileOpen
              ? "fixed inset-y-0 left-0 z-50 lg:relative lg:z-auto"
              : "hidden lg:flex"
          }
        >
          <SidebarNav
            collapsed={sidebarCollapsed}
            onToggle={() => {
              setSidebarCollapsed((value) => !value);
              if (mobileOpen) setMobileOpen(false);
            }}
          />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <DashboardTopbar onMobileMenuToggle={() => setMobileOpen((v) => !v)} />
          <main className="min-w-0 flex-1 overflow-y-auto">
            <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-6 px-4 py-6 sm:px-5 md:px-7">
              {children}
            </div>
          </main>
        </div>
      </div>
      <Toaster richColors />
    </AuthGuard>
  );
}
