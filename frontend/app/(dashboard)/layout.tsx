"use client";

import { useState } from "react";
import { AuthGuard } from "@/components/auth-guard";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
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
      <div className="flex h-svh overflow-hidden bg-gray-100 text-gray-900">
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
          <Sidebar
            collapsed={sidebarCollapsed}
            onToggle={() => {
              setSidebarCollapsed((v) => !v);
              if (mobileOpen) setMobileOpen(false);
            }}
          />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onMobileMenuToggle={() => setMobileOpen((v) => !v)} />
          <main className="flex-1 overflow-y-auto bg-gray-100 p-6">
            <div className="mx-auto w-full max-w-[1600px]">{children}</div>
          </main>
        </div>
      </div>
      <Toaster richColors />
    </AuthGuard>
  );
}
