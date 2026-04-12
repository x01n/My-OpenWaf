"use client";

import { AuthGuard } from "@/components/auth-guard";
import { DashboardTopbar } from "@/components/dashboard-topbar";
import { SidebarNav } from "@/components/sidebar-nav";
import { Toaster } from "@/components/ui/sonner";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <div className="flex h-svh overflow-hidden bg-background">
        <SidebarNav />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <DashboardTopbar />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-6xl px-6 py-6">{children}</div>
          </main>
        </div>
      </div>
      <Toaster />
    </AuthGuard>
  );
}
