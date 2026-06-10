"use client"

import { useState } from "react"
import { AuthGuard } from "@/components/auth-guard"
import { Sidebar } from "@/components/layout/sidebar"
import { Topbar } from "@/components/layout/topbar"
import { Toaster } from "@/components/ui/sonner"
import { AdminRealtimeProvider } from "@/lib/admin-realtime"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <AuthGuard>
      <AdminRealtimeProvider>
        <div className="console-app-shell flex h-svh overflow-hidden text-foreground">
          {mobileOpen && (
            <div
              className="fixed inset-0 z-40 bg-foreground/40 lg:hidden"
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
                setSidebarCollapsed((v) => !v)
                if (mobileOpen) setMobileOpen(false)
              }}
            />
          </div>
          <div className="flex min-w-0 flex-1 flex-col">
            <Topbar onMobileMenuToggle={() => setMobileOpen((v) => !v)} />
            <main className="flex-1 overflow-y-auto p-4 sm:p-5 lg:p-6">
              <div className="w-full">{children}</div>
            </main>
          </div>
        </div>
      </AdminRealtimeProvider>
      <Toaster richColors />
    </AuthGuard>
  )
}
