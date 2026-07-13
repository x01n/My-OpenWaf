/**
 * Dashboard 布局
 * 包含侧边栏 + 顶部栏 + 主内容区
 */

import { Sidebar } from "@/components/sidebar-nav";
import { TopBar } from "@/components/top-bar";
import { BreadcrumbNav } from "@/components/breadcrumb-nav";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-svh">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-auto bg-background p-4 lg:p-6">
          <BreadcrumbNav />
          {children}
        </main>
      </div>
    </div>
  );
}
