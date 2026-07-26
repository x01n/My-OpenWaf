/**
 * Dashboard 布局
 * SidebarProvider 包裹 shadcn 侧边栏 + 顶部栏 + 多标签工作区 + 主内容区。
 */

import { AppSidebar } from "@/components/sidebar-nav";
import { TopBar } from "@/components/top-bar";
import { BreadcrumbNav } from "@/components/breadcrumb-nav";
import { TabWorkspaceProvider } from "@/components/tab-workspace";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <TopBar />
        <TabWorkspaceProvider>
          <main className="flex-1 overflow-auto bg-background p-4 lg:p-6">
            <BreadcrumbNav />
            {children}
          </main>
        </TabWorkspaceProvider>
      </SidebarInset>
    </SidebarProvider>
  );
}
