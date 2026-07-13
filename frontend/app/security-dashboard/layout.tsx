/**
 * 安全防护监控大屏独立布局
 *
 * 不引入侧边栏和顶部栏，作为可全屏投屏使用的独立页面。
 * 通过 `dark` class 强制暗色主题，确保 shadcn Card 等组件跟随深色变量渲染。
 * 根 layout 已提供 ThemeProvider、I18nProvider 和 TooltipProvider。
 */

export default function SecurityDashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="dark min-h-svh bg-slate-950 text-slate-100 antialiased">
      {children}
    </div>
  );
}
