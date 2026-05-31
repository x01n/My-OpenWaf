import type { Metadata } from "next"

import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"

export const metadata: Metadata = {
  title: {
    default: "My-OpenWAF 控制台",
    template: "%s · My-OpenWAF",
  },
  description: "面向站点接入、规则治理、日志审计与防护策略编排的 My-OpenWAF 管理控制台。",
  applicationName: "My-OpenWAF",
  keywords: ["WAF", "Web Application Firewall", "安全防护", "My-OpenWAF"],
  authors: [{ name: "My-OpenWAF" }],
  creator: "My-OpenWAF",
  icons: {
    icon: "/favicon.ico",
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="zh-CN"
      suppressHydrationWarning
      className="font-sans antialiased"
    >
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  )
}
