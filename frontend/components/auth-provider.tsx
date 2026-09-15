"use client"

import { AuthContext, useAuthController } from "@/hooks/use-auth"

/** 在根布局中只创建一个认证控制器，统一管理 refresh 定时器和跨标签页事件。 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const value = useAuthController()
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
