"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { getAccessToken, refreshAccess } from "@/lib/api"

export default function RootPage() {
  const router = useRouter()

  useEffect(() => {
    let cancelled = false
    async function routeBySession() {
      if (getAccessToken() || (await refreshAccess())) {
        if (!cancelled) router.replace("/dashboard/")
        return
      }
      if (!cancelled) router.replace("/login/")
    }
    routeBySession()
    return () => {
      cancelled = true
    }
  }, [router])

  return null
}
