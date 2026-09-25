"use client"

import { useEffect, useRef, useState } from "react"
import { realtimeApi, getAccessToken } from "@/lib/api"
import type {
  SecurityEvent,
  RealtimeMessage,
  UpstreamStatus,
} from "@/lib/types"

const REALTIME_TICKET_TTL_MS = 55_000
const REALTIME_RECONNECT_DELAY_MS = 3_000

type WsStatus = "idle" | "connecting" | "open" | "closed"

function buildRealtimeURL(ticket: string, topics: string[]): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws"
  const params = new URLSearchParams({
    ticket,
    topics: topics.join(","),
  })
  return `${proto}://${window.location.host}/api/v1/realtime/ws?${params.toString()}`
}

/**
 * 订阅控制面实时推送的 security_event_snapshot，用于监控大屏的生命播报。
 *
 * 首次挂载即获取一次性 ticket（55 秒后重新取票重连），WS 异常断开后 3 秒退避
 * 重连。只有当 security_event_snapshot 载荷的条目集合发生变化时才触发渲染，
 * 快照型轮询推送（条目数与上次一致）不打断页面。
 */
export function useRealtimeEvents() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [status, setStatus] = useState<WsStatus>("idle")
  const socketRef = useRef<WebSocket | null>(null)
  const closedRef = useRef<boolean>(false)
  const signRef = useRef<string>("")

  useEffect(() => {
    let reloadTimer: ReturnType<typeof setTimeout> | undefined
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined

    const connect = () => {
      // 静态导出页面只在浏览器运行；SSR/预渲染期直接跳过。
      if (typeof window === "undefined") return

      // 未登录（无 access token）时静默放弃，避免向控制面刷无效 ticket。
      if (!getAccessToken()) {
        setStatus("closed")
        return
      }
      closedRef.current = false
      setStatus("connecting")

      realtimeApi
        .ticket()
        .then((resp) => {
          if (closedRef.current) return
          const ws = new WebSocket(
            buildRealtimeURL(resp.ticket, ["audit", "heartbeat"])
          )
          socketRef.current = ws
          ws.onopen = () => setStatus("open")
          ws.onmessage = (ev) => {
            try {
              const msg: RealtimeMessage<{
                security_events?: { items?: SecurityEvent[] }
              }> = JSON.parse(ev.data)
              if (msg.type !== "security_event_snapshot") return
              const items = msg.payload?.security_events?.items ?? []
              // sign 取最新条目 ID：快照重量随插入增长，仅变化时重渲染。
              const sign = items
                .map((e) => e.id)
                .join(",")
                .slice(0, 2000)
              if (sign !== signRef.current) {
                signRef.current = sign
                setEvents(items)
              }
            } catch {
              // 非 JSON 心跳等帧忽略；解析失败不打断连接。
            }
          }
          ws.onclose = () => {
            setStatus("closed")
            socketRef.current = null
            if (closedRef.current) return
            reconnectTimer = setTimeout(connect, REALTIME_RECONNECT_DELAY_MS)
          }
          ws.onerror = () => {
            // 错误通常伴随 onclose；此处只静音，重连由 onclose 负责。
            try {
              ws.close()
            } catch {
              // 已断开时 close 会抛，忽略。
            }
          }

          // ticket 有效期 60 秒（后端签发时约定的期限）。在到期前主动
          // 重连取新票：第一次换票即重新建立连接。
          reloadTimer = setTimeout(() => {
            try {
              ws.close()
            } catch {
              // 连接已断开时 close 会抛，忽略。
            }
          }, REALTIME_TICKET_TTL_MS)
        })
        .catch(() => {
          if (closedRef.current) return
          setStatus("closed")
          reconnectTimer = setTimeout(connect, REALTIME_RECONNECT_DELAY_MS)
        })
    }

    connect()
    return () => {
      closedRef.current = true
      if (reloadTimer) clearTimeout(reloadTimer)
      if (reconnectTimer) clearTimeout(reconnectTimer)
      const ws = socketRef.current
      if (ws) {
        socketRef.current = null
        try {
          ws.close()
        } catch {
          // 关闭时抛错忽略。
        }
      }
    }
  }, [])

  return { events, status }
}

/**
 * 订阅控制面实时推送的 upstream_snapshot，用于上游状态页的快速刷新。
 *
 * 结构对齐 useRealtimeEvents：挂载即取一次性 ticket（55 秒换票重连），
 * 异常断开后 3 秒退避重连。仅消费 upstream_snapshot 载荷的 items 与 total，
 * 其余帧忽略。未收到任何快照时返回空 items 与 total 0。
 */
export function useRealtimeOverview(): {
  items: UpstreamStatus[]
  total: number
} {
  const [overview, setOverview] = useState<{
    items: UpstreamStatus[]
    total: number
  } | null>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const closedRef = useRef<boolean>(false)

  useEffect(() => {
    let reloadTimer: ReturnType<typeof setTimeout> | undefined
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined

    const connect = () => {
      // 静态导出页面只在浏览器运行；SSR/预渲染期直接跳过。
      if (typeof window === "undefined") return

      // 未登录（无 access token）时静默放弃，避免向控制面刷无效 ticket。
      if (!getAccessToken()) return
      closedRef.current = false

      realtimeApi
        .ticket()
        .then((resp) => {
          if (closedRef.current) return
          const ws = new WebSocket(
            buildRealtimeURL(resp.ticket, ["upstreams"])
          )
          socketRef.current = ws
          ws.onmessage = (ev) => {
            try {
              const msg: RealtimeMessage<{
                upstreams?: { items?: UpstreamStatus[]; total?: number }
              }> = JSON.parse(ev.data)
              if (msg.type !== "upstream_snapshot") return
              const payload = msg.payload?.upstreams
              if (!payload) return
              setOverview({
                items: payload.items ?? [],
                total: payload.total ?? payload.items?.length ?? 0,
              })
            } catch {
              // 非 JSON 心跳等帧忽略；解析失败不打断连接。
            }
          }
          ws.onclose = () => {
            socketRef.current = null
            if (closedRef.current) return
            reconnectTimer = setTimeout(connect, REALTIME_RECONNECT_DELAY_MS)
          }
          ws.onerror = () => {
            // 错误通常伴随 onclose；此处只静音，重连由 onclose 负责。
            try {
              ws.close()
            } catch {
              // 已断开时 close 会抛，忽略。
            }
          }

          // ticket 有效期 60 秒（后端签发时约定的期限）。在到期前主动
          // 重连取新票：第一次换票即重新建立连接。
          reloadTimer = setTimeout(() => {
            try {
              ws.close()
            } catch {
              // 连接已断开时 close 会抛，忽略。
            }
          }, REALTIME_TICKET_TTL_MS)
        })
        .catch(() => {
          if (closedRef.current) return
          reconnectTimer = setTimeout(connect, REALTIME_RECONNECT_DELAY_MS)
        })
    }

    connect()
    return () => {
      closedRef.current = true
      if (reloadTimer) clearTimeout(reloadTimer)
      if (reconnectTimer) clearTimeout(reconnectTimer)
      const ws = socketRef.current
      if (ws) {
        socketRef.current = null
        try {
          ws.close()
        } catch {
          // 关闭时抛错忽略。
        }
      }
    }
  }, [])

  return overview || { items: [], total: 0 }
}