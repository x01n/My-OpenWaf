"use client"

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"
import {
  api,
  type AccessLog,
  type DashboardSummary,
  type FingerprintSummary,
  type PaginatedResponse,
  type SecurityEvent,
  type UpstreamStatusResponse,
} from "@/lib/api"

const REALTIME_TOPICS = [
  "dashboard",
  "runtime",
  "upstreams",
  "audit",
  "fingerprints",
  "heartbeat",
] as const

export type RealtimeTopic = (typeof REALTIME_TOPICS)[number]

export interface RealtimeMessage<TPayload = unknown> {
  schema: "admin.realtime.v1"
  type: string
  seq: number
  sent_at: string
  payload: TPayload
}

export interface RuntimeSnapshot {
  status?: string
  [key: string]: unknown
}

interface DashboardPayload {
  dashboard: DashboardSummary
}

interface RuntimePayload {
  runtime: RuntimeSnapshot
}

interface UpstreamsPayload {
  upstreams: UpstreamStatusResponse
}

interface AccessLogPayload {
  access_logs: PaginatedResponse<AccessLog>
}

interface SecurityEventPayload {
  security_events: PaginatedResponse<SecurityEvent>
}

interface FingerprintPayload {
  fingerprints: PaginatedResponse<FingerprintSummary>
}

interface HeartbeatPayload {
  connection: string
}

interface HelloPayload {
  connection: string
  topics: Array<RealtimeTopic | "all">
}

interface RealtimeTicketResponse {
  ticket: string
  expires_at: string
}

export type RealtimeStatus =
  | "idle"
  | "connecting"
  | "open"
  | "closed"
  | "error"

export interface RealtimeState {
  status: RealtimeStatus
  topics: RealtimeTopic[]
  seq: number | null
  connectedAt: string | null
  lastMessageAt: string | null
  lastError: string | null
  dashboard: DashboardSummary | null
  dashboardPoints: Array<{
    time: string
    requests: number
    qps: number
    blocks: number
  }>
  runtime: RuntimeSnapshot | null
  upstreams: UpstreamStatusResponse | null
  accessLogs: PaginatedResponse<AccessLog> | null
  securityEvents: PaginatedResponse<SecurityEvent> | null
  fingerprints: PaginatedResponse<FingerprintSummary> | null
  heartbeat: HeartbeatPayload | null
}

const initialState: RealtimeState = {
  status: "idle",
  topics: [...REALTIME_TOPICS],
  seq: null,
  connectedAt: null,
  lastMessageAt: null,
  lastError: null,
  dashboard: null,
  dashboardPoints: [],
  runtime: null,
  upstreams: null,
  accessLogs: null,
  securityEvents: null,
  fingerprints: null,
  heartbeat: null,
}

const AdminRealtimeContext = createContext<RealtimeState>(initialState)

export function AdminRealtimeProvider({
  children,
}: {
  children: React.ReactNode
}) {
  const [state, setState] = useState<RealtimeState>(initialState)
  const reconnectTimerRef = useRef<number | null>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const stoppedRef = useRef(false)

  useEffect(() => {
    stoppedRef.current = false

    async function connect() {
      setState((current) => ({
        ...current,
        status: "connecting",
        lastError: null,
      }))

      try {
        const { ticket } = await api<RealtimeTicketResponse>(
          "/api/v1/realtime/ticket"
        )
        if (stoppedRef.current) return

        const params = new URLSearchParams({
          ticket,
          topics: REALTIME_TOPICS.join(","),
        })
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
        const socket = new WebSocket(
          `${protocol}//${window.location.host}/api/v1/realtime/ws?${params.toString()}`
        )
        socketRef.current = socket

        socket.onopen = () => {
          setState((current) => ({
            ...current,
            status: "open",
            connectedAt: new Date().toISOString(),
            lastError: null,
          }))
        }

        socket.onmessage = (event) => {
          const message = parseRealtimeMessage(event.data)
          if (!message) return
          setState((current) => reduceRealtimeMessage(current, message))
        }

        socket.onerror = () => {
          setState((current) => ({
            ...current,
            status: "error",
            lastError: "realtime websocket error",
          }))
        }

        socket.onclose = () => {
          if (socketRef.current === socket) socketRef.current = null
          setState((current) => ({
            ...current,
            status: stoppedRef.current ? "closed" : current.status,
          }))
          if (!stoppedRef.current) {
            reconnectTimerRef.current = window.setTimeout(connect, 3000)
          }
        }
      } catch (error) {
        if (stoppedRef.current) return
        setState((current) => ({
          ...current,
          status: "error",
          lastError:
            error instanceof Error ? error.message : "realtime ticket failed",
        }))
        reconnectTimerRef.current = window.setTimeout(connect, 5000)
      }
    }

    void connect()

    return () => {
      stoppedRef.current = true
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      socketRef.current?.close()
      socketRef.current = null
    }
  }, [])

  const value = useMemo(() => state, [state])

  return (
    <AdminRealtimeContext.Provider value={value}>
      {children}
    </AdminRealtimeContext.Provider>
  )
}

export function useAdminRealtime() {
  return useContext(AdminRealtimeContext)
}

function parseRealtimeMessage(input: unknown): RealtimeMessage | null {
  if (typeof input !== "string") return null
  try {
    const value = JSON.parse(input) as Partial<RealtimeMessage>
    if (
      value.schema !== "admin.realtime.v1" ||
      typeof value.type !== "string" ||
      typeof value.seq !== "number" ||
      typeof value.sent_at !== "string"
    ) {
      return null
    }
    return value as RealtimeMessage
  } catch {
    return null
  }
}

function reduceRealtimeMessage(
  current: RealtimeState,
  message: RealtimeMessage
): RealtimeState {
  const base: RealtimeState = {
    ...current,
    seq: message.seq,
    lastMessageAt: message.sent_at,
    lastError: null,
  }

  switch (message.type) {
    case "hello": {
      const payload = message.payload as HelloPayload
      return {
        ...base,
        status: "open",
        topics: payload.topics.filter(isRealtimeTopic),
      }
    }
    case "dashboard_snapshot":
      const dashboard = (message.payload as DashboardPayload).dashboard
      return {
        ...base,
        dashboard,
        dashboardPoints: appendDashboardPoint(
          current.dashboardPoints,
          dashboard,
          message.sent_at
        ),
      }
    case "runtime_snapshot":
      return {
        ...base,
        runtime: (message.payload as RuntimePayload).runtime,
      }
    case "upstream_snapshot":
      return {
        ...base,
        upstreams: (message.payload as UpstreamsPayload).upstreams,
      }
    case "access_log_snapshot":
      return {
        ...base,
        accessLogs: (message.payload as AccessLogPayload).access_logs,
      }
    case "security_event_snapshot":
      return {
        ...base,
        securityEvents: (message.payload as SecurityEventPayload)
          .security_events,
      }
    case "fingerprint_snapshot":
      return {
        ...base,
        fingerprints: (message.payload as FingerprintPayload).fingerprints,
      }
    case "heartbeat":
      return {
        ...base,
        heartbeat: message.payload as HeartbeatPayload,
      }
    default:
      return base
  }
}

function isRealtimeTopic(value: string): value is RealtimeTopic {
  return REALTIME_TOPICS.some((topic) => topic === value)
}

function appendDashboardPoint(
  points: RealtimeState["dashboardPoints"],
  dashboard: DashboardSummary,
  sentAt: string
): RealtimeState["dashboardPoints"] {
  const point = {
    time: new Date(sentAt).toLocaleTimeString("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    requests: dashboard.requests_total,
    qps: Number(dashboard.qps_5s.toFixed(2)),
    blocks: dashboard.waf_blocks,
  }
  const last = points[points.length - 1]
  if (
    last &&
    last.time === point.time &&
    last.requests === point.requests &&
    last.blocks === point.blocks
  ) {
    return points
  }
  return [...points, point].slice(-30)
}
