"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api/client";

/** 后端实时消息契约（internal/admin/system/realtime/realtime.go） */
export type RealtimeMessage = {
  schema: "admin.realtime.v1";
  type: string;
  seq: number;
  sent_at: string;
  payload: Record<string, unknown>;
};

export type RealtimeTopic =
  | "dashboard"
  | "runtime"
  | "upstreams"
  | "audit"
  | "fingerprints"
  | "heartbeat"
  | "all";

type RealtimeStatus = "connecting" | "open" | "closed";

/**
 * 订阅后端实时推送。
 * 流程：先取一次性 ticket（60 秒有效），再用 ticket 建立 WebSocket。
 * 断线自动指数退避重连；组件卸载时关闭连接。
 */
export function useRealtime(
  topics: RealtimeTopic[],
  onMessage: (msg: RealtimeMessage) => void,
) {
  const [status, setStatus] = useState<RealtimeStatus>("closed");
  const handlerRef = useRef(onMessage);
  handlerRef.current = onMessage;
  const topicsKey = topics.join(",");

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retryDelay = 1000;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    async function connect() {
      if (closed) return;
      try {
        setStatus("connecting");
        const { ticket } = await api.get<{ ticket: string; expires_at: string }>(
          "/realtime/ticket",
        );
        const proto = window.location.protocol === "https:" ? "wss" : "ws";
        const url = `${proto}://${window.location.host}/api/v1/realtime/ws?ticket=${ticket}&topics=${topicsKey}`;
        ws = new WebSocket(url);

        ws.onopen = () => {
          retryDelay = 1000;
          setStatus("open");
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data as string) as RealtimeMessage;
            if (msg.schema === "admin.realtime.v1") handlerRef.current(msg);
          } catch {
            /* 忽略无法解析的帧 */
          }
        };
        ws.onclose = () => {
          setStatus("closed");
          if (!closed) {
            retryTimer = setTimeout(connect, retryDelay);
            retryDelay = Math.min(retryDelay * 2, 15000);
          }
        };
        ws.onerror = () => ws?.close();
      } catch {
        // ticket 获取失败（如会话过期），退避后重试
        setStatus("closed");
        if (!closed) {
          retryTimer = setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, 15000);
        }
      }
    }

    void connect();

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      ws?.close();
    };
  }, [topicsKey]);

  return { status };
}
