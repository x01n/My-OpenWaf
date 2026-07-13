"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { format } from "date-fns";
import { zhCN } from "date-fns/locale";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  IconCopy,
  IconShieldExclamation,
  IconShieldOff,
  IconLock,
  IconChevronDown,
  IconListDetails,
  IconWorld,
  IconFingerprint,
  IconTag,
  IconRoute,
  IconClock,
  IconHash,
  IconUser,
  IconFileDescription,
  IconAlertTriangle,
  IconMessageReport,
  IconShieldLock,
  IconMapPin,
} from "@tabler/icons-react";
import type { SecurityEvent, IPEntry } from "@/lib/types";
import { ipListApi, falsePositiveApi } from "@/lib/api";
import { countryFlag, countryName } from "@/lib/country-names";
import { categoryLabel } from "@/lib/attack-category";
import { Textarea } from "@/components/ui/textarea";

interface SecurityEventDetailDialogProps {
  event: SecurityEvent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * 判断动作是否属于"拦截/阻断"类型
 */
function isBlockAction(action: string): boolean {
  return action === "block" || action === "intercept" || action === "drop";
}

/**
 * 判断动作是否属于"挑战"类型
 */
function isChallengeAction(action: string): boolean {
  return (
    action === "challenge" ||
    action === "captcha_challenge" ||
    action === "shield_challenge" ||
    action === "chain_challenge"
  );
}

/**
 * 获取动作对应的 Badge 样式类名
 */
function getActionBadgeClass(action: string): string {
  if (isBlockAction(action))
    return "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400";
  if (action === "observe" || action === "log_only")
    return "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400";
  if (isChallengeAction(action))
    return "border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400";
  if (action === "allow")
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400";
  return "";
}

/**
 * 印章类型：拦截 -> deny；观察 -> observe；放行 -> allow
 */
function stampVariant(action: string): "deny" | "allow" | "observe" | null {
  if (isBlockAction(action) || isChallengeAction(action)) return "deny";
  if (action === "allow") return "allow";
  if (action === "observe" || action === "log_only") return "observe";
  return null;
}

/**
 * 构建完整请求 URL
 */
function buildFullUrl(ev: SecurityEvent): string {
  const scheme = ev.tls_version ? "https" : "http";
  const host = ev.host || "unknown";
  const path = ev.path || "/";
  const qs = ev.query_string ? `?${ev.query_string}` : "";
  return `${scheme}://${host}${path}${qs}`;
}

/**
 * 重建 HTTP 请求报文用于展示。
 *
 * @param ev 安全事件
 * @param encoding "utf8"（默认）或 "ascii"（对非 ASCII 字符转义为 \xHH）
 */
function reconstructRequest(ev: SecurityEvent, encoding: "utf8" | "ascii"): string {
  const path = ev.path || "/";
  const qs = ev.query_string ? `?${ev.query_string}` : "";
  let text = `${ev.method} ${path}${qs} HTTP/1.1\r\nHost: ${ev.host}\r\n`;
  if (ev.request_headers) {
    text += ev.request_headers
      .split("\n")
      .filter((l) => !/^host:/i.test(l.trim()))
      .join("\n");
  }
  if (ev.request_body_preview) {
    text += `\r\n\r\n${ev.request_body_preview}`;
    if (ev.request_body_truncated) text += "\n... (truncated)";
  }
  if (encoding === "ascii") {
    return text.replace(/[^\x00-\x7F]/g, (ch) => {
      const cp = ch.codePointAt(0) ?? 0;
      if (cp <= 0xff) return `\\x${cp.toString(16).padStart(2, "0")}`;
      return `\\u${cp.toString(16).padStart(4, "0")}`;
    });
  }
  return text;
}

/**
 * 根据事件详情生成 cURL 命令
 */
function buildCurlCommand(ev: SecurityEvent): string {
  const url = buildFullUrl(ev);
  let cmd = `curl -X ${ev.method} '${url}'`;
  if (ev.request_headers) {
    const lines = ev.request_headers.split("\n").filter(Boolean);
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) cmd += ` \\\n  -H '${trimmed}'`;
    }
  }
  if (ev.request_body_preview) {
    const escaped = ev.request_body_preview.replace(/'/g, "'\\''");
    cmd += ` \\\n  --data '${escaped}'`;
  }
  if (ev.tls_version) cmd += " \\\n  --insecure";
  return cmd;
}

/**
 * 简单 HTTP 报文语法高亮渲染
 */
function renderHttpSyntax(raw: string): React.ReactNode {
  const lines = raw.split(/\r?\n/);
  return lines.map((line, i) => {
    const colonIdx = line.indexOf(":");
    if (i === 0) {
      const parts = line.match(/^(\S+)\s(.+?)\s(HTTP\/\S+)/);
      if (parts) {
        return (
          <span key={i}>
            <span className="text-emerald-400 font-semibold">{parts[1]}</span>{" "}
            <span className="text-sky-300">{parts[2]}</span>{" "}
            <span className="text-zinc-500">{parts[3]}</span>
            {"\n"}
          </span>
        );
      }
    }
    if (
      colonIdx > 0 &&
      i > 0 &&
      !line.startsWith(" ") &&
      !line.startsWith("\t")
    ) {
      const headerName = line.slice(0, colonIdx);
      const headerVal = line.slice(colonIdx);
      return (
        <span key={i}>
          <span className="text-violet-400">{headerName}</span>
          <span className="text-zinc-400">{headerVal}</span>
          {"\n"}
        </span>
      );
    }
    return (
      <span key={i}>
        {line}
        {"\n"}
      </span>
    );
  });
}

/**
 * 复制文本到剪贴板，成功/失败均以 toast 反馈。
 */
function copyToClipboard(text: string, successMsg: string, failMsg: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success(successMsg),
    () => toast.error(failMsg),
  );
}

/**
 * 印章角标：Deny / Allow / Observe，纯视觉装饰。
 */
function StampBadge({ variant }: { variant: "deny" | "allow" | "observe" }) {
  const cls =
    variant === "deny"
      ? "border-red-500/60 text-red-500/80"
      : variant === "allow"
        ? "border-emerald-500/60 text-emerald-500/80"
        : "border-amber-500/60 text-amber-500/80";
  const text =
    variant === "deny" ? "DENY" : variant === "allow" ? "ALLOW" : "OBSERVE";
  return (
    <div
      className={`pointer-events-none absolute right-6 top-1/2 -translate-y-1/2 rotate-[-12deg] rounded-md border-[3px] px-3 py-1 font-mono text-lg font-black tracking-widest opacity-70 select-none ${cls}`}
      aria-hidden
    >
      {text}
    </div>
  );
}

/**
 * 单元格条目：图标 + 标签 + 值 + 可选操作。
 */
function InfoRow({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2.5 rounded-md border bg-muted/20 px-3 py-2.5">
      <div className="mt-0.5 shrink-0 text-muted-foreground">{icon}</div>
      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </div>
        <div className="text-sm">{children}</div>
      </div>
    </div>
  );
}

/**
 * 安全事件详情弹窗组件。
 *
 * 展示雷池风格的攻击详情：顶部动作徽章 + URL + Deny 印章；
 * 中部关键信息网格；底部 Tab 切换请求/响应报文与 AI 分析（占位）；
 * 支持复制 cURL、加入黑名单、误报反馈等快捷操作。
 */
export function SecurityEventDetailDialog({
  event,
  open,
  onOpenChange,
}: SecurityEventDetailDialogProps) {
  const { t } = useTranslation();
  const [reqEncoding, setReqEncoding] = useState<"utf8" | "ascii">("utf8");
  const [uaExpanded, setUaExpanded] = useState(false);
  const [banLoading, setBanLoading] = useState(false);
  const [fpDialogOpen, setFpDialogOpen] = useState(false);
  const [fpNote, setFpNote] = useState("");
  const [fpLoading, setFpLoading] = useState(false);

  const actionLabelMap: Record<string, string> = useMemo(
    () => ({
      block: t("securityEvents.action.block"),
      intercept: t("securityEvents.action.intercept"),
      observe: t("securityEvents.action.observe"),
      challenge: t("securityEvents.action.challenge"),
      captcha_challenge: t("securityEvents.action.captcha_challenge"),
      shield_challenge: t("securityEvents.action.shield_challenge"),
      chain_challenge: t("securityEvents.action.chain_challenge"),
      allow: t("securityEvents.action.allow"),
      drop: t("securityEvents.action.drop"),
      log_only: t("securityEvents.action.log_only"),
    }),
    [t],
  );

  if (!event) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-4xl" />
      </Dialog>
    );
  }

  const ev = event;
  const fullUrl = buildFullUrl(ev);
  const stamp = stampVariant(ev.action);
  const hasTls =
    ev.tls_version ||
    ev.tls_sni ||
    ev.tls_ja3 ||
    ev.tls_ja3_hash ||
    ev.tls_ja4 ||
    ev.tls_alpn ||
    ev.tls_cipher_suites;

  const attackTime = (() => {
    try {
      return format(new Date(ev.created_at), "yyyy-MM-dd HH:mm:ss", {
        locale: zhCN,
      });
    } catch {
      return ev.created_at;
    }
  })();

  const copySuccess = t("common.copied", { defaultValue: "已复制" });
  const copyFail = t("common.copyFailed", { defaultValue: "复制失败" });

  const handleAddToBlocklist = async () => {
    setBanLoading(true);
    try {
      const payload: Partial<IPEntry> = {
        value: ev.client_ip,
        kind: "blacklist",
        action: "intercept",
        note: t("securityEventDetail.blocklistNote", {
          defaultValue: `来自安全事件 #${ev.id}`,
          id: ev.id,
        }),
      };
      await ipListApi.create(payload);
      toast.success(
        t("securityEventDetail.addedToBlocklist", {
          defaultValue: "已加入 IP 黑名单",
        }),
      );
    } catch {
      toast.error(
        t("securityEventDetail.addBlocklistFailed", {
          defaultValue: "加入黑名单失败",
        }),
      );
    } finally {
      setBanLoading(false);
    }
  };

  const handleReportFalsePositive = () => {
    setFpNote("");
    setFpDialogOpen(true);
  };

  const handleSubmitFalsePositive = async () => {
    setFpLoading(true);
    try {
      await falsePositiveApi.create({
        security_event_id: ev.id,
        request_id: ev.request_id,
        rule_id_str: ev.rule_id_str || String(ev.rule_id ?? ""),
        category: ev.category,
        client_ip: ev.client_ip,
        host: ev.host,
        path: ev.path,
        match_desc: ev.match_desc || "",
        note: fpNote,
      });
      toast.success(
        t("falsePositives.submitSuccess", {
          defaultValue: "反馈已提交",
        }),
      );
      setFpDialogOpen(false);
    } catch {
      toast.error(
        t("falsePositives.submitFailed", {
          defaultValue: "反馈提交失败",
        }),
      );
    } finally {
      setFpLoading(false);
    }
  };

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto p-0">
        <div className="sr-only">
          <DialogTitle>
            {t("securityEventDetail.dialogTitle", {
              defaultValue: "安全事件详情",
            })}
          </DialogTitle>
          <DialogDescription>{fullUrl}</DialogDescription>
        </div>

        {/* ====== 顶部横幅：动作 Badge + URL + Deny/Allow 印章 ====== */}
        <div className="relative overflow-hidden border-b bg-gradient-to-br from-muted/60 via-muted/30 to-transparent px-6 py-5">
          <div className="flex items-start gap-3 pr-24">
            <Badge
              className={`mt-0.5 shrink-0 border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${getActionBadgeClass(
                ev.action,
              )}`}
            >
              {actionLabelMap[ev.action] || ev.action}
            </Badge>
            <button
              type="button"
              className="min-w-0 break-all text-left font-mono text-sm leading-relaxed text-foreground/90 hover:text-primary"
              title={t("securityEventDetail.clickToCopyUrl", {
                defaultValue: "点击复制 URL",
              })}
              onClick={() => copyToClipboard(fullUrl, copySuccess, copyFail)}
            >
              {fullUrl}
            </button>
          </div>
          {stamp && <StampBadge variant={stamp} />}
          <div className="pointer-events-none absolute -bottom-6 -left-4 opacity-[0.05]">
            <IconShieldOff className="h-40 w-40" strokeWidth={1} />
          </div>
        </div>

        {/* ====== 关键信息网格 ====== */}
        <div className="grid grid-cols-1 gap-2.5 border-b px-6 py-5 md:grid-cols-2">
          {/* 攻击者来源 */}
          <InfoRow
            icon={<IconWorld className="h-4 w-4" />}
            label={t("securityEventDetail.attackSource", {
              defaultValue: "攻击者来源",
            })}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono font-medium">{ev.client_ip}</span>
              {ev.geo_country && (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <span className="text-base leading-none">
                    {countryFlag(ev.geo_country)}
                  </span>
                  <span>{countryName(ev.geo_country)}</span>
                  {ev.geo_city && <span>/ {ev.geo_city}</span>}
                </span>
              )}
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 gap-1 px-1.5 text-xs text-primary hover:bg-primary/10"
                  disabled={banLoading}
                  onClick={handleAddToBlocklist}
                >
                  <IconShieldLock className="h-3 w-3" />
                  {t("securityEventDetail.addToBlocklist", {
                    defaultValue: "加入黑名单",
                  })}
                </Button>
              </div>
            </div>
          </InfoRow>

          {/* JA4 指纹 */}
          <InfoRow
            icon={<IconFingerprint className="h-4 w-4" />}
            label={t("securityEventDetail.ja4Fingerprint", {
              defaultValue: "JA4 指纹",
            })}
          >
            {ev.tls_ja4 ? (
              <button
                type="button"
                className="break-all text-left font-mono text-xs hover:text-primary"
                onClick={() =>
                  copyToClipboard(ev.tls_ja4 || "", copySuccess, copyFail)
                }
                title={t("securityEventDetail.clickToCopy", {
                  defaultValue: "点击复制",
                })}
              >
                {ev.tls_ja4}
              </button>
            ) : (
              <span className="text-xs text-muted-foreground">
                {t("securityEventDetail.noFingerprint", {
                  defaultValue: "无（非 TLS 连接）",
                })}
              </span>
            )}
          </InfoRow>

          {/* 命中防护模块 */}
          <InfoRow
            icon={<IconShieldExclamation className="h-4 w-4" />}
            label={t("securityEventDetail.hitModule", {
              defaultValue: "命中防护模块",
            })}
          >
            <div className="flex items-center gap-2">
              <span>{categoryLabel(ev.category)}</span>
              <span className="text-xs text-muted-foreground">
                ({ev.phase})
              </span>
            </div>
          </InfoRow>

          {/* 规则名称 */}
          <InfoRow
            icon={<IconTag className="h-4 w-4" />}
            label={t("securityEventDetail.ruleName", {
              defaultValue: "规则名称",
            })}
          >
            <span className="font-mono text-xs">
              {ev.rule_id_str || `#${ev.rule_id}`}
            </span>
          </InfoRow>

          {/* 攻击时间 */}
          <InfoRow
            icon={<IconClock className="h-4 w-4" />}
            label={t("securityEventDetail.attackTime", {
              defaultValue: "攻击时间",
            })}
          >
            <span>{attackTime}</span>
          </InfoRow>

          {/* 请求 ID */}
          <InfoRow
            icon={<IconHash className="h-4 w-4" />}
            label={t("securityEventDetail.requestId", {
              defaultValue: "请求 ID",
            })}
          >
            <button
              type="button"
              className="break-all text-left font-mono text-xs text-foreground/70 hover:text-primary"
              onClick={() =>
                copyToClipboard(ev.request_id, copySuccess, copyFail)
              }
            >
              {ev.request_id}
            </button>
          </InfoRow>

          {/* HTTP 方法 + 状态码 */}
          <InfoRow
            icon={<IconRoute className="h-4 w-4" />}
            label={t("securityEventDetail.methodStatus", {
              defaultValue: "方法 / 状态码",
            })}
          >
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="h-5 px-1.5 text-xs">
                {ev.method}
              </Badge>
              {ev.status_code > 0 && (
                <Badge
                  variant="outline"
                  className={`h-5 px-1.5 text-xs ${
                    ev.status_code >= 400
                      ? "border-red-500/40 text-red-600 dark:text-red-400"
                      : ""
                  }`}
                >
                  {ev.status_code}
                </Badge>
              )}
            </div>
          </InfoRow>

          {/* Host 与站点 ID */}
          <InfoRow
            icon={<IconMapPin className="h-4 w-4" />}
            label={t("securityEventDetail.hostSite", {
              defaultValue: "Host / 站点",
            })}
          >
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="break-all font-mono text-xs">{ev.host}</span>
              <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">
                site #{ev.site_id}
              </Badge>
            </div>
          </InfoRow>

          {/* User-Agent（可展开） */}
          {ev.user_agent && (
            <div className="md:col-span-2">
              <InfoRow
                icon={<IconUser className="h-4 w-4" />}
                label={t("securityEventDetail.userAgent", {
                  defaultValue: "User-Agent",
                })}
              >
                <button
                  type="button"
                  onClick={() => setUaExpanded((v) => !v)}
                  className={`block w-full break-all text-left font-mono text-xs text-foreground/80 hover:text-primary ${
                    uaExpanded ? "" : "line-clamp-1"
                  }`}
                  title={
                    uaExpanded
                      ? t("securityEventDetail.collapse", {
                          defaultValue: "点击收起",
                        })
                      : t("securityEventDetail.expand", {
                          defaultValue: "点击展开",
                        })
                  }
                >
                  {ev.user_agent}
                </button>
              </InfoRow>
            </div>
          )}
        </div>

        {/* ====== 攻击载荷 ====== */}
        {ev.match_desc && (
          <div className="border-b px-6 py-4">
            <div className="mb-2 flex items-center gap-1.5">
              <IconAlertTriangle className="h-4 w-4 text-amber-500" />
              <span className="text-xs font-medium text-foreground/80">
                {t("securityEventDetail.attackPayload", {
                  defaultValue: "攻击载荷",
                })}
              </span>
            </div>
            <div className="rounded-md border border-red-500/20 bg-red-500/5 px-4 py-3 dark:border-red-500/10 dark:bg-red-500/5">
              <p className="break-all font-mono text-xs leading-relaxed text-red-700 dark:text-red-300">
                {ev.match_desc}
              </p>
            </div>
          </div>
        )}

        {/* ====== Tab 切换：请求 / 响应 / AI 分析 ====== */}
        <div className="border-b px-6 py-4">
          <Tabs defaultValue="request">
            <div className="mb-3 flex items-center justify-between">
              <TabsList>
                <TabsTrigger value="request">
                  <IconListDetails className="mr-1 h-3.5 w-3.5" />
                  {t("securityEventDetail.requestMessage", {
                    defaultValue: "请求报文",
                  })}
                </TabsTrigger>
                <TabsTrigger value="response">
                  <IconFileDescription className="mr-1 h-3.5 w-3.5" />
                  {t("securityEventDetail.responseMessage", {
                    defaultValue: "响应报文",
                  })}
                </TabsTrigger>
                <TabsTrigger value="ai" disabled>
                  <IconMessageReport className="mr-1 h-3.5 w-3.5" />
                  {t("securityEventDetail.aiAnalysis", {
                    defaultValue: "AI 分析",
                  })}
                </TabsTrigger>
              </TabsList>
              <Select
                value={reqEncoding}
                onValueChange={(v) => setReqEncoding(v as "utf8" | "ascii")}
              >
                <SelectTrigger className="h-7 w-[120px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent align="end">
                  <SelectItem value="utf8">UTF-8</SelectItem>
                  <SelectItem value="ascii">ASCII</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <TabsContent value="request">
              <div className="overflow-auto rounded-lg bg-zinc-900 p-4 dark:bg-zinc-950">
                <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-zinc-200">
                  {renderHttpSyntax(reconstructRequest(ev, reqEncoding))}
                </pre>
              </div>
            </TabsContent>

            <TabsContent value="response">
              <div className="overflow-auto rounded-lg bg-zinc-900 p-4 dark:bg-zinc-950">
                <pre className="font-mono text-xs leading-relaxed text-zinc-400">
                  {ev.status_code
                    ? `HTTP/1.1 ${ev.status_code}\r\n\r\n(${t(
                        "securityEventDetail.responseNotCaptured",
                        { defaultValue: "响应正文未捕获" },
                      )})`
                    : t("securityEventDetail.noResponseData", {
                        defaultValue: "暂无响应数据",
                      })}
                </pre>
              </div>
            </TabsContent>

            <TabsContent value="ai">
              <div className="rounded-lg border border-dashed bg-muted/20 p-6 text-center text-xs text-muted-foreground">
                {t("securityEventDetail.aiAnalysisPlaceholder", {
                  defaultValue:
                    "智能 AI 攻击分析即将上线，将根据请求特征给出攻击类型判断和处置建议",
                })}
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* ====== TLS 信息折叠区 ====== */}
        {hasTls && (
          <div className="border-b px-6 py-4">
            <Collapsible>
              <CollapsibleTrigger className="group flex w-full items-center gap-2 text-xs font-medium text-foreground/80 hover:text-foreground">
                <IconLock className="h-3.5 w-3.5 text-emerald-500" />
                {t("securityEventDetail.tlsInfo", { defaultValue: "TLS 信息" })}
                <IconChevronDown className="ml-auto h-3.5 w-3.5 transition-transform group-data-[state=open]:rotate-180" />
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 rounded-lg border bg-muted/30 p-4">
                  {ev.tls_version && (
                    <div>
                      <span className="text-xs text-muted-foreground">
                        TLS Version
                      </span>
                      <p className="font-mono text-xs">{ev.tls_version}</p>
                    </div>
                  )}
                  {ev.tls_sni && (
                    <div>
                      <span className="text-xs text-muted-foreground">SNI</span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_sni}
                      </p>
                    </div>
                  )}
                  {ev.tls_alpn && (
                    <div>
                      <span className="text-xs text-muted-foreground">
                        ALPN
                      </span>
                      <p className="font-mono text-xs">{ev.tls_alpn}</p>
                    </div>
                  )}
                  {ev.tls_ja3_hash && (
                    <div>
                      <span className="text-xs text-muted-foreground">
                        JA3 Hash
                      </span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_ja3_hash}
                      </p>
                    </div>
                  )}
                  {ev.tls_ja3 && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">JA3</span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_ja3}
                      </p>
                    </div>
                  )}
                  {ev.tls_ja4 && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">JA4</span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_ja4}
                      </p>
                    </div>
                  )}
                  {ev.tls_cipher_suites && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">
                        Cipher Suites
                      </span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_cipher_suites}
                      </p>
                    </div>
                  )}
                  {ev.tls_extensions && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">
                        Extensions
                      </span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_extensions}
                      </p>
                    </div>
                  )}
                  {ev.tls_curves && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">
                        Curves
                      </span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_curves}
                      </p>
                    </div>
                  )}
                  {ev.tls_point_formats && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">
                        Point Formats
                      </span>
                      <p className="break-all font-mono text-xs">
                        {ev.tls_point_formats}
                      </p>
                    </div>
                  )}
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>
        )}

        {/* ====== 底部操作栏 ====== */}
        <div className="flex flex-wrap items-center justify-between gap-2 px-6 py-4">
          <Button
            variant="link"
            size="sm"
            className="h-auto gap-1 p-0 text-xs text-muted-foreground hover:text-primary"
            onClick={handleReportFalsePositive}
            disabled={fpLoading}
          >
            <IconMessageReport className="h-3.5 w-3.5" />
            {t("securityEventDetail.reportFalsePositive", {
              defaultValue: "这是误报，点击反馈",
            })}
          </Button>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-xs"
              onClick={() =>
                copyToClipboard(
                  buildCurlCommand(ev),
                  copySuccess,
                  copyFail,
                )
              }
            >
              <IconCopy className="h-3.5 w-3.5" />
              {t("securityEventDetail.copyCurl", { defaultValue: "复制 cURL" })}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-xs"
              onClick={() => onOpenChange(false)}
            >
              {t("common.close", { defaultValue: "关闭" })}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>

      {/* ====== 误报反馈提交对话框 ====== */}
      <Dialog open={fpDialogOpen} onOpenChange={setFpDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogTitle>
            {t("falsePositives.reportDialogTitle", {
              defaultValue: "提交误报反馈",
            })}
          </DialogTitle>
          <DialogDescription>
            {t("falsePositives.reportDialogDesc", {
              defaultValue:
                "确认该请求被误判为攻击？可留下备注帮助后续审查。",
            })}
          </DialogDescription>
          <div className="space-y-3 pt-2">
            <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
              <div className="text-muted-foreground">
                {t("falsePositives.noteRuleId", { defaultValue: "命中规则" })}
              </div>
              <div className="mt-0.5 font-mono">
                {ev.rule_id_str || `#${ev.rule_id}`}{" "}
                <span className="text-muted-foreground">
                  ({categoryLabel(ev.category)})
                </span>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">
                {t("falsePositives.noteLabel", { defaultValue: "备注（可选）" })}
              </label>
              <Textarea
                rows={4}
                value={fpNote}
                onChange={(e) => setFpNote(e.target.value)}
                placeholder={t("falsePositives.notePlaceholder", {
                  defaultValue:
                    "说明为什么这是误报，例如：正常业务参数、误命中的规则等",
                })}
                maxLength={2000}
              />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setFpDialogOpen(false)}
              disabled={fpLoading}
            >
              {t("common.cancel")}
            </Button>
            <Button
              size="sm"
              onClick={handleSubmitFalsePositive}
              disabled={fpLoading}
            >
              {fpLoading
                ? t("common.submitting")
                : t("falsePositives.submit", { defaultValue: "提交" })}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
