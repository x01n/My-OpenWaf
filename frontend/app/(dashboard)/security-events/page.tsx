"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
  PaginationEllipsis,
} from "@/components/ui/pagination";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import {
  IconFilter,
  IconShieldExclamation,
  IconEye,
  IconShieldOff,
  IconCopy,
  IconChevronDown,
  IconLock,
  IconListDetails,
} from "@tabler/icons-react";
import { useSecurityEvents } from "@/hooks/use-api";
import type { SecurityEvent } from "@/lib/types";
import { format } from "date-fns";
import { zhCN } from "date-fns/locale";

const actionColorMap: Record<string, string> = {
  block: "destructive",
  intercept: "destructive",
  observe: "secondary",
  challenge: "outline",
  captcha_challenge: "outline",
  shield_challenge: "outline",
  chain_challenge: "outline",
  allow: "ghost",
  drop: "destructive",
  log_only: "secondary",
};

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
    return "border-red-500/30 bg-red-500/15 text-red-600 dark:text-red-400";
  if (action === "observe" || action === "log_only")
    return "border-amber-500/30 bg-amber-500/15 text-amber-600 dark:text-amber-400";
  if (isChallengeAction(action))
    return "border-blue-500/30 bg-blue-500/15 text-blue-600 dark:text-blue-400";
  return "";
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
 * 重建 HTTP 请求报文用于展示
 */
function reconstructRequest(ev: SecurityEvent): string {
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
      // 请求行: METHOD PATH HTTP/X.X
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
    if (colonIdx > 0 && i > 0 && !line.startsWith(" ") && !line.startsWith("\t")) {
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

export default function SecurityEventsPage() {
  const { t } = useTranslation();

  const actionLabelMap: Record<string, string> = {
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
  };

  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({
    action: "",
    category: "",
    client_ip: "",
    host: "",
    start_time: "",
    end_time: "",
  });
  const [showFilters, setShowFilters] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const { data, isLoading } = useSecurityEvents({
    page,
    page_size: pageSize,
    ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== "")),
  });

  const items = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / pageSize) || 1;

  const handleFilterChange = (key: string, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({
      action: "",
      category: "",
      client_ip: "",
      host: "",
      start_time: "",
      end_time: "",
    });
    setPage(1);
  };

  const columns = [
    { key: "created_at", title: t("securityEvents.time"), width: "180px" },
    { key: "client_ip", title: t("securityEvents.clientIp"), width: "140px" },
    { key: "host", title: "Host", width: "180px" },
    { key: "path", title: "Path", width: "200px" },
    { key: "method", title: "Method", width: "80px" },
    {
      key: "action",
      title: "Action",
      width: "100px",
      render: (row: SecurityEvent) => (
        <Badge
          variant={(actionColorMap[row.action] || "secondary") as any}
          className="h-5 px-1.5 text-[10px]"
        >
          {actionLabelMap[row.action] || row.action}
        </Badge>
      ),
    },
    { key: "category", title: "Category", width: "120px" },
    { key: "rule_id_str", title: "Rule", width: "120px" },
    {
      key: "operations",
      title: t("common.action"),
      width: "80px",
      render: (row: SecurityEvent) => (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => setSelectedEvent(row)}
        >
          <IconEye className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <IconShieldExclamation className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">{t("securityEvents.title")}</h1>
        <Badge variant="secondary" className="h-5 px-2 text-xs">
          {t("securityEvents.total", { count: total })}
        </Badge>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("securityEvents.eventList")}</CardTitle>
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={() => setShowFilters(!showFilters)}
            >
              <IconFilter className="h-3.5 w-3.5" />
              {showFilters ? t("common.collapseFilter") : t("common.advancedFilter")}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showFilters && (
            <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2 lg:grid-cols-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Action</Label>
                <Select
                  value={filters.action}
                  onValueChange={(v) => handleFilterChange("action", v)}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("securityEvents.allActions")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">{t("common.all")}</SelectItem>
                    {Object.entries(actionLabelMap).map(([key, label]) => (
                      <SelectItem key={key} value={key}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Category</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.categoryPlaceholder")}
                  value={filters.category}
                  onChange={(e) => handleFilterChange("category", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("securityEvents.clientIp")}</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.ipPlaceholder")}
                  value={filters.client_ip}
                  onChange={(e) => handleFilterChange("client_ip", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Host</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.domainPlaceholder")}
                  value={filters.host}
                  onChange={(e) => handleFilterChange("host", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("securityEvents.startTime")}</Label>
                <Input
                  type="datetime-local"
                  className="h-8 text-xs"
                  value={filters.start_time}
                  onChange={(e) => handleFilterChange("start_time", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("securityEvents.endTime")}</Label>
                <Input
                  type="datetime-local"
                  className="h-8 text-xs"
                  value={filters.end_time}
                  onChange={(e) => handleFilterChange("end_time", e.target.value)}
                />
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-3">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 text-xs"
                  onClick={clearFilters}
                >
                  {t("common.clearFilters")}
                </Button>
              </div>
            </div>
          )}

          <DataTable
            columns={columns}
            data={items}
            loading={isLoading}
            rowKey={(row) => row.id}
            emptyText={t("securityEvents.empty")}
          />

          {totalPages > 1 && (
            <Pagination>
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className={page <= 1 ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const pageNum = i + 1;
                  return (
                    <PaginationItem key={pageNum}>
                      <PaginationLink
                        isActive={page === pageNum}
                        onClick={() => setPage(pageNum)}
                      >
                        {pageNum}
                      </PaginationLink>
                    </PaginationItem>
                  );
                })}
                {totalPages > 5 && (
                  <PaginationItem>
                    <PaginationEllipsis />
                  </PaginationItem>
                )}
                <PaginationItem>
                  <PaginationNext
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    className={page >= totalPages ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!selectedEvent} onOpenChange={() => setSelectedEvent(null)}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto p-0">
          {selectedEvent && (() => {
            const ev = selectedEvent;
            const fullUrl = buildFullUrl(ev);
            const hasTls =
              ev.tls_version ||
              ev.tls_sni ||
              ev.tls_ja3 ||
              ev.tls_ja3_hash ||
              ev.tls_ja4 ||
              ev.tls_alpn ||
              ev.tls_cipher_suites;

            return (
              <div className="flex flex-col">
                {/* ====== 顶部横幅：动作 Badge + URL + 装饰图标 ====== */}
                <div className="relative overflow-hidden border-b bg-muted/40 px-6 py-5">
                  <div className="flex items-start gap-3">
                    <Badge
                      className={`mt-0.5 shrink-0 border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${getActionBadgeClass(ev.action)}`}
                    >
                      {actionLabelMap[ev.action] || ev.action}
                    </Badge>
                    <p
                      className="min-w-0 break-all font-mono text-sm leading-relaxed text-foreground/90"
                      title={fullUrl}
                    >
                      {fullUrl}
                    </p>
                  </div>
                  {/* 装饰性盾牌水印 */}
                  <div className="pointer-events-none absolute -right-4 -top-2 opacity-[0.06]">
                    <IconShieldOff className="h-32 w-32" strokeWidth={1} />
                  </div>
                </div>

                {/* ====== 关键信息行 ====== */}
                <div className="space-y-3 border-b px-6 py-5">
                  {/* 攻击者来自 */}
                  <div className="flex items-start gap-2">
                    <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">
                      {t("securityEvents.detail.attackerFrom", { defaultValue: "攻击者来自" })}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium">{ev.client_ip}</span>
                      {ev.geo_country && (
                        <span className="text-xs text-muted-foreground">
                          ({ev.geo_country}{ev.geo_city ? ` / ${ev.geo_city}` : ""})
                        </span>
                      )}
                      <Button
                        variant="link"
                        size="sm"
                        className="h-auto p-0 text-xs text-primary"
                        onClick={() =>
                          window.open(`/ip-lists?add=${encodeURIComponent(ev.client_ip)}`, "_blank")
                        }
                      >
                        {t("securityEvents.detail.addToIpList", { defaultValue: "加入 IP 列表" })}
                      </Button>
                    </div>
                  </div>

                  {/* JA4 指纹 */}
                  {ev.tls_ja4 && (
                    <div className="flex items-start gap-2">
                      <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">
                        {t("securityEvents.detail.ja4Fingerprint", { defaultValue: "JA4 指纹" })}
                      </span>
                      <span className="font-mono text-xs text-foreground/80 break-all">
                        {ev.tls_ja4}
                      </span>
                    </div>
                  )}

                  {/* 命中防护模块 */}
                  <div className="flex items-start gap-2">
                    <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">
                      {t("securityEvents.detail.hitModule", { defaultValue: "命中防护模块" })}
                    </span>
                    <span className="text-sm">{ev.category}</span>
                  </div>

                  {/* 规则名称 */}
                  <div className="flex items-start gap-2">
                    <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">
                      {t("securityEvents.detail.ruleName", { defaultValue: "规则名称" })}
                    </span>
                    <span className="font-mono text-xs">{ev.rule_id_str || ev.rule_id}</span>
                  </div>

                  {/* 攻击时间 */}
                  <div className="flex items-start gap-2">
                    <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">
                      {t("securityEvents.detail.attackTime", { defaultValue: "攻击时间" })}
                    </span>
                    <span className="text-sm">
                      {(() => {
                        try {
                          return format(new Date(ev.created_at), "yyyy-MM-dd HH:mm:ss", {
                            locale: zhCN,
                          });
                        } catch {
                          return ev.created_at;
                        }
                      })()}
                    </span>
                  </div>

                  {/* ID */}
                  <div className="flex items-start gap-2">
                    <span className="w-28 shrink-0 text-xs text-muted-foreground pt-0.5">ID</span>
                    <span className="font-mono text-xs text-foreground/70 break-all">
                      {ev.request_id}
                    </span>
                  </div>
                </div>

                {/* ====== 攻击载荷 ====== */}
                {ev.match_desc && (
                  <div className="border-b px-6 py-4">
                    <div className="mb-2 flex items-center gap-1.5">
                      <IconShieldExclamation className="h-4 w-4 text-amber-500" />
                      <span className="text-xs font-medium text-foreground/80">
                        {t("securityEvents.detail.attackPayload", { defaultValue: "攻击载荷" })}
                      </span>
                    </div>
                    <div className="rounded-md border border-red-500/20 bg-red-500/5 px-4 py-3 dark:border-red-500/10 dark:bg-red-500/5">
                      <p className="break-all font-mono text-xs leading-relaxed text-red-700 dark:text-red-300">
                        {ev.match_desc}
                      </p>
                    </div>
                  </div>
                )}

                {/* ====== 请求/响应报文 Tabs ====== */}
                <div className="border-b px-6 py-4">
                  <Tabs defaultValue="request">
                    <TabsList className="mb-3">
                      <TabsTrigger value="request">
                        <IconListDetails className="mr-1 h-3.5 w-3.5" />
                        {t("securityEvents.detail.requestMessage", { defaultValue: "请求报文" })}
                      </TabsTrigger>
                      <TabsTrigger value="response">
                        <IconListDetails className="mr-1 h-3.5 w-3.5" />
                        {t("securityEvents.detail.responseMessage", { defaultValue: "响应报文" })}
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="request">
                      <div className="overflow-auto rounded-lg bg-zinc-900 p-4 dark:bg-zinc-950">
                        <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-zinc-200">
                          {renderHttpSyntax(reconstructRequest(ev))}
                        </pre>
                      </div>
                    </TabsContent>

                    <TabsContent value="response">
                      <div className="overflow-auto rounded-lg bg-zinc-900 p-4 dark:bg-zinc-950">
                        <pre className="font-mono text-xs leading-relaxed text-zinc-400">
                          {ev.status_code
                            ? `HTTP/1.1 ${ev.status_code}\r\n\r\n(${t(
                                "securityEvents.detail.responseNotCaptured",
                                { defaultValue: "响应正文未捕获" },
                              )})`
                            : t("securityEvents.detail.noResponseData", {
                                defaultValue: "暂无响应数据",
                              })}
                        </pre>
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
                        {t("securityEvents.detail.tlsInfo", { defaultValue: "TLS 信息" })}
                        <IconChevronDown className="ml-auto h-3.5 w-3.5 transition-transform group-data-[state=open]:rotate-180" />
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 rounded-lg border bg-muted/30 p-4">
                          {ev.tls_version && (
                            <div>
                              <span className="text-xs text-muted-foreground">TLS Version</span>
                              <p className="font-mono text-xs">{ev.tls_version}</p>
                            </div>
                          )}
                          {ev.tls_sni && (
                            <div>
                              <span className="text-xs text-muted-foreground">SNI</span>
                              <p className="font-mono text-xs break-all">{ev.tls_sni}</p>
                            </div>
                          )}
                          {ev.tls_alpn && (
                            <div>
                              <span className="text-xs text-muted-foreground">ALPN</span>
                              <p className="font-mono text-xs">{ev.tls_alpn}</p>
                            </div>
                          )}
                          {ev.tls_ja3_hash && (
                            <div>
                              <span className="text-xs text-muted-foreground">JA3 Hash</span>
                              <p className="font-mono text-xs break-all">{ev.tls_ja3_hash}</p>
                            </div>
                          )}
                          {ev.tls_ja3 && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">JA3</span>
                              <p className="font-mono text-xs break-all">{ev.tls_ja3}</p>
                            </div>
                          )}
                          {ev.tls_ja4 && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">JA4</span>
                              <p className="font-mono text-xs break-all">{ev.tls_ja4}</p>
                            </div>
                          )}
                          {ev.tls_cipher_suites && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">Cipher Suites</span>
                              <p className="font-mono text-xs break-all">{ev.tls_cipher_suites}</p>
                            </div>
                          )}
                          {ev.tls_extensions && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">Extensions</span>
                              <p className="font-mono text-xs break-all">{ev.tls_extensions}</p>
                            </div>
                          )}
                          {ev.tls_curves && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">Curves</span>
                              <p className="font-mono text-xs break-all">{ev.tls_curves}</p>
                            </div>
                          )}
                          {ev.tls_point_formats && (
                            <div className="col-span-2">
                              <span className="text-xs text-muted-foreground">Point Formats</span>
                              <p className="font-mono text-xs break-all">{ev.tls_point_formats}</p>
                            </div>
                          )}
                        </div>
                      </CollapsibleContent>
                    </Collapsible>
                  </div>
                )}

                {/* ====== 底部操作栏 ====== */}
                <div className="flex items-center justify-between px-6 py-4">
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1.5 text-xs"
                    onClick={() => {
                      const cmd = buildCurlCommand(ev);
                      navigator.clipboard.writeText(cmd).then(
                        () => toast.success(t("common.copied", { defaultValue: "已复制" })),
                        () => toast.error(t("common.copyFailed", { defaultValue: "复制失败" })),
                      );
                    }}
                  >
                    <IconCopy className="h-3.5 w-3.5" />
                    {t("securityEvents.detail.copyCurl", { defaultValue: "复制 cURL" })}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs"
                    onClick={() => setSelectedEvent(null)}
                  >
                    {t("common.close", { defaultValue: "关闭" })}
                  </Button>
                </div>
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}
