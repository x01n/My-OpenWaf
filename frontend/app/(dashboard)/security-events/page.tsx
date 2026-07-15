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
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
  PaginationEllipsis,
} from "@/components/ui/pagination";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DataTable } from "@/components/data-table";
import { SecurityEventDetailDialog } from "@/components/security-event-detail-dialog";
import { DateRangePicker } from "@/components/date-range-picker";
import { IpHoverPreview } from "@/components/ip-hover-preview";
import { EmptyState } from "@/components/empty-state";
import Link from "next/link";
import {
  IconFilter,
  IconEye,
  IconChevronDown,
  IconDownload,
  IconShieldLock,
  IconX,
  IconRoute,
  IconShieldOff,
} from "@tabler/icons-react";
import { useSecurityEvents } from "@/hooks/use-api";
import { ipListApi } from "@/lib/api";
import type { SecurityEvent } from "@/lib/types";
import { format } from "date-fns";

const actionColorMap: Record<string, string> = {
  block: "destructive",
  intercept: "destructive",
  observe: "secondary",
  challenge: "outline",
  captcha_challenge: "outline",
  shield_challenge: "outline",
  chain_challenge: "outline",
  allow: "default",
  drop: "destructive",
  log_only: "secondary",
};

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
    since: "",
    until: "",
  });
  const [showFilters, setShowFilters] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [batchLoading, setBatchLoading] = useState(false);

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
      since: "",
      until: "",
    });
    setPage(1);
  };

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((item) => item.id)));
    }
  };

  const clearSelection = () => setSelectedIds(new Set());

  const exportCSV = () => {
    if (items.length === 0) return;
    const headers = [
      "ID",
      t("securityEvents.csv.time", { defaultValue: "时间" }),
      t("securityEvents.csv.clientIp", { defaultValue: "客户端IP" }),
      "Host",
      t("securityEvents.csv.path", { defaultValue: "路径" }),
      t("securityEvents.csv.method", { defaultValue: "方法" }),
      t("securityEvents.csv.action", { defaultValue: "动作" }),
      t("securityEvents.csv.category", { defaultValue: "分类" }),
      t("securityEvents.csv.rule", { defaultValue: "规则" }),
      t("securityEvents.csv.statusCode", { defaultValue: "状态码" }),
      t("securityEvents.csv.matchDesc", { defaultValue: "匹配描述" }),
    ];
    const rows = items.map((ev) => [
      ev.id,
      ev.created_at,
      ev.client_ip,
      ev.host,
      ev.path,
      ev.method,
      ev.action,
      ev.category,
      ev.rule_id_str || ev.rule_id,
      ev.status_code,
      (ev.match_desc || "").replace(/"/g, '""'),
    ]);
    const csv = [
      headers.join(","),
      ...rows.map((r) => r.map((v) => `"${v}"`).join(",")),
    ].join("\n");
    const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8;" });
    downloadBlob(blob, `security-events-${formatFileDate()}.csv`);
    toast.success(t("securityEvents.export.csvSuccess", { defaultValue: "CSV 导出成功" }));
  };

  const exportJSON = () => {
    if (items.length === 0) return;
    const json = JSON.stringify(items, null, 2);
    const blob = new Blob([json], { type: "application/json;charset=utf-8;" });
    downloadBlob(blob, `security-events-${formatFileDate()}.json`);
    toast.success(t("securityEvents.export.jsonSuccess", { defaultValue: "JSON 导出成功" }));
  };

  const formatFileDate = () => {
    return format(new Date(), "yyyyMMdd-HHmmss");
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const batchAddToBlocklist = async () => {
    const selectedItems = items.filter((item) => selectedIds.has(item.id));
    const uniqueIPs = [...new Set(selectedItems.map((item) => item.client_ip))];
    if (uniqueIPs.length === 0) return;

    setBatchLoading(true);
    let success = 0;
    let failed = 0;
    for (const ip of uniqueIPs) {
      try {
        await ipListApi.create({
          value: ip,
          kind: "blacklist",
          action: "intercept",
          note: t("securityEvents.batch.blocklistNote", {
            defaultValue: "批量加入黑名单 - 安全事件",
          }),
        });
        success++;
      } catch {
        failed++;
      }
    }
    setBatchLoading(false);
    clearSelection();
    if (failed === 0) {
      toast.success(
        t("securityEvents.batch.blocklistSuccess", {
          defaultValue: `已将 ${success} 个 IP 加入黑名单`,
          success,
        })
      );
    } else {
      toast.warning(
        t("securityEvents.batch.blocklistPartial", {
          defaultValue: `${success} 个成功，${failed} 个失败`,
          success,
          failed,
        })
      );
    }
  };

  const columns = [
    {
      key: "select",
      title: (
        <Checkbox
          checked={items.length > 0 && selectedIds.size === items.length}
          onCheckedChange={toggleSelectAll}
          aria-label={t("common.selectAll", { defaultValue: "全选" })}
        />
      ),
      width: "40px",
      render: (row: SecurityEvent) => (
        <Checkbox
          checked={selectedIds.has(row.id)}
          onCheckedChange={() => toggleSelect(row.id)}
          aria-label={`选择事件 ${row.id}`}
        />
      ),
    },
    { key: "created_at", title: t("securityEvents.time"), width: "180px" },
    {
      key: "client_ip",
      title: t("securityEvents.clientIp"),
      width: "140px",
      render: (row: SecurityEvent) =>
        row.client_ip ? (
          <IpHoverPreview ip={row.client_ip} />
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    { key: "host", title: "Host", width: "180px" },
    { key: "path", title: "Path", width: "200px" },
    { key: "method", title: "Method", width: "80px" },
    {
      key: "action",
      title: "Action",
      width: "100px",
      render: (row: SecurityEvent) => (
        <Badge
          variant={(actionColorMap[row.action] || "secondary") as React.ComponentProps<typeof Badge>["variant"]}
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
      width: "110px",
      render: (row: SecurityEvent) => (
        <div className="flex items-center gap-0.5">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setSelectedEvent(row)}
            title={t("common.viewDetail")}
          >
            <IconEye className="h-4 w-4" />
          </Button>
          {row.request_id && (
            <Button
              asChild
              variant="ghost"
              size="icon-sm"
              title={t("requestTrace.trackThisRequest")}
            >
              <Link
                href={`/request-trace?id=${encodeURIComponent(row.request_id)}`}
              >
                <IconRoute className="h-4 w-4" />
              </Link>
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("securityEvents.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("securityEvents.description")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="h-5 px-2 text-xs">
            {t("securityEvents.total", { count: total })}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("securityEvents.eventList")}</CardTitle>
            <div className="flex items-center gap-2">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 gap-1 text-xs"
                    disabled={items.length === 0}
                  >
                    <IconDownload className="h-3.5 w-3.5" />
                    {t("securityEvents.export.title", { defaultValue: "导出" })}
                    <IconChevronDown className="h-3 w-3" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={exportCSV}>
                    {t("securityEvents.export.csv", { defaultValue: "导出 CSV" })}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportJSON}>
                    {t("securityEvents.export.json", { defaultValue: "导出 JSON" })}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
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
              <div className="space-y-1.5 sm:col-span-2 lg:col-span-2">
                <Label className="text-xs">
                  {t("securityEvents.timeRange", {
                    defaultValue: "时间范围",
                  })}
                </Label>
                <DateRangePicker
                  value={{ since: filters.since, until: filters.until }}
                  onChange={(v) => {
                    setFilters((prev) => ({
                      ...prev,
                      since: v.since,
                      until: v.until,
                    }));
                    setPage(1);
                  }}
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
            emptyContent={
              <EmptyState
                icon={IconShieldOff}
                title={t("securityEvents.empty")}
                description={t("securityEvents.emptyHint", "暂未检测到安全事件，当 WAF 拦截或观察到可疑请求时将在此展示")}
                className="py-16"
              />
            }
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

      {selectedIds.size > 0 && (
        <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2">
          <div className="flex items-center gap-3 rounded-xl border bg-background/95 px-5 py-3 shadow-lg backdrop-blur-sm">
            <span className="text-sm font-medium text-muted-foreground">
              {t("securityEvents.batch.selected", {
                defaultValue: `已选择 ${selectedIds.size} 条`,
                count: selectedIds.size,
              })}
            </span>
            <Button
              variant="default"
              size="sm"
              className="h-8 gap-1.5 text-xs"
              disabled={batchLoading}
              onClick={batchAddToBlocklist}
            >
              <IconShieldLock className="h-3.5 w-3.5" />
              {t("securityEvents.batch.addToBlocklist", { defaultValue: "批量加入黑名单" })}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={clearSelection}
            >
              <IconX className="h-3.5 w-3.5" />
              {t("common.cancel", { defaultValue: "取消" })}
            </Button>
          </div>
        </div>
      )}

      <SecurityEventDetailDialog
        event={selectedEvent}
        open={!!selectedEvent}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null);
        }}
      />
    </div>
  );
}
