"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
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
import { DataTable } from "@/components/data-table";
import { IconFilter, IconFileText } from "@tabler/icons-react";
import { useAccessLogs } from "@/hooks/use-api";
import type { AccessLog } from "@/lib/types";

export default function AccessLogsPage() {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({
    waf_action: "",
    status_code: "",
    client_ip: "",
    host: "",
  });
  const [showFilters, setShowFilters] = useState(false);

  const { data, isLoading } = useAccessLogs({
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
    setFilters({ waf_action: "", status_code: "", client_ip: "", host: "" });
    setPage(1);
  };

  const columns = [
    { key: "created_at", title: t("accessLogs.time"), width: "180px" },
    { key: "client_ip", title: "IP", width: "140px" },
    { key: "host", title: "Host", width: "180px" },
    { key: "path", title: "Path", width: "200px" },
    { key: "method", title: "Method", width: "80px" },
    { key: "status_code", title: "Status", width: "80px" },
    {
      key: "waf_action",
      title: "WAF Action",
      width: "100px",
      render: (row: AccessLog) =>
        row.waf_action ? (
          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
            {row.waf_action}
          </Badge>
        ) : (
          "-"
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <IconFileText className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">{t("accessLogs.title")}</h1>
        <Badge variant="secondary" className="h-5 px-2 text-xs">
          {t("accessLogs.total", { count: total })}
        </Badge>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("accessLogs.listTitle")}</CardTitle>
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
            <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="space-y-1.5">
                <Label className="text-xs">WAF Action</Label>
                <Select
                  value={filters.waf_action}
                  onValueChange={(v) => handleFilterChange("waf_action", v)}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("common.all")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">{t("common.all")}</SelectItem>
                    <SelectItem value="allow">{t("securityEvents.action.allow")}</SelectItem>
                    <SelectItem value="block">{t("securityEvents.action.block")}</SelectItem>
                    <SelectItem value="intercept">{t("securityEvents.action.intercept")}</SelectItem>
                    <SelectItem value="challenge">{t("securityEvents.action.challenge")}</SelectItem>
                    <SelectItem value="observe">{t("securityEvents.action.observe")}</SelectItem>
                    <SelectItem value="log_only">{t("securityEvents.action.log_only")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Status</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("accessLogs.statusCodePlaceholder")}
                  value={filters.status_code}
                  onChange={(e) => handleFilterChange("status_code", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">IP</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("accessLogs.ipPlaceholder")}
                  value={filters.client_ip}
                  onChange={(e) => handleFilterChange("client_ip", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Host</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("accessLogs.domainPlaceholder")}
                  value={filters.host}
                  onChange={(e) => handleFilterChange("host", e.target.value)}
                />
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-4">
                <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearFilters}>
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
            emptyText={t("accessLogs.empty")}
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
                      <PaginationLink isActive={page === pageNum} onClick={() => setPage(pageNum)}>
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
    </div>
  );
}
