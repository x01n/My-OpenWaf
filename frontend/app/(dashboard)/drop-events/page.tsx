"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { IconFilter } from "@tabler/icons-react";
import { useDropEvents } from "@/hooks/use-api";
import type { DropEvent } from "@/lib/types";

export default function DropEventsPage() {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({
    source: "",
    client_ip: "",
    host: "",
  });
  const [showFilters, setShowFilters] = useState(false);

  const { data, isLoading } = useDropEvents({
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
    setFilters({ source: "", client_ip: "", host: "" });
    setPage(1);
  };

  const columns = [
    { key: "created_at", title: t("dropEvents.time"), width: "180px" },
    { key: "client_ip", title: "IP", width: "140px" },
    { key: "source", title: "Source", width: "120px" },
    { key: "host", title: "Host", width: "180px" },
    { key: "path", title: "Path", width: "200px" },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("dropEvents.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("dropEvents.description")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="h-5 px-2 text-xs">
            {t("dropEvents.total", { count: total })}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("dropEvents.list")}</CardTitle>
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
                <Label className="text-xs">Source</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("dropEvents.sourcePlaceholder")}
                  value={filters.source}
                  onChange={(e) => handleFilterChange("source", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">IP</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("dropEvents.ipPlaceholder")}
                  value={filters.client_ip}
                  onChange={(e) => handleFilterChange("client_ip", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Host</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("dropEvents.domainPlaceholder")}
                  value={filters.host}
                  onChange={(e) => handleFilterChange("host", e.target.value)}
                />
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-3">
                <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearFilters}>
                  {t("common.clearFilter")}
                </Button>
              </div>
            </div>
          )}

          <DataTable<DropEvent>
            columns={columns}
            data={items}
            loading={isLoading}
            rowKey={(row) => row.id}
            emptyText={t("dropEvents.empty")}
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
