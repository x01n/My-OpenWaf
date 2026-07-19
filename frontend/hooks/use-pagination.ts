import { useState, useMemo } from "react";

interface UsePaginationOptions {
  defaultPage?: number;
  defaultPageSize?: number;
}

interface UsePaginationReturn {
  page: number;
  pageSize: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
  totalPages: (total: number) => number;
  offset: number;
}

export function usePagination(options?: UsePaginationOptions): UsePaginationReturn {
  const [page, setPage] = useState(options?.defaultPage ?? 1);
  const [pageSize, setPageSize] = useState(options?.defaultPageSize ?? 20);

  const offset = useMemo(() => (page - 1) * pageSize, [page, pageSize]);
  const totalPages = (total: number) => Math.ceil(total / pageSize) || 1;

  return { page, pageSize, setPage, setPageSize, totalPages, offset };
}
