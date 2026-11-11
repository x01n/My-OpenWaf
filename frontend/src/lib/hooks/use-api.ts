"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiGet, ApiError, type ListResponse } from "@/lib/api/client";

/**
 * 通用数据获取 Hook：统一 loading / error / 手动刷新。
 * 依赖为空时仅在挂载后请求一次；依赖变化自动重新请求。
 */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: readonly unknown[] = [],
  options: { enabled?: boolean } = {},
) {
  const enabled = options.enabled ?? true;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);
  const versionRef = useRef(0);

  const load = useCallback(async () => {
    const version = ++versionRef.current;
    setLoading(true);
    setError(null);
    try {
      const result = await fetcher();
      if (versionRef.current === version) setData(result);
    } catch (e) {
      if (versionRef.current === version) {
        setError(e instanceof ApiError ? e.message : "加载失败");
      }
    } finally {
      if (versionRef.current === version) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (enabled) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);

  return { data, loading, error, reload: load, setData };
}

/** 分页参数状态 */
export function usePagination(defaultPageSize = 20) {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(defaultPageSize);
  return { page, pageSize, setPage };
}

/** 防抖值 */
export function useDebounced<T>(value: T, delay = 350): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/**
 * 分页列表 Hook：统一 page/pageSize/翻页/搜索条件与刷新。
 * extraQuery 变化时回到第 1 页并重新请求。
 */
export function useList<T>(
  path: string,
  extraQuery: Record<string, unknown> = {},
  defaultPageSize = 20,
) {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(defaultPageSize);
  const queryKey = JSON.stringify(extraQuery);
  const fetcher = useCallback(
    () =>
      apiGet<ListResponse<T>>(path, {
        page,
        page_size: pageSize,
        ...JSON.parse(queryKey),
      }),
    [path, page, pageSize, queryKey],
  );
  const { data, loading, error, reload } = useApi(fetcher, [path, page, queryKey]);

  const setPageAndReset = useCallback((p: number) => setPage(p), []);
  const search = useCallback(
    (q: Record<string, unknown>) => {
      setPage(1);
      return q;
    },
    [],
  );
  void search;

  return {
    items: data?.items ?? [],
    total: data?.total ?? 0,
    page,
    pageSize,
    setPage: setPageAndReset,
    loading,
    error,
    reload,
  };
}
