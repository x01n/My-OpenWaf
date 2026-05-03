"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  Fingerprint,
  Globe2,
  RefreshCcw,
  ShieldAlert,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getDashboardSummary,
  getFingerprints,
  type DashboardSummary,
  type FingerprintStats,
} from "@/lib/api";

function RiskBadge({ isKnown }: { isKnown: boolean }) {
  if (isKnown) {
    return (
      <Badge className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-50">
        <CheckCircle2 className="h-3 w-3" /> 正常
      </Badge>
    );
  }
  return (
    <Badge className="gap-1 border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-50">
      <AlertTriangle className="h-3 w-3" /> 可疑
    </Badge>
  );
}

function shortenHash(hash: string, len = 16) {
  if (!hash) return "(empty)";
  if (hash.length <= len) return hash;
  return hash.slice(0, len) + "...";
}

export default function FingerprintsPage() {
  const [stats, setStats] = useState<FingerprintStats | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedHash, setSelectedHash] = useState<string | null>(null);

  function load() {
    setLoading(true);
    Promise.all([getFingerprints(), getDashboardSummary()])
      .then(([fp, dash]) => {
        setStats(fp);
        setSummary(dash);
      })
      .catch((err) => toast.error(err instanceof Error ? err.message : "加载失败"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    let ignore = false;
    Promise.all([getFingerprints(), getDashboardSummary()])
      .then(([fp, dash]) => {
        if (ignore) return;
        setStats(fp);
        setSummary(dash);
      })
      .catch((err) => toast.error(err instanceof Error ? err.message : "加载失败"))
      .finally(() => {
        if (!ignore) setLoading(false);
      });
    return () => {
      ignore = true;
    };
  }, []);

  const topJA3 = stats?.top_ja3 ?? [];
  const browsers = stats?.browser_distribution ?? [];
  const totalCount = stats?.total_count ?? 0;
  const knownCount = topJA3.filter((j) => j.is_known_good).length;
  const knownPct = topJA3.length > 0 ? Math.round((knownCount / topJA3.length) * 100) : 0;
  const anomaly24h = summary?.fingerprint_anomaly_24h ?? 0;

  const selectedItem = topJA3.find((j) => j.ja3_hash === selectedHash);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">指纹分析</h1>
          <p className="mt-1 text-sm text-slate-500">
            TLS JA3 指纹聚合与浏览器分布，识别自动化流量与未知客户端
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5 rounded-lg"
          onClick={load}
        >
          <RefreshCcw className="h-3.5 w-3.5" /> 刷新
        </Button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <Fingerprint className="h-3.5 w-3.5 text-cyan-500" /> 唯一指纹数
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {loading ? "--" : totalCount.toLocaleString()}
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" /> 已知指纹占比
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {loading ? "--" : `${knownPct}%`}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {knownCount} / {topJA3.length} 条 Top 指纹
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <ShieldAlert className="h-3.5 w-3.5 text-red-500" /> 异常指纹数
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {loading ? "--" : anomaly24h.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-400">近 24 小时</div>
        </div>
      </div>

      {/* Fingerprint table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <h3 className="text-sm font-medium text-slate-900">JA3 指纹排行</h3>
          <p className="text-xs text-slate-400">按请求数倒序排列</p>
        </div>
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">加载中...</div>
        ) : topJA3.length === 0 ? (
          <div className="p-16 text-center text-sm text-slate-400">
            暂无 JA3 指纹数据
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                  <th className="px-4 py-3">JA3 哈希</th>
                  <th className="px-4 py-3">客户端标识</th>
                  <th className="px-4 py-3">请求数</th>
                  <th className="px-4 py-3">风险等级</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {topJA3.map((item, idx) => (
                  <tr
                    key={`${item.ja3_hash}-${idx}`}
                    className="transition-colors hover:bg-slate-50/50"
                  >
                    <td className="px-4 py-3">
                      <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700">
                        {shortenHash(item.ja3_hash)}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {item.is_known_good ? "已知浏览器" : "未知客户端"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs font-medium text-slate-900">
                      {item.count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <RiskBadge isKnown={item.is_known_good} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 rounded-lg px-2 text-cyan-600 hover:text-cyan-700"
                        onClick={() => setSelectedHash(item.ja3_hash)}
                      >
                        <Eye className="mr-1 h-3.5 w-3.5" /> 详情
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Browser distribution */}
      {!loading && browsers.length > 0 && (
        <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3">
            <h3 className="text-sm font-medium text-slate-900">浏览器分布</h3>
          </div>
          <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
            {browsers.map((b, idx) => (
              <div
                key={`${b.browser}-${idx}`}
                className="flex items-center justify-between rounded-lg border border-slate-100 bg-slate-50 p-3"
              >
                <div className="flex items-center gap-2">
                  <Globe2 className="h-4 w-4 text-cyan-500" />
                  <span className="text-sm text-slate-700">
                    {b.browser || "未知浏览器"}
                  </span>
                </div>
                <span className="font-mono text-sm font-medium text-slate-900">
                  {b.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Dialog */}
      <Dialog open={!!selectedHash} onOpenChange={() => setSelectedHash(null)}>
        <DialogContent className="max-w-lg rounded-xl">
          <DialogHeader>
            <DialogTitle>指纹详情</DialogTitle>
            <DialogDescription>JA3 指纹完整信息</DialogDescription>
          </DialogHeader>
          {selectedItem && (
            <div className="space-y-3">
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                  完整 JA3 哈希
                </div>
                <code className="mt-1 block break-all text-xs text-slate-700">
                  {selectedItem.ja3_hash || "(empty)"}
                </code>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    请求数
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-900">
                    {selectedItem.count.toLocaleString()}
                  </div>
                </div>
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    状态
                  </div>
                  <div className="mt-1">
                    <RiskBadge isKnown={selectedItem.is_known_good} />
                  </div>
                </div>
              </div>
              <div className="rounded-lg border border-amber-100 bg-amber-50 p-3 text-xs text-amber-800">
                当前后端接口仅提供 JA3 哈希、请求数和已知标识信息。TLS 版本、加密套件等详细字段需后端扩展支持。
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
