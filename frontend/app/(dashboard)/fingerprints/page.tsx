"use client";

import { useEffect, useState } from "react";
import { Fingerprint, Globe2, ShieldAlert } from "lucide-react";
import { PageIntro, InlineMeta, Surface } from "@/components/console-shell";
import { getDashboardSummary, getFingerprints, type DashboardSummary, type FingerprintStats } from "@/lib/api";

export default function FingerprintsPage() {
  const [stats, setStats] = useState<FingerprintStats | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getFingerprints(), getDashboardSummary()])
      .then(([fingerprintStats, dashboardSummary]) => {
        setStats(fingerprintStats);
        setSummary(dashboardSummary);
      })
      .finally(() => setLoading(false));
  }, []);

  const topJA3 = stats?.top_ja3 ?? [];
  const browsers = stats?.browser_distribution ?? [];

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Fingerprint Intelligence"
        title="指纹分析"
        description="当前后端提供 TLS JA3 聚合与浏览器分布数据，帮助识别自动化流量与未知客户端特征。"
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <Surface title="核心指标" description="聚合自 /api/v1/fingerprints 与总览接口。" className="xl:col-span-1">
          <div className="grid gap-3">
            <InlineMeta label="指纹总量" value={stats ? stats.total_count.toLocaleString() : "--"} />
            <InlineMeta label="异常指纹（24h）" value={summary ? summary.fingerprint_anomaly_24h.toLocaleString() : "--"} />
            <InlineMeta label="浏览器类型" value={browsers.length ? browsers.length : "--"} />
          </div>
        </Surface>

        <Surface title="JA3 热点指纹" description="按累计出现次数倒序展示后端返回的 top_ja3。" className="xl:col-span-2">
          {loading ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
          ) : topJA3.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">暂无 JA3 聚合数据。</div>
          ) : (
            <div className="space-y-3">
              {topJA3.map((item, index) => (
                <div key={`${item.ja3_hash}-${index}`} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-900 text-white">
                      <Fingerprint className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-slate-700 truncate">{item.ja3_hash || "(empty)"}</div>
                      <div className="text-xs text-slate-500">{item.is_known_good ? "已知良性" : "待人工确认"}</div>
                    </div>
                  </div>
                  <div className="text-sm font-medium text-slate-950">{item.count.toLocaleString()}</div>
                </div>
              ))}
            </div>
          )}
        </Surface>
      </div>

      <Surface title="浏览器分布" description="Fingerprint 仓库仅返回 browser_distribution 聚合。">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : browsers.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">暂无浏览器分布数据。</div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {browsers.map((item, index) => (
              <div key={`${item.browser}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-900">
                  <Globe2 className="h-4 w-4 text-cyan-700" />
                  {item.browser || "未知浏览器"}
                </div>
                <div className="text-2xl font-semibold text-slate-950">{item.count.toLocaleString()}</div>
              </div>
            ))}
          </div>
        )}
      </Surface>

      <Surface title="当前接口说明" description="为避免误导，页面只展示后端实际可用数据。">
        <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-4 text-sm leading-6 text-amber-900">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <p>
            当前后端指纹接口未提供 JA4 排行与异常详情列表，因此新版页面不再展示伪造占位数据；异常数量仍可在总览页通过 fingerprint_anomaly_24h 观察。
          </p>
        </div>
      </Surface>
    </div>
  );
}
