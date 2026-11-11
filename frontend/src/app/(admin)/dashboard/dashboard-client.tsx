"use client";

import { useCallback, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { Button } from "@heroui/react";
import { RefreshCw, Activity, Users, Bug, Ban, Globe, MousePointerClick, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useRealtime, type RealtimeMessage } from "@/lib/hooks/use-realtime";
import type { DashboardSummary } from "@/lib/types/dashboard";
import {
  PageHeader,
  Panel,
  StatCard,
  StatusChip,
  CardSkeleton,
  ErrorState,
  type StatusTone,
} from "@/components/ui/primitives";
import { useI18n, useNumberFormat, type MessageKey, type TranslateFn } from "@/i18n";

/** 运行时长格式化：按天/小时/分钟选择最合适的粒度。 */
function formatUptime(t: TranslateFn, sec: number | undefined): string {
  const s = sec ?? 0;
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return t("dashboard.uptime.days", { days: d, hours: h });
  if (h > 0) return t("dashboard.uptime.hours", { hours: h, minutes: m });
  return t("dashboard.uptime.minutes", { minutes: m });
}

/**
 * 计算「其他非安全动作」数量：访问记录总数减去人类、Bot 与未判定拦截三类。
 * 后端 dashboard.go 明确该差额为其他非安全类动作，负值按 0 兜底。
 */
function otherVisitActions(summary: DashboardSummary): number {
  const total = summary.visit_kind_total_24h ?? 0;
  const known =
    (summary.human_visits_24h ?? 0) +
    (summary.bot_visits_24h ?? 0) +
    (summary.unclassified_intercept_24h ?? 0);
  return Math.max(0, total - known);
}

/** 百分比格式化，分母为 0 时返回 0.0%。 */
function formatPercent(numerator: number | undefined, denominator: number | undefined): string {
  const den = denominator ?? 0;
  if (den <= 0) return "0.0%";
  return `${(((numerator ?? 0) / den) * 100).toFixed(1)}%`;
}

/** 统计卡描述：value 由渲染期计算好的展示字符串传入。 */
type StatSpec = {
  label: string;
  value: string | number;
  tone?: StatusTone;
  hint?: string;
  emphasis?: boolean;
  icon?: ReactNode;
  /** 在 6 列网格中的跨度类（Bento 尺寸表达优先级） */
  span?: string;
};

function StatGrid({
  specs,
  columns = 6,
  className,
}: {
  specs: StatSpec[];
  columns?: 2 | 3 | 4 | 5 | 6;
  className?: string;
}) {
  const colClass: Record<2 | 3 | 4 | 5 | 6, string> = {
    2: "grid-cols-2",
    3: "grid-cols-2 md:grid-cols-3",
    4: "grid-cols-2 md:grid-cols-4",
    5: "grid-cols-2 md:grid-cols-3 xl:grid-cols-5",
    6: "grid-cols-2 md:grid-cols-3 xl:grid-cols-6",
  };
  return (
    <div className={`grid gap-3 ${colClass[columns]} ${className ?? ""}`}>
      {specs.map((spec) => (
        <div key={spec.label} className={spec.span}>
          <StatCard
            label={spec.label}
            value={spec.value}
            tone={spec.tone}
            hint={spec.hint}
            emphasis={spec.emphasis}
            icon={spec.icon}
          />
        </div>
      ))}
    </div>
  );
}

/** 仪表盘分区：统一标题栏、玻璃层次与错峰入场。 */
function Section({
  title,
  icon,
  index,
  footnote,
  children,
}: {
  title: string;
  icon: ReactNode;
  index: number;
  footnote?: string;
  children: ReactNode;
}) {
  return (
    <section className="enter" style={{ "--enter-index": index } as CSSProperties}>
      <Panel title={title} icon={icon}>
        {children}
      </Panel>
      {footnote && <p className="text-muted mt-2 text-xs leading-relaxed">{footnote}</p>}
    </section>
  );
}

function DashboardClient() {
  const { t } = useI18n();
  const formatNumber = useNumberFormat();
  const [live, setLive] = useState<DashboardSummary | null>(null);
  const { data, loading, error, reload } = useApi<DashboardSummary>(
    useCallback(() => api.get<DashboardSummary>("/dashboard/summary"), []),
  );

  const summary = live ?? data;

  const onMessage = useCallback((msg: RealtimeMessage) => {
    if (msg.type === "dashboard_snapshot") {
      const payload = msg.payload as { dashboard?: DashboardSummary };
      if (payload.dashboard) setLive(payload.dashboard);
    }
  }, []);

  const { status } = useRealtime(["dashboard"], onMessage);

  return (
    <div>
      <PageHeader
        title={t("dashboard.title")}
        description={t("dashboard.description")}
        actions={
          <>
            <StatusChip tone={status === "open" ? "success" : status === "connecting" ? "warning" : "neutral"}>
              {status === "open"
                ? t("dashboard.live")
                : status === "connecting"
                  ? t("dashboard.connecting")
                  : t("dashboard.disconnected")}
            </StatusChip>
            <Button size="sm" variant="ghost" onPress={() => { setLive(null); void reload(); }}>
              <RefreshCw className="size-3.5" /> {t("common.refresh")}
            </Button>
          </>
        }
      />

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !summary ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 12 }).map((_, i) => (
            <CardSkeleton key={i} height="h-24" />
          ))}
        </div>
      ) : summary ? (
        <div className="flex flex-col gap-4">
          {/* 实时流量：主次两行，大卡承载最高优先级指标 */}
          <Section
            index={0}
            title={t("dashboard.panel.traffic")}
            icon={<Activity className="text-accent size-3.5" />}
          >
            <StatGrid
              specs={[
                {
                  label: t("dashboard.stat.qps1s"),
                  value: formatNumber(summary.qps_1s),
                  tone: "info",
                  emphasis: true,
                  hint: t("dashboard.hint.qps1s"),
                  span: "xl:col-span-3",
                  icon: <Activity className="size-3.5" />,
                },
                {
                  label: t("dashboard.stat.requestsTotal"),
                  value: formatNumber(summary.requests_total),
                  emphasis: true,
                  hint: t("dashboard.hint.requestsTotal"),
                  span: "xl:col-span-3",
                },
              ]}
            />
            <StatGrid
              className="mt-3"
              columns={4}
              specs={[
                { label: t("dashboard.stat.qps5s"), value: formatNumber(summary.qps_5s) },
                { label: t("dashboard.stat.status2xx"), value: formatNumber(summary.status_2xx), tone: "success" },
                { label: t("dashboard.stat.upstream4xx"), value: formatNumber(summary.errors_upstream_4xx), tone: "warning" },
                { label: t("dashboard.stat.upstream5xx"), value: formatNumber(summary.errors_upstream_5xx), tone: "danger" },
              ]}
            />
          </Section>

          {/* 访客概况 */}
          <Section
            index={1}
            title={t("dashboard.panel.visitors")}
            icon={<Users className="text-accent size-3.5" />}
          >
            <StatGrid
              specs={[
                { label: t("dashboard.stat.uniqueVisitors"), value: formatNumber(summary.unique_visitors_24h) },
                { label: t("dashboard.stat.humanVisits"), value: formatNumber(summary.visitor_fusion_human_24h), tone: "success" },
                { label: t("dashboard.stat.botVisits"), value: formatNumber(summary.visitor_fusion_bot_24h), tone: "warning" },
                { label: t("dashboard.stat.unknownVisitors"), value: formatNumber(summary.visitor_fusion_unknown_24h) },
                { label: t("dashboard.stat.uniqueIps"), value: formatNumber(summary.unique_ips) },
                { label: t("dashboard.stat.attackIps"), value: formatNumber(summary.attack_ips), tone: "danger" },
              ]}
            />
          </Section>

          {/* 访问分类（口径二）：按 visit kind 统计，与上方访客融合口径相互独立 */}
          <Section
            index={2}
            title={t("dashboard.panel.visitClass")}
            icon={<MousePointerClick className="text-accent size-3.5" />}
            footnote={t("dashboard.note.visitClass")}
          >
            <StatGrid
              columns={5}
              specs={[
                { label: t("dashboard.stat.visitTotal"), value: formatNumber(summary.visit_kind_total_24h) },
                { label: t("dashboard.stat.humanVisits"), value: formatNumber(summary.human_visits_24h), tone: "success" },
                { label: t("dashboard.stat.botVisits"), value: formatNumber(summary.bot_visits_24h), tone: "warning" },
                { label: t("dashboard.stat.unclassified"), value: formatNumber(summary.unclassified_intercept_24h), tone: "danger" },
                { label: t("dashboard.stat.otherActions"), value: formatNumber(otherVisitActions(summary)), tone: "neutral" },
              ]}
            />
          </Section>

          {/* 安全拦截 */}
          <Section
            index={3}
            title={t("dashboard.panel.security")}
            icon={<Bug className="text-danger size-3.5" />}
          >
            <StatGrid
              columns={4}
              specs={[
                {
                  label: t("dashboard.stat.wafBlocks"),
                  value: formatNumber(summary.waf_blocks),
                  tone: "danger",
                  emphasis: true,
                  hint: t("dashboard.hint.wafBlocks"),
                  icon: <Bug className="size-3.5" />,
                },
                { label: t("dashboard.stat.wafObserves"), value: formatNumber(summary.waf_observes), tone: "warning" },
                { label: t("dashboard.stat.cveEvents"), value: formatNumber(summary.cve_total_24h), tone: "danger" },
                { label: t("dashboard.stat.dropTotal"), value: formatNumber(summary.drop_total_24h), tone: "danger" },
              ]}
            />
          </Section>

          {/* Bot 评分（24 小时） */}
          <Section
            index={4}
            title={t("dashboard.panel.botScore")}
            icon={<ShieldAlert className="text-warning size-3.5" />}
          >
            <StatGrid
              columns={4}
              specs={[
                { label: t("dashboard.stat.botTotal"), value: formatNumber(summary.bot_total_24h) },
                { label: t("dashboard.stat.botBlocked"), value: formatNumber(summary.bot_blocked_24h), tone: "danger" },
                { label: t("dashboard.stat.botHighRisk"), value: formatNumber(summary.bot_high_risk_24h), tone: "warning" },
                {
                  label: t("dashboard.stat.blockRate"),
                  value: formatPercent(summary.bot_blocked_24h, summary.bot_total_24h),
                  tone: "info",
                },
              ]}
            />
          </Section>

          {/* 事件分布：双列并排形成宽卡阅读区 */}
          <div className="grid gap-4 lg:grid-cols-2">
            {summary.cve_by_type_24h?.length ? (
              <Section index={5} title={t("dashboard.panel.cvePhase")} icon={<Bug className="text-danger size-3.5" />}>
                <CvePhaseBars items={summary.cve_by_type_24h} total={summary.cve_total_24h} />
              </Section>
            ) : null}

            <Section index={6} title={t("dashboard.panel.dropSource")} icon={<Ban className="text-warning size-3.5" />}>
              <DropSourceBars bySource={summary.drop_by_source_24h} total={summary.drop_total_24h} />
            </Section>
          </div>

          {/* 运行信息 */}
          <Section index={7} title={t("dashboard.panel.runtime")} icon={<Globe className="text-accent size-3.5" />}>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <InfoRow label={t("dashboard.info.uptime")} value={formatUptime(t, summary.uptime_sec)} />
              <InfoRow label={t("dashboard.info.revision")} value={`#${summary.revision}`} />
              <InfoRow label={t("dashboard.info.builtinHits")} value={formatNumber(summary.builtin_hits)} />
              <InfoRow label={t("dashboard.info.httpsReleased")} value={formatNumber(summary.visitor_fusion_https_released_total_24h)} />
            </div>
          </Section>
        </div>
      ) : null}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-muted text-xs">{label}</div>
      <div className="tabular mt-0.5 text-sm font-medium">{value}</div>
    </div>
  );
}

const SOURCE_LABELS: Record<string, MessageKey> = {
  bot: "dashboard.source.bot",
  cve: "dashboard.source.cve",
  rule: "dashboard.source.rule",
  ip_reputation: "dashboard.source.ipReputation",
};

const CVE_PHASE_LABELS: Record<string, MessageKey> = {
  cve_detection: "dashboard.cvePhase.cveDetection",
};

/** CVE 命中阶段分布：按事件 phase 聚合，展示各阶段占比。 */
function CvePhaseBars({
  items,
  total,
}: {
  items: { category: string; count: number }[];
  total: number;
}) {
  const { t } = useI18n();
  const formatNumber = useNumberFormat();
  if (items.length === 0) {
    return <div className="text-muted py-4 text-center text-sm">{t("dashboard.empty.cve")}</div>;
  }
  return (
    <div className="flex flex-col gap-3">
      {items.map((it) => (
        <div key={it.category || "unknown"}>
          <div className="mb-1 flex items-center justify-between text-xs">
            <span>
              {CVE_PHASE_LABELS[it.category] ? t(CVE_PHASE_LABELS[it.category]) : it.category || t("dashboard.unknownCategory")}
            </span>
            <span className="tabular text-muted">
              {t("dashboard.stat.percentOfTotal", {
                count: formatNumber(it.count),
                percent: formatPercent(it.count, total),
              })}
            </span>
          </div>
          <div className="bg-default h-2 w-full overflow-hidden rounded-full">
            <div
              className="bg-danger h-full rounded-full transition-all"
              style={{ width: `${total > 0 ? Math.max(2, (it.count / total) * 100) : 0}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function DropSourceBars({ bySource, total }: { bySource: Record<string, number>; total: number }) {
  const { t } = useI18n();
  const formatNumber = useNumberFormat();
  const entries = Object.entries(bySource ?? {});
  if (entries.length === 0 || total === 0) {
    return <div className="text-muted py-4 text-center text-sm">{t("dashboard.empty.drop")}</div>;
  }
  return (
    <div className="flex flex-col gap-3">
      {entries.map(([source, count]) => (
        <div key={source}>
          <div className="mb-1 flex items-center justify-between text-xs">
            <span>{SOURCE_LABELS[source] ? t(SOURCE_LABELS[source]) : source}</span>
            <span className="tabular text-muted">
              {t("dashboard.stat.percentOfTotal", {
                count: formatNumber(count),
                percent: `${total > 0 ? ((count / total) * 100).toFixed(1) : 0}%`,
              })}
            </span>
          </div>
          <div className="bg-default h-2 w-full overflow-hidden rounded-full">
            <div
              className="bg-warning h-full rounded-full transition-all"
              style={{ width: `${total > 0 ? Math.max(2, (count / total) * 100) : 0}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export default DashboardClient;
