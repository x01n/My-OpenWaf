"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatNumber } from "@/lib/utils";
import { countryName, countryFlag } from "@/lib/country-names";
import { useTranslation } from "react-i18next";

interface GeoAttackDistributionProps {
  /** 攻击来源国家排行，country 为 ISO alpha-2 代码 */
  data?: Array<{ country: string; count: number }>;
  /** 时间窗口小时数，用于右上角徽标展示 */
  hours?: number;
}

/**
 * 地理攻击分布卡片。
 *
 * 以"国家攻击排行"横向进度条形式展示 top_countries，最多 10 条，
 * 每行含国旗 emoji、中文国名、按最大值归一化的 teal 进度条与数量。
 */
export function GeoAttackDistribution({ data, hours }: GeoAttackDistributionProps) {
  const { t } = useTranslation();
  const rows = (data ?? []).slice(0, 10);
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium">
          {t("dashboard.geoDistribution")}
        </CardTitle>
        {hours !== undefined && (
          <Badge variant="outline" className="h-5 text-[10px]">
            {hours}h
          </Badge>
        )}
      </CardHeader>
      <CardContent>
        {rows.length > 0 ? (
          <div className="space-y-2.5">
            {rows.map((item, idx) => {
              const pct = max > 0 ? Math.max(2, (item.count / max) * 100) : 0;
              return (
                <div key={item.country || idx} className="flex items-center gap-3 text-sm">
                  <span className="w-5 text-center text-xs font-medium text-muted-foreground">
                    {idx + 1}
                  </span>
                  <span className="text-base leading-none" aria-hidden>
                    {countryFlag(item.country)}
                  </span>
                  <span className="w-20 shrink-0 truncate text-xs">
                    {countryName(item.country)}
                  </span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-teal-500 transition-all"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="w-14 shrink-0 text-right font-mono text-xs tabular-nums">
                    {formatNumber(item.count)}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
            {t("dashboard.geoNoData")}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
