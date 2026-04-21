"use client";

import { useCallback, useEffect, useState } from "react";
import {
  getBotSettings,
  updateBotSettings,
  getBotScores,
  type BotSettings,
  type BotScoreLog,
  type BotScoreQuery,
} from "@/lib/api";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "sonner";
import { Loader2, Plus, X } from "lucide-react";
import { Pagination } from "@/components/pagination";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

// ── Tag Input Component ──
function TagInput({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [input, setInput] = useState("");
  function add() {
    const v = input.trim();
    if (v && !value.includes(v)) {
      onChange([...value, v]);
    }
    setInput("");
  }
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          className="flex-1"
        />
        <Button type="button" size="sm" variant="outline" onClick={add}>
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((tag) => (
            <Badge key={tag} variant="secondary" className="gap-1 pr-1">
              {tag}
              <button
                type="button"
                onClick={() => onChange(value.filter((t) => t !== tag))}
                className="ml-0.5 hover:text-red-500"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function NumberTagInput({
  value,
  onChange,
  placeholder,
}: {
  value: number[];
  onChange: (v: number[]) => void;
  placeholder?: string;
}) {
  const [input, setInput] = useState("");
  function add() {
    const n = parseInt(input.trim(), 10);
    if (!isNaN(n) && !value.includes(n)) {
      onChange([...value, n]);
    }
    setInput("");
  }
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          type="number"
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          className="flex-1"
        />
        <Button type="button" size="sm" variant="outline" onClick={add}>
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((n) => (
            <Badge key={n} variant="secondary" className="gap-1 pr-1">
              {n}
              <button
                type="button"
                onClick={() => onChange(value.filter((x) => x !== n))}
                className="ml-0.5 hover:text-red-500"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Settings Tab ──
function SettingsTab() {
  const [settings, setSettings] = useState<BotSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getBotSettings()
      .then((s) => setSettings(s))
      .catch(() => toast.error("加载Bot配置失败"))
      .finally(() => setLoading(false));
  }, []);

  async function save() {
    if (!settings) return;
    setSaving(true);
    try {
      await updateBotSettings(settings);
      toast.success("Bot配置已保存");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="py-12 text-center text-gray-400">加载中...</div>;
  if (!settings) return <div className="py-12 text-center text-gray-400">加载失败</div>;

  return (
    <div className="space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <Label className="text-base font-medium">Bot 检测</Label>
          <p className="text-sm text-gray-500">启用后将对请求进行Bot评分检测</p>
        </div>
        <Switch
          checked={settings.enabled}
          onCheckedChange={(v) => setSettings({ ...settings, enabled: v })}
        />
      </div>

      <div className="space-y-2">
        <Label>评分阈值 ({settings.score_threshold})</Label>
        <input
          type="range"
          min={0}
          max={100}
          value={settings.score_threshold}
          onChange={(e) =>
            setSettings({ ...settings, score_threshold: Number(e.target.value) })
          }
          className="w-full accent-teal-500"
        />
        <div className="flex justify-between text-xs text-gray-400">
          <span>0 (宽松)</span>
          <span>100 (严格)</span>
        </div>
      </div>

      <div className="space-y-2">
        <Label>高风险国家 (ISO 代码)</Label>
        <TagInput
          value={settings.high_risk_countries}
          onChange={(v) => setSettings({ ...settings, high_risk_countries: v })}
          placeholder="如 CN, US, RU"
        />
      </div>

      <div className="space-y-2">
        <Label>数据中心 ASN 列表</Label>
        <NumberTagInput
          value={settings.datacenter_asns}
          onChange={(v) => setSettings({ ...settings, datacenter_asns: v })}
          placeholder="输入ASN号码"
        />
      </div>

      <div className="space-y-2">
        <Label>VPN/代理 ASN 列表</Label>
        <NumberTagInput
          value={settings.vpn_proxy_asns}
          onChange={(v) => setSettings({ ...settings, vpn_proxy_asns: v })}
          placeholder="输入ASN号码"
        />
      </div>

      <div className="space-y-2">
        <Label>GeoIP 数据库路径</Label>
        <Input
          value={settings.geoip_db_path}
          onChange={(e) => setSettings({ ...settings, geoip_db_path: e.target.value })}
          placeholder="/path/to/GeoLite2-City.mmdb"
        />
      </div>

      <Button onClick={save} disabled={saving} className="bg-teal-500 hover:bg-teal-600 text-white">
        {saving && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
        保存配置
      </Button>
    </div>
  );
}

// ── Score Logs Tab ──
function ScoreLogsTab() {
  const [items, setItems] = useState<BotScoreLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<BotScoreQuery>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getBotScores({ ...filters, page, page_size: PAGE_SIZE });
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label className="text-xs text-gray-500">IP</Label>
          <Input
            className="w-[160px] h-8 text-sm"
            placeholder="筛选IP"
            value={filters.ip ?? ""}
            onChange={(e) => { setFilters({ ...filters, ip: e.target.value }); setPage(1); }}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs text-gray-500">最低分</Label>
          <Input
            className="w-[100px] h-8 text-sm"
            type="number"
            placeholder="0"
            value={filters.min_score ?? ""}
            onChange={(e) => { setFilters({ ...filters, min_score: e.target.value ? Number(e.target.value) : undefined }); setPage(1); }}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs text-gray-500">最高分</Label>
          <Input
            className="w-[100px] h-8 text-sm"
            type="number"
            placeholder="100"
            value={filters.max_score ?? ""}
            onChange={(e) => { setFilters({ ...filters, max_score: e.target.value ? Number(e.target.value) : undefined }); setPage(1); }}
          />
        </div>
        <Button size="sm" variant="outline" onClick={() => { setFilters({}); setPage(1); }}>
          重置
        </Button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-gray-200 overflow-hidden bg-white">
        <Table>
          <TableHeader>
            <TableRow className="bg-gray-50">
              <TableHead className="text-gray-600 font-medium">IP</TableHead>
              <TableHead className="text-gray-600 font-medium">域名</TableHead>
              <TableHead className="text-gray-600 font-medium">路径</TableHead>
              <TableHead className="text-gray-600 font-medium w-[70px]">总分</TableHead>
              <TableHead className="text-gray-600 font-medium w-[70px]">GeoIP</TableHead>
              <TableHead className="text-gray-600 font-medium w-[70px]">指纹</TableHead>
              <TableHead className="text-gray-600 font-medium w-[70px]">行为</TableHead>
              <TableHead className="text-gray-600 font-medium w-[80px]">动作</TableHead>
              <TableHead className="text-gray-600 font-medium w-[150px]">时间</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={9} className="h-32 text-center text-gray-400">加载中...</TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-32 text-center text-gray-400">暂无数据</TableCell>
              </TableRow>
            ) : (
              items.map((item) => (
                <TableRow key={item.id} className="hover:bg-gray-50">
                  <TableCell className="font-mono text-xs">{item.client_ip}</TableCell>
                  <TableCell className="text-sm truncate max-w-[120px]">{item.host}</TableCell>
                  <TableCell className="text-sm truncate max-w-[160px]">{item.path}</TableCell>
                  <TableCell>
                    <Badge className={item.total_score >= 70 ? "bg-red-100 text-red-700" : item.total_score >= 40 ? "bg-amber-100 text-amber-700" : "bg-green-100 text-green-700"}>
                      {item.total_score}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-gray-600">{item.geoip_score}</TableCell>
                  <TableCell className="text-xs text-gray-600">{item.fingerprint_score}</TableCell>
                  <TableCell className="text-xs text-gray-600">{item.behavior_score}</TableCell>
                  <TableCell>
                    <Badge variant={item.action === "drop" ? "destructive" : "secondary"} className="text-xs">
                      {item.action}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-gray-500">{formatDate(item.created_at)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={total}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
        />
      )}
    </div>
  );
}

// ── Score Explanation Tab ──
function ScoreExplanationTab() {
  const dimensions = [
    { name: "GeoIP 评分", range: "0-30", desc: "基于IP地理位置的风险评估。高风险国家/地区、数据中心IP、VPN/代理ASN会增加分数。" },
    { name: "指纹评分", range: "0-25", desc: "基于TLS指纹(JA3/JA4)的分析。已知爬虫/自动化工具的指纹特征会被识别。" },
    { name: "行为评分", range: "0-25", desc: "基于请求行为的分析。包括请求频率、路径模式、User-Agent一致性等。" },
    { name: "IP信誉评分", range: "0-20", desc: "基于IP历史信誉的评估。来自已知恶意IP段或有攻击历史的IP会被加分。" },
  ];

  return (
    <div className="max-w-2xl space-y-4">
      <p className="text-sm text-gray-500">
        Bot评分系统将多个维度的评估结果汇总为一个总分(0-100)。分数越高表示越可能是Bot流量。
        当总分超过设定的阈值时，系统将根据阻断策略执行相应动作。
      </p>
      <div className="rounded-lg border border-gray-200 overflow-hidden bg-white">
        <Table>
          <TableHeader>
            <TableRow className="bg-gray-50">
              <TableHead className="text-gray-600 font-medium w-[150px]">评分维度</TableHead>
              <TableHead className="text-gray-600 font-medium w-[100px]">分值范围</TableHead>
              <TableHead className="text-gray-600 font-medium">说明</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {dimensions.map((d) => (
              <TableRow key={d.name}>
                <TableCell className="font-medium text-gray-800">{d.name}</TableCell>
                <TableCell><Badge variant="outline">{d.range}</Badge></TableCell>
                <TableCell className="text-sm text-gray-600">{d.desc}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="bg-teal-50 border border-teal-200 rounded-lg p-4 text-sm text-teal-800">
        <strong>总分计算：</strong>总分 = GeoIP分 + 指纹分 + 行为分 + IP信誉分（最高100分）
      </div>
    </div>
  );
}

// ── Main Page ──
export default function BotProtectionPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-gray-800">Bot 防护</h1>
        <p className="text-gray-500 text-sm mt-0.5">配置Bot检测参数，查看评分日志</p>
      </div>

      <Tabs defaultValue="settings">
        <TabsList>
          <TabsTrigger value="settings">配置</TabsTrigger>
          <TabsTrigger value="logs">评分日志</TabsTrigger>
          <TabsTrigger value="explanation">评分说明</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <SettingsTab />
        </TabsContent>
        <TabsContent value="logs">
          <ScoreLogsTab />
        </TabsContent>
        <TabsContent value="explanation">
          <ScoreExplanationTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
