"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { ShieldAlert, Clock, Zap, AlertTriangle, Plus, Trash2, Pencil } from "lucide-react";

interface ProtectionConfig {
  request_ratelimit_enabled: boolean;
  request_ratelimit_window: number;
  request_ratelimit_max: number;
  request_ratelimit_action: string;
  error_ratelimit_enabled: boolean;
  error_ratelimit_window: number;
  error_ratelimit_max: number;
  error_ratelimit_action: string;
  error_ratelimit_count_4xx: boolean;
  error_ratelimit_count_5xx: boolean;
  error_ratelimit_count_block: boolean;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  auto_ban_window: number;
  auto_ban_duration: number;
  waiting_room_enabled?: boolean;
  cc_use_custom?: boolean;
  cc_rules?: string; // JSON-encoded CCRule[]
  [key: string]: unknown;
}

interface RuleCondition {
  target: string;
  operator: string;
  value: string;
}

interface CCRule {
  name: string;
  conditions: RuleCondition[];
  window: number;
  threshold: number;
  action: string;
  duration: number;
}

const MATCH_TARGETS = [
  { value: "url_path", label: "URL 路径" },
  { value: "header", label: "请求 Header" },
  { value: "query", label: "Query 参数" },
  { value: "source_ip", label: "源 IP" },
  { value: "method", label: "请求方法" },
];

const MATCH_OPERATORS = [
  { value: "equals", label: "等于" },
  { value: "contains", label: "包含" },
  { value: "prefix", label: "前缀关键字" },
  { value: "regex", label: "正则匹配" },
];

export default function CCProtectionPage() {
  const [cfg, setCfg] = useState<ProtectionConfig | null>(null);
  const [ccRules, setCCRules] = useState<CCRule[]>([]);
  const [saving, setSaving] = useState(false);
  const [showRuleDialog, setShowRuleDialog] = useState(false);
  const [editingSection, setEditingSection] = useState<string | null>(null);

  // Rule dialog state
  const [ruleName, setRuleName] = useState("");
  const [ruleConditions, setRuleConditions] = useState<RuleCondition[]>([
    { target: "url_path", operator: "equals", value: "" },
  ]);
  const [ruleWindow, setRuleWindow] = useState(60);
  const [ruleThreshold, setRuleThreshold] = useState(100);
  const [ruleAction, setRuleAction] = useState("captcha");
  const [ruleDuration, setRuleDuration] = useState(5);

  useEffect(() => {
    api<ProtectionConfig>("/api/v1/protection-settings")
      .then((data) => {
        setCfg(data);
        if (data.cc_rules) {
          try {
            setCCRules(JSON.parse(data.cc_rules));
          } catch {
            setCCRules([]);
          }
        }
      })
      .catch(() => {});
  }, []);

  function update<K extends keyof ProtectionConfig>(
    key: K,
    value: ProtectionConfig[K]
  ) {
    setCfg((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  async function handleSave() {
    if (!cfg) return;
    setSaving(true);
    try {
      await api("/api/v1/protection-settings", {
        method: "POST",
        body: JSON.stringify({ ...cfg, cc_rules: JSON.stringify(ccRules) }),
      });
      toast.success("已保存，配置重载后生效");
    } catch {
      toast.error("保存失败");
    } finally {
      setSaving(false);
    }
  }

  function addCondition() {
    setRuleConditions((prev) => [
      ...prev,
      { target: "url_path", operator: "equals", value: "" },
    ]);
  }

  function removeCondition(index: number) {
    setRuleConditions((prev) => prev.filter((_, i) => i !== index));
  }

  function updateCondition(
    index: number,
    field: keyof RuleCondition,
    value: string
  ) {
    setRuleConditions((prev) =>
      prev.map((c, i) => (i === index ? { ...c, [field]: value } : c))
    );
  }

  function openEditDialog(section: string) {
    setEditingSection(section);
    if (section === "request") {
      setRuleWindow(cfg?.request_ratelimit_window || 60);
      setRuleThreshold(cfg?.request_ratelimit_max || 100);
      setRuleDuration(5);
    } else if (section === "attack") {
      setRuleWindow(cfg?.auto_ban_window || 60);
      setRuleThreshold(cfg?.auto_ban_threshold || 10);
      setRuleDuration(Math.floor((cfg?.auto_ban_duration || 3600) / 60));
    } else if (section === "error") {
      setRuleWindow(cfg?.error_ratelimit_window || 60);
      setRuleThreshold(cfg?.error_ratelimit_max || 50);
      setRuleDuration(5);
    }
    setShowRuleDialog(false);
  }

  function saveEditDialog() {
    if (!cfg || !editingSection) return;
    if (editingSection === "request") {
      update("request_ratelimit_window", ruleWindow);
      update("request_ratelimit_max", ruleThreshold);
    } else if (editingSection === "attack") {
      update("auto_ban_window", ruleWindow);
      update("auto_ban_threshold", ruleThreshold);
      update("auto_ban_duration", ruleDuration * 60);
    } else if (editingSection === "error") {
      update("error_ratelimit_window", ruleWindow);
      update("error_ratelimit_max", ruleThreshold);
    }
    setEditingSection(null);
    handleSave();
  }

  if (!cfg)
    return (
      <p className="text-sm text-muted-foreground py-12 text-center">
        加载中...
      </p>
    );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-800">CC 防护</h1>
          <p className="text-sm text-gray-500 mt-0.5">配置频率限制与自动封禁策略，防止 CC 攻击</p>
        </div>
        <Button onClick={() => setShowRuleDialog(true)} className="bg-teal-500 hover:bg-teal-600 text-white">
          <Plus className="h-4 w-4 mr-1.5" />
          添加规则
        </Button>
      </div>

      {/* Waiting Room */}
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="w-1 h-5 rounded bg-teal-500 inline-block" />
            <div>
              <span className="font-medium text-gray-800">等候室</span>
              <p className="text-xs text-gray-500 mt-0.5">启用后，当并发访问量过高时，新访客将进入等候队列，按序放行</p>
            </div>
          </div>
          <Switch
            checked={cfg.waiting_room_enabled || false}
            onCheckedChange={(v) => update("waiting_room_enabled", v)}
          />
        </div>
      </div>

      {/* Frequency Limit Section */}
      <div className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <span className="w-1 h-5 rounded bg-teal-500 inline-block" />
            <span className="font-medium text-gray-800">频率限制</span>
          </div>
          <div className="flex items-center gap-0 rounded-md border border-gray-200 overflow-hidden">
            <button
              onClick={() => update("cc_use_custom", false)}
              className={`px-3 py-1.5 text-xs transition-colors ${!cfg.cc_use_custom ? "bg-teal-500 text-white" : "bg-white text-gray-600 hover:bg-gray-50"}`}
            >跟随全局配置</button>
            <button
              onClick={() => update("cc_use_custom", true)}
              className={`px-3 py-1.5 text-xs transition-colors ${cfg.cc_use_custom ? "bg-teal-500 text-white" : "bg-white text-gray-600 hover:bg-gray-50"}`}
            >使用自定义配置</button>
          </div>
        </div>

        <div className="p-4 space-y-3">
          {/* High Frequency Access */}
          <div className="rounded-lg border border-gray-100 bg-gray-50 px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Switch checked={cfg.request_ratelimit_enabled} onCheckedChange={(v) => update("request_ratelimit_enabled", v)} />
                <div>
                  <p className="text-sm font-medium text-gray-700">高频访问限制</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    某 IP 在 <span className="text-teal-600 font-medium">{cfg.request_ratelimit_window}</span> 秒内请求达到 <span className="text-teal-600 font-medium">{cfg.request_ratelimit_max}</span> 次，需要进行人机验证
                  </p>
                </div>
              </div>
              <button onClick={() => openEditDialog("request")} className="text-xs text-teal-600 hover:text-teal-700">编辑</button>
            </div>
          </div>

          {/* High Frequency Attack */}
          <div className="rounded-lg border border-gray-100 bg-gray-50 px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Switch checked={cfg.auto_ban_enabled} onCheckedChange={(v) => update("auto_ban_enabled", v)} />
                <div>
                  <p className="text-sm font-medium text-gray-700">高频攻击限制</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    某 IP 在 <span className="text-teal-600 font-medium">{cfg.auto_ban_window}</span> 秒内触发攻击拦截次数达到 <span className="text-teal-600 font-medium">{cfg.auto_ban_threshold}</span> 次，<span className="text-teal-600 font-medium">{Math.floor(cfg.auto_ban_duration / 60)}</span> 分钟内再次访问需要进行人机验证
                  </p>
                </div>
              </div>
              <button onClick={() => openEditDialog("attack")} className="text-xs text-teal-600 hover:text-teal-700">编辑</button>
            </div>
          </div>

          {/* High Frequency Error */}
          <div className="rounded-lg border border-gray-100 bg-gray-50 px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Switch checked={cfg.error_ratelimit_enabled} onCheckedChange={(v) => update("error_ratelimit_enabled", v)} />
                <div>
                  <p className="text-sm font-medium text-gray-700">高频错误限制</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    某 IP 在 <span className="text-teal-600 font-medium">{cfg.error_ratelimit_window}</span> 秒内触发 4xx 错误码达到 <span className="text-teal-600 font-medium">{cfg.error_ratelimit_max}</span> 次，自动封禁此 IP
                  </p>
                </div>
              </div>
              <button onClick={() => openEditDialog("error")} className="text-xs text-teal-600 hover:text-teal-700">编辑</button>
            </div>
          </div>
        </div>
      </div>

      {/* Custom CC Rules list */}
      {ccRules.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-3">
            <span className="w-1 h-5 rounded bg-teal-500 inline-block" />
            <span className="font-medium text-gray-800">自定义规则</span>
          </div>
          <div className="divide-y divide-gray-100">
            {ccRules.map((rule, idx) => (
              <div key={idx} className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium text-gray-700">{rule.name}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {rule.window}s 内触发 {rule.threshold} 次 → {rule.action === "captcha" ? "人机验证" : "直接封禁"} {rule.duration} 分钟
                  </p>
                </div>
                <button
                  onClick={() => {
                    const updated = ccRules.filter((_, i) => i !== idx);
                    setCCRules(updated);
                    if (cfg) {
                      const updatedCfg = { ...cfg, cc_rules: JSON.stringify(updated) };
                      api("/api/v1/protection-settings", {
                        method: "POST",
                        body: JSON.stringify(updatedCfg),
                      }).then(() => toast.success("规则已删除")).catch(() => toast.error("保存失败"));
                    }
                  }}
                  className="text-gray-400 hover:text-rose-500 transition-colors"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Edit Parameter Dialog */}
      <Dialog
        open={editingSection !== null}
        onOpenChange={(open) => !open && setEditingSection(null)}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              编辑
              {editingSection === "request"
                ? "高频访问限制"
                : editingSection === "attack"
                  ? "高频攻击限制"
                  : "高频错误限制"}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label>经过时间（秒）</Label>
              <Input
                type="number"
                min={1}
                value={ruleWindow}
                onChange={(e) => setRuleWindow(+e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>
                {editingSection === "error"
                  ? "错误次数达到"
                  : editingSection === "attack"
                    ? "拦截次数达到"
                    : "请求次数达到"}
              </Label>
              <Input
                type="number"
                min={1}
                value={ruleThreshold}
                onChange={(e) => setRuleThreshold(+e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>限制时间（分钟）</Label>
              <Input
                type="number"
                min={1}
                value={ruleDuration}
                onChange={(e) => setRuleDuration(+e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingSection(null)}>
              取消
            </Button>
            <Button onClick={saveEditDialog}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Rule Dialog */}
      <Dialog open={showRuleDialog} onOpenChange={setShowRuleDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>添加规则</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2 max-h-[60vh] overflow-y-auto">
            <div className="space-y-1.5">
              <Label>名称</Label>
              <Input
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="输入规则名称"
              />
            </div>

            {/* Condition builder */}
            <div className="space-y-3">
              <Label>匹配条件</Label>
              {ruleConditions.map((cond, index) => (
                <div key={index} className="flex items-center gap-2">
                  <Select
                    value={cond.target}
                    onValueChange={(v) => updateCondition(index, "target", v)}
                  >
                    <SelectTrigger className="w-[130px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {MATCH_TARGETS.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          {t.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select
                    value={cond.operator}
                    onValueChange={(v) =>
                      updateCondition(index, "operator", v)
                    }
                  >
                    <SelectTrigger className="w-[120px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {MATCH_OPERATORS.map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    className="flex-1"
                    value={cond.value}
                    onChange={(e) =>
                      updateCondition(index, "value", e.target.value)
                    }
                    placeholder="匹配内容"
                  />
                  {ruleConditions.length > 1 && (
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeCondition(index)}
                    >
                      <Trash2 className="h-4 w-4 text-muted-foreground" />
                    </Button>
                  )}
                </div>
              ))}
              <Button
                variant="outline"
                size="sm"
                onClick={addCondition}
                className="w-full"
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
                添加一个 AND 条件
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>经过时间（秒）</Label>
                <Input
                  type="number"
                  min={1}
                  value={ruleWindow}
                  onChange={(e) => setRuleWindow(+e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>请求次数达到</Label>
                <Input
                  type="number"
                  min={1}
                  value={ruleThreshold}
                  onChange={(e) => setRuleThreshold(+e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>限制结果</Label>
                <Select value={ruleAction} onValueChange={setRuleAction}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="captcha">人机验证</SelectItem>
                    <SelectItem value="block">直接封禁</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>
                  {ruleAction === "captcha"
                    ? "人机验证时间（分钟）"
                    : "封禁时间（分钟）"}
                </Label>
                <Input
                  type="number"
                  min={1}
                  value={ruleDuration}
                  onChange={(e) => setRuleDuration(+e.target.value)}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRuleDialog(false)} className="text-teal-600 border-teal-500">取消</Button>
            <Button onClick={() => {
              const newRule: CCRule = {
                name: ruleName || `规则 ${ccRules.length + 1}`,
                conditions: ruleConditions,
                window: ruleWindow,
                threshold: ruleThreshold,
                action: ruleAction,
                duration: ruleDuration,
              };
              const updated = [...ccRules, newRule];
              setCCRules(updated);
              if (cfg) {
                const updatedCfg = { ...cfg, cc_rules: JSON.stringify(updated) };
                api("/api/v1/protection-settings", {
                  method: "POST",
                  body: JSON.stringify(updatedCfg),
                }).then(() => toast.success("规则已添加")).catch(() => toast.error("保存失败"));
              }
              setShowRuleDialog(false);
              setRuleName("");
              setRuleConditions([{ target: "url_path", operator: "equals", value: "" }]);
            }} className="bg-teal-500 hover:bg-teal-600 text-white">提交</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
