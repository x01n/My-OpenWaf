"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Shield, ShieldCheck, Link2, RotateCcw, TrendingUp,
  Plus, Trash2, ArrowUp, ArrowDown, Loader2, Play,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageIntro, Surface } from "@/components/console-shell";
import {
  getCaptchaConfig, updateCaptchaConfig, testCaptcha,
  getChainConfig, updateChainConfig,
  getEscalationConfig, updateEscalationConfig,
  type CaptchaConfig, type ChainStep,
  type EscalationStep, type EscalationConfig,
} from "@/lib/security-api";

/* ───────── 验证码 Tab ───────── */
function CaptchaTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({
    captcha_enabled: false, captcha_type: "math", captcha_timeout: 120,
    shield_enabled: false, shield_difficulty: 4,
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => { getCaptchaConfig().then(setCfg).catch(() => {}); }, []);

  async function save() {
    setSaving(true);
    try { await updateCaptchaConfig(cfg); toast.success("验证码配置已保存"); }
    catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  async function doTest() {
    setTesting(true);
    try {
      const r = await testCaptcha();
      if (r.implemented === false || r.supported === false) {
        toast.warning(r.message || "验证码测试预览暂未接入真实后端能力");
        return;
      }
      toast.success(r.message || "测试成功");
    } catch (e) { toast.error(String(e)); }
    finally { setTesting(false); }
  }

  return (
    <Surface title="验证码配置" description="配置人机验证码类型和难度。">
      <div className="space-y-5 max-w-xl">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
          <Label className="font-medium">启用验证码</Label>
          <Switch checked={cfg.captcha_enabled} onCheckedChange={(v) => setCfg({ ...cfg, captcha_enabled: v })} />
        </div>
        <div className="space-y-2">
          <Label>验证码类型</Label>
          <Select value={cfg.captcha_type} onValueChange={(v: CaptchaConfig["captcha_type"]) => setCfg({ ...cfg, captcha_type: v })}>
            <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="math">Math（算术验证码）</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>超时时间（秒）</Label>
          <Input type="number" min={10} max={600} value={cfg.captcha_timeout}
            onChange={(e) => setCfg({ ...cfg, captcha_timeout: Number(e.target.value) })} className="rounded-md" />
        </div>
        <div className="flex gap-3 pt-2">
          <Button onClick={doTest} variant="outline" className="rounded-md" disabled={testing}>
            {testing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
            测试预览
          </Button>
          <Button onClick={save} disabled={saving} className="rounded-md bg-slate-950 text-white hover:bg-slate-800">
            {saving ? "保存中..." : "保存配置"}
          </Button>
        </div>
      </div>
    </Surface>
  );
}

/* ───────── 5秒盾 Tab ───────── */
function ShieldTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({
    captcha_enabled: false, captcha_type: "math", captcha_timeout: 120,
    shield_enabled: false, shield_difficulty: 4,
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => { getCaptchaConfig().then(setCfg).catch(() => {}); }, []);

  async function save() {
    setSaving(true);
    try { await updateCaptchaConfig(cfg); toast.success("5秒盾配置已保存"); }
    catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  return (
    <Surface title="5秒盾配置" description="基于 PoW + 验证码的浏览器环境挑战。">
      <div className="space-y-5 max-w-xl">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
          <Label className="font-medium">启用5秒盾</Label>
          <Switch checked={cfg.shield_enabled} onCheckedChange={(v) => setCfg({ ...cfg, shield_enabled: v })} />
        </div>
        <div className="space-y-2">
          <Label>PoW 难度（前导零位数）</Label>
          <Input type="number" min={1} max={32} value={cfg.shield_difficulty}
            onChange={(e) => setCfg({ ...cfg, shield_difficulty: Number(e.target.value) })} className="rounded-md" />
        </div>
        <div className="space-y-2">
          <Label>验证码类型</Label>
          <Select value={cfg.captcha_type} onValueChange={(v: CaptchaConfig["captcha_type"]) => setCfg({ ...cfg, captcha_type: v })}>
            <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="math">Math（算术验证码）</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button onClick={save} disabled={saving} className="rounded-md bg-slate-950 text-white hover:bg-slate-800">
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </Surface>
  );
}

/* ───────── 连锁策略 Tab ───────── */
function ChainTab() {
  const [enabled, setEnabled] = useState(false);
  const [steps, setSteps] = useState<ChainStep[]>([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getChainConfig().then((c) => {
      setEnabled(c.chain_enabled);
      setSteps(Array.isArray(c.chain_steps) ? c.chain_steps : []);
    }).catch(() => {});
  }, []);

  function addStep() {
    setSteps([...steps, { type: "env", condition: "all" }]);
  }
  function removeStep(i: number) { setSteps(steps.filter((_, idx) => idx !== i)); }
  function moveStep(i: number, dir: -1 | 1) {
    const j = i + dir;
    if (j < 0 || j >= steps.length) return;
    const arr = [...steps];
    [arr[i], arr[j]] = [arr[j], arr[i]];
    setSteps(arr);
  }
  function updateStep(i: number, patch: Partial<ChainStep>) {
    setSteps(steps.map((s, idx) => idx === i ? { ...s, ...patch } : s));
  }

  async function save() {
    setSaving(true);
    try {
      await updateChainConfig({ chain_enabled: enabled, chain_steps: steps });
      toast.success("连锁策略已保存");
    } catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  return (
    <Surface title="连锁策略" description="多步骤逐级验证链路，按顺序执行每个挑战步骤。">
      <div className="space-y-5">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 max-w-xl">
          <Label className="font-medium">启用连锁策略</Label>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <div className="space-y-3">
          {steps.map((step, i) => (
            <div key={i} className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white p-4">
              <span className="text-xs font-bold text-slate-400 w-8">#{i + 1}</span>
              <Select value={step.type} onValueChange={(v: ChainStep["type"]) => updateStep(i, { type: v })}>
                <SelectTrigger className="w-[180px] rounded-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="env">环境检测</SelectItem>
                  <SelectItem value="pow">PoW 验证</SelectItem>
                  <SelectItem value="captcha">算术验证码</SelectItem>
                </SelectContent>
              </Select>
              <Select value={step.condition} onValueChange={(v) => updateStep(i, { condition: v })}>
                <SelectTrigger className="w-[180px] rounded-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部（all）</SelectItem>
                  <SelectItem value="score>50">score &gt; 50</SelectItem>
                  <SelectItem value="score>80">score &gt; 80</SelectItem>
                  <SelectItem value="env_score<30">env_score &lt; 30</SelectItem>
                </SelectContent>
              </Select>
              <div className="ml-auto flex gap-1">
                <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => moveStep(i, -1)} disabled={i === 0}>
                  <ArrowUp className="h-4 w-4" />
                </Button>
                <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => moveStep(i, 1)} disabled={i === steps.length - 1}>
                  <ArrowDown className="h-4 w-4" />
                </Button>
                <Button size="icon" variant="ghost" className="h-8 w-8 text-rose-500 hover:text-rose-700" onClick={() => removeStep(i)}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
        </div>
        <Button variant="outline" className="rounded-md" onClick={addStep}>
          <Plus className="mr-2 h-4 w-4" /> 添加步骤
        </Button>
        {steps.length > 0 && (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            <span className="font-medium text-slate-500">流程预览：</span>{" "}
            {steps.map((s, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1 text-slate-600">→</span>}
                <span className="font-mono text-xs bg-white rounded px-1.5 py-0.5 border border-slate-200">{s.type}</span>
              </span>
            ))}
            <span className="mx-1 text-slate-600">→</span>
            <span className="font-mono text-xs bg-emerald-50 text-emerald-700 rounded px-1.5 py-0.5 border border-emerald-200">pass</span>
          </div>
        )}
        <Button onClick={save} disabled={saving} className="rounded-md bg-slate-950 text-white hover:bg-slate-800">
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </Surface>
  );
}

/* ───────── 防重放 Tab ───────── */
function AntiReplayTab() {
  const [enabled] = useState(false);
  const [ttl] = useState(300);
  const [action] = useState("shield_challenge");

  return (
    <Surface title="防重放配置" description="基于 Nonce 的请求重放防护。此策略在各站点级别独立配置。">
      <div className="space-y-5 max-w-xl">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
          <Label className="font-medium">启用防重放</Label>
          <Switch checked={enabled} disabled />
        </div>
        <div className="space-y-2">
          <Label>Nonce TTL（秒）</Label>
          <Input type="number" min={10} max={86400} value={ttl} readOnly className="rounded-md" />
        </div>
        <div className="space-y-2">
          <Label>动作</Label>
          <Select value={action} disabled>
            <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="shield_challenge">Shield Challenge（挑战）</SelectItem>
              <SelectItem value="intercept">Intercept（拦截）</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
          防重放策略当前按站点配置持久化，暂无全局保存接口。请前往「防护应用 → 站点详情」修改站点级配置。
        </div>
        <Button disabled variant="outline" className="rounded-md">
          全局保存暂未接入
        </Button>
      </div>
    </Surface>
  );
}

/* ───────── 阶梯升级 Tab ───────── */
function EscalationTab() {
  const [cfg, setCfg] = useState<EscalationConfig>({
    escalation_enabled: false, escalation_window_secs: 60, escalation_steps: [],
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => { getEscalationConfig(1).then(setCfg).catch(() => {}); }, []);

  function addStep() {
    const steps = [...cfg.escalation_steps];
    const last = steps[steps.length - 1];
    steps.push({ threshold: (last?.threshold ?? 0) + 5, action: "challenge" });
    setCfg({ ...cfg, escalation_steps: steps });
  }
  function removeStep(i: number) {
    setCfg({ ...cfg, escalation_steps: cfg.escalation_steps.filter((_, idx) => idx !== i) });
  }
  function updateStep(i: number, patch: Partial<EscalationStep>) {
    setCfg({
      ...cfg,
      escalation_steps: cfg.escalation_steps.map((s, idx) => idx === i ? { ...s, ...patch } : s),
    });
  }

  async function save() {
    setSaving(true);
    try {
      await updateEscalationConfig(1, cfg);
      toast.success("阶梯升级配置已保存");
    } catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  return (
    <Surface title="阶梯升级" description="在 WAF 命中后按客户端违规次数升级响应动作，不作为独立检测阶段。">
      <div className="space-y-5">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 max-w-xl">
          <Label className="font-medium">启用阶梯升级</Label>
          <Switch checked={cfg.escalation_enabled} onCheckedChange={(v) => setCfg({ ...cfg, escalation_enabled: v })} />
        </div>
        <div className="max-w-xl space-y-2">
          <Label>时间窗口（秒）</Label>
          <Input type="number" min={1} value={cfg.escalation_window_secs}
            onChange={(e) => setCfg({ ...cfg, escalation_window_secs: Number(e.target.value) })} className="rounded-md" />
        </div>
        {cfg.escalation_steps.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">阈值</TableHead>
                  <TableHead>动作</TableHead>
                  <TableHead className="w-20 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cfg.escalation_steps.map((step, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Input type="number" min={1} value={step.threshold} className="w-24 rounded-md"
                        onChange={(e) => updateStep(i, { threshold: Number(e.target.value) })} />
                    </TableCell>
                    <TableCell>
                      <Select value={step.action} onValueChange={(v) => updateStep(i, { action: v })}>
                        <SelectTrigger className="w-[160px] rounded-md"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="challenge">Challenge（挑战）</SelectItem>
                          <SelectItem value="intercept">Intercept（拦截）</SelectItem>
                          <SelectItem value="block">Block（阻断）</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="icon" variant="ghost" className="h-8 w-8 text-rose-500 hover:text-rose-700" onClick={() => removeStep(i)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <Button variant="outline" className="rounded-md" onClick={addStep}>
          <Plus className="mr-2 h-4 w-4" /> 添加步骤
        </Button>
        <div>
          <Button onClick={save} disabled={saving} className="rounded-md bg-slate-950 text-white hover:bg-slate-800">
            {saving ? "保存中..." : "保存配置"}
          </Button>
        </div>
      </div>
    </Surface>
  );
}

/* ───────── 主页面 ───────── */
export default function SecurityPolicyPage() {
  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Security Policy"
        title="安全策略"
        description="验证码、5秒盾、连锁策略、防重放与阶梯升级，构建多层次安全防护体系。"
      />
      <Tabs defaultValue="captcha" className="space-y-4">
        <TabsList>
          <TabsTrigger value="captcha" className="gap-1.5">
            <ShieldCheck className="h-4 w-4" /> 验证码
          </TabsTrigger>
          <TabsTrigger value="shield" className="gap-1.5">
            <Shield className="h-4 w-4" /> 5秒盾
          </TabsTrigger>
          <TabsTrigger value="chain" className="gap-1.5">
            <Link2 className="h-4 w-4" /> 连锁策略
          </TabsTrigger>
          <TabsTrigger value="antireplay" className="gap-1.5">
            <RotateCcw className="h-4 w-4" /> 防重放
          </TabsTrigger>
          <TabsTrigger value="escalation" className="gap-1.5">
            <TrendingUp className="h-4 w-4" /> 阶梯升级
          </TabsTrigger>
        </TabsList>

        <TabsContent value="captcha"><CaptchaTab /></TabsContent>
        <TabsContent value="shield"><ShieldTab /></TabsContent>
        <TabsContent value="chain"><ChainTab /></TabsContent>
        <TabsContent value="antireplay"><AntiReplayTab /></TabsContent>
        <TabsContent value="escalation"><EscalationTab /></TabsContent>
      </Tabs>
    </div>
  );
}
