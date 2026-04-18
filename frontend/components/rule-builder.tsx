"use client";

import { useState, useCallback, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Plus, Trash2, Code, Eye, TestTube, AlertCircle, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

// Rule kinds with metadata
const RULE_KINDS = [
  { value: "block_ip", label: "封禁 IP/CIDR", placeholder: "192.168.1.0/24", group: "ACL", action: "block" },
  { value: "allow_ip", label: "放行 IP/CIDR", placeholder: "10.0.0.0/8", group: "ACL", action: "allow" },
  { value: "block_path", label: "路径前缀", placeholder: "/admin", group: "路径", action: "block" },
  { value: "allow_path", label: "放行路径", placeholder: "/health", group: "路径", action: "allow" },
  { value: "block_path_exact", label: "路径精确", placeholder: "/.env", group: "路径", action: "block" },
  { value: "block_path_regex", label: "路径正则", placeholder: "(?i)/admin.*\\.php", group: "路径", action: "block" },
  { value: "allow_path_regex", label: "放行路径正则", placeholder: "(?i)/api/public/.*", group: "路径", action: "allow" },
  { value: "block_query_contains", label: "查询包含", placeholder: "union+select", group: "查询", action: "block" },
  { value: "block_query_regex", label: "查询正则", placeholder: "(?i)union\\s+select", group: "查询", action: "block" },
  { value: "block_header", label: "请求头包含", placeholder: "User-Agent:BadBot", group: "请求头", action: "block" },
  { value: "allow_header", label: "放行请求头", placeholder: "X-API-Key:secret", group: "请求头", action: "allow" },
  { value: "block_header_regex", label: "请求头正则", placeholder: "User-Agent:(?i)bot|crawl", group: "请求头", action: "block" },
  { value: "block_method", label: "HTTP方法", placeholder: "DELETE", group: "协议", action: "block" },
  { value: "block_content_type", label: "Content-Type", placeholder: "application/xml", group: "协议", action: "block" },
  { value: "block_body_contains", label: "Body包含", placeholder: "eval(", group: "Body", action: "block" },
  { value: "block_body_regex", label: "Body正则", placeholder: "(?i)<script", group: "Body", action: "block" },
] as const;

interface Condition {
  id: string;
  kind: string;
  arg: string;
}

interface CompoundGroup {
  op: "and" | "or" | "not";
  children: Condition[];
}

function newId() {
  return Math.random().toString(36).slice(2, 11);
}

interface RuleBuilderProps {
  value: string;
  onChange: (pattern: string) => void;
}

/**
 * Parse DSL pattern back to visual state
 */
function parsePattern(raw: string): { mode: "simple" | "compound"; condition?: Condition; compound?: CompoundGroup } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { mode: "simple", condition: { id: newId(), kind: "block_ip", arg: "" } };
  }

  // Try JSON compound
  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed);
      if (obj.op && obj.children) {
        const children = (obj.children as { kind: string; arg: string }[]).map((c) => ({
          id: newId(),
          kind: c.kind || "",
          arg: c.arg || "",
        }));
        return { mode: "compound", compound: { op: obj.op, children } };
      }
    } catch {
      // Fall through
    }
  }

  // Simple pattern: kind:arg
  const colonIdx = trimmed.indexOf(":");
  if (colonIdx > 0) {
    const kind = trimmed.slice(0, colonIdx);
    const arg = trimmed.slice(colonIdx + 1);
    if (RULE_KINDS.some((k) => k.value === kind)) {
      return { mode: "simple", condition: { id: newId(), kind, arg } };
    }
  }

  return { mode: "simple", condition: { id: newId(), kind: "", arg: trimmed } };
}

function buildDSL(mode: "simple" | "compound", condition: Condition, compound: CompoundGroup): string {
  if (mode === "simple") {
    if (!condition.kind || !condition.arg) return "";
    return `${condition.kind}:${condition.arg}`;
  }

  // Compound
  const validChildren = compound.children.filter((c) => c.kind && c.arg);
  if (validChildren.length === 0) return "";
  if (validChildren.length === 1 && compound.op !== "not") {
    return `${validChildren[0].kind}:${validChildren[0].arg}`;
  }

  return JSON.stringify({
    op: compound.op,
    children: validChildren.map((c) => ({ kind: c.kind, arg: c.arg })),
  });
}

export function RuleBuilder({ value, onChange }: RuleBuilderProps) {
  const parsed = parsePattern(value);
  const [mode, setMode] = useState<"simple" | "compound">(parsed.mode);
  const [condition, setCondition] = useState<Condition>(
    parsed.condition || { id: newId(), kind: "block_ip", arg: "" }
  );
  const [compound, setCompound] = useState<CompoundGroup>(
    parsed.compound || { op: "and", children: [{ id: newId(), kind: "block_ip", arg: "" }] }
  );
  const [advancedMode, setAdvancedMode] = useState(false);
  const [rawDSL, setRawDSL] = useState(value);
  const [testInput, setTestInput] = useState({
    path: "/admin",
    method: "GET",
    ip: "192.168.1.100",
    headers: "User-Agent: Mozilla/5.0",
    query: "",
    body: "",
  });
  const [testResult, setTestResult] = useState<{ match: boolean; message: string } | null>(null);
  const [validating, setValidating] = useState(false);

  const emitChange = useCallback(
    (m: "simple" | "compound", c: Condition, g: CompoundGroup) => {
      const dsl = buildDSL(m, c, g);
      setRawDSL(dsl);
      onChange(dsl);
    },
    [onChange]
  );

  // Sync rawDSL when switching from visual to advanced
  useEffect(() => {
    if (advancedMode) {
      setRawDSL(buildDSL(mode, condition, compound));
    }
  }, [advancedMode, mode, condition, compound]);

  const handleSimpleKindChange = (kind: string) => {
    const next = { ...condition, kind };
    setCondition(next);
    emitChange("simple", next, compound);
  };

  const handleSimpleArgChange = (arg: string) => {
    const next = { ...condition, arg };
    setCondition(next);
    emitChange("simple", next, compound);
  };

  const toggleMode = () => {
    const nextMode = mode === "simple" ? "compound" : "simple";
    setMode(nextMode);
    if (nextMode === "compound" && compound.children.length === 0) {
      const g = { ...compound, children: [{ id: newId(), kind: condition.kind, arg: condition.arg }] };
      setCompound(g);
      emitChange(nextMode, condition, g);
    } else {
      emitChange(nextMode, condition, compound);
    }
  };

  const updateCompoundOp = (op: "and" | "or" | "not") => {
    const g = { ...compound, op };
    setCompound(g);
    emitChange("compound", condition, g);
  };

  const addChild = () => {
    const g = { ...compound, children: [...compound.children, { id: newId(), kind: "block_ip", arg: "" }] };
    setCompound(g);
    emitChange("compound", condition, g);
  };

  const removeChild = (id: string) => {
    const g = { ...compound, children: compound.children.filter((c) => c.id !== id) };
    setCompound(g);
    emitChange("compound", condition, g);
  };

  const updateChild = (id: string, field: "kind" | "arg", val: string) => {
    const g = {
      ...compound,
      children: compound.children.map((c) => (c.id === id ? { ...c, [field]: val } : c)),
    };
    setCompound(g);
    emitChange("compound", condition, g);
  };

  const handleRawDSLChange = (val: string) => {
    setRawDSL(val);
    onChange(val);
  };

  const validateRule = async () => {
    if (!rawDSL.trim()) {
      toast.error("规则不能为空");
      return;
    }
    setValidating(true);
    try {
      await api("/api/v1/rules/validate", {
        method: "POST",
        body: JSON.stringify({ pattern: rawDSL }),
      });
      toast.success("规则语法正确");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "验证失败";
      toast.error(`规则验证失败: ${message}`);
    } finally {
      setValidating(false);
    }
  };

  const testRule = () => {
    // Client-side simple test logic
    const dsl = rawDSL.trim();
    if (!dsl) {
      setTestResult({ match: false, message: "规则为空" });
      return;
    }

    try {
      // Simple pattern test
      if (dsl.includes(":") && !dsl.startsWith("{")) {
        const [kind, arg] = dsl.split(":", 2);
        let match = false;
        let message = "";

        if (kind.includes("_ip")) {
          match = testInput.ip.includes(arg) || arg.includes(testInput.ip);
          message = match ? `IP ${testInput.ip} 匹配规则` : `IP ${testInput.ip} 不匹配`;
        } else if (kind.includes("_path")) {
          if (kind.includes("_exact")) {
            match = testInput.path === arg;
          } else if (kind.includes("_regex")) {
            match = new RegExp(arg).test(testInput.path);
          } else {
            match = testInput.path.startsWith(arg);
          }
          message = match ? `路径 ${testInput.path} 匹配规则` : `路径 ${testInput.path} 不匹配`;
        } else if (kind.includes("_method")) {
          match = testInput.method.toUpperCase() === arg.toUpperCase();
          message = match ? `方法 ${testInput.method} 匹配规则` : `方法 ${testInput.method} 不匹配`;
        } else if (kind.includes("_header")) {
          if (kind.includes("_regex")) {
            match = new RegExp(arg.split(":")[1] || arg).test(testInput.headers);
          } else {
            match = testInput.headers.toLowerCase().includes(arg.toLowerCase());
          }
          message = match ? "请求头匹配规则" : "请求头不匹配";
        } else if (kind.includes("_query")) {
          if (kind.includes("_regex")) {
            match = new RegExp(arg).test(testInput.query);
          } else {
            match = testInput.query.includes(arg);
          }
          message = match ? "查询参数匹配规则" : "查询参数不匹配";
        } else if (kind.includes("_body")) {
          if (kind.includes("_regex")) {
            match = new RegExp(arg).test(testInput.body);
          } else {
            match = testInput.body.includes(arg);
          }
          message = match ? "Body匹配规则" : "Body不匹配";
        } else {
          message = "未知规则类型";
        }

        setTestResult({ match, message });
      } else if (dsl.startsWith("{")) {
        // Compound rule - simplified test
        setTestResult({ match: false, message: "复合规则测试需要后端支持" });
      } else {
        setTestResult({ match: false, message: "无效的规则格式" });
      }
    } catch (err) {
      setTestResult({ match: false, message: `测试错误: ${err instanceof Error ? err.message : "未知错误"}` });
    }
  };

  const kindMeta = (kind: string) => RULE_KINDS.find((k) => k.value === kind);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">规则构建器</CardTitle>
          <div className="flex gap-2">
            <Button
              type="button"
              variant={advancedMode ? "default" : "outline"}
              size="sm"
              onClick={() => setAdvancedMode(!advancedMode)}
            >
              <Code className="h-3 w-3 mr-1" />
              {advancedMode ? "可视化模式" : "高级模式"}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <Tabs value={advancedMode ? "advanced" : "visual"} className="w-full">
          <TabsList className="hidden">
            <TabsTrigger value="visual">可视化</TabsTrigger>
            <TabsTrigger value="advanced">高级</TabsTrigger>
          </TabsList>

          <TabsContent value="visual" className="space-y-4">
            {mode === "simple" ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Label className="w-20 text-xs">匹配类型</Label>
                  <Select value={condition.kind} onValueChange={handleSimpleKindChange}>
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="选择匹配类型" />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(
                        RULE_KINDS.reduce((acc, k) => {
                          if (!acc[k.group]) acc[k.group] = [];
                          acc[k.group].push(k);
                          return acc;
                        }, {} as Record<string, typeof RULE_KINDS[number][]>)
                      ).map(([group, items]) => (
                        <div key={group}>
                          <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">{group}</div>
                          {items.map((k) => (
                            <SelectItem key={k.value} value={k.value}>
                              {k.label}
                            </SelectItem>
                          ))}
                        </div>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button type="button" variant="outline" size="sm" onClick={toggleMode}>
                    复合条件
                  </Button>
                </div>
                <div className="flex items-center gap-2">
                  <Label className="w-20 text-xs">参数值</Label>
                  <Input
                    className="flex-1"
                    value={condition.arg}
                    onChange={(e) => handleSimpleArgChange(e.target.value)}
                    placeholder={kindMeta(condition.kind)?.placeholder || "输入匹配参数"}
                  />
                </div>
                {condition.kind && (
                  <Alert>
                    <Eye className="h-4 w-4" />
                    <AlertDescription className="text-xs">
                      <strong>DSL预览:</strong>{" "}
                      <code className="bg-muted px-1 rounded">{buildDSL("simple", condition, compound) || "..."}</code>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Label className="w-20 text-xs">逻辑运算</Label>
                  <Select value={compound.op} onValueChange={(v) => updateCompoundOp(v as "and" | "or" | "not")}>
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="and">AND (且)</SelectItem>
                      <SelectItem value="or">OR (或)</SelectItem>
                      <SelectItem value="not">NOT (非)</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button type="button" variant="outline" size="sm" onClick={toggleMode} className="ml-auto">
                    简单模式
                  </Button>
                </div>

                <div className="space-y-2 pl-4 border-l-2 border-muted">
                  {compound.children.map((child, idx) => (
                    <div key={child.id} className="space-y-2">
                      {idx > 0 && (
                        <div className="text-xs font-semibold text-muted-foreground">
                          {compound.op.toUpperCase()}
                        </div>
                      )}
                      <div className="flex items-center gap-2">
                        <Select value={child.kind} onValueChange={(v) => updateChild(child.id, "kind", v)}>
                          <SelectTrigger className="w-[160px]">
                            <SelectValue placeholder="类型" />
                          </SelectTrigger>
                          <SelectContent>
                            {RULE_KINDS.map((k) => (
                              <SelectItem key={k.value} value={k.value}>
                                {k.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Input
                          className="flex-1"
                          value={child.arg}
                          onChange={(e) => updateChild(child.id, "arg", e.target.value)}
                          placeholder={kindMeta(child.kind)?.placeholder || "参数"}
                        />
                        {compound.children.length > 1 && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            onClick={() => removeChild(child.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                <Button type="button" variant="outline" size="sm" onClick={addChild} className="w-full">
                  <Plus className="h-3 w-3 mr-1" /> 添加条件
                </Button>

                <Alert>
                  <Eye className="h-4 w-4" />
                  <AlertDescription className="text-xs break-all">
                    <strong>DSL预览:</strong>{" "}
                    <code className="bg-muted px-1 rounded text-[10px]">
                      {buildDSL("compound", condition, compound) || "..."}
                    </code>
                  </AlertDescription>
                </Alert>
              </div>
            )}

            {/* Test Tool */}
            <div className="border-t pt-4 mt-4">
              <div className="flex items-center gap-2 mb-3">
                <TestTube className="h-4 w-4" />
                <Label className="text-sm font-semibold">规则测试</Label>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <Input
                  placeholder="路径: /admin"
                  value={testInput.path}
                  onChange={(e) => setTestInput({ ...testInput, path: e.target.value })}
                />
                <Input
                  placeholder="方法: GET"
                  value={testInput.method}
                  onChange={(e) => setTestInput({ ...testInput, method: e.target.value })}
                />
                <Input
                  placeholder="IP: 192.168.1.100"
                  value={testInput.ip}
                  onChange={(e) => setTestInput({ ...testInput, ip: e.target.value })}
                />
                <Input
                  placeholder="查询: ?id=1"
                  value={testInput.query}
                  onChange={(e) => setTestInput({ ...testInput, query: e.target.value })}
                />
                <Input
                  placeholder="请求头: User-Agent: ..."
                  value={testInput.headers}
                  onChange={(e) => setTestInput({ ...testInput, headers: e.target.value })}
                  className="col-span-2"
                />
                <Textarea
                  placeholder="Body内容"
                  value={testInput.body}
                  onChange={(e) => setTestInput({ ...testInput, body: e.target.value })}
                  className="col-span-2 h-16 text-xs"
                />
              </div>
              <Button type="button" variant="secondary" size="sm" onClick={testRule} className="w-full mt-2">
                <TestTube className="h-3 w-3 mr-1" /> 测试匹配
              </Button>
              {testResult && (
                <Alert className="mt-2" variant={testResult.match ? "default" : "destructive"}>
                  {testResult.match ? (
                    <CheckCircle2 className="h-4 w-4" />
                  ) : (
                    <AlertCircle className="h-4 w-4" />
                  )}
                  <AlertDescription className="text-xs">{testResult.message}</AlertDescription>
                </Alert>
              )}
            </div>
          </TabsContent>

          <TabsContent value="advanced" className="space-y-3">
            <div>
              <Label className="text-xs mb-2 block">DSL 规则（JSON或 kind:arg 格式）</Label>
              <Textarea
                value={rawDSL}
                onChange={(e) => handleRawDSLChange(e.target.value)}
                placeholder='{"op":"and","children":[{"kind":"block_ip","arg":"1.2.3.0/24"}]}'
                className="font-mono text-xs h-32"
              />
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={validateRule}
                disabled={validating}
              >
                {validating ? "验证中..." : "验证规则"}
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  const parsed = parsePattern(rawDSL);
                  setMode(parsed.mode);
                  if (parsed.condition) setCondition(parsed.condition);
                  if (parsed.compound) setCompound(parsed.compound);
                  setAdvancedMode(false);
                }}
              >
                切换到可视化
              </Button>
            </div>
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="text-xs">
                <strong>提示:</strong> 简单规则格式为 <code>kind:arg</code>，复合规则使用 JSON 格式。
                <br />
                示例: <code>block_ip:192.168.1.0/24</code> 或{" "}
                <code>{`{"op":"and","children":[...]}`}</code>
              </AlertDescription>
            </Alert>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
