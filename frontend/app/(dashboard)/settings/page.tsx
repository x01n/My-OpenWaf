"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ShieldCheck,
  Settings2,
  FileText,
  Plus,
  Trash2,
  Copy,
  Eye,
  EyeOff,
} from "lucide-react";

/* ---------- types ---------- */

interface Certificate {
  id: number;
  name: string;
  domains?: string;
  not_after?: string;
  created_at?: string;
}

interface ApiKey {
  id: number;
  name: string;
  prefix?: string;
  key?: string; // only returned on creation
  created_at?: string;
  last_used_at?: string;
}

/* ---------- section header component ---------- */

function SectionHeader({
  title,
  children,
}: {
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        <span className="w-1 h-4 rounded bg-teal-500 inline-block" />
        <h3 className="text-sm font-semibold text-gray-700">{title}</h3>
      </div>
      {children}
    </div>
  );
}

/* =================================================================
   Tab 1 — 防护配置
   ================================================================= */

function ProtectionTab() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loadingCerts, setLoadingCerts] = useState(true);
  const [showAddCert, setShowAddCert] = useState(false);
  const [certForm, setCertForm] = useState({
    name: "",
    certificate: "",
    private_key: "",
  });
  const [submittingCert, setSubmittingCert] = useState(false);

  const [blockPageType, setBlockPageType] = useState("default");
  const [blockPageText, setBlockPageText] = useState("");
  const [logRetention, setLogRetention] = useState("0");

  const fetchCerts = useCallback(async () => {
    try {
      const data = await api<{ items?: Certificate[]; data?: Certificate[] }>(
        "/api/v1/certificates",
      );
      setCerts(data.items ?? data.data ?? []);
    } catch {
      /* ignore */
    } finally {
      setLoadingCerts(false);
    }
  }, []);

  useEffect(() => {
    fetchCerts();
  }, [fetchCerts]);

  const handleAddCert = async () => {
    setSubmittingCert(true);
    try {
      await api("/api/v1/certificates", {
        method: "POST",
        body: JSON.stringify(certForm),
      });
      setCertForm({ name: "", certificate: "", private_key: "" });
      setShowAddCert(false);
      fetchCerts();
    } catch {
      /* ignore */
    } finally {
      setSubmittingCert(false);
    }
  };

  const handleDeleteCert = async (id: number) => {
    if (!confirm("确认删除该证书？")) return;
    try {
      await api(`/api/v1/certificates/${id}/delete`, { method: "POST" });
      fetchCerts();
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="space-y-8">
      {/* 证书管理 */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader title="证书管理">
            <Button
              size="sm"
              className="bg-teal-500 hover:bg-teal-600 text-white"
              onClick={() => setShowAddCert(true)}
            >
              <Plus className="mr-1 h-4 w-4" /> 添加证书
            </Button>
          </SectionHeader>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[200px]">名称</TableHead>
                <TableHead>关联域名</TableHead>
                <TableHead>到期时间</TableHead>
                <TableHead>创建时间</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loadingCerts ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                    加载中…
                  </TableCell>
                </TableRow>
              ) : certs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                    暂无证书
                  </TableCell>
                </TableRow>
              ) : (
                certs.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell>{c.domains || "-"}</TableCell>
                    <TableCell>{c.not_after || "-"}</TableCell>
                    <TableCell>{c.created_at?.slice(0, 10) || "-"}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-red-500 hover:text-red-600"
                        onClick={() => handleDeleteCert(c.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* 拦截页面 */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader title="拦截页面" />
          <div className="space-y-4 px-1">
            <div className="grid gap-2">
              <Label>展示方式</Label>
              <Select value={blockPageType} onValueChange={setBlockPageType}>
                <SelectTrigger className="w-[280px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">默认拦截页面</SelectItem>
                  <SelectItem value="custom_text">自定义文本</SelectItem>
                  <SelectItem value="redirect">重定向 URL</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {blockPageType !== "default" && (
              <div className="grid gap-2">
                <Label>
                  {blockPageType === "custom_text" ? "自定义文本内容" : "重定向地址"}
                </Label>
                <Input
                  value={blockPageText}
                  onChange={(e) => setBlockPageText(e.target.value)}
                  placeholder={
                    blockPageType === "custom_text"
                      ? "请输入拦截提示文本"
                      : "https://example.com/blocked"
                  }
                />
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 数据清理 */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader title="数据清理" />
          <div className="px-1">
            <Label className="mb-3 block">安全日志保留时长</Label>
            <RadioGroup
              value={logRetention}
              onValueChange={setLogRetention}
              className="flex flex-wrap gap-4"
            >
              {[
                { value: "0", label: "不清理" },
                { value: "1", label: "1 天" },
                { value: "3", label: "3 天" },
                { value: "7", label: "7 天" },
                { value: "15", label: "15 天" },
                { value: "30", label: "30 天" },
              ].map((opt) => (
                <div key={opt.value} className="flex items-center space-x-2">
                  <RadioGroupItem value={opt.value} id={`ret-${opt.value}`} />
                  <Label htmlFor={`ret-${opt.value}`} className="cursor-pointer">
                    {opt.label}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>
        </CardContent>
      </Card>

      {/* Save */}
      <div className="flex justify-end">
        <Button className="bg-teal-500 hover:bg-teal-600 text-white px-8">
          保存设置
        </Button>
      </div>

      {/* Add Certificate Dialog */}
      <Dialog open={showAddCert} onOpenChange={setShowAddCert}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>添加证书</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label>证书名称</Label>
              <Input
                value={certForm.name}
                onChange={(e) =>
                  setCertForm({ ...certForm, name: e.target.value })
                }
                placeholder="例如: example.com"
              />
            </div>
            <div className="grid gap-2">
              <Label>证书内容 (PEM)</Label>
              <Textarea
                rows={5}
                value={certForm.certificate}
                onChange={(e) =>
                  setCertForm({ ...certForm, certificate: e.target.value })
                }
                placeholder="-----BEGIN CERTIFICATE-----"
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>私钥内容 (PEM)</Label>
              <Textarea
                rows={5}
                value={certForm.private_key}
                onChange={(e) =>
                  setCertForm({ ...certForm, private_key: e.target.value })
                }
                placeholder="-----BEGIN PRIVATE KEY-----"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddCert(false)}>
              取消
            </Button>
            <Button
              className="bg-teal-500 hover:bg-teal-600 text-white"
              onClick={handleAddCert}
              disabled={
                submittingCert ||
                !certForm.name ||
                !certForm.certificate ||
                !certForm.private_key
              }
            >
              {submittingCert ? "提交中…" : "确认添加"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/* =================================================================
   Tab 2 — 控制台管理
   ================================================================= */

function ConsoleTab() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [visibleKeyId, setVisibleKeyId] = useState<number | null>(null);

  /* password policy */
  const [minLength, setMinLength] = useState("8");
  const [maxAttempts, setMaxAttempts] = useState("5");
  const [lockoutMinutes, setLockoutMinutes] = useState("30");
  const [savingPolicy, setSavingPolicy] = useState(false);

  const fetchKeys = useCallback(async () => {
    try {
      const data = await api<{ items?: ApiKey[]; data?: ApiKey[] }>(
        "/api/v1/api-keys",
      );
      setKeys(data.items ?? data.data ?? []);
    } catch {
      /* ignore */
    } finally {
      setLoadingKeys(false);
    }
  }, []);

  // Load login security policy from protection-settings
  useEffect(() => {
    api<{ login_min_password_length?: number; login_max_attempts?: number; login_lockout_minutes?: number }>(
      "/api/v1/protection-settings"
    ).then((data) => {
      if (data.login_min_password_length) setMinLength(String(data.login_min_password_length));
      if (data.login_max_attempts) setMaxAttempts(String(data.login_max_attempts));
      if (data.login_lockout_minutes) setLockoutMinutes(String(data.login_lockout_minutes));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  const handleCreate = async () => {
    setSubmitting(true);
    try {
      const data = await api<ApiKey>("/api/v1/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: newKeyName }),
      });
      setCreatedKey(data.key ?? null);
      setNewKeyName("");
      fetchKeys();
    } catch {
      /* ignore */
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("确认删除该 API 令牌？")) return;
    try {
      await api(`/api/v1/api-keys/${id}/delete`, { method: "POST" });
      fetchKeys();
    } catch {
      /* ignore */
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className="space-y-8">
      {/* API 令牌 */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader title="API 令牌">
            <Button
              size="sm"
              className="bg-teal-500 hover:bg-teal-600 text-white"
              onClick={() => {
                setCreatedKey(null);
                setShowCreate(true);
              }}
            >
              <Plus className="mr-1 h-4 w-4" /> 创建
            </Button>
          </SectionHeader>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead>令牌前缀</TableHead>
                <TableHead>创建时间</TableHead>
                <TableHead>最后使用</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loadingKeys ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                    加载中…
                  </TableCell>
                </TableRow>
              ) : keys.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                    暂无 API 令牌
                  </TableCell>
                </TableRow>
              ) : (
                keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {k.prefix ? `${k.prefix}••••••` : "-"}
                    </TableCell>
                    <TableCell>{k.created_at?.slice(0, 10) || "-"}</TableCell>
                    <TableCell>{k.last_used_at?.slice(0, 10) || "从未使用"}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-red-500 hover:text-red-600"
                        onClick={() => handleDelete(k.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* 登录安全设置 */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader title="登录安全设置" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 px-1">
            <div className="grid gap-2">
              <Label>密码最小长度</Label>
              <Input
                type="number"
                min="6"
                max="32"
                value={minLength}
                onChange={(e) => setMinLength(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>最大登录失败次数</Label>
              <Input
                type="number"
                min="1"
                max="20"
                value={maxAttempts}
                onChange={(e) => setMaxAttempts(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>锁定时长（分钟）</Label>
              <Input
                type="number"
                min="1"
                max="1440"
                value={lockoutMinutes}
                onChange={(e) => setLockoutMinutes(e.target.value)}
              />
            </div>
          </div>
          <div className="flex justify-end mt-6">
            <Button
              className="bg-teal-500 hover:bg-teal-600 text-white px-8"
              disabled={savingPolicy}
              onClick={async () => {
                setSavingPolicy(true);
                try {
                  // Merge into existing protection settings
                  const existing = await api<Record<string, unknown>>("/api/v1/protection-settings");
                  await api("/api/v1/protection-settings", {
                    method: "POST",
                    body: JSON.stringify({
                      ...existing,
                      login_min_password_length: parseInt(minLength) || 8,
                      login_max_attempts: parseInt(maxAttempts) || 5,
                      login_lockout_minutes: parseInt(lockoutMinutes) || 30,
                    }),
                  });
                  // toast not imported here, use alert
                  alert("登录安全设置已保存");
                } catch {
                  alert("保存失败");
                } finally {
                  setSavingPolicy(false);
                }
              }}
            >
              {savingPolicy ? "保存中..." : "保存设置"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Create API Key Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {createdKey ? "令牌已创建" : "创建 API 令牌"}
            </DialogTitle>
          </DialogHeader>

          {createdKey ? (
            <div className="space-y-3">
              <p className="text-sm text-slate-600">
                请立即复制此令牌，关闭后将无法再次查看。
              </p>
              <div className="flex items-center gap-2 rounded-md border bg-slate-50 p-3">
                <code className="flex-1 break-all text-xs">{createdKey}</code>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => copyToClipboard(createdKey)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="grid gap-2">
              <Label>令牌名称</Label>
              <Input
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="例如: CI/CD Pipeline"
              />
            </div>
          )}

          <DialogFooter>
            {createdKey ? (
              <Button
                className="bg-teal-500 hover:bg-teal-600 text-white"
                onClick={() => setShowCreate(false)}
              >
                关闭
              </Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setShowCreate(false)}>
                  取消
                </Button>
                <Button
                  className="bg-teal-500 hover:bg-teal-600 text-white"
                  onClick={handleCreate}
                  disabled={submitting || !newKeyName.trim()}
                >
                  {submitting ? "创建中…" : "确认创建"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/* =================================================================
   Tab 3 — 系统日志
   ================================================================= */

function SystemLogTab() {
  return (
    <Card>
      <CardContent className="py-20 text-center">
        <FileText className="mx-auto h-12 w-12 text-slate-300 mb-4" />
        <p className="text-slate-400 text-sm">暂无系统日志</p>
      </CardContent>
    </Card>
  );
}

/* =================================================================
   Main Page
   ================================================================= */

export default function SettingsPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-gray-800">通用设置</h1>
        <p className="text-sm text-gray-500 mt-0.5">管理证书、拦截页面、API 令牌和系统配置</p>
      </div>

      <Tabs defaultValue="protection" className="w-full">
        <TabsList className="bg-transparent border-b border-gray-200 rounded-none w-full justify-start h-auto p-0 gap-0">
          <TabsTrigger
            value="protection"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600 hover:text-gray-800"
          >
            <ShieldCheck className="mr-1.5 h-4 w-4" />
            防护配置
          </TabsTrigger>
          <TabsTrigger
            value="console"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600 hover:text-gray-800"
          >
            <Settings2 className="mr-1.5 h-4 w-4" />
            控制台管理
          </TabsTrigger>
          <TabsTrigger
            value="logs"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600 hover:text-gray-800"
          >
            <FileText className="mr-1.5 h-4 w-4" />
            系统日志
          </TabsTrigger>
        </TabsList>

        <TabsContent value="protection" className="mt-5">
          <ProtectionTab />
        </TabsContent>
        <TabsContent value="console" className="mt-5">
          <ConsoleTab />
        </TabsContent>
        <TabsContent value="logs" className="mt-6">
          <SystemLogTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
