"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api";
import { toast } from "sonner";

// Mode: off / observe / mid / high
type ModuleMode = "off" | "observe" | "mid" | "high";

interface OWASPModuleSetting {
  key: string;
  label: string;
  mode: ModuleMode;
}

const DEFAULT_MODULES: OWASPModuleSetting[] = [
  { key: "sqli", label: "SQL 注入检测", mode: "mid" },
  { key: "xss", label: "XSS 检测", mode: "mid" },
  { key: "file_upload", label: "文件上传检测", mode: "mid" },
  { key: "path_traversal", label: "文件包含检测", mode: "mid" },
  { key: "cmd_injection", label: "命令注入检测", mode: "mid" },
  { key: "java_code_injection", label: "JAVA 代码注入检测", mode: "mid" },
  { key: "java_deserialization", label: "JAVA 反序列化检测", mode: "mid" },
  { key: "php_deserialization", label: "PHP 反序列化检测", mode: "mid" },
  { key: "php_code_injection", label: "PHP 代码注入检测", mode: "mid" },
  { key: "asp_code_injection", label: "ASP 代码注入检测", mode: "mid" },
  { key: "ssrf", label: "SSRF 检测", mode: "mid" },
  { key: "xxe", label: "XXE 检测", mode: "mid" },
  { key: "crlf", label: "CRLF 注入检测", mode: "mid" },
  { key: "ldap_injection", label: "LDAP 注入检测", mode: "mid" },
];

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
  builtin_owasp_enabled: boolean;
  builtin_owasp_sensitivity: string;
  builtin_owasp_on_hit: string;
  maintenance_global_enabled: boolean;
  maintenance_global_html: string;
  maintenance_global_status: number;
  bot_detection_enabled: boolean;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  auto_ban_window: number;
  auto_ban_duration: number;
  owasp_modules?: Record<string, ModuleMode>;
}

export default function ProtectionPage() {
  const [cfg, setCfg] = useState<ProtectionConfig | null>(null);
  const [modules, setModules] = useState<OWASPModuleSetting[]>(DEFAULT_MODULES);
  const [useCustomConfig, setUseCustomConfig] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api<ProtectionConfig>("/api/v1/protection-settings")
      .then((data) => {
        setCfg(data);
        if (data.owasp_modules) {
          setUseCustomConfig(true);
          setModules((prev) =>
            prev.map((m) => ({
              ...m,
              mode: data.owasp_modules![m.key] || m.mode,
            }))
          );
        }
      })
      .catch(() => {});
  }, []);

  const setModuleMode = useCallback((key: string, mode: ModuleMode) => {
    setModules((prev) =>
      prev.map((m) => (m.key === key ? { ...m, mode } : m))
    );
  }, []);

  const batchSetAll = useCallback((mode: ModuleMode) => {
    setModules((prev) => prev.map((m) => ({ ...m, mode })));
  }, []);

  async function handleSave() {
    if (!cfg) return;
    setSaving(true);
    try {
      const moduleMap: Record<string, ModuleMode> = {};
      modules.forEach((m) => {
        moduleMap[m.key] = m.mode;
      });

      const anyEnabled = modules.some((m) => m.mode !== "off");
      const hasIntercept = modules.some(
        (m) => m.mode === "mid" || m.mode === "high"
      );

      const payload: ProtectionConfig = {
        ...cfg,
        builtin_owasp_enabled: anyEnabled,
        builtin_owasp_on_hit: hasIntercept ? "intercept" : "observe",
        owasp_modules: useCustomConfig ? moduleMap : undefined,
      };

      await api("/api/v1/protection-settings", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast.success("已保存，配置重载后生效");
    } catch {
      toast.error("保存失败");
    } finally {
      setSaving(false);
    }
  }

  if (!cfg)
    return (
      <p className="text-sm text-gray-500 py-12 text-center">加载中...</p>
    );

  return (
    <div className="space-y-6">
      {/* 页面标题 */}
      <div>
        <h1 className="text-2xl font-semibold text-gray-900">攻击防护</h1>
        <p className="text-sm text-gray-500 mt-1">
          配置语义分析引擎的各检测模块及防护级别
        </p>
      </div>

      {/* 主卡片 */}
      <Card className="bg-white shadow-sm border border-gray-200">
        <CardContent className="p-6 space-y-4">
          {/* 顶部操作栏 */}
          <div className="flex items-center justify-between">
            {/* Tab 切换按钮 */}
            <div className="flex items-center rounded-md border border-gray-200 overflow-hidden">
              <button
                onClick={() => setUseCustomConfig(false)}
                className={`px-4 py-2 text-sm transition-colors ${
                  !useCustomConfig
                    ? "bg-teal-500 text-white"
                    : "bg-white text-gray-600 hover:bg-gray-50"
                }`}
              >
                跟随全局配置
              </button>
              <button
                onClick={() => setUseCustomConfig(true)}
                className={`px-4 py-2 text-sm border-l border-gray-200 transition-colors ${
                  useCustomConfig
                    ? "bg-teal-500 text-white"
                    : "bg-white text-gray-600 hover:bg-gray-50"
                }`}
              >
                使用自定义配置
              </button>
            </div>

            {/* 批量配置下拉（仅自定义模式显示） */}
            {useCustomConfig && (
              <Select onValueChange={(v) => batchSetAll(v as ModuleMode)}>
                <SelectTrigger className="w-40 border-gray-200 text-sm">
                  <SelectValue placeholder="批量配置为" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="off">禁用</SelectItem>
                  <SelectItem value="observe">仅观察</SelectItem>
                  <SelectItem value="mid">平衡防护</SelectItem>
                  <SelectItem value="high">高强度防护</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>

          {/* 自定义配置表格 */}
          {useCustomConfig && (
            <div className="rounded-lg border border-gray-200 overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="bg-gray-50 hover:bg-gray-50">
                    <TableHead className="w-[240px] text-gray-600 font-medium py-3 pl-4">
                      检测模块
                    </TableHead>
                    <TableHead className="text-center text-gray-600 font-medium py-3">
                      禁用
                    </TableHead>
                    <TableHead className="text-center text-gray-600 font-medium py-3">
                      仅观察
                    </TableHead>
                    <TableHead className="text-center text-gray-600 font-medium py-3">
                      平衡防护
                    </TableHead>
                    <TableHead className="text-center text-gray-600 font-medium py-3">
                      高强度防护
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {modules.map((mod) => (
                    <TableRow
                      key={mod.key}
                      className="border-t border-gray-100 hover:bg-gray-50"
                    >
                      <TableCell className="font-medium text-gray-800 py-3 pl-4">
                        {mod.label}
                      </TableCell>
                      {(["off", "observe", "mid", "high"] as ModuleMode[]).map(
                        (mode) => (
                          <TableCell key={mode} className="text-center py-3">
                            <RadioGroup
                              value={mod.mode}
                              onValueChange={(v) =>
                                setModuleMode(mod.key, v as ModuleMode)
                              }
                              className="flex justify-center"
                            >
                              <RadioGroupItem
                                value={mode}
                                className="mx-auto accent-teal-500"
                              />
                            </RadioGroup>
                          </TableCell>
                        )
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* 全局配置提示 */}
          {!useCustomConfig && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-6 text-center text-sm text-gray-500">
              当前使用全局配置：
              <span className="font-medium text-gray-800 ml-1">
                {cfg.builtin_owasp_enabled ? "已启用" : "已禁用"}
              </span>
              {cfg.builtin_owasp_enabled && (
                <>
                  ，敏感度：
                  <span className="font-medium text-gray-800">
                    {cfg.builtin_owasp_sensitivity === "low"
                      ? "低"
                      : cfg.builtin_owasp_sensitivity === "mid"
                        ? "中"
                        : "高"}
                  </span>
                  ，命中动作：
                  <span className="font-medium text-gray-800">
                    {cfg.builtin_owasp_on_hit === "intercept" ? "拦截" : "观察"}
                  </span>
                </>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 底部操作按钮 */}
      <div className="flex justify-end gap-3">
        <Button
          variant="outline"
          onClick={() => window.location.reload()}
          className="text-teal-500 border-teal-500 hover:bg-teal-50 hover:text-teal-600"
        >
          取消
        </Button>
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-teal-500 hover:bg-teal-600 text-white border-0"
        >
          {saving ? "保存中..." : "保存"}
        </Button>
      </div>
    </div>
  );
}
