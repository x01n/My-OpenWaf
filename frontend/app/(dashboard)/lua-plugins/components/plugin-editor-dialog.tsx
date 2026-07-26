"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { LuaCodeEditor } from "@/components/lua-code-editor";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useSites,
  useLuaPluginMutation,
  useLuaPluginValidate,
} from "@/hooks/use-api";
import {
  IconFileCode,
  IconFlask,
  IconBook,
  IconCircleCheck,
  IconAlertTriangle,
  IconInfoCircle,
} from "@tabler/icons-react";
import type {
  LuaPlugin,
  LuaPluginStage,
  LuaValidateResult,
} from "@/lib/types";
import { LUA_SKELETON } from "./examples";
import { DryRunPanel } from "./dry-run-panel";
import { LuaHelpPanel } from "./lua-help-panel";

/** 作用域下拉里代表「全站生效」的选项值（Select 不接受空字符串作为 value）。 */
const SCOPE_GLOBAL = "global";

/** 超时上限（毫秒），与后端 luaMaxTimeoutMS 一致。 */
const MAX_TIMEOUT_MS = 1000;

/**
 * @typedef {object} PluginForm
 * @description 编辑器本地表单态。scope 用字符串承载「全站/具体站点」两态，
 *   提交时再映射回 site_id 的 null / number。
 */
interface PluginForm {
  name: string;
  stage: LuaPluginStage;
  source: string;
  priority: number;
  timeout_ms: number;
  scope: string;
  description: string;
  enabled: boolean;
}

const emptyForm: PluginForm = {
  name: "",
  stage: "pre",
  source: LUA_SKELETON,
  priority: 100,
  timeout_ms: 0,
  scope: SCOPE_GLOBAL,
  description: "",
  enabled: true,
};

/**
 * 把超时输入钳制到后端接受的区间。
 *
 * type="number" 的 min/max 只约束步进按钮，手输 5000 照样能提交；
 * 前端先钳一次可以省掉一次注定 400 的往返。
 *
 * @param {string} raw 输入框原始值
 * @returns {number} 0 到 MAX_TIMEOUT_MS 之间的整数
 */
function clampTimeout(raw: string): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.round(n), MAX_TIMEOUT_MS);
}

/**
 * 由 editing 推导初始表单态。
 *
 * @param {LuaPlugin | null} editing 正在编辑的脚本；null 表示新建
 * @returns {PluginForm} 初始表单态
 */
function initialForm(editing: LuaPlugin | null): PluginForm {
  if (!editing) return emptyForm;
  return {
    name: editing.name,
    stage: editing.stage,
    source: editing.source,
    priority: editing.priority,
    timeout_ms: editing.timeout_ms,
    scope:
      editing.site_id === undefined || editing.site_id === null
        ? SCOPE_GLOBAL
        : String(editing.site_id),
    description: editing.description ?? "",
    enabled: editing.enabled,
  };
}

/**
 * @typedef {object} PluginEditorDialogProps
 * @property {boolean} open 是否展开
 * @property {(open: boolean) => void} onOpenChange 展开状态变化回调
 * @property {LuaPlugin | null} editing 正在编辑的脚本；null 表示新建
 * @property {() => void} onSaved 保存成功回调，供父级刷新列表
 */
export interface PluginEditorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: LuaPlugin | null;
  onSaved: () => void;
}

/**
 * 脚本编辑对话框：元信息表单 + 源码编辑 + 语法校验 + 试运行 + 帮助。
 *
 * 表单态只在挂载时由 editing 初始化，不用 useEffect 回填：父级每次打开都会
 * 换掉 key 强制重挂载，既保证不残留上一次的源码，也避免在 effect 里 setState
 * 触发级联渲染（React Compiler 的 set-state-in-effect 会直接报错）。
 *
 * @param {PluginEditorDialogProps} props 组件属性
 * @returns {React.ReactElement} 对话框元素
 */
export function PluginEditorDialog({
  open,
  onOpenChange,
  editing,
  onSaved,
}: PluginEditorDialogProps) {
  const { t } = useTranslation();
  const [form, setForm] = useState<PluginForm>(() => initialForm(editing));
  const [tab, setTab] = useState("script");
  const [validation, setValidation] = useState<LuaValidateResult | null>(null);

  const { data: sitesData } = useSites({ page_size: 500 });
  const sites = useMemo(() => sitesData?.items || [], [sitesData]);

  const { execute: save, loading: saving } = useLuaPluginMutation();
  const { execute: validate, loading: validating } = useLuaPluginValidate();

  const set = <K extends keyof PluginForm>(key: K, value: PluginForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  /**
   * 改动源码或阶段后作废上一次校验结果。
   *
   * 留着旧的「校验通过」徽章会让用户以为改动后的脚本也已通过校验。
   */
  const setSource = (source: string) => {
    setValidation(null);
    set("source", source);
  };

  const setStage = (stage: LuaPluginStage) => {
    setValidation(null);
    set("stage", stage);
  };

  const handleApplyExample = (source: string, stage: LuaPluginStage) => {
    setValidation(null);
    setForm((f) => ({ ...f, source, stage }));
    setTab("script");
    toast.success(t("luaPlugins.help.applied"));
  };

  const handleValidate = async () => {
    try {
      const res = await validate({ stage: form.stage, source: form.source });
      setValidation(res);
      if (res.valid) {
        toast.success(t("luaPlugins.validatePassed"));
      }
    } catch (err) {
      setValidation({
        valid: false,
        error: (err as Error)?.message || t("error.unexpectedError"),
      });
    }
  };

  const handleSubmit = async () => {
    // site_id 显式传 null 才会改回全站；省略会被后端当作「保持原值」。
    const payload: Partial<LuaPlugin> = {
      name: form.name.trim(),
      stage: form.stage,
      source: form.source,
      priority: form.priority,
      timeout_ms: form.timeout_ms,
      description: form.description,
      enabled: form.enabled,
      site_id: form.scope === SCOPE_GLOBAL ? null : Number(form.scope),
    };

    try {
      await save({ id: editing?.id, data: payload });
      toast.success(
        editing ? t("common.updateSuccess") : t("common.createSuccess"),
      );
      onOpenChange(false);
      onSaved();
    } catch (err) {
      // 后端保存前会编译校验，语法错误会以 400 返回；原样透出比泛化文案有用。
      const message = (err as Error)?.message;
      toast.error(
        message ||
          (editing ? t("common.updateFailed") : t("common.createFailed")),
      );
      if (message) {
        setValidation({ valid: false, error: message });
      }
    }
  };

  const canSubmit = form.name.trim() !== "" && form.source.trim() !== "";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>
            {editing ? t("luaPlugins.editTitle") : t("luaPlugins.addTitle")}
          </DialogTitle>
          <DialogDescription>{t("luaPlugins.dialogHint")}</DialogDescription>
        </DialogHeader>

        <Tabs value={tab} onValueChange={setTab} className="space-y-4">
          <TabsList>
            <TabsTrigger value="script">
              <IconFileCode className="mr-1 h-4 w-4" />
              {t("luaPlugins.tabs.script")}
            </TabsTrigger>
            <TabsTrigger value="dryRun">
              <IconFlask className="mr-1 h-4 w-4" />
              {t("luaPlugins.tabs.dryRun")}
            </TabsTrigger>
            <TabsTrigger value="help">
              <IconBook className="mr-1 h-4 w-4" />
              {t("luaPlugins.tabs.help")}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="script" className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>{t("luaPlugins.name")}</Label>
                <Input
                  value={form.name}
                  onChange={(e) => set("name", e.target.value)}
                  placeholder={t("luaPlugins.namePlaceholder")}
                />
              </div>
              <div className="space-y-2">
                <Label>{t("luaPlugins.stage")}</Label>
                <Select
                  value={form.stage}
                  onValueChange={(v) => setStage(v as LuaPluginStage)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pre">
                      {t("luaPlugins.stagePre")}
                    </SelectItem>
                    <SelectItem value="post">
                      {t("luaPlugins.stagePost")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("luaPlugins.priority")}</Label>
                <Input
                  type="number"
                  value={form.priority}
                  onChange={(e) => set("priority", Number(e.target.value))}
                />
                <p className="text-xs text-muted-foreground">
                  {t("luaPlugins.priorityHint")}
                </p>
              </div>
              <div className="space-y-2">
                <Label>{t("luaPlugins.timeout")}</Label>
                <Input
                  type="number"
                  min={0}
                  max={MAX_TIMEOUT_MS}
                  value={form.timeout_ms}
                  onChange={(e) =>
                    set("timeout_ms", clampTimeout(e.target.value))
                  }
                />
                <p className="text-xs text-muted-foreground">
                  {t("luaPlugins.timeoutHint", { max: MAX_TIMEOUT_MS })}
                </p>
              </div>
              <div className="space-y-2">
                <Label>{t("luaPlugins.scope")}</Label>
                <Select
                  value={form.scope}
                  onValueChange={(v) => set("scope", v)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={SCOPE_GLOBAL}>
                      {t("luaPlugins.scopeGlobal")}
                    </SelectItem>
                    {sites.map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        {s.host}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {t("luaPlugins.scopeHint")}
                </p>
              </div>
              <div className="space-y-2">
                <Label>{t("common.description")}</Label>
                <Textarea
                  className="min-h-9"
                  value={form.description}
                  onChange={(e) => set("description", e.target.value)}
                  placeholder={t("luaPlugins.descriptionPlaceholder")}
                />
              </div>
            </div>

            <StageNotice stage={form.stage} />

            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <Label>{t("luaPlugins.enabled")}</Label>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {t("luaPlugins.enabledHint")}
                </p>
              </div>
              <Switch
                checked={form.enabled}
                onCheckedChange={(v) => set("enabled", v)}
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>{t("luaPlugins.source")}</Label>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleValidate}
                  disabled={validating || !form.source.trim()}
                >
                  <IconCircleCheck className="h-4 w-4" />
                  {validating
                    ? t("luaPlugins.validating")
                    : t("luaPlugins.validate")}
                </Button>
              </div>
              <LuaCodeEditor
                value={form.source}
                onChange={setSource}
                rows={18}
                ariaLabel={t("luaPlugins.source")}
                placeholder={LUA_SKELETON}
              />
              <p className="text-xs text-muted-foreground">
                {t("luaPlugins.sourceHint")}
              </p>
              {validation && <ValidationResult result={validation} />}
            </div>
          </TabsContent>

          <TabsContent value="dryRun">
            <DryRunPanel
              stage={form.stage}
              source={form.source}
              timeoutMs={form.timeout_ms}
            />
          </TabsContent>

          <TabsContent value="help">
            <LuaHelpPanel onApplyExample={handleApplyExample} />
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button onClick={handleSubmit} disabled={saving || !canSubmit}>
            {saving
              ? t("common.submitting")
              : editing
                ? t("common.save")
                : t("common.create")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * 阶段语义说明。两个阶段的执行时机与可覆盖范围差别很大，
 * 必须随选择实时说明，否则用户会把 post 脚本当 pre 用。
 *
 * @param {{ stage: LuaPluginStage }} props 组件属性
 * @returns {React.ReactElement} 提示元素
 */
function StageNotice({ stage }: { stage: LuaPluginStage }) {
  const { t } = useTranslation();

  return (
    <Alert>
      <IconInfoCircle className="h-4 w-4" />
      <AlertTitle>
        {stage === "pre"
          ? t("luaPlugins.stagePre")
          : t("luaPlugins.stagePost")}
      </AlertTitle>
      <AlertDescription className="space-y-1">
        <span>
          {stage === "pre"
            ? t("luaPlugins.stagePreDesc")
            : t("luaPlugins.stagePostDesc")}
        </span>
        {stage === "post" && (
          <span className="font-medium text-foreground">
            {t("luaPlugins.stagePostOverride")}
          </span>
        )}
      </AlertDescription>
    </Alert>
  );
}

/**
 * 语法校验结果。
 *
 * @param {{ result: LuaValidateResult }} props 组件属性
 * @returns {React.ReactElement} 结果元素
 */
function ValidationResult({ result }: { result: LuaValidateResult }) {
  const { t } = useTranslation();

  if (result.valid) {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-emerald-500/30 bg-emerald-500/12 text-emerald-700 dark:border-emerald-400/30 dark:bg-emerald-400/15 dark:text-emerald-300"
      >
        <IconCircleCheck className="h-3.5 w-3.5" />
        {t("luaPlugins.validatePassed")}
      </Badge>
    );
  }

  return (
    <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3">
      <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
        <IconAlertTriangle className="h-4 w-4" />
        {t("luaPlugins.compileError")}
      </p>
      <pre className="mt-1.5 overflow-x-auto font-mono text-xs whitespace-pre-wrap text-destructive">
        {result.error || t("error.unexpectedError")}
      </pre>
    </div>
  );
}
