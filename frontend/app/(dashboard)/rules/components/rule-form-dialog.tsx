"use client";

import { useEffect, useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useForm, Controller, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { cn } from "@/lib/utils";
import { IconShieldCheck, IconBan, IconPlus, IconTrash } from "@tabler/icons-react";
import { useRuleMutation } from "@/hooks/use-api";
import { toast } from "sonner";
import type { Rule } from "@/lib/types";

// ============================================================
// 条件行与条件组类型定义
// ============================================================

/** 单个匹配条件行 */
interface ConditionRow {
  target: string;
  method: string;
  content: string;
}

/**
 * 条件组结构：外层数组为 OR 关系，内层数组为 AND 关系
 * 例如: [[row1, row2], [row3]] 表示 (row1 AND row2) OR (row3)
 */
type ConditionGroups = ConditionRow[][];

/** 序列化后的条件 JSON 结构 */
interface ConditionNode {
  op?: "and" | "or";
  children?: ConditionNode[];
  target?: string;
  method?: string;
  content?: string;
}

// ============================================================
// 匹配选项常量
// ============================================================

/** 匹配目标选项 */
const matchTargets = [
  { value: "src_ip", label: "rules.targetSrcIp" },
  { value: "url", label: "rules.targetUrl" },
  { value: "url_path", label: "rules.targetUrlPath" },
  { value: "host", label: "rules.targetHost" },
  { value: "get_param", label: "rules.targetGetParam" },
  { value: "post_param", label: "rules.targetPostParam" },
  { value: "req_header", label: "rules.targetReqHeader" },
  { value: "req_body", label: "rules.targetReqBody" },
  { value: "resp_body", label: "rules.targetRespBody" },
  { value: "http_req", label: "rules.targetHttpReq" },
  { value: "http_resp", label: "rules.targetHttpResp" },
  { value: "method", label: "rules.targetMethod" },
  { value: "ja4", label: "rules.targetJa4" },
];

/** 匹配方式选项 */
const matchMethods = [
  { value: "eq", label: "rules.methodEq" },
  { value: "ne", label: "rules.methodNe" },
  { value: "contains", label: "rules.methodContains" },
  { value: "in_cidr", label: "rules.methodInCidr" },
  { value: "not_in_cidr", label: "rules.methodNotInCidr" },
  { value: "in_ip_group", label: "rules.methodInIpGroup" },
  { value: "not_in_ip_group", label: "rules.methodNotInIpGroup" },
  { value: "in_geo", label: "rules.methodInGeo" },
  { value: "not_in_geo", label: "rules.methodNotInGeo" },
];

/** 限制结果选项 */
const limitActions = [
  { value: "captcha_challenge", label: "rules.actionCaptcha" },
  { value: "block", label: "rules.actionBlock" },
];

// ============================================================
// 条件组序列化/反序列化
// ============================================================

/** 创建一个空的条件行 */
function createEmptyRow(): ConditionRow {
  return { target: "src_ip", method: "eq", content: "" };
}

/** 创建包含一个空条件行的默认条件组 */
function createDefaultGroups(): ConditionGroups {
  return [[createEmptyRow()]];
}

/**
 * 将条件组序列化为后端 pattern JSON 格式
 * 单条件直接输出为对象，多条件使用 and/or 嵌套
 */
function serializeGroups(groups: ConditionGroups): string {
  const orChildren: ConditionNode[] = groups.map((rows) => {
    if (rows.length === 1) {
      return {
        target: rows[0].target,
        method: rows[0].method,
        content: rows[0].content,
      };
    }
    return {
      op: "and" as const,
      children: rows.map((r) => ({
        target: r.target,
        method: r.method,
        content: r.content,
      })),
    };
  });

  if (orChildren.length === 1) {
    return JSON.stringify(orChildren[0]);
  }

  return JSON.stringify({ op: "or", children: orChildren });
}

/**
 * 将后端 pattern 字符串解析回条件组
 * 兼容旧格式（纯字符串）和新格式（JSON）
 */
function parsePattern(pattern: string): ConditionGroups {
  if (!pattern || pattern.trim() === "") {
    return createDefaultGroups();
  }

  try {
    const parsed = JSON.parse(pattern) as ConditionNode;
    return nodeToGroups(parsed);
  } catch {
    // 旧格式：纯字符串作为单条件的 content
    return [[{ target: "src_ip", method: "eq", content: pattern }]];
  }
}

/** 递归解析条件节点为条件组 */
function nodeToGroups(node: ConditionNode): ConditionGroups {
  // 叶子节点：包含 target/method/content
  if (node.target && node.method) {
    return [[{
      target: node.target,
      method: node.method,
      content: node.content || "",
    }]];
  }

  if (node.op === "or" && node.children) {
    return node.children.flatMap((child) => {
      if (child.op === "and" && child.children) {
        return [child.children.map((leaf) => ({
          target: leaf.target || "src_ip",
          method: leaf.method || "eq",
          content: leaf.content || "",
        }))];
      }
      // 单叶子作为一个 OR 组
      return [[{
        target: child.target || "src_ip",
        method: child.method || "eq",
        content: child.content || "",
      }]];
    });
  }

  if (node.op === "and" && node.children) {
    return [node.children.map((leaf) => ({
      target: leaf.target || "src_ip",
      method: leaf.method || "eq",
      content: leaf.content || "",
    }))];
  }

  return createDefaultGroups();
}

// ============================================================
// 表单验证 Schema（条件组由 useState 管理，不走 zod）
// ============================================================

const formSchema = z.object({
  type: z.enum(["allow", "block"]),
  name: z.string().min(1, "rules.nameRequired"),
  windowSeconds: z.number().min(0, "rules.timeWindowInvalid").optional(),
  requestCount: z.number().min(0, "rules.countInvalid").optional(),
  action: z.string().min(1, "rules.actionRequired"),
  captchaMinutes: z.number().min(0, "rules.captchaMinutesInvalid").optional(),
  enabled: z.boolean(),
});

type FormValues = {
  type: "allow" | "block";
  name: string;
  windowSeconds?: number;
  requestCount?: number;
  action: string;
  captchaMinutes?: number;
  enabled: boolean;
};

interface RuleFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule?: Rule | null;
}

/**
 * 规则添加/编辑弹窗组件
 * 支持白名单/黑名单切换、AND/OR 条件组、限制结果配置
 */
export function RuleFormDialog({
  open,
  onOpenChange,
  rule,
}: RuleFormDialogProps) {
  const { execute: mutateRule, loading } = useRuleMutation();
  const { t } = useTranslation();

  // 条件组状态，独立于 react-hook-form 管理
  const [conditionGroups, setConditionGroups] = useState<ConditionGroups>(
    createDefaultGroups()
  );
  const [conditionError, setConditionError] = useState<string>("");

  const {
    register,
    handleSubmit,
    reset,
    control,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    defaultValues: {
      type: "block",
      name: "",
      windowSeconds: 60,
      requestCount: 10,
      action: "block",
      captchaMinutes: 5,
      enabled: true,
    },
  });

  const typeValue = useWatch({ control, name: "type" });

  // ============================================================
  // 条件组操作方法
  // ============================================================

  /** 更新指定条件行的某个字段 */
  const updateRow = useCallback(
    (groupIdx: number, rowIdx: number, field: keyof ConditionRow, value: string) => {
      setConditionGroups((prev) => {
        const next = prev.map((g) => g.map((r) => ({ ...r })));
        next[groupIdx][rowIdx][field] = value;
        return next;
      });
      setConditionError("");
    },
    []
  );

  /** 在指定 AND 组内添加一行条件 */
  const addRowToGroup = useCallback((groupIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.map((g) => [...g]);
      next[groupIdx] = [...next[groupIdx], createEmptyRow()];
      return next;
    });
  }, []);

  /** 删除指定条件行；如果组内只有一行则删除整个组 */
  const removeRow = useCallback((groupIdx: number, rowIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.map((g) => [...g]);
      if (next[groupIdx].length <= 1) {
        // 删除整个 OR 组
        next.splice(groupIdx, 1);
        // 至少保留一个组
        if (next.length === 0) return createDefaultGroups();
        return next;
      }
      next[groupIdx] = next[groupIdx].filter((_, i) => i !== rowIdx);
      return next;
    });
  }, []);

  /** 删除整个 OR 条件组 */
  const removeGroup = useCallback((groupIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.filter((_, i) => i !== groupIdx);
      if (next.length === 0) return createDefaultGroups();
      return next;
    });
  }, []);

  /** 添加一个新的 OR 条件组 */
  const addGroup = useCallback(() => {
    setConditionGroups((prev) => [...prev, [createEmptyRow()]]);
  }, []);

  // ============================================================
  // 表单初始化
  // ============================================================

  // 表单初始化
   
  useEffect(() => {
    if (open && rule) {
      reset({
        type: rule.action === "allow" ? "allow" : "block",
        name: rule.name || "",
        windowSeconds: 60,
        requestCount: 10,
        action: rule.action === "allow" ? "block" : rule.action,
        captchaMinutes: 5,
        enabled: rule.enabled,
      });
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setConditionGroups(parsePattern(rule.pattern));
       
      setConditionError("");
    } else if (open && !rule) {
      reset({
        type: "block",
        name: "",
        windowSeconds: 60,
        requestCount: 10,
        action: "block",
        captchaMinutes: 5,
        enabled: true,
      });
       
      setConditionGroups(createDefaultGroups());
       
      setConditionError("");
    }
  }, [open, rule, reset]);

  // ============================================================
  // 条件组验证
  // ============================================================

  /** 校验条件组至少有一个组且每行内容不为空 */
  const validateConditions = (): boolean => {
    for (const group of conditionGroups) {
      for (const row of group) {
        if (!row.target || !row.method || !row.content.trim()) {
          setConditionError(t("rules.conditionIncomplete", "请完善所有匹配条件"));
          return false;
        }
      }
    }
    if (conditionGroups.length === 0 || conditionGroups.every((g) => g.length === 0)) {
      setConditionError(t("rules.conditionRequired", "至少需要一个匹配条件"));
      return false;
    }
    setConditionError("");
    return true;
  };

  // ============================================================
  // 表单提交
  // ============================================================

  const onSubmit = async (values: FormValues) => {
    if (!validateConditions()) return;

    try {
      const patternJson = serializeGroups(conditionGroups);

      const payload: Record<string, unknown> = {
        name: values.name,
        pattern: patternJson,
        action: values.type === "allow" ? "allow" : values.action,
        phase: "custom",
        enabled: values.enabled,
        priority: 0,
        status_code: 403,
        window_seconds: values.windowSeconds,
        request_count: values.requestCount,
        captcha_minutes: values.captchaMinutes,
      };

      await mutateRule({
        id: rule?.id,
        data: payload,
      });

      toast.success(rule ? t("rules.updateSuccess") : t("rules.createSuccess"));
      onOpenChange(false);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : rule
            ? t("rules.updateFailed")
            : t("rules.createFailed");
      toast.error(message);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {rule ? t("rules.editTitle") : t("rules.addTitle")}
          </DialogTitle>
        </DialogHeader>

        <form
          onSubmit={handleSubmit(onSubmit)}
          className="max-h-[70vh] space-y-5 overflow-y-auto pr-1"
        >
          {/* 白名单/黑名单 单选卡片 */}
          <Controller
            control={control}
            name="type"
            render={({ field }) => (
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => field.onChange("allow")}
                  className={cn(
                    "flex cursor-pointer items-center gap-3 rounded-2xl border px-4 py-3 transition-all",
                    field.value === "allow"
                      ? "border-primary bg-primary/5 text-primary"
                      : "border-border bg-muted/50 hover:bg-muted"
                  )}
                >
                  <IconShieldCheck className="h-5 w-5" />
                  <span className="text-sm font-medium">
                    {t("rules.typeAllow", "白名单")}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => field.onChange("block")}
                  className={cn(
                    "flex cursor-pointer items-center gap-3 rounded-2xl border px-4 py-3 transition-all",
                    field.value === "block"
                      ? "border-primary bg-primary/5 text-primary"
                      : "border-border bg-muted/50 hover:bg-muted"
                  )}
                >
                  <IconBan className="h-5 w-5" />
                  <span className="text-sm font-medium">
                    {t("rules.typeBlock", "黑名单")}
                  </span>
                </button>
              </div>
            )}
          />

          {/* 名称 */}
          <div className="space-y-2">
            <Label>
              {t("common.name")} <span className="text-destructive">*</span>
            </Label>
            <Input
              {...register("name")}
              placeholder={t("rules.namePlaceholder", "请输入规则名称")}
            />
            {errors.name && (
              <p className="text-xs text-destructive">
                {t(errors.name.message!)}
              </p>
            )}
          </div>

          {/* 匹配条件区域 - AND/OR 条件组 */}
          <div className="space-y-3">
            <p className="text-sm font-medium text-muted-foreground">
              {t("rules.matchConditions", "匹配条件")}
            </p>

            {conditionGroups.map((group, groupIdx) => (
              <div key={groupIdx}>
                {/* OR 分隔标签 */}
                {groupIdx > 0 && (
                  <div className="relative my-3 flex items-center justify-center">
                    <div className="absolute inset-x-0 top-1/2 border-t border-dashed border-muted-foreground/30" />
                    <span className="relative z-10 rounded-full bg-orange-500/10 px-3 py-0.5 text-xs font-semibold text-orange-600">
                      OR
                    </span>
                  </div>
                )}

                {/* 单个 AND 条件组 */}
                <div className="rounded-2xl border border-dashed p-4 space-y-3">
                  {group.map((row, rowIdx) => (
                    <div key={rowIdx}>
                      {/* AND 分隔标签 */}
                      {rowIdx > 0 && (
                        <div className="relative my-2 flex items-center justify-center">
                          <div className="absolute inset-x-0 top-1/2 border-t border-muted-foreground/20" />
                          <span className="relative z-10 rounded-full bg-primary/10 px-3 py-0.5 text-xs font-semibold text-primary">
                            AND
                          </span>
                        </div>
                      )}

                      {/* 条件行：匹配目标 + 匹配方式 + 匹配内容 + 删除 */}
                      <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-end">
                        {/* 匹配目标 */}
                        <div className="space-y-1">
                          {rowIdx === 0 && (
                            <Label className="text-xs text-muted-foreground">
                              {t("rules.target")}
                            </Label>
                          )}
                          <Select
                            value={row.target}
                            onValueChange={(v) =>
                              updateRow(groupIdx, rowIdx, "target", v)
                            }
                          >
                            <SelectTrigger className="h-9">
                              <SelectValue
                                placeholder={t(
                                  "rules.targetPlaceholder",
                                  "选择目标"
                                )}
                              />
                            </SelectTrigger>
                            <SelectContent>
                              {matchTargets.map((item) => (
                                <SelectItem key={item.value} value={item.value}>
                                  {t(item.label)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>

                        {/* 匹配方式 */}
                        <div className="space-y-1">
                          {rowIdx === 0 && (
                            <Label className="text-xs text-muted-foreground">
                              {t("rules.method")}
                            </Label>
                          )}
                          <Select
                            value={row.method}
                            onValueChange={(v) =>
                              updateRow(groupIdx, rowIdx, "method", v)
                            }
                          >
                            <SelectTrigger className="h-9">
                              <SelectValue
                                placeholder={t(
                                  "rules.methodPlaceholder",
                                  "选择方式"
                                )}
                              />
                            </SelectTrigger>
                            <SelectContent>
                              {matchMethods.map((m) => (
                                <SelectItem key={m.value} value={m.value}>
                                  {t(m.label)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>

                        {/* 匹配内容 */}
                        <div className="space-y-1">
                          {rowIdx === 0 && (
                            <Label className="text-xs text-muted-foreground">
                              {t("rules.content")}
                            </Label>
                          )}
                          <Input
                            className="h-9"
                            value={row.content}
                            onChange={(e) =>
                              updateRow(
                                groupIdx,
                                rowIdx,
                                "content",
                                e.target.value
                              )
                            }
                            placeholder={t(
                              "rules.contentPlaceholder",
                              "匹配内容"
                            )}
                          />
                        </div>

                        {/* 删除按钮 */}
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="h-9 w-9 text-muted-foreground hover:text-destructive"
                          onClick={() => removeRow(groupIdx, rowIdx)}
                        >
                          <IconTrash className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}

                  {/* 组内操作栏 */}
                  <div className="flex items-center justify-between pt-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="text-primary border-primary/30 hover:bg-primary/5"
                      onClick={() => addRowToGroup(groupIdx)}
                    >
                      <IconPlus className="mr-1 h-3.5 w-3.5" />
                      {t("rules.addAndCondition", "添加一个 AND 条件")}
                    </Button>

                    {conditionGroups.length > 1 && (
                      <Button
                        type="button"
                        variant="destructive"
                        size="sm"
                        onClick={() => removeGroup(groupIdx)}
                      >
                        <IconTrash className="mr-1 h-3.5 w-3.5" />
                        {t("rules.deleteGroup", "删除该条件组")}
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {/* 添加 OR 条件组按钮 */}
            <Button
              type="button"
              variant="outline"
              className="w-full border-dashed border-primary/40 text-primary hover:bg-primary/5"
              onClick={addGroup}
            >
              <IconPlus className="mr-1.5 h-4 w-4" />
              {t("rules.addOrCondition", "添加一个 OR 条件")}
            </Button>

            {/* 条件组验证错误提示 */}
            {conditionError && (
              <p className="text-xs text-destructive">{conditionError}</p>
            )}
          </div>

          {/* 限制配置（仅黑名单） */}
          {typeValue === "block" && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>{t("rules.timeWindowLabel", "时间窗口（秒）")}</Label>
                <Input type="number" {...register("windowSeconds")} />
              </div>
              <div className="space-y-2">
                <Label>{t("rules.requestCountLabel", "请求次数")}</Label>
                <Input type="number" {...register("requestCount")} />
              </div>
              <div className="space-y-2">
                <Label>
                  {t("rules.actionResult")}{" "}
                  <span className="text-destructive">*</span>
                </Label>
                <Controller
                  control={control}
                  name="action"
                  render={({ field }) => (
                    <Select value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger>
                        <SelectValue
                          placeholder={t(
                            "rules.actionPlaceholder",
                            "选择限制结果"
                          )}
                        />
                      </SelectTrigger>
                      <SelectContent>
                        {limitActions.map((a) => (
                          <SelectItem key={a.value} value={a.value}>
                            {t(a.label)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
                {errors.action && (
                  <p className="text-xs text-destructive">
                    {t(errors.action.message!)}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label>
                  {t("rules.captchaMinutesLabel", "验证码时间（分钟）")}
                </Label>
                <Input type="number" {...register("captchaMinutes")} />
              </div>
            </div>
          )}

          {/* 启用开关 */}
          <div className="flex items-center gap-2">
            <Controller
              control={control}
              name="enabled"
              render={({ field }) => (
                <Checkbox
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              )}
            />
            <Label className="cursor-pointer">
              {t("rules.enableRule", "启用规则")}
            </Label>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? t("common.submitting") : t("common.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
