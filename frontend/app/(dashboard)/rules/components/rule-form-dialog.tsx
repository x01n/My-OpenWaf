"use client"

import { useEffect, useState, useCallback } from "react"
import { useTranslation } from "react-i18next"
import {
  useForm,
  Controller,
  useWatch,
  type FieldErrors,
} from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { cn } from "@/lib/utils"
import {
  IconShieldCheck,
  IconBan,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react"
import { useRuleMutation } from "@/hooks/use-api"
import { ruleApi } from "@/lib/api"
import { toast } from "sonner"
import type { CaptchaType, Rule } from "@/lib/types"
import {
  serializeGroupsToPattern,
  parsePatternToRows,
  type ConditionRow,
} from "./rule-pattern-mapper"

/**
 * 条件组结构：外层数组为 OR 关系，内层数组为 AND 关系
 * 例如: [[row1, row2], [row3]] 表示 (row1 AND row2) OR (row3)
 */
type ConditionGroups = ConditionRow[][]

/** 匹配目标选项 */
const matchTargets = [
  { value: "src_ip", label: "rules.targetSrcIp" },
  { value: "url", label: "rules.targetUrl" },
  { value: "url_path", label: "rules.targetUrlPath" },
  { value: "host", label: "rules.targetHost" },
  { value: "host_full", label: "rules.targetHostFull" },
  { value: "get_param", label: "rules.targetGetParam" },
  { value: "post_param", label: "rules.targetPostParam" },
  { value: "req_header", label: "rules.targetReqHeader" },
  { value: "req_body", label: "rules.targetReqBody" },
  { value: "resp_body", label: "rules.targetRespBody" },
  { value: "http_req", label: "rules.targetHttpReq" },
  { value: "http_resp", label: "rules.targetHttpResp" },
  { value: "method", label: "rules.targetMethod" },
  { value: "ja4", label: "rules.targetJa4" },
]

/** 匹配方式选项 */
const matchMethods = [
  { value: "eq", label: "rules.methodEq" },
  { value: "ne", label: "rules.methodNe" },
  { value: "contains", label: "rules.methodContains" },
  { value: "regex", label: "rules.methodRegex" },
  { value: "prefix", label: "rules.methodPrefix" },
  { value: "wildcard", label: "rules.methodWildcard" },
  { value: "in_cidr", label: "rules.methodInCidr" },
  { value: "not_in_cidr", label: "rules.methodNotInCidr" },
  { value: "in_ip_group", label: "rules.methodInIpGroup" },
  { value: "not_in_ip_group", label: "rules.methodNotInIpGroup" },
  { value: "in_geo", label: "rules.methodInGeo" },
  { value: "not_in_geo", label: "rules.methodNotInGeo" },
]

/** 限制结果选项 */
const limitActions = [
  { value: "captcha_challenge", label: "rules.actionCaptcha" },
  { value: "block", label: "rules.actionBlock" },
]

const captchaTypeOptions: Array<{ value: CaptchaType; label: string }> = [
  { value: "math", label: "数学" },
  { value: "click", label: "点选" },
  { value: "slide", label: "滑块" },
  { value: "rotate", label: "旋转" },
]

/** 创建一个空的条件行 */
function createEmptyRow(): ConditionRow {
  return { target: "src_ip", method: "eq", content: "" }
}

/** 创建包含一个空条件行的默认条件组 */
function createDefaultGroups(): ConditionGroups {
  return [[createEmptyRow()]]
}

/**
 * 将条件组序列化为后端 pattern JSON 格式。
 *
 * ——契约要求——
 * 后端 `parseCompoundJSON`（matcher.go 行 1137-1143）只识别以下节点：
 *   - `{op: "and"|"or"|"not"|"if"|"cc_rate", children: [...]}` 复合节点
 *   - 叶子 `{kind, arg}`
 * 旧形态 `{target, method, content}` 落到 `buildCompound` 的 default 分支
 * 后会返回 `neverMatcher`，等价于空规则。本函数通过
 * `rule-pattern-mapper.serializeGroupsToPattern` 把 UI 行翻译成合法
 * kind/arg 后再序列化为 compound JSON。
 */
function serializeGroups(
  groups: ConditionGroups,
  options: { allowIP?: boolean } = {}
): string {
  return serializeGroupsToPattern(groups, options)
}

/**
 * 将后端 pattern 字符串解析回条件组。
 * 兼容后端的两类持久化形态：
 *   - 简单 DSL：`block_path_exact:/admin`（个人脚本上手写的旧规则）
 *   - JSON compound 条件（`serializeGroupsToPattern` 产出的形态）
 * 旧版前端写出的 `{target, method, content}` 残留 JSON 形态会通过
 * `parsePatternToRows` 兜底成单行 src_ip + eq。
 */
function parsePattern(pattern: string): ConditionGroups {
  return parsePatternToRows(pattern)
}

/**
 * 数字输入字段的 schema。
 *
 * `register()` 未配置 `valueAsNumber` 时，react-hook-form 会把 DOM 的
 * 字符串原样写回字段值（用户一旦编辑过输入框），而 zod v4 的
 * `z.number()` 对字符串直接判 invalid_type，导致 `handleSubmit` 连
 * `onSubmit` 都不会进入——表现为「点了提交没有任何反应」。这里用
 * `z.preprocess` 先做归一化：空串/未填 → undefined（走 optional），
 * 数字字符串 → Number，其余交给 `z.number()` 判定（NaN 与负数仍报错）。
 *
 * @param invalidMessage i18n 键，校验失败时的提示文案
 */
const optionalNumberField = (invalidMessage: string) =>
  z.preprocess(
    (value) => {
      if (value === undefined || value === null || value === "") {
        return undefined
      }
      return typeof value === "string" ? Number(value) : value
    },
    z.number({ message: invalidMessage }).min(0, invalidMessage).optional()
  )

const formSchema = z.object({
  type: z.enum(["allow", "block"]),
  name: z.string().min(1, "rules.nameRequired"),
  windowSeconds: optionalNumberField("rules.timeWindowInvalid"),
  requestCount: optionalNumberField("rules.countInvalid"),
  action: z.string().min(1, "rules.actionRequired"),
  captchaType: z.enum(["", "math", "click", "slide", "rotate"]),
  captchaMinutes: optionalNumberField("rules.captchaMinutesInvalid"),
  enabled: z.boolean(),
})

type FormValues = {
  type: "allow" | "block"
  name: string
  windowSeconds?: number
  requestCount?: number
  action: string
  captchaType: "" | CaptchaType
  captchaMinutes?: number
  enabled: boolean
}

interface RuleFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule?: Rule | null
  policyId?: number
}

/**
 * 规则添加/编辑弹窗组件
 * 支持白名单/黑名单切换、AND/OR 条件组、限制结果配置
 */
export function RuleFormDialog({
  open,
  onOpenChange,
  rule,
  policyId,
}: RuleFormDialogProps) {
  const { execute: mutateRule, loading } = useRuleMutation()
  const { t } = useTranslation()

  // 条件组状态，独立于 react-hook-form 管理
  const [conditionGroups, setConditionGroups] = useState<ConditionGroups>(
    createDefaultGroups()
  )
  const [conditionError, setConditionError] = useState<string>("")

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
      captchaType: "",
      captchaMinutes: 5,
      enabled: true,
    },
  })

  const typeValue = useWatch({ control, name: "type" })
  const actionValue = useWatch({ control, name: "action" })
  const hasUneditableCondition = conditionGroups.some((group) =>
    group.some((row) => row.uneditable)
  )

  /** 更新指定条件行的某个字段 */
  const updateRow = useCallback(
    (
      groupIdx: number,
      rowIdx: number,
      field: "target" | "method" | "content" | "headerName" | "paramName",
      value: string
    ) => {
      setConditionGroups((prev) => {
        const next = prev.map((g) => g.map((r) => ({ ...r })))
        next[groupIdx][rowIdx] = {
          ...next[groupIdx][rowIdx],
          [field]: value,
        }
        return next
      })
      setConditionError("")
    },
    []
  )

  /** 在指定 AND 组内添加一行条件 */
  const addRowToGroup = useCallback((groupIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.map((g) => [...g])
      next[groupIdx] = [...next[groupIdx], createEmptyRow()]
      return next
    })
  }, [])

  /** 删除指定条件行；如果组内只有一行则删除整个组 */
  const removeRow = useCallback((groupIdx: number, rowIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.map((g) => [...g])
      if (next[groupIdx].length <= 1) {
        // 删除整个 OR 组
        next.splice(groupIdx, 1)
        // 至少保留一个组
        if (next.length === 0) return createDefaultGroups()
        return next
      }
      next[groupIdx] = next[groupIdx].filter((_, i) => i !== rowIdx)
      return next
    })
  }, [])

  /** 删除整个 OR 条件组 */
  const removeGroup = useCallback((groupIdx: number) => {
    setConditionGroups((prev) => {
      const next = prev.filter((_, i) => i !== groupIdx)
      if (next.length === 0) return createDefaultGroups()
      return next
    })
  }, [])

  /** 添加一个新的 OR 条件组 */
  const addGroup = useCallback(() => {
    setConditionGroups((prev) => [...prev, [createEmptyRow()]])
  }, [])

  // 表单初始化

  useEffect(() => {
    if (open && rule) {
      reset({
        type: rule.action === "allow" ? "allow" : "block",
        name: rule.name || "",
        // 空值保持 undefined，让输入框显示为空而不是伪造一个 0；
        // 后端把 0 解释为「未配置」（不启用频次限制 / 继承全局验证码有效期）。
        windowSeconds: rule.window_seconds || undefined,
        requestCount: rule.request_count || undefined,
        action: rule.action === "allow" ? "block" : rule.action,
        captchaType: rule.captcha_type ?? "",
        captchaMinutes: rule.captcha_minutes || undefined,
        enabled: rule.enabled,
      })
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setConditionGroups(parsePattern(rule.pattern))

      setConditionError("")
    } else if (open && !rule) {
      reset({
        type: "block",
        name: "",
        windowSeconds: 60,
        requestCount: 10,
        action: "block",
        captchaType: "",
        captchaMinutes: 5,
        enabled: true,
      })

      setConditionGroups(createDefaultGroups())

      setConditionError("")
    }
  }, [open, rule, reset])

  /**
   * 校验失败时的统一收尾：展示原因并阻止提交。
   *
   * 条件组状态独立于 react-hook-form，其错误不会进入 `errors`，只在表单
   * 底部的 `conditionError` 处渲染；弹窗内容可滚动时该提示容易落在可视区
   * 之外。这里同时弹 toast，保证「点了提交没反应」不会再次出现。
   *
   * @param message 已本地化的失败原因
   * @returns 恒为 false，供调用方直接 return
   */
  const rejectSubmit = (message: string) => {
    setConditionError(message)
    toast.error(message)
    return false
  }

  /** `handleSubmit` 的第二个回调：zod 校验失败时不会进入 onSubmit，必须在此显式提示。 */
  const onInvalid = (formErrors: FieldErrors<FormValues>) => {
    const firstMessage = Object.values(formErrors).find(
      (error) => typeof error?.message === "string"
    )?.message
    rejectSubmit(firstMessage ? t(firstMessage) : t("error.formInvalid"))
  }

  /** 校验条件组至少有一个组且每行内容不为空，且每行能映射到后端合法 matcher。 */
  const validateConditions = async (): Promise<boolean> => {
    for (const group of conditionGroups) {
      for (const row of group) {
        if (row.uneditable) {
          return rejectSubmit(
            t(
              "rules.conditionUneditable",
              "该规则包含当前表单无法安全编辑的条件，请保留原规则或使用支持该条件的编辑方式。"
            )
          )
        }
        if (!row.target || !row.method || !row.content.trim()) {
          return rejectSubmit(
            t("rules.conditionIncomplete", "请完善所有匹配条件")
          )
        }
      }
    }
    if (
      conditionGroups.length === 0 ||
      conditionGroups.every((g) => g.length === 0)
    ) {
      return rejectSubmit(t("rules.conditionRequired", "至少需要一个匹配条件"))
    }
    // 二次校验：所有 (target, method) 组合都必须能映射到后端合法 matcher。
    // 否则会被后端落成 neverMatcher，等同空规则。
    try {
      const pattern = serializeGroups(conditionGroups, {
        allowIP: typeValue === "allow",
      })
      if (!pattern) {
        return rejectSubmit(
          t("rules.conditionRequired", "至少需要一个匹配条件")
        )
      }
      const result = (await ruleApi.validate({ pattern })) as {
        valid?: boolean
        message?: string
        errors?: string[]
      }
      if (!result.valid) {
        return rejectSubmit(
          result.errors?.join("；") ||
            result.message ||
            t("rules.conditionInvalid", "规则条件无法通过后端校验")
        )
      }
    } catch (err) {
      return rejectSubmit(
        err instanceof Error
          ? `条件无法编译为合法规则: ${err.message}`
          : "条件无法编译为合法规则"
      )
    }
    setConditionError("")
    return true
  }

  const onSubmit = async (values: FormValues) => {
    if (!(await validateConditions())) return

    try {
      const patternJson = serializeGroups(conditionGroups, {
        allowIP: values.type === "allow",
      })

      const payload: Record<string, unknown> = {
        name: values.name,
        pattern: patternJson,
        action: values.type === "allow" ? "allow" : values.action,
        enabled: values.enabled,
        captcha_type:
          values.type === "block" && values.action === "captcha_challenge"
            ? values.captchaType
            : "",
        // 规则级执行参数。清空输入框时 values 为 undefined，这里统一折算成 0，
        // 与后端的「0 = 未配置」契约一致（频次限制关闭 / 继承全局验证码有效期）。
        // 更新时同样显式下发，管理员把参数清空才能真的取消限制。
        window_seconds: values.windowSeconds ?? 0,
        request_count: values.requestCount ?? 0,
        // 与同为验证码专用的 captcha_type 保持同一口径：动作不是
        // captcha_challenge 时归一为 0（继承全局）。否则把规则从
        // captcha_challenge 改成 intercept 会留下一段不生效的陈旧有效期，
        // 之后改回验证码动作时会静默复活一个没人记得设置过的值。
        captcha_minutes:
          values.type === "block" && values.action === "captcha_challenge"
            ? (values.captchaMinutes ?? 0)
            : 0,
      }

      if (!rule) {
        // 创建时仅补充本表单负责的默认元数据。更新时省略 phase、
        // status_code、priority、redirect_to 等字段，由后端保留原值，
        // 避免编辑规则时覆盖其他管理入口维护的配置。
        payload.policy_id = policyId
        payload.phase = values.type === "allow" ? "acl" : "custom"
        payload.status_code = 403
      }

      await mutateRule({
        id: rule?.id,
        data: payload,
      })

      toast.success(rule ? t("rules.updateSuccess") : t("rules.createSuccess"))
      onOpenChange(false)
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : rule
            ? t("rules.updateFailed")
            : t("rules.createFailed")
      toast.error(message)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {rule ? t("rules.editTitle") : t("rules.addTitle")}
          </DialogTitle>
        </DialogHeader>

        <form
          onSubmit={handleSubmit(onSubmit, onInvalid)}
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
                <div className="space-y-3 rounded-2xl border border-dashed p-4">
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

                      {row.uneditable ? (
                        <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
                          <p className="text-xs text-muted-foreground">
                            {t(
                              "rules.conditionUneditable",
                              "该规则包含当前表单无法安全编辑的条件，请保留原规则或使用支持该条件的编辑方式。"
                            )}
                          </p>
                          <code className="block max-h-32 overflow-auto rounded bg-muted px-2 py-1 text-xs break-all whitespace-pre-wrap">
                            {row.rawPattern ?? ""}
                          </code>
                        </div>
                      ) : (
                        <>
                          {/* 条件行：匹配目标 + 匹配方式 + 匹配内容 + 删除 */}
                          <div className="grid grid-cols-[1fr_1fr_1fr_auto] items-end gap-2">
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
                                    <SelectItem
                                      key={item.value}
                                      value={item.value}
                                    >
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

                          {/* Header / Param 名称输入：仅当 target 需要 name 时显示。
                          后端 matcher 接受 `Name:value` 形式（splitHeaderArg 切分）。 */}
                          {(row.target === "req_header" ||
                            row.target === "get_param" ||
                            row.target === "post_param") && (
                            <div className="mt-2 grid grid-cols-[1fr_auto] items-end gap-2 pl-1">
                              <div className="space-y-1">
                                <Label className="text-xs text-muted-foreground">
                                  {row.target === "req_header"
                                    ? t(
                                        "rules.headerName",
                                        "Header 名称（如 User-Agent）"
                                      )
                                    : t("rules.paramName", "参数名称（如 id）")}
                                </Label>
                                <Input
                                  className="h-9"
                                  value={
                                    row.target === "req_header"
                                      ? (row.headerName ?? "")
                                      : (row.paramName ?? "")
                                  }
                                  onChange={(e) =>
                                    updateRow(
                                      groupIdx,
                                      rowIdx,
                                      row.target === "req_header"
                                        ? "headerName"
                                        : "paramName",
                                      e.target.value
                                    )
                                  }
                                  placeholder={
                                    row.target === "req_header"
                                      ? "User-Agent"
                                      : "id"
                                  }
                                />
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  ))}

                  {/* 组内操作栏 */}
                  <div className="flex items-center justify-between pt-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="border-primary/30 text-primary hover:bg-primary/5"
                      onClick={() => addRowToGroup(groupIdx)}
                      disabled={hasUneditableCondition}
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
                        disabled={hasUneditableCondition}
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
              disabled={hasUneditableCondition}
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
              {actionValue === "captcha_challenge" && (
                <div className="space-y-2">
                  <Label>{t("rules.captchaTypeLabel", "验证码类型")}</Label>
                  <Controller
                    control={control}
                    name="captchaType"
                    render={({ field }) => (
                      <Select
                        value={field.value || "inherit"}
                        onValueChange={(value) =>
                          field.onChange(value === "inherit" ? "" : value)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="inherit">
                            {t("rules.captchaTypeInherit", "继承全局")}
                          </SelectItem>
                          {captchaTypeOptions.map((option) => (
                            <SelectItem key={option.value} value={option.value}>
                              {t(
                                `rules.captchaType.${option.value}`,
                                option.label
                              )}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  />
                </div>
              )}
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
            <Button type="submit" disabled={loading || hasUneditableCondition}>
              {loading ? t("common.submitting") : t("common.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
