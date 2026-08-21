"use client"

import { useTranslation } from "react-i18next"
import { IconPlus, IconTrash } from "@tabler/icons-react"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import type { SkipPathByPhase, SkipPathPhase } from "@/lib/types"
import {
  SKIP_PATH_PHASE_LABELS,
  SKIP_PATH_PHASES,
} from "@/lib/skip-path-by-phase"

interface SkipPathByPhaseEditorProps {
  value: SkipPathByPhase
  onChange: (value: SkipPathByPhase) => void
  disabled?: boolean
  idPrefix: string
}

/** 按 phase 编辑跳过路径列表，保留空输入供保存前显示精确校验错误。 */
export function SkipPathByPhaseEditor({
  value,
  onChange,
  disabled = false,
  idPrefix,
}: SkipPathByPhaseEditorProps) {
  const { t, i18n } = useTranslation()
  const useChinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh")
  const fallback = (zh: string, en: string) => (useChinese ? zh : en)

  const updatePhase = (phase: SkipPathPhase, paths: string[]) => {
    const next = { ...value }
    if (paths.length === 0) delete next[phase]
    else next[phase] = paths
    onChange(next)
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {t("skipPathByPhase.description", {
          defaultValue: fallback(
            "匹配路径的请求会跳过所选检测阶段；未配置的阶段继续正常执行。",
            "Requests matching a path skip the selected phase; unconfigured phases continue normally."
          ),
        })}
      </p>
      <Accordion
        type="multiple"
        defaultValue={SKIP_PATH_PHASES.filter(
          (phase) => (value[phase]?.length ?? 0) > 0
        )}
        className="rounded-xl"
      >
        {SKIP_PATH_PHASES.map((phase) => {
          const paths = value[phase] ?? []
          const label = t(`skipPathByPhase.phases.${phase}`, {
            defaultValue: fallback(
              SKIP_PATH_PHASE_LABELS[phase].zh,
              SKIP_PATH_PHASE_LABELS[phase].en
            ),
          })
          return (
            <AccordionItem key={phase} value={phase}>
              <AccordionTrigger className="items-center px-3 py-3 hover:no-underline sm:px-4">
                <span className="flex min-w-0 items-center gap-2">
                  <span className="truncate">{label}</span>
                  <code className="hidden text-xs font-normal text-muted-foreground sm:inline">
                    {phase}
                  </code>
                </span>
                <Badge variant="secondary" className="shrink-0 tabular-nums">
                  {paths.length}
                </Badge>
              </AccordionTrigger>
              <AccordionContent className="space-y-2 px-3 sm:px-4">
                {paths.length === 0 ? (
                  <p className="rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground">
                    {t("skipPathByPhase.emptyPhase", {
                      defaultValue: fallback(
                        "此阶段未配置跳过路径。",
                        "No skipped paths are configured for this phase."
                      ),
                    })}
                  </p>
                ) : (
                  paths.map((path, index) => {
                    const inputId = `${idPrefix}-${phase}-${index}`
                    const invalid = path.trim() === ""
                    return (
                      <div key={inputId} className="space-y-1">
                        <Label htmlFor={inputId} className="sr-only">
                          {t("skipPathByPhase.pathLabel", {
                            label,
                            index: index + 1,
                            defaultValue: fallback(
                              "{{label}} 路径 {{index}}",
                              "{{label}} path {{index}}"
                            ),
                          })}
                        </Label>
                        <div className="flex min-w-0 items-center gap-2">
                          <Input
                            id={inputId}
                            value={path}
                            disabled={disabled}
                            aria-invalid={invalid}
                            autoComplete="off"
                            className="font-mono text-xs"
                            placeholder={t("skipPathByPhase.pathPlaceholder", {
                              defaultValue: fallback(
                                "输入路径",
                                "Enter a path"
                              ),
                            })}
                            onChange={(event) => {
                              const next = [...paths]
                              next[index] = event.target.value
                              updatePhase(phase, next)
                            }}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            disabled={disabled}
                            className="shrink-0 text-muted-foreground hover:text-destructive"
                            aria-label={t("skipPathByPhase.removePath", {
                              defaultValue: fallback("删除路径", "Remove path"),
                            })}
                            onClick={() =>
                              updatePhase(
                                phase,
                                paths.filter(
                                  (_, pathIndex) => pathIndex !== index
                                )
                              )
                            }
                          >
                            <IconTrash />
                          </Button>
                        </div>
                        {invalid && (
                          <p className="text-xs text-destructive" role="alert">
                            {t("skipPathByPhase.pathRequired", {
                              defaultValue: fallback(
                                "路径不能为空。",
                                "Path cannot be empty."
                              ),
                            })}
                          </p>
                        )}
                      </div>
                    )
                  })
                )}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={disabled}
                  className="w-full border-dashed sm:w-auto"
                  onClick={() => updatePhase(phase, [...paths, ""])}
                >
                  <IconPlus className="size-3.5" />
                  {t("skipPathByPhase.addPath", {
                    defaultValue: fallback("添加路径", "Add path"),
                  })}
                </Button>
              </AccordionContent>
            </AccordionItem>
          )
        })}
      </Accordion>
    </div>
  )
}
