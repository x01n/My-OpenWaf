"use client"

import { useState } from "react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { CopyableBlock } from "@/components/log-presentation"
import { Ban, TrendingUp } from "@/lib/icons"
import { toast } from "sonner"

interface TopItem {
  label: string
  value: string | number
  count: number
  actionable?: boolean
}

interface TopListCardProps {
  title: string
  icon?: React.ReactNode
  items: TopItem[]
  emptyText?: string
  onAddToBlacklist?: (value: string) => Promise<unknown>
}

type TopListOperationDetails = {
  operation: "add_to_blacklist"
  value: string
  response: unknown
}

export function TopListCard({
  title,
  icon,
  items,
  emptyText = "暂无数据",
  onAddToBlacklist,
}: TopListCardProps) {
  const [loading, setLoading] = useState<string | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<TopListOperationDetails | null>(null)

  const handleAddToBlacklist = async (value: string) => {
    if (!onAddToBlacklist) return

    setLoading(value)
    setOperationDetails(null)
    try {
      const response = await onAddToBlacklist(value)
      setOperationDetails({
        operation: "add_to_blacklist",
        value,
        response: response ?? null,
      })
      toast.success(`已将 ${value} 加入黑名单`)
    } catch (error) {
      toast.error(
        `加入黑名单失败: ${error instanceof Error ? error.message : "未知错误"}`
      )
    } finally {
      setLoading(null)
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted-foreground">
            {emptyText}
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-2">
              {items.map((item, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between rounded-lg p-2 transition-colors hover:bg-muted/50"
                >
                  <div className="flex min-w-0 flex-1 items-center gap-3">
                    <Badge variant="outline" className="shrink-0">
                      #{index + 1}
                    </Badge>
                    <div className="min-w-0 flex-1">
                      <p
                        className="truncate text-sm font-medium"
                        title={String(item.value)}
                      >
                        {item.label}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {item.value}
                      </p>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge variant="secondary" className="font-mono">
                      <TrendingUp data-icon="inline-start" />
                      {item.count}
                    </Badge>
                    {item.actionable && onAddToBlacklist && (
                      <Button
                        size="icon-sm"
                        variant="destructive"
                        aria-label={`将 ${item.label} 加入黑名单`}
                        onClick={() => handleAddToBlacklist(String(item.value))}
                        disabled={loading === String(item.value)}
                      >
                        <Ban data-icon="inline-start" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
            {operationDetails ? (
              <Alert>
                <AlertTitle>最近黑名单操作响应</AlertTitle>
                <AlertDescription>
                  后端已返回加入黑名单操作响应体；请核对 operation、value 与
                  response 字段。
                </AlertDescription>
                <CopyableBlock
                  label="黑名单操作响应体"
                  value={JSON.stringify(operationDetails, null, 2)}
                  redact
                  defaultOpen={false}
                />
              </Alert>
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
