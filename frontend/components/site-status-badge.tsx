import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface SiteStatusBadgeProps {
  status: "running" | "stopped" | "error"
  className?: string
}

export function SiteStatusBadge({ status, className }: SiteStatusBadgeProps) {
  const variants = {
    running: {
      label: "运行中",
      className:
        "bg-green-500/10 text-green-700 border-green-500/20 dark:bg-green-500/20 dark:text-green-400",
    },
    stopped: {
      label: "已停止",
      className:
        "bg-gray-500/10 text-gray-700 border-gray-500/20 dark:bg-gray-500/20 dark:text-gray-400",
    },
    error: {
      label: "错误",
      className:
        "bg-red-500/10 text-red-700 border-red-500/20 dark:bg-red-500/20 dark:text-red-400",
    },
  }

  const variant = variants[status]

  return (
    <Badge variant="outline" className={cn(variant.className, className)}>
      <span
        className={cn("mr-1.5 size-1.5 rounded-full", {
          "bg-green-500": status === "running",
          "bg-gray-500": status === "stopped",
          "bg-red-500": status === "error",
        })}
      />
      {variant.label}
    </Badge>
  )
}
