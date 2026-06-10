import { Badge } from "@/components/ui/badge"

interface SiteStatusBadgeProps {
  status: "running" | "stopped" | "error"
  className?: string
}

export function SiteStatusBadge({ status, className }: SiteStatusBadgeProps) {
  const variants = {
    running: {
      label: "运行中",
      variant: "default",
    },
    stopped: {
      label: "已停止",
      variant: "secondary",
    },
    error: {
      label: "错误",
      variant: "destructive",
    },
  } as const

  const variant = variants[status]

  return (
    <Badge variant={variant.variant} className={className}>
      <span
        aria-hidden="true"
        className="size-1.5 rounded-full bg-current opacity-80"
      />
      {variant.label}
    </Badge>
  )
}
