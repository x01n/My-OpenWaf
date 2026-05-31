import type { ReactNode } from "react"

export function DetailField({
  label,
  value,
  mono = false,
  className = "",
}: {
  label: string
  value: ReactNode
  mono?: boolean
  className?: string
}) {
  return (
    <div
      className={`min-w-0 rounded-lg border border-slate-100 bg-slate-50 p-3 ${className}`}
    >
      <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
        {label}
      </div>
      <div
        className={`mt-1 min-w-0 text-sm font-medium break-all text-slate-900 ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </div>
    </div>
  )
}

export function TruncatedCell({
  value,
  className = "",
  mono = false,
}: {
  value?: string | number | null
  className?: string
  mono?: boolean
}) {
  const text =
    value === undefined || value === null || value === "" ? "-" : String(value)
  return (
    <span
      className={`block min-w-0 truncate ${mono ? "font-mono" : ""} ${className}`}
      title={text}
    >
      {text}
    </span>
  )
}
