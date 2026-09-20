"use client"

import { useEffect, useRef, useState } from "react"

/**
 * 在指定静默窗口后提交最新值，避免输入过程为每个字符触发远端查询。
 *
 * @param value 需要延迟提交的值
 * @param delayMs 静默窗口，单位毫秒
 * @param onCommit 值真正提交时执行的同步回调
 * @returns 已完成延迟提交的值
 */
export function useDebouncedValue<T>(
  value: T,
  delayMs: number,
  onCommit?: (value: T) => void
): T {
  const [debouncedValue, setDebouncedValue] = useState(value)
  const committedValueRef = useRef(value)

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (Object.is(committedValueRef.current, value)) return
      committedValueRef.current = value
      setDebouncedValue(value)
      onCommit?.(value)
    }, delayMs)
    return () => window.clearTimeout(timer)
  }, [delayMs, onCommit, value])

  return debouncedValue
}
