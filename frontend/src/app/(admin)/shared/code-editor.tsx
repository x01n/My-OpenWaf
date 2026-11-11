"use client";

import { useEffect, useRef } from "react";

/**
 * 通用代码编辑器：等宽字体 TextArea + 可选行号。
 *
 * KISS 实现，不做语法高亮：textarea 高度随内容自动增长，行号与正文
 * 处于同一个外层滚动流内，天然保持纵向对齐。
 */
export function CodeEditor({
  value,
  onChange,
  ariaLabel,
  placeholder,
  minHeight = "12rem",
  maxHeight = "26rem",
  showLineNumbers = true,
  readOnly = false,
}: {
  value: string;
  onChange?: (v: string) => void;
  ariaLabel: string;
  placeholder?: string;
  /** 容器最小高度（Tailwind 高度类或任意 CSS 高度值） */
  minHeight?: string;
  /** 容器最大高度，超出后内部滚动 */
  maxHeight?: string;
  showLineNumbers?: boolean;
  readOnly?: boolean;
}) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineCount = value.split("\n").length;

  // 高度自适应：内容变化时重算 scrollHeight
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [value]);

  return (
    <div
      className="overflow-auto rounded-lg border border-separator bg-surface"
      style={{ minHeight, maxHeight }}
    >
      <div className="flex min-h-full">
        {showLineNumbers && (
          <div
            aria-hidden
            className="text-muted/60 select-none border-r border-separator bg-surface py-2 pr-2 pl-3 font-mono text-xs leading-5 tabular"
          >
            {Array.from({ length: lineCount }, (_, i) => (
              <div key={i}>{i + 1}</div>
            ))}
          </div>
        )}
        <textarea
          ref={textareaRef}
          aria-label={ariaLabel}
          value={value}
          readOnly={readOnly}
          placeholder={placeholder}
          spellCheck={false}
          onChange={(e) => onChange?.(e.target.value)}
          className="min-w-0 flex-1 resize-none bg-transparent px-3 py-2 font-mono text-xs leading-5 whitespace-pre outline-none placeholder:text-muted/50"
        />
      </div>
    </div>
  );
}
