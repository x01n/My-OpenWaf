"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * 缩进宽度。Lua 社区惯例为 2 空格，与内置示例脚本保持一致。
 */
const INDENT = "  ";

/**
 * 行高（px）。行号栏与文本域必须逐像素对齐，因此写成常量而非分散的
 * Tailwind 类——两侧任一处改动都会立刻错位。
 */
const LINE_HEIGHT = 20;

/** 上下内边距（px），同样需要两侧一致。 */
const PAD_Y = 12;

/**
 * @typedef {object} LuaCodeEditorProps
 * @property {string} value 源码内容
 * @property {(value: string) => void} onChange 内容变化回调
 * @property {string} [placeholder] 空内容时的占位提示
 * @property {number} [rows] 可见行数，决定初始高度
 * @property {boolean} [readOnly] 只读模式
 * @property {string} [className] 外层容器附加 className
 * @property {string} [ariaLabel] 无障碍标签
 */
export interface LuaCodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
  readOnly?: boolean;
  className?: string;
  ariaLabel?: string;
}

/**
 * 轻量 Lua 源码编辑区：等宽字体 + 行号栏 + Tab 缩进。
 *
 * 刻意不引入 Monaco/CodeMirror：本项目是 Next.js 静态导出，重型编辑器会显著
 * 拖大产物体积，而策略脚本通常只有几十行，行号与等宽排版已够用。
 *
 * @param {LuaCodeEditorProps} props 组件属性
 * @returns {React.ReactElement} 编辑区元素
 */
export function LuaCodeEditor({
  value,
  onChange,
  placeholder,
  rows = 16,
  readOnly,
  className,
  ariaLabel,
}: LuaCodeEditorProps) {
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const gutterRef = React.useRef<HTMLDivElement>(null);

  const lineCount = React.useMemo(
    () => value.split("\n").length,
    [value],
  );

  /**
   * 行号栏与文本域滚动同步。
   *
   * textarea 无法内嵌行号，只能并排渲染再同步 scrollTop。
   */
  const handleScroll = React.useCallback(() => {
    const gutter = gutterRef.current;
    const textarea = textareaRef.current;
    if (gutter && textarea) {
      gutter.scrollTop = textarea.scrollTop;
    }
  }, []);

  /**
   * Tab 插入缩进而非移动焦点。
   *
   * 代码编辑区里按 Tab 跳走焦点几乎总是误操作。受控组件在 onChange 后会
   * 重置光标，故需在下一帧手动还原到缩进之后。
   */
  const handleKeyDown = React.useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key !== "Tab" || e.shiftKey || readOnly) return;
      e.preventDefault();

      const el = e.currentTarget;
      const start = el.selectionStart;
      const end = el.selectionEnd;
      onChange(value.slice(0, start) + INDENT + value.slice(end));

      const caret = start + INDENT.length;
      requestAnimationFrame(() => {
        el.selectionStart = caret;
        el.selectionEnd = caret;
      });
    },
    [onChange, readOnly, value],
  );

  // 行号栏宽度随位数增长，避免四位行号被裁切。
  const gutterWidth = `calc(${String(lineCount).length}ch + 1.25rem)`;

  return (
    <div
      className={cn(
        "flex overflow-hidden rounded-md border bg-muted/30 focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50",
        className,
      )}
    >
      <div
        ref={gutterRef}
        aria-hidden="true"
        className="shrink-0 select-none overflow-hidden border-e bg-muted/60 text-end font-mono text-xs text-muted-foreground"
        style={{
          width: gutterWidth,
          paddingTop: PAD_Y,
          paddingBottom: PAD_Y,
          lineHeight: `${LINE_HEIGHT}px`,
        }}
      >
        {Array.from({ length: lineCount }, (_, i) => (
          <div key={i} className="pe-2.5">
            {i + 1}
          </div>
        ))}
      </div>
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onScroll={handleScroll}
        onKeyDown={handleKeyDown}
        readOnly={readOnly}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        autoCorrect="off"
        placeholder={placeholder}
        aria-label={ariaLabel}
        dir="ltr"
        className="min-w-0 flex-1 resize-none bg-transparent px-3 font-mono text-xs text-foreground outline-none placeholder:text-muted-foreground disabled:opacity-50"
        style={{
          paddingTop: PAD_Y,
          paddingBottom: PAD_Y,
          lineHeight: `${LINE_HEIGHT}px`,
          height: rows * LINE_HEIGHT + PAD_Y * 2,
        }}
      />
    </div>
  );
}
