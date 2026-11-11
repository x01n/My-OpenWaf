"use client";

import { Switch as HeroSwitch } from "@heroui/react";
import type { ReactNode } from "react";

/**
 * 带完整开关轨道的 Switch 封装。
 *
 * HeroUI v3 的 Switch 必须用 Switch > Switch.Content > Switch.Control > Switch.Thumb
 * 复合结构才有轨道视觉；直接传文本子元素只会渲染纯文字（无轨道 DOM，CSS 无法补救）。
 * 本组件固化该结构，供全站布尔开关复用，props 与 HeroUI Switch 保持一致。
 */
export function ToggleSwitch({
  isSelected,
  onChange,
  children,
  isDisabled,
  size,
}: {
  isSelected: boolean;
  onChange: (v: boolean) => void;
  /** 无 children 时必须由调用方提供 aria-label */
  children?: ReactNode;
  isDisabled?: boolean;
  size?: "sm" | "md" | "lg";
}) {
  return (
    <HeroSwitch
      isSelected={isSelected}
      onChange={onChange}
      isDisabled={isDisabled}
      size={size}
    >
      <HeroSwitch.Content>
        <HeroSwitch.Control>
          <HeroSwitch.Thumb />
        </HeroSwitch.Control>
        {children}
      </HeroSwitch.Content>
    </HeroSwitch>
  );
}
