"use client";

import * as React from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { IconMinus, IconPlus } from "@tabler/icons-react";

interface NumberFieldContextValue {
  value: number;
  onValueChange: (v: number | undefined) => void;
  min?: number;
  max?: number;
  step: number;
  disabled?: boolean;
}

const NumberFieldContext = React.createContext<NumberFieldContextValue | null>(null);

function useNumberField() {
  const ctx = React.useContext(NumberFieldContext);
  if (!ctx) throw new Error("NumberField components must be used within NumberField.Root");
  return ctx;
}

interface RootProps {
  value?: number;
  onValueChange?: (value: number | undefined) => void;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
  className?: string;
  children: React.ReactNode;
}

function Root({
  value = 0,
  onValueChange,
  min,
  max,
  step = 1,
  disabled,
  className,
  children,
}: RootProps) {
  return (
    <NumberFieldContext.Provider
      value={{ value, onValueChange: onValueChange ?? (() => {}), min, max, step, disabled }}
    >
      <div className={cn("inline-flex", className)}>{children}</div>
    </NumberFieldContext.Provider>
  );
}

function Group({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-center rounded-md border", className)}>
      {children}
    </div>
  );
}

function NumberInput({ className }: { className?: string }) {
  const { value, onValueChange, min, max, step, disabled } = useNumberField();
  return (
    <Input
      type="number"
      value={value}
      onChange={(e) => {
        const v = e.target.value === "" ? undefined : Number(e.target.value);
        if (v !== undefined && isNaN(v)) return;
        onValueChange(v);
      }}
      min={min}
      max={max}
      step={step}
      disabled={disabled}
      className={cn("border-0 text-center tabular-nums [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none", className)}
    />
  );
}

function Increment({ className }: { className?: string }) {
  const { value, onValueChange, max, step, disabled } = useNumberField();
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={cn("h-8 w-8 shrink-0", className)}
      disabled={disabled || (max !== undefined && value >= max)}
      onClick={() => onValueChange(Math.min(value + step, max ?? Infinity))}
    >
      <IconPlus className="h-3 w-3" />
    </Button>
  );
}

function Decrement({ className }: { className?: string }) {
  const { value, onValueChange, min, step, disabled } = useNumberField();
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={cn("h-8 w-8 shrink-0", className)}
      disabled={disabled || (min !== undefined && value <= min)}
      onClick={() => onValueChange(Math.max(value - step, min ?? -Infinity))}
    >
      <IconMinus className="h-3 w-3" />
    </Button>
  );
}

export const NumberField = {
  Root,
  Group,
  Input: NumberInput,
  Increment,
  Decrement,
};
