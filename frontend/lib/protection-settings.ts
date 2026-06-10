import type { ProtectionSettings } from "@/lib/api"

export function assignChangedProtectionField<
  K extends keyof ProtectionSettings,
>(
  patch: Partial<ProtectionSettings>,
  current: ProtectionSettings,
  baseline: ProtectionSettings,
  field: K
) {
  if (current[field] !== baseline[field]) {
    patch[field] = current[field]
  }
}
