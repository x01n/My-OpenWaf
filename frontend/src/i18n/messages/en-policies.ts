/**
 * English language pack for the policy domain.
 *
 * Mirrors `zh-policies.ts` key by key; `en.ts` merges it and the
 * `satisfies Record<keyof typeof zh, string>` guard enforces parity.
 */

const enPolicies = {
  /* ---------- Page and list ---------- */
  "policies.title": "Policy management",
  "policies.description":
    "Policies are containers for custom rules; sites pick up protection configuration by binding a policy",
  "policies.create": "New policy",
  "policies.listAria": "Policy list",
  "policies.empty": "No policies",
  "policies.col.name": "Name",
  "policies.col.description": "Description",
  "policies.col.isDefault": "Default",
  "policies.col.createdAt": "Created at",
  "policies.defaultBadge": "Default",
  "policies.yes": "Yes",
  "policies.no": "No",

  /* ---------- Row actions ---------- */
  "policies.owaspSummary": "OWASP summary",
  "policies.setDefault": "Set default",
  "policies.setDefaultConfirm":
    "Set \"{name}\" as the default policy? Sites without an explicit policy will use it immediately.",
  "policies.setDefaultSuccess": "Set as default",
  "policies.deleteConfirm":
    "Delete policy \"{name}\"? Policies still referenced by sites cannot be deleted.",
  "policies.deleteSuccess": "Deleted",

  /* ---------- Create / edit form ---------- */
  "policies.form.createTitle": "New policy",
  "policies.form.editTitle": "Edit policy #{id}",
  "policies.form.name": "Policy name",
  "policies.form.namePlaceholder": "Policy name (required)",
  "policies.form.description": "Description",
  "policies.form.descriptionPlaceholder": "Description (optional)",
  "policies.error.name": "Enter a policy name",
  "policies.saveFailed": "Save failed",
  "policies.saved": "Saved",

  /* ---------- Detail drawer ---------- */
  "policies.detail.title": "Policy details",
  "policies.detail.subtitle": "Policy #{id}",
  "policies.field.description": "Description",
  "policies.field.isDefault": "Default policy",
  "policies.field.createdAt": "Created at",
  "policies.field.updatedAt": "Updated at",

  /* ---------- OWASP summary ---------- */
  "policies.owasp.title": "OWASP rules overview",
  "policies.owasp.total": "Total rules",
  "policies.owasp.enabled": "Enabled",
  "policies.owasp.disabled": "Disabled",
  "policies.owasp.empty": "No OWASP categories enabled for this policy",
} as const;

export default enPolicies;
