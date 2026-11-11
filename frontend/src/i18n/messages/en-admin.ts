/**
 * English language pack for the account & keys domain.
 *
 * Mirrors `zh-admin.ts` key by key; `en.ts` merges it and the
 * `satisfies Record<keyof typeof zh, string>` guard enforces parity.
 */

const enAdmin = {
  /* ---------- Page and tabs ---------- */
  "admin.title": "Account & keys",
  "admin.description": "Admin accounts, API keys and session management",
  "admin.tabsAria": "Account & keys",
  "admin.navAria": "Account & keys navigation",
  "admin.tab.users": "Admin accounts",
  "admin.tab.apiKeys": "API keys",
  "admin.tab.sessions": "Sessions",
  "admin.tab.password": "Change password",

  /* ---------- Admin accounts: list ---------- */
  "admin.users.create": "New account",
  "admin.users.listAria": "Admin account list",
  "admin.users.empty": "No accounts",
  "admin.users.col.username": "Username",
  "admin.users.col.role": "Role",
  "admin.users.col.createdAt": "Created at",
  "admin.users.changePassword": "Change password",
  "admin.users.changeRole": "Change role",
  "admin.users.deleteConfirm":
    "Delete account {name}? All of its sessions and API keys will be revoked.",
  "admin.users.created": "Account created",
  "admin.users.createFailed": "Failed to create",

  /* ---------- Admin accounts: role enum ---------- */
  "admin.users.role": "Role",
  "admin.users.role.admin": "admin",
  "admin.users.role.operator": "operator",
  "admin.users.role.readonly": "readonly",

  /* ---------- Admin accounts: create dialog ---------- */
  "admin.users.form.createTitle": "New admin account",
  "admin.users.form.createDesc": "Password must be at least 8 characters; takes effect immediately",
  "admin.users.form.submit": "Create",
  "admin.users.form.username": "Username",
  "admin.users.form.usernamePlaceholder": "Username (≤64 characters)",
  "admin.users.form.initialPassword": "Initial password",
  "admin.users.form.initialPasswordPlaceholder": "Initial password (at least 8 characters)",
  "admin.users.form.newPassword": "New password",
  "admin.users.form.newPasswordPlaceholder": "New password (at least 8 characters)",

  /* ---------- Admin accounts: password / role dialogs ---------- */
  "admin.users.passwordDialogTitle": "Change password",
  "admin.users.passwordDialogDesc": "Account: {name}; it will have to sign in again after saving",
  "admin.users.passwordUpdated": "Password updated for {name}; its existing sessions have been revoked",
  "admin.users.passwordChangeFailed": "Failed to change password",
  "admin.users.roleDialogTitle": "Change role",
  "admin.users.roleDialogDesc": "Account: {name}",
  "admin.users.roleUpdated": "Role updated for {name}; its existing sessions have been revoked",
  "admin.users.roleChangeFailed": "Failed to change role",

  /* ---------- API keys ---------- */
  "admin.keys.create": "New API key",
  "admin.keys.listAria": "API key list",
  "admin.keys.empty": "No API keys",
  "admin.keys.col.name": "Name",
  "admin.keys.col.owner": "Owner",
  "admin.keys.col.lastUsed": "Last used",
  "admin.keys.col.createdAt": "Created at",
  "admin.keys.deleteConfirm":
    "Delete API key \"{name}\"? Requests using it will fail immediately.",
  "admin.keys.createFailed": "Failed to create",
  "admin.keys.form.createTitle": "New API key",
  "admin.keys.form.createDesc": "The token belongs to the signed-in account and inherits its role permissions",
  "admin.keys.form.submit": "Create",
  "admin.keys.form.name": "Key name",
  "admin.keys.form.namePlaceholder": "e.g. ci-runner",
  "admin.keys.createdTitle": "API key created",
  "admin.keys.ackSaved": "I've saved it",
  "admin.keys.revealWarning":
    "This token is shown only once and cannot be viewed again after closing. Copy and store it now.",
  "admin.keys.copy": "Copy",
  "admin.keys.copied": "Copied",
  "admin.keys.copiedToast": "Copied to clipboard",
  "admin.keys.copyFailed": "Copy failed",
  "admin.keys.copyFailedDesc": "Clipboard permission was not granted by the browser; select and copy manually",
  "admin.keys.usageHint": "Use Authorization: Bearer <token> in the request header",

  /* ---------- Login sessions ---------- */
  "admin.sessions.activeCount": "{count} active sessions",
  "admin.sessions.listAria": "Login session list",
  "admin.sessions.empty": "No active sessions",
  "admin.sessions.col.username": "Account",
  "admin.sessions.col.ip": "IP",
  "admin.sessions.col.device": "Device / client",
  "admin.sessions.col.loginAt": "Signed in at",
  "admin.sessions.col.lastActiveAt": "Last active",
  "admin.sessions.col.expiresAt": "Expires at",
  "admin.sessions.revoke": "Force logout",
  "admin.sessions.revokeConfirm":
    "Force logout this session of {name}? Its access and refresh tokens will be revoked together.",
  "admin.sessions.revoked": "Forced logout",

  /* ---------- Change own password ---------- */
  "admin.account.title": "Change your password",
  "admin.account.desc": "After a successful change all old credentials are invalidated and you must sign in again",
  "admin.account.warning":
    "The new password must be at least 8 characters; the current session is invalidated immediately after a successful change.",
  "admin.account.currentPassword": "Current password",
  "admin.account.newPassword": "New password",
  "admin.account.minChars": "At least 8 characters",
  "admin.account.confirmPassword": "Confirm new password",
  "admin.account.mismatch": "The new passwords do not match",
  "admin.account.changePassword": "Change password",
  "admin.account.changedRelogin": "Password changed; please sign in again",
  "admin.account.changeFailed": "Change failed",
} as const;

export default enAdmin;
