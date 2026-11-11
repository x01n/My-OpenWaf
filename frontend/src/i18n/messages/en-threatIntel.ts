/**
 * English language pack for the threat intelligence domain.
 *
 * Mirrors `zh-threatIntel.ts` key by key; `en.ts` merges it and the
 * `satisfies Record<keyof typeof zh, string>` guard enforces parity.
 */

const enThreatIntel = {
  /* ---------- Page and tabs ---------- */
  "threatIntel.title": "Threat intelligence",
  "threatIntel.description":
    "Subscribe to external IP allow/deny feeds and sync them into local lists on schedule",
  "threatIntel.tabsAria": "Threat intelligence navigation",
  "threatIntel.tab.feeds": "Feeds",
  "threatIntel.tab.logs": "Sync logs",
  "threatIntel.create": "New feed",
  "threatIntel.saved": "Saved",
  "threatIntel.saveFailed": "Save failed",

  /* ---------- Enums: list kind and action ---------- */
  "threatIntel.kind.blacklist": "Blacklist",
  "threatIntel.kind.whitelist": "Whitelist",
  "threatIntel.action.intercept": "Intercept",
  "threatIntel.action.drop": "Drop",

  /* ---------- Sync interval options and formatting ---------- */
  "threatIntel.interval.every5m": "Every 5 minutes",
  "threatIntel.interval.every30m": "Every 30 minutes",
  "threatIntel.interval.every1h": "Every hour",
  "threatIntel.interval.every6h": "Every 6 hours",
  "threatIntel.interval.daily": "Daily",
  "threatIntel.interval.days": "{count} days",
  "threatIntel.interval.dayOne": "1 day",
  "threatIntel.interval.hours": "{count} hours",
  "threatIntel.interval.hourOne": "1 hour",
  "threatIntel.interval.minutes": "{count} minutes",
  "threatIntel.interval.minuteOne": "1 minute",
  "threatIntel.interval.seconds": "{count} seconds",
  "threatIntel.interval.secondOne": "1 second",

  /* ---------- Feed list ---------- */
  "threatIntel.col.name": "Name",
  "threatIntel.col.url": "URL",
  "threatIntel.col.kind": "Kind",
  "threatIntel.col.action": "Action",
  "threatIntel.col.status": "Status",
  "threatIntel.col.syncInterval": "Sync interval",
  "threatIntel.col.entryCount": "Entries",
  "threatIntel.col.lastSync": "Last sync",
  "threatIntel.col.lastError": "Last error",
  "threatIntel.sync": "Sync",
  "threatIntel.syncDone": "Sync completed",
  "threatIntel.syncFailed": "Sync failed",
  "threatIntel.deleteConfirm":
    'Delete feed "{name}"? Entries imported from it are kept',
  "threatIntel.deleted": "Deleted",
  "threatIntel.feedsAria": "Threat intelligence feeds",
  "threatIntel.feedsEmpty": "No feeds",

  /* ---------- Sync logs ---------- */
  "threatIntel.logs.col.feed": "Feed",
  "threatIntel.logs.col.startedAt": "Started at",
  "threatIntel.logs.col.duration": "Duration",
  "threatIntel.logs.col.result": "Result",
  "threatIntel.logs.col.counts": "Added / skipped / lines read",
  "threatIntel.logs.col.trigger": "Trigger",
  "threatIntel.logs.col.error": "Error",
  "threatIntel.logs.success": "Success",
  "threatIntel.logs.failed": "Failed",
  "threatIntel.logs.manual": "Manual",
  "threatIntel.logs.scheduled": "Scheduled",
  "threatIntel.logsAria": "Sync log entries",
  "threatIntel.logsEmpty": "No sync logs",

  /* ---------- Feed form ---------- */
  "threatIntel.form.createTitle": "New feed",
  "threatIntel.form.editTitle": "Edit feed",
  "threatIntel.form.name": "Name",
  "threatIntel.form.namePlaceholder": "Feed name",
  "threatIntel.form.url": "Feed URL",
  "threatIntel.form.kind": "List kind",
  "threatIntel.form.action": "Action on match",
  "threatIntel.form.authName": "Auth header name",
  "threatIntel.form.authNamePlaceholder": "Auth header name (optional, e.g. X-Auth-Key)",
  "threatIntel.form.authValue": "Auth header value",
  "threatIntel.form.authValuePlaceholder": "Auth header value (optional)",
  "threatIntel.form.syncInterval": "Sync interval",
  "threatIntel.form.site": "Bound site",
  "threatIntel.form.siteGlobal": "Global (no site binding)",
  "threatIntel.form.enabled": "Enable feed",
  "threatIntel.form.required": "Enter a name and feed URL",
} as const;

export default enThreatIntel;
