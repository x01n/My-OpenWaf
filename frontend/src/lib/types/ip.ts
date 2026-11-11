/** IP 名单与威胁情报类型 */

export type IPListEntry = {
  id: number;
  created_at: string;
  updated_at: string;
  kind: "blacklist" | "whitelist";
  value: string;
  note: string;
  enabled: boolean;
  action: "intercept" | "drop";
  site_id: number | null;
  feed_id: number | null;
};

export type ThreatIntelFeed = {
  id: number;
  name: string;
  url: string;
  kind: string;
  action: string;
  auth_header_name: string;
  auth_header_value: string;
  enabled: boolean;
  sync_interval: number;
  site_id: number | null;
  last_sync_at: string;
  last_error: string;
  entry_count: number;
};

export type ThreatIntelSyncLog = {
  id: number;
  feed_id: number;
  feed_name: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  success: boolean;
  entries_added: number;
  entries_skipped: number;
  lines_read: number;
  trigger: string;
  error: string;
};
