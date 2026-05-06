export function parseSiteUpstreams(raw: string | string[] | null | undefined): string[] {
  if (!raw) return [];

  if (Array.isArray(raw)) {
    return raw.map((item) => item.trim()).filter(Boolean);
  }

  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
    }
  } catch {
    // fall through to comma-separated fallback
  }

  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function serializeSiteUpstreams(upstreams: string[]): string {
  return JSON.stringify(upstreams.map((item) => item.trim()).filter(Boolean));
}

export function isValidSiteUpstream(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;

  try {
    const url = new URL(trimmed);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function findInvalidSiteUpstream(upstreams: string[]): string | null {
  for (const upstream of upstreams) {
    const trimmed = upstream.trim();
    if (!trimmed) continue;
    if (!isValidSiteUpstream(trimmed)) return trimmed;
  }
  return null;
}
