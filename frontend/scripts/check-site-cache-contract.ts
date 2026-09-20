import {
  parseSiteCacheRules,
  serializeSiteCacheRules,
  siteCacheKeyPreview,
  validateSiteCacheConfig,
} from "../lib/site-cache"

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

const parsed = parseSiteCacheRules(
  '[{"type":"prefix","value":"/Assets/","ttl":0,"ignore_query":true,"note":"static","stale_if_error_seconds":30}]'
)
assert(parsed.error === null, `unexpected parse error: ${parsed.error}`)
assert(parsed.rules.length === 1, "expected one parsed rule")
assert(parsed.rules[0].note === "static", "note was not preserved")
assert(
  siteCacheKeyPreview(parsed.rules[0], "/Assets/App.js?v=1") ===
    "/Assets/App.js",
  "ignore_query preview must preserve path casing and remove only the query"
)
assert(
  validateSiteCacheConfig(true, 60, parsed.rules) === null,
  "valid cache config was rejected"
)
assert(
  validateSiteCacheConfig(true, 0, parsed.rules) ===
    "sites.detail.cacheRuleTtlInvalid",
  "ttl inheritance without a default was accepted"
)
assert(
  parseSiteCacheRules("{}").error === "sites.detail.cacheRulesInvalid",
  "non-array cache config was silently accepted"
)
assert(
  serializeSiteCacheRules(parsed.rules).includes('"stale_if_error_seconds":30'),
  "stale fallback was lost during serialization"
)

console.log("site cache frontend contract: ok")
