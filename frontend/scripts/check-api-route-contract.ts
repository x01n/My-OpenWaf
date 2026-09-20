import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const api = readFileSync(resolve(root, "lib/api.ts"), "utf8")
const types = readFileSync(resolve(root, "lib/types.ts"), "utf8")

const requiredTypeFields = [
  "name: string",
  "enabled: boolean",
  "priority: number",
  "target: string",
  "op: string",
  "pattern: string",
  "header_key?: string",
]
for (const field of requiredTypeFields) {
  if (!types.includes(field)) {
    throw new Error(`AppRouteRule contract is missing ${field}`)
  }
}

const requiredApiPaths = [
  "/application-route-rules",
  "/application-route-rules/${rid}/update",
  "/application-route-rules/${rid}/delete",
  "/recorded-resources/clear",
]
for (const path of requiredApiPaths) {
  if (!api.includes(path)) {
    throw new Error(`site API contract is missing ${path}`)
  }
}

console.log("API route contract checks passed")
