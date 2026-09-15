import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const page = readFileSync(resolve(root, "app/login/page.tsx"), "utf8")

const requiredAttributes = [
  'name="username"',
  'autoComplete="username"',
  'name="password"',
  'autoComplete="current-password"',
]
for (const attribute of requiredAttributes) {
  if (!page.includes(attribute)) {
    throw new Error(`login form contract is missing ${attribute}`)
  }
}

console.log("login form contract checks passed")
