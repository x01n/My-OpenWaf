import { readdirSync, readFileSync } from "node:fs"
import { dirname, extname, relative, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import ts from "typescript"
import {
  assertSkipPathByPhaseContract,
  findEmptySkipPaths,
  parseSkipPathByPhase,
  SKIP_PATH_PHASES,
  toSkipPathByPhasePayload,
} from "../lib/skip-path-by-phase"

function readBackendPhaseKeys(): string[] {
  const source = readFileSync("../internal/store/protection.go", "utf8")
  const declaration = source.match(
    /var skipPathPhaseKeys = map\[string\]struct\{\}\{([\s\S]*?)\n\}/
  )
  if (!declaration) {
    throw new Error("skipPathPhaseKeys declaration was not found")
  }
  return Array.from(
    declaration[1].matchAll(/"([^"]+)":\s*\{\}/g),
    (match) => match[1]
  ).sort()
}

const FRONTEND_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const LOCALE_DIR = resolve(FRONTEND_DIR, "lib/i18n/locales")
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx"])
const SKIP_DIRECTORIES = new Set(["node_modules", "out", ".next"])

function collectLocaleLeaves(
  value: unknown,
  prefix = "",
  leaves = new Map<string, string>()
): Map<string, string> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value)) {
      collectLocaleLeaves(child, prefix ? `${prefix}.${key}` : key, leaves)
    }
    return leaves
  }

  leaves.set(prefix, Array.isArray(value) ? "array" : typeof value)
  return leaves
}

function readLocaleLeaves(name: string): Map<string, string> {
  const source = readFileSync(resolve(LOCALE_DIR, `${name}.json`), "utf8")
  return collectLocaleLeaves(JSON.parse(source))
}

function listSourceFiles(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)) continue
    const file = resolve(directory, entry.name)
    if (entry.isDirectory()) listSourceFiles(file, files)
    else if (SOURCE_EXTENSIONS.has(extname(entry.name))) files.push(file)
  }
  return files
}

function checkStaticTranslationKeys(): void {
  const zhLeaves = readLocaleLeaves("zh")
  const enLeaves = readLocaleLeaves("en")
  const onlyZh = [...zhLeaves.keys()].filter((key) => !enLeaves.has(key)).sort()
  const onlyEn = [...enLeaves.keys()].filter((key) => !zhLeaves.has(key)).sort()
  const typeMismatches = [...zhLeaves.keys()]
    .filter((key) => enLeaves.has(key) && zhLeaves.get(key) !== enLeaves.get(key))
    .sort()
  const missing = new Map<string, string[]>()

  for (const file of listSourceFiles(FRONTEND_DIR)) {
    const source = readFileSync(file, "utf8")
    const scriptKind = file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    const sourceFile = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      scriptKind
    )
    const visit = (node: ts.Node): void => {
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "t"
      ) {
        const firstArgument = node.arguments[0]
        if (
          firstArgument &&
          (ts.isStringLiteral(firstArgument) ||
            ts.isNoSubstitutionTemplateLiteral(firstArgument))
        ) {
          const key = firstArgument.text
          if (!zhLeaves.has(key) || !enLeaves.has(key)) {
            const line = sourceFile.getLineAndCharacterOfPosition(
              node.getStart(sourceFile)
            ).line + 1
            const locations = missing.get(key) ?? []
            locations.push(`${relative(FRONTEND_DIR, file)}:${line}`)
            missing.set(key, locations)
          }
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sourceFile)
  }

  const failures: string[] = []
  if (onlyZh.length > 0) failures.push(`keys only in zh.json: ${onlyZh.join(", ")}`)
  if (onlyEn.length > 0) failures.push(`keys only in en.json: ${onlyEn.join(", ")}`)
  if (typeMismatches.length > 0) {
    failures.push(`leaf type mismatches: ${typeMismatches.join(", ")}`)
  }
  if (missing.size > 0) {
    failures.push(
      `missing static t() keys:\n${[...missing.keys()]
        .sort()
        .map((key) => `  ${key}: ${missing.get(key)?.join(", ")}`)
        .join("\n")}`
    )
  }
  if (failures.length > 0) throw new Error(failures.join("\n"))
  console.log(`i18n key check passed (${zhLeaves.size} leaves)`)
}

/** 对比前端 phase 镜像、后端声明及三态载荷归一化。 */
function main() {
  assertSkipPathByPhaseContract()
  checkStaticTranslationKeys()

  const frontendKeys = [...SKIP_PATH_PHASES].sort()
  const backendKeys = readBackendPhaseKeys()
  if (frontendKeys.join("\n") !== backendKeys.join("\n")) {
    throw new Error(
      `skip-path-by-phase keys differ\nfrontend: ${frontendKeys.join(", ")}\nbackend: ${backendKeys.join(", ")}`
    )
  }

  if (Object.keys(parseSkipPathByPhase(null)).length !== 0) {
    throw new Error("null must parse as an empty editable mapping")
  }
  if (Object.keys(parseSkipPathByPhase("{}")).length !== 0) {
    throw new Error(
      "an explicit empty object must remain an empty editable mapping"
    )
  }
  const draft = { owasp_default: [" /health ", ""] }
  if (findEmptySkipPaths(draft).join(",") !== "owasp_default") {
    throw new Error("empty path validation did not identify the phase")
  }
  const payload = toSkipPathByPhasePayload({
    owasp_default: [" /health "],
  })
  if (payload.owasp_default?.[0] !== "/health") {
    throw new Error("path payload was not trimmed")
  }

  console.log("skip-path-by-phase contract check passed")
}

main()
