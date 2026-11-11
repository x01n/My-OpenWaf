#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"
if command -v pnpm >/dev/null 2>&1; then
  pnpm install --frozen-lockfile
  pnpm run build
else
  bun install --frozen-lockfile
  bun run build
fi
rm -rf "$ROOT/internal/core/adminweb/dist"
cp -r "$ROOT/frontend/out" "$ROOT/internal/core/adminweb/dist"
cd "$ROOT/wasm-pow-solver"
make optimize
cd "$ROOT"
go mod tidy
CGO_ENABLED=1 go build -tags=quickjs -o bin/my-openwaf ./cmd/...
