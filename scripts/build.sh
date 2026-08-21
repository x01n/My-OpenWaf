#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"
bun install --frozen-lockfile
bun run build
rm -rf "$ROOT/internal/core/adminweb/dist"
cp -r "$ROOT/frontend/out" "$ROOT/internal/core/adminweb/dist"
cd "$ROOT/wasm-pow-solver"
make optimize
cd "$ROOT"
go mod tidy
CGO_ENABLED=1 go build -tags=quickjs -o bin/my-openwaf ./cmd/...
