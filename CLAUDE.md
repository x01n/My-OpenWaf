# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

My-OpenWaf is a Go-based Web Application Firewall with a dual-server architecture:
- **Control-plane** (admin): REST API + embedded Next.js dashboard on `:9443`
- **Data-plane**: HTTP listener(s) that run traffic through the WAF pipeline then proxy to upstream

## Build & Run

```bash
# Full build (frontend + Go binary)
./scripts/build.sh          # Unix → bin/my-openwaf
./scripts/build.ps1         # Windows → bin\my-openwaf.exe

# Go backend only (requires frontend already built into internal/core/adminweb/dist)
go build -o bin/my-openwaf ./cmd/...

# Frontend only
cd frontend && npm run build   # outputs to frontend/out

# Run
./bin/my-openwaf               # admin UI at :9443, SQLite by default
```

Build flow: `npx next build` → copy `frontend/out` → `internal/core/adminweb/dist` → `go build` (frontend is embedded via Go embed).

## Testing

```bash
go test -v ./...                        # all tests
go test -v ./internal/waf/...           # single package
go test -v -run TestOWASP ./internal/waf/...  # single test
```

Test files: `internal/admin/auth/jwt_test.go`, `internal/core/rules/compiler_test.go`, `internal/core/adminweb/static_test.go`, `internal/waf/owasp_test.go`, `internal/waf/ratelimit_test.go`.

## Frontend

```bash
cd frontend
npm run dev          # dev server with Turbopack
npm run lint         # eslint
npm run format       # prettier
npm run typecheck    # tsc --noEmit
```

Stack: Next.js 16 (static export) + React 19 + TypeScript + Tailwind CSS 4 + shadcn/ui.

For local frontend dev against a running backend, set `MY_OPENWAF_ADMIN_STATIC_DIR=./frontend/out`.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MY_OPENWAF_DB_DRIVER` | `sqlite` | `sqlite`, `mysql`, or `postgres` |
| `MY_OPENWAF_DSN` | `./data/waf.db` | Database connection string |
| `MY_OPENWAF_DATA` | `./data` | Data directory (SQLite default path) |
| `MY_OPENWAF_ADMIN_BIND` | `:9443` | Admin server listen address |
| `MY_OPENWAF_ADMIN_STATIC_DIR` | (embedded) | Override embedded frontend with local dir |
| `MY_OPENWAF_REDIS_ADDR` | (none) | Optional Redis address |
| `MY_OPENWAF_JWT_SECRET` | (auto-generated) | JWT signing key; persisted to DB if not set |

## Architecture

### Startup (`cmd/main.go` → `internal/app/server.go`)

`app.Run()`: load config → open DB → optional Redis → auto-migrate → seed defaults → build snapshot → create WAF engine + rate limiters → start admin server → start data-plane listeners → wait for shutdown signal.

### Snapshot Pattern

All runtime config (sites, rules, listeners, policies, protection settings) is compiled into an immutable `Snapshot` struct held behind `atomic.Pointer`. Data-plane reads without locks. Admin API mutations call `reload()` which bumps revision, rebuilds from DB, and atomically swaps the pointer.

### WAF Pipeline (`internal/core/engine` → `internal/core/pipeline`)

Phases run in order: **ACL → RateLimit → OWASP → Signature → Custom**. Each phase returns an action (`allow`, `intercept`, `observe`). First non-allow action short-circuits. The engine is in `internal/core/engine/engine.go`; phase implementations in `internal/core/rules/phases.go` and `internal/waf/`.

### Key Packages

| Package | Role |
|---------|------|
| `internal/app` | Startup wiring, lifecycle |
| `internal/core` | Config, Runtime (DB/Redis/Snapshot/Cache), Engine, Pipeline, Rules, Sites |
| `internal/admin` | REST API handlers + JWT auth middleware |
| `internal/dataplane` | Data listener: client IP → engine → proxy/block |
| `internal/proxy` | HTTP reverse proxy to upstream |
| `internal/snapshot` | Immutable config holder (`atomic.Pointer[Snapshot]`) |
| `internal/store` | GORM models, migrations, seeding, `repository/` for per-model CRUD |
| `internal/waf` | OWASP pattern detection, token-bucket rate limiter (ristretto-backed) |
| `internal/pkg` | Shared utilities: `logger` (slog), `apierr` (error responses) |

### Admin API Pattern

Handlers in `internal/admin/handler_*.go` follow: `func Name(deps) app.HandlerFunc`. Routes registered in `internal/admin/router.go`. Auth via JWT access token + httpOnly refresh cookie, or admin API key. All config mutations must call `deps.Reload()` to trigger snapshot rebuild.

### Data-Plane Flow (`internal/dataplane/handler.go`)

Request → resolve client IP (X-Forwarded-For + trusted CIDR) → match virtual host (listener ID + Host header) → `engine.Process(reqCtx)` → action is allow? proxy to upstream : return 403 block page → record metrics.

## Go Dependencies

- **HTTP framework**: `github.com/cloudwego/hertz` (ByteDance)
- **ORM**: `gorm.io/gorm` with sqlite/mysql/postgres drivers
- **Auth**: `github.com/golang-jwt/jwt/v5`, `golang.org/x/crypto` (bcrypt)
- **Cache**: `github.com/dgraph-io/ristretto`
- **Redis**: `github.com/redis/go-redis/v9`

Go version: 1.25.5
