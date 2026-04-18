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

## Detection Engine Load Test (MANDATORY)

> **每次对检测引擎进行任何更新之后，必须执行以下步骤，缺一不可：**

1. 启动服务端：`./bin/my-openwaf`（确保数据面监听在 `:80`）
2. 执行压测：
   ```bash
   .\blazehttp.exe -t http://127.0.0.1:80 -c 40
   ```
3. 检查输出中无异常崩溃、无明显性能下降、无非预期的 block/pass 结果。

这是检测引擎变更的**强制验收标准**，不得跳过。涉及以下任意文件的修改均须执行：
`internal/waf/`、`internal/core/rules/`、`internal/core/engine/`、`internal/core/pipeline/`、`internal/dataplane/handler.go`

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
| `MY_OPENWAF_REDIS_ADDR` | (none) | Optional Redis address for distributed deployments |
| `MY_OPENWAF_JWT_SECRET` | (auto-generated) | JWT signing key; persisted to DB if not set |

## Architecture

### Startup (`cmd/main.go` → `internal/app/server.go`)

`app.Run()`: load config → open DB → optional Redis → auto-migrate → seed defaults → build snapshot → create WAF engine + rate limiters → start admin server → start data-plane listeners → wait for shutdown signal.

### Snapshot Pattern

All runtime config (sites, rules, listeners, policies, protection settings) is compiled into an immutable `Snapshot` struct held behind `atomic.Pointer`. Data-plane reads without locks. Admin API mutations call `reload()` which bumps the `config_revisions` counter, rebuilds from DB (with ristretto local cache for same-revision reloads), and atomically swaps the pointer.

### WAF Pipeline (`internal/core/engine` → `internal/core/pipeline`)

Phases run in this exact order: **IPReputation → ACL → BotDetection → RequestRateLimit → OWASP → Signature → Custom**

- Each phase returns `allow`, `intercept`, or `observe`. The first `intercept` short-circuits the remaining phases.
- **ACL `allow` rules bypass the entire pipeline** — a request matching an allow rule skips OWASP, Signature, and Custom phases entirely. This is the whitelist mechanism.
- Phase implementations are in `internal/core/rules/phases.go` and `internal/waf/`. The engine is in `internal/core/engine/engine.go`.

### Data-Plane Flow (`internal/dataplane/handler.go`)

1. Requests to `/__owaf/*` are served directly as static assets (block/maintenance pages + their `_next/` assets), bypassing WAF entirely.
2. Resolve client IP via X-Forwarded-For + trusted CIDR (`internal/security/clientip.go`).
3. Match virtual host: `listenerID + Host header` → `SiteRuntime` (exact match or `*.` wildcard).
4. Acquire `RequestCtx` from `sync.Pool`, copy headers, read body (capped at **65536 bytes**).
5. `engine.Process(reqCtx)` → pipeline runs phases in order.
6. Action: `intercept` → render block page; else proxy to upstream.
7. Post-proxy error-rate limiting based on 4xx/5xx response codes.
8. Release `RequestCtx` back to pool. Write security event asynchronously (channel-buffered, batch DB insert every 64 events or 2s).

Protocol upgrades are handled specially: WebSocket → raw TCP tunnel (`io.Copy` both directions via `net.Conn`); SSE → chunked streaming with `Flusher.Flush()` after each write.

### OWASP Detection Engine (`internal/waf/owasp.go`, `internal/waf/owasp_extended.go`)

Multi-layer performance design:
1. **Byte-scan pre-filter** (`hasSuspiciousContent`): alphanumeric-only strings skip all regex.
2. **Keyword pre-filter** per category (e.g., `hasSQLiIndicator` checks 38 SQL keywords via `strings.Contains`).
3. **Regex battery with scoring**: each regex has a score; accumulated score vs. threshold (`low=6, mid=4, high=2`).
4. **False-positive suppression**: `isSQLiFalsePositive` etc. applied after match.
5. **Input normalization** (applied before scanning): multi-pass URL decode (max 3x), HTML entity decode (max 2x), SQL comment stripping, overlong UTF-8 normalization, base64 transparent decode.

Body parsing: form-urlencoded → split on `&`; JSON → recursive walk (depth ≤ 10, values ≤ 50), **keys also scanned**; multipart → filename via `checkFileUpload`, field values via OWASP scan; binary (< 90% printable in first 512 bytes) → skipped. Single target truncated at **8192 bytes**.

Covers 17 attack categories: SQLi, XSS, WebShell, RevShell, PathTraversal, SSRF, CmdInjection, XXE, LDAPi, NoSQLi, SSTI, JNDI, CRLF, EL, Deserialization, FileUpload, ProtocolViolation.

### Rule DSL (`internal/core/rules/compiler.go`)

Pattern format: `kind:arg` (e.g., `block_path:/admin`, `allow_ip:1.2.3.0/24`, `block_query_regex:(?i)union select`). Compound rules use JSON with `op: "and"/"or"/"not"` and nested `children`. Rules execute in `priority ASC, ID ASC` order. Compiled regex is cached globally.

### Listener Hot-Reload

`reconcileListeners()` computes a SHA-256 `listenerFingerprint` over bind address, TLS version, ALPN, and certificate bytes. Any change triggers graceful shutdown and recreation of only the affected Hertz server instance — no full process restart needed.

### Key Packages

| Package | Role |
|---------|------|
| `internal/app` | Startup wiring, lifecycle |
| `internal/core` | Config, Runtime (DB/Redis/Snapshot/Cache), Engine, Pipeline, Rules, Sites |
| `internal/admin` | REST API handlers + JWT auth middleware |
| `internal/dataplane` | Data listener: client IP → engine → proxy/block |
| `internal/proxy` | HTTP reverse proxy to upstream (shared transport pool) |
| `internal/snapshot` | Immutable config holder (`atomic.Pointer[Snapshot]`) |
| `internal/store` | GORM models (13 tables), migrations, seeding, `repository/` for per-model CRUD |
| `internal/waf` | OWASP detection, rate limiters (local fixed-window + Redis sliding-window), IP reputation, bot detection |
| `internal/observability` | Async security event writer, event archiver (30-day retention), Prometheus `/metrics` |
| `internal/pkg` | Shared utilities: `logger` (slog), `apierr` (error responses) |

### Admin API Pattern

Handlers in `internal/admin/handler_*.go` follow: `func Name(deps) app.HandlerFunc`. Routes registered in `internal/admin/router.go`. Auth: JWT access token (15m, HS256) + httpOnly refresh cookie (7d, with token rotation), or admin API key (bcrypt-hashed in DB).

**All mutating operations use `POST` only** — routes follow `POST /resource/:id/update` and `POST /resource/:id/delete` patterns (no `PUT`/`DELETE`). This is intentional to simplify reverse-proxy and CORS configuration.

All config mutations must call `deps.Reload()` to trigger snapshot rebuild.

### Observability

- **Security events**: async channel (buffer 4096), batch-inserted every 64 events or 2 seconds. Auto-archived after 30 days.
- **Prometheus metrics**: `/metrics` on admin server (text/plain 0.0.4 format) — request counts, block/observe counts, rule hits, cache hit/miss, upstream errors, GC/memory stats.
- **Health checks**: `/healthz`, `/readyz`, `/status` on admin server.

## Go Dependencies

- **HTTP framework**: `github.com/cloudwego/hertz` (ByteDance) — data-plane TLS requires `standard.NewTransporter` (not netpoll) for native Go TLS support
- **ORM**: `gorm.io/gorm` with sqlite/mysql/postgres drivers
- **Auth**: `github.com/golang-jwt/jwt/v5`, `golang.org/x/crypto` (bcrypt)
- **Cache**: `github.com/dgraph-io/ristretto`
- **Redis**: `github.com/redis/go-redis/v9`

Go version: 1.25.5
