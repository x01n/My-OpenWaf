# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

My-OpenWaf is a Go-based Web Application Firewall with two planes:
- **Control-plane**: Hertz REST API plus embedded Next.js dashboard, default admin bind `:9443`.
- **Data-plane**: per-enabled-site Hertz listener(s) from site bind settings; each request is matched to a site, processed by the WAF pipeline, then proxied to an upstream.

SQLite is the default database. MySQL/Postgres and Redis are optional; Redis is used for distributed/shared state such as config reload pub/sub, event fan-out, challenges, and rate-limit/anti-replay helpers where configured.

## Build & Run

```bash
# Full build on Unix-like shells: frontend export + embedded Go binary
./scripts/build.sh          # outputs bin/my-openwaf

# Full build from PowerShell on Windows
./scripts/build.ps1         # outputs bin\my-openwaf.exe

# Go backend only; requires internal/core/adminweb/dist to already contain the exported frontend
go build -o bin/my-openwaf ./cmd/...

# Frontend static export only
cd frontend && npm run build # outputs frontend/out

# Run locally
./bin/my-openwaf             # admin UI/API at :9443 by default

# Docker
docker build -t my-openwaf .
docker run -p 9443:9443 -v waf-data:/app/data my-openwaf
```

Full build flow: `npx next build` exports `frontend/out`, the scripts copy it to `internal/core/adminweb/dist`, then run `go mod tidy` and `go build` so the dashboard is embedded via Go embed.

## Testing

```bash
# All Go tests
go test -v ./...

# Single package
go test -v ./internal/waf/...

# Single test or test family
go test -v ./internal/waf/... -run TestOWASP
```

There is no repo-level Go lint command. Frontend lint/typecheck commands are in `frontend/package.json`.

## Detection Engine Load Test (MANDATORY)

> **每次对检测引擎进行任何更新之后，必须执行以下步骤，缺一不可：**

1. 启动服务端：`./bin/my-openwaf`（确保数据面监听在 `:80`）。
2. 执行压测：
   ```bash
   ./blazehttp.exe -t http://127.0.0.1:80 -c 40
   ```
3. 检查输出中无异常崩溃、无明显性能下降、无非预期的 block/pass 结果。

这是检测引擎变更的**强制验收标准**，不得跳过。涉及以下任意路径的修改均须执行：`internal/waf/`、`internal/core/rules/`、`internal/core/engine/`、`internal/core/pipeline/`、`internal/dataplane/handler.go`。

## Frontend

```bash
cd frontend
npm run dev          # Next.js dev server with Turbopack
npm run build        # static export to frontend/out
npm run lint         # eslint
npm run format       # prettier --write "**/*.{ts,tsx}"
npm run typecheck    # tsc --noEmit
```

Stack: Next.js 16 static export (`output: 'export'`, `distDir: 'out'`) + React 19 + TypeScript + Tailwind CSS 4 + shadcn/ui. For local backend serving a disk-built dashboard instead of embedded assets, set `MY_OPENWAF_ADMIN_STATIC_DIR=./frontend/out` before starting the Go server.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MY_OPENWAF_DB_DRIVER` | `sqlite` | `sqlite`, `mysql`, or `postgres` |
| `MY_OPENWAF_DSN` / `MY_OPENWAF_DB` | `./data/waf.db` | DB connection string; `MY_OPENWAF_DSN` wins over legacy `MY_OPENWAF_DB` |
| `MY_OPENWAF_DATA` | `./data` | Data directory used for default SQLite path |
| `MY_OPENWAF_ADMIN_BIND` | `:9443` | Admin control-plane listen address |
| `MY_OPENWAF_ADMIN_STATIC_DIR` | embedded FS | Serve dashboard from disk instead of Go embed |
| `MY_OPENWAF_REDIS_ADDR` | empty | Optional Redis address |
| `MY_OPENWAF_REDIS_PASSWORD` | empty | Optional Redis password |
| `MY_OPENWAF_REDIS_DB` | `0` | Optional Redis database number |
| `MY_OPENWAF_JWT_SECRET` | generated and persisted | JWT signing secret override |
| `MY_OPENWAF_GEOIP_DB` | empty | Optional MaxMind DB path for bot GeoIP scoring |
| `MY_OPENWAF_BOT_THRESHOLD` | `80` | Bot score threshold |
| `MY_OPENWAF_DROP_ENABLED` | `true` | Set to `false` to disable TCP drop strategy |
| `MY_OPENWAF_DROP_BOT_THRESHOLD` | `80` | Bot score threshold for drop-related decisions |
| `MY_OPENWAF_LOG_LEVEL` | info | Logger level override |
| `MY_OPENWAF_LOG_COLOR` | auto | Logger color override |

## Architecture

### Startup (`cmd/main.go` → `internal/app/server.go`)

`app.Run()` loads env config through `core.NewRuntime()`, validates it, opens SQL and optional Redis, creates local cache/snapshot holder, runs migrations and default seeding, builds the initial snapshot, wires rate limiters/IP reputation/WAF engine/drop/GeoIP/challenge/anti-replay/escalation managers, starts the admin server, starts data-plane listeners for enabled sites, then waits for shutdown.

### Snapshot Pattern

Runtime config is compiled into immutable `snapshot.Snapshot` instances held by `atomic.Pointer` in `snapshot.Holder`. `snapshot.Build()` loads enabled sites, certificates, rules, and global protection settings from the DB; rules are sorted by `priority ASC, ID ASC` and compiled into lightweight runtime rules per policy.

`core.Runtime.ReloadSnapshot()` reads the current `config_revisions` value, reuses a ristretto-cached snapshot for the same revision when possible, or rebuilds and atomically swaps the holder. Admin mutations call `deps.Reload()`, which bumps the revision, rebuilds the snapshot, reloads IP lists, reconfigures runtime protection knobs, hot-reconciles site listeners, and publishes a Redis reload notification when Redis is enabled.

### WAF Pipeline (`internal/core/engine` → `internal/core/pipeline`)

`engine.Process()` builds the ordered phase list for each resolved site:

**IPReputation → AntiReplay → Parallel(OWASP, CVE) → ACL → BotDetection → RequestRateLimit → Signature → Custom**

- IP reputation and anti-replay phases are included only when their managers exist; OWASP/CVE, bot detection, and request rate limit are controlled by effective protection settings.
- `Parallel(OWASP, CVE)` runs OWASP and CVE detection concurrently when both are enabled, or directly runs the single enabled detector.
- Terminal actions short-circuit the pipeline: `drop`, `intercept`, `challenge`/`captcha_challenge`/`shield_challenge`/`chain_challenge`, and `redirect`. `observe` hits are collected for logging and do not block upstream proxying.
- IP whitelist decisions short-circuit the engine pipeline. ACL `allow` rules short-circuit only the remaining phases because ACL runs after OWASP/CVE in the current engine order.
- Rules are compiled once per snapshot revision and policy, then partitioned into ACL/signature/custom phases.

### Data-Plane Flow (`internal/dataplane/handler.go`)

1. Requests under `/__owaf/*` and challenge verification endpoints are handled before normal WAF processing.
2. Load the current snapshot and match a site by listener bind + Host header, with exact, wildcard, bind fallback, and host fallback matching.
3. Resolve client IP from X-Forwarded-For/trusted CIDR settings and apply a pre-pipeline IP reputation block/drop fast path.
4. Apply per-site anti-replay cookie handling when enabled.
5. Acquire a pooled `pipeline.RequestCtx`, copy headers, preserve raw path/query, and cap WAF body inspection at **48 KiB**.
6. Run `engine.Process(reqCtx)`.
7. Handle terminal actions: TCP drop closes the connection, challenge renders the appropriate challenge page, redirect sends an HTTP redirect, and intercept renders the block page.
8. Otherwise proxy to a round-robin upstream. WebSocket uses raw TCP tunneling, SSE streams with flushing, and normal HTTP can use the per-site response cache when eligible.
9. Record status metrics, post-proxy error-rate-limit counters, async security/access logs, and drop events.

### OWASP Detection Engine (`internal/waf/owasp.go`, `internal/waf/owasp_extended.go`)

The OWASP detector is layered for performance and false-positive control:

1. Clean-target prefilter skips strings without suspicious content.
2. Normalization performs repeated URL/HTML/entity/Unicode-style decoding and case-preserving base64 token decoding for suspicious tokens.
3. Each target is bounded by `maxTargetLen` (**16 KiB**, keeping both head and tail for overlong values).
4. Per-category thresholds derive from global sensitivity or category overrides: `low=7`, `mid/medium=4`, `high=3`, `very_high=2`, `strict=1`, `off=disabled`.
5. Category-specific regex batteries accumulate scores; false-positive suppressors run after matches where applicable.

Body parsing happens before scanning: form-urlencoded keys and values are scanned; JSON string values and keys are walked recursively with depth/quantity bounds; multipart filenames, raw filename patterns, text fields, and limited file content snippets are scanned; likely binary bodies are skipped unless content-type/heuristics make them text-like. Current categories include SQLi, XSS, WebShell, RevShell, PathTraversal, SSRF, CmdInjection, XXE, LDAPi, NoSQLi, SSTI/template injection, JNDI, CRLF, expression language, deserialization, file upload, protocol violation, and GraphQL injection.

### Rule DSL (`internal/core/rules/compiler.go`, `internal/snapshot/build.go`)

Rule patterns use `kind:arg`, for example `allow_ip:1.2.3.0/24`, `block_path:/admin`, or `block_query_regex:(?i)union select`. Compound rules are JSON with `op: "and" | "or" | "not"` and nested `children`. Snapshot build parses patterns into runtime `CompiledRule`s, while the engine compiler builds matchers and caches compiled regex globally.

### Listener Hot-Reload

Listeners are site-based. `reconcileListeners()` compares desired enabled sites from the snapshot with running Hertz servers; `siteListenerFingerprint()` hashes site ID, bind address, TLS settings, certificate bytes, and SNI certs. Only stale or changed site listeners are stopped/recreated. Data-plane TLS uses Hertz with `standard.NewTransporter` for native Go TLS support.

### Admin API Pattern

Handlers live in `internal/admin/handler_*.go` and routes are registered in `internal/admin/router.go`. Auth supports JWT access tokens, httpOnly refresh-token sessions, and admin API keys. RBAC roles are `admin`, `operator`, and `readonly`, enforced with `RequireRole()` route middleware.

The admin API intentionally uses only `GET` and `POST`: updates/deletes follow patterns like `POST /resource/:id/update` and `POST /resource/:id/delete`; no `PUT` or `DELETE` routes are used. All configuration mutations must call the injected reload function so the snapshot and listeners are refreshed.

### Observability

- Security events and access logs use buffered async writers (`4096` channel, batch size `64`).
- The archiver removes old security events, access logs, and drop events after 30 days.
- Prometheus-compatible metrics are served at `/metrics` on the admin server.
- Health endpoints are `/healthz`, `/readyz`, and `/status` on the admin server.

### Key Packages

| Package | Role |
|---------|------|
| `internal/app` | Startup wiring, lifecycle, admin/data-plane server construction |
| `internal/core` | Env config, DB/Redis/cache runtime, snapshot reload orchestration |
| `internal/core/engine` | Per-request WAF pipeline assembly and rule compilation cache |
| `internal/core/pipeline` | Request context pooling and ordered phase execution |
| `internal/core/rules` | Rule DSL compilation and phase implementations |
| `internal/admin` | REST API, auth middleware, RBAC, embedded dashboard routing |
| `internal/dataplane` | Site matching, WAF invocation, block/challenge/drop/proxy flow |
| `internal/proxy` | HTTP/SSE/WebSocket upstream forwarding and response cache helpers |
| `internal/snapshot` | Immutable runtime config and atomic holder |
| `internal/store` | GORM models, migrations, default seeding, repositories |
| `internal/waf` | OWASP/CVE/bot/IP reputation/rate limit/challenge/drop logic |
| `internal/observability` | Metrics, async event/access-log writers, retention archiver |
| `internal/security` | Client IP resolution and outbound forwarding headers |

## Go Dependencies

- HTTP framework: `github.com/cloudwego/hertz`.
- ORM/database: `gorm.io/gorm` with sqlite/mysql/postgres drivers.
- Auth: `github.com/golang-jwt/jwt/v5`, `golang.org/x/crypto` bcrypt.
- Cache: `github.com/dgraph-io/ristretto` plus optional Redis (`github.com/redis/go-redis/v9`).
- GeoIP/bot support: `github.com/oschwald/maxminddb-golang`.

Go version: `1.25.5`.
