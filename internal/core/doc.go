// Package core holds process-wide infrastructure and WAF engine:
//
//   - [My-OpenWaf/internal/core/action]:    WAF action types (allow/block/log_only/challenge)
//   - [My-OpenWaf/internal/core/adminweb]:  embedded Next.js static export
//   - [My-OpenWaf/internal/core/database]:  GORM open (sqlite / mysql / postgres)
//   - [My-OpenWaf/internal/core/engine]:    top-level WAF processing engine
//   - [My-OpenWaf/internal/core/errors]:    core error types (config/rule/pipeline)
//   - [My-OpenWaf/internal/core/health]:    liveness / readiness / status probes
//   - [My-OpenWaf/internal/core/lifecycle]: multi-server startup + graceful shutdown
//   - [My-OpenWaf/internal/core/pipeline]:  ordered request processing phases
//   - [My-OpenWaf/internal/core/redis]:     optional go-redis client
//   - [My-OpenWaf/internal/core/rules]:     rule compiler, matchers, phase implementations
//   - [My-OpenWaf/internal/core/sites]:     virtual host resolver over snapshot
//
// Bootstrap config and runtime wiring live in config.go / runtime.go.
// Domain persistence models live in [My-OpenWaf/internal/store].
package core
