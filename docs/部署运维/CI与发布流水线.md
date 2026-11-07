# CI 与发布流水线

> 参见：[构建脚本与工具链](构建脚本与工具链.md)（本地三条构建链）· [部署运维](部署运维.md)（运行与编排）· 开发流程与代码规范见 [开发者指南](../项目概述/开发者指南.md)

<cite>
**本文档引用的文件**
- [.github/workflows/ci.yml](file://.github/workflows/ci.yml)
- [.github/workflows/release-pr.yml](file://.github/workflows/release-pr.yml)
- [.github/workflows/release.yml](file://.github/workflows/release.yml)
- [scripts/build.sh](file://scripts/build.sh)
- [scripts/build.ps1](file://scripts/build.ps1)
- [wasm-pow-solver/Makefile](file://wasm-pow-solver/Makefile)
- [wasm-pow-solver/Cargo.toml](file://wasm-pow-solver/Cargo.toml)
- [frontend/package.json](file://frontend/package.json)
- [frontend/next.config.ts](file://frontend/next.config.ts)
- [go.mod](file://go.mod)
- [Dockerfile](file://Dockerfile)
- [.dockerignore](file://.dockerignore)
- [README.md](file://README.md)
- [internal/core/adminweb/embed.go](file://internal/core/adminweb/embed.go)
- [internal/core/adminweb/static.go](file://internal/core/adminweb/static.go)
- [internal/waf/jsplugin/quickjs_cgo.go](file://internal/waf/jsplugin/quickjs_cgo.go)
- [internal/waf/jsplugin/quickjs_stub.go](file://internal/waf/jsplugin/quickjs_stub.go)
- [docs/部署运维/构建脚本与工具链.md](file://docs/部署运维/构建脚本与工具链.md)
</cite>

## 目录

1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构总览](#架构总览)
5. [详细组件分析](#详细组件分析)
6. [依赖关系分析](#依赖关系分析)
7. [性能考虑](#性能考虑)
8. [故障排查指南](#故障排查指南)
9. [结论](#结论)
10. [附录](#附录)

## 简介

`.github/workflows/` 实测只有 3 个清单文件、共 10 个 job、3 条独立流水线：`CI`（质量门禁）、`Release PR`（版本递增与发布 PR 生成）、`Release`（打 tag、多平台构建、发布）。三条链之间**没有任何 workflow 级 `needs` 关系**，衔接全靠 Git 事件：push 到 `main` 触发前两条，PR 被合并关闭触发第三条。

本篇只写流水线编排与交付闸门。构建命令本身的语义、脚本差异与产物落位归 [构建脚本与工具链](构建脚本与工具链.md)，不在这里重复其表格；镜像运行与端口编排归 [部署运维](部署运维.md)。

一条必须先说清的结论：**CI 不构建镜像，也不重建 WASM**。全库 workflow 中既没有 `docker build`，也没有 `make optimize`；`pow.wasm` 与 `pow_glue.js` 按仓库快照交付，镜像只能人工构建。这一点决定了「CI 绿」不等于「可发布镜像」。

**章节来源**
- [.github/workflows/ci.yml:1-201](file://.github/workflows/ci.yml#L1-L201)
- [.github/workflows/release-pr.yml:1-171](file://.github/workflows/release-pr.yml#L1-L171)
- [.github/workflows/release.yml:1-238](file://.github/workflows/release.yml#L1-L238)

## 项目结构

### 清单文件与作业分布

三条流水线写在三个文件里，职责互不重叠，但 `gofmt` + `go vet` + 全量 `go test` 这套动作在 `ci.yml` 与 `release-pr.yml` 中各写了一遍。

| 文件 | name | 触发 | permissions | concurrency | job 数 |
|---|---|---|---|---|:--:|
| `ci.yml` | `CI` | `push: main`（`:4-5`）、`pull_request: main`（`:6-7`）、`workflow_dispatch`（`:8`） | `contents: read`（`:10-11`） | `ci-${{ github.ref }}` + 取消进行中（`:13-15`） | 4 |
| `release-pr.yml` | `Release PR` | `push: main`（`:4-5`）、`workflow_dispatch`（`:6-11`，可选 `version` 输入） | `contents: write`、`pull-requests: write`（`:13-15`） | `release-pr` + **不**取消（`:17-19`） | 2 |
| `release.yml` | `Release` | `pull_request: main` 且 `types: [closed]`（`:4-6`）、`workflow_dispatch`（`:7-12`，必填 `tag` 输入） | `contents: write`（`:14-15`） | **无** | 4 |

`ci.yml` 与 `release-pr.yml` 都监听 `push: branches: [main]`，因此**一次合并到 main 会同时跑两条链**：前者跑测试与产物，后者再跑一遍同样测试并开出一个 `release/vX.Y.Z` PR。

```mermaid
graph TB
  subgraph W1["ci.yml"]
    FT["frontend-test<br/>Frontend checks"]
    BT["backend-test<br/>Go test"]
    DM["dialect-migration<br/>DB dialect migration"]
    FB["full-build<br/>Full application build"]
  end
  subgraph W2["release-pr.yml"]
    VF["verify<br/>Build and test"]
    RP["release-pr<br/>Create or update release PR"]
  end
  subgraph W3["release.yml"]
    RM["release-meta<br/>Release metadata + 打 tag"]
    FE["frontend<br/>Build frontend export"]
    BD["build<br/>Build 六平台矩阵"]
    PB["publish<br/>Publish GitHub release"]
  end
  FT --> BT
  FT --> DM
  FT --> FB
  BT --> FB
  VF --> RP
  RP -. PR merged + closed 事件 .-> RM
  RM --> FE
  FE --> BD
  RM --> BD
  BD --> PB
```

**图表来源**
- [.github/workflows/ci.yml:18-21](file://.github/workflows/ci.yml#L18-L21)
- [.github/workflows/ci.yml:81-89](file://.github/workflows/ci.yml#L81-L89)
- [.github/workflows/ci.yml:137-142](file://.github/workflows/ci.yml#L137-L142)
- [.github/workflows/ci.yml:171-174](file://.github/workflows/ci.yml#L171-L174)
- [.github/workflows/release-pr.yml:22-24](file://.github/workflows/release-pr.yml#L22-L24)
- [.github/workflows/release-pr.yml:83-86](file://.github/workflows/release-pr.yml#L83-L86)
- [.github/workflows/release.yml:18-23](file://.github/workflows/release.yml#L18-L23)
- [.github/workflows/release.yml:65-68](file://.github/workflows/release.yml#L65-L68)
- [.github/workflows/release.yml:95-98](file://.github/workflows/release.yml#L95-L98)
- [.github/workflows/release.yml:220-223](file://.github/workflows/release.yml#L220-L223)

一个容易踩空的声明细节：`ci.yml:44` 写的是 `grep -Fq 'runs-on: $''{{ matrix.runner }}'`，用 PowerShell/单引号拼接技巧避开 Actions 表达式插值；直接改成 `${{ matrix.runner }}` 会被 Runner 先行展开成实际值，导致校验静默失效。

**章节来源**
- [.github/workflows/ci.yml:44](file://.github/workflows/ci.yml#L44)
- [.github/workflows/ci.yml:3-15](file://.github/workflows/ci.yml#L3-L15)
- [.github/workflows/release-pr.yml:3-19](file://.github/workflows/release-pr.yml#L3-L19)
- [.github/workflows/release.yml:3-15](file://.github/workflows/release.yml#L3-L15)

## 核心组件

### 作业清单

10 个 job 中只有 4 个是「阻塞型」，其余为旁路验证或产物终接。

| job | 所在文件:行 | 显示名 | 依赖（needs） | 关键动作 |
|---|---|---|---|---|
| `frontend-test` | `ci.yml:137-169` | Frontend checks | 无（根作业） | `typecheck` → `lint` → `build` → 上传 `frontend-out` |
| `backend-test` | `ci.yml:18-79` | Go test | `frontend-test` | `gofmt` → release 契约校验 → 取产物 → `vet` → 全量 `test` |
| `dialect-migration` | `ci.yml:81-135` | DB dialect migration | `frontend-test` | MySQL/PG 服务容器上跑 `TestAutoMigrateOnExternalDialect` |
| `full-build` | `ci.yml:171-201` | Full application build | `backend-test`、`frontend-test` | `go mod tidy` + CGO 编译 + 上传 Linux 二进制 |
| `verify` | `release-pr.yml:22-81` | Build and test | 无（根作业） | 同一套测试 + 前端构建 + 复制 dist + 二次 typecheck/lint |
| `release-pr` | `release-pr.yml:83-171` | Create or update release PR | `verify` | 算版本 → 建分支 → 写 `.release.json` → 推分支 → 开/改 PR |
| `release-meta` | `release.yml:18-63` | Release metadata | 无（带 `if` 闸门） | 解析 tag → 打附注 tag → 推送 refs/tags |
| `frontend` | `release.yml:65-93` | Build frontend export | `release-meta` | 按 tag 检出 → Bun 构建 → 上传 `frontend-out` |
| `build` | `release.yml:95-218` | Build 各平台 | `release-meta`、`frontend` | 校验 QuickJS → 编译 → 打包 → 校验和 → 上传 |
| `publish` | `release.yml:220-238` | Publish GitHub release | `release-meta`、`build` | 汇总产物 → `softprops/action-gh-release@v2` 发布 |

**章节来源**
- [.github/workflows/ci.yml:18-201](file://.github/workflows/ci.yml#L18-L201)
- [.github/workflows/release-pr.yml:22-171](file://.github/workflows/release-pr.yml#L22-L171)
- [.github/workflows/release.yml:18-238](file://.github/workflows/release.yml#L18-L238)

## 架构总览

流水线整体是「双入口 + 单出口」结构：入口一是 PR（跑 `ci.yml`），入口二是合并到 `main`（同时跑 `ci.yml` 与 `release-pr.yml`）；出口只有 GitHub Release 产物，镜像不在此链上。

```mermaid
sequenceDiagram
  autonumber
  actor DEV as 开发者
  participant GH as GitHub 事件
  participant CI as ci.yml
  participant RP as release-pr.yml
  participant REL as release.yml
  DEV->>GH: 提交 PR 到 main
  GH->>CI: pull_request 触发
  CI->>CI: frontend-test 上传 frontend-out（ci.yml:164-169）
  CI->>CI: backend-test 契约校验 + vet + 全量 test（ci.yml:41-79）
  CI->>CI: full-build 产出 Linux 二进制（ci.yml:191-201）
  DEV->>GH: 合并 PR（push main）
  GH->>CI: push 触发（再跑一次）
  GH->>RP: push 触发
  RP->>RP: verify 全量测试（release-pr.yml:42-81）
  RP->>GH: 建 release/vX.Y.Z 分支 + 开 PR（:129-171）
  DEV->>GH: 合并该 release PR
  GH->>REL: pull_request closed 且 head ref 以 release/v 开头
  REL->>GH: 打附注 tag 并推送（release.yml:54-63）
  REL->>REL: frontend + build(6) + publish
```

**图表来源**
- [.github/workflows/ci.yml:3-8](file://.github/workflows/ci.yml#L3-L8)
- [.github/workflows/ci.yml:164-201](file://.github/workflows/ci.yml#L164-L201)
- [.github/workflows/release-pr.yml:4-5](file://.github/workflows/release-pr.yml#L4-L5)
- [.github/workflows/release-pr.yml:42-81](file://.github/workflows/release-pr.yml#L42-L81)
- [.github/workflows/release-pr.yml:129-171](file://.github/workflows/release-pr.yml#L129-L171)
- [.github/workflows/release.yml:4-6](file://.github/workflows/release.yml#L4-L6)
- [.github/workflows/release.yml:54-63](file://.github/workflows/release.yml#L54-L63)

### 流水线作业表

| job | 触发 | 步骤（位置:行） | 失败影响 |
|---|---|---|---|
| `frontend-test` | PR / push main / 手动 | Checkout `:144-145`；Setup Bun `:147-150`；install `:152-153`；typecheck `:155-156`；lint `:158-159`；build `:161-162`；上传产物 `:164-169` | **阻断全局**：`backend-test`、`dialect-migration`、`full-build` 全部 `needs` 它，产物缺失则后端连编译都做不了 |
| `backend-test` | 同上 | Checkout `:23-24`；Setup Go `:26-30`；gofmt `:32-39`；release 契约 `:41-67`；取产物 `:69-73`；vet `:75-76`；test `:78-79` | 阻断 `full-build`；不阻断 `release-pr.yml`（两条链互不引用） |
| `dialect-migration` | 同上 | Checkout `:116-117`；Setup Go `:119-123`；取产物 `:125-129`；方言测试 `:131-135` | **仅旁路告警**：无任何 job `needs` 它，MySQL/PG 迁移失败不影响 `full-build` 与发布 |
| `full-build` | 同上 | Checkout `:176-177`；Setup Go `:179-183`；取产物 `:185-189`；构建 `:191-194`；上传二进制 `:196-201` | 终接作业，仅影响 `my-openwaf-linux-amd64` 产物可得性 |
| `verify` | push main / 手动 | gofmt `:42-49`；前端装包 `:51-53`；前端构建 `:55-57`；复制 dist `:59-62`；vet `:64-65`；test `:67-68`；typecheck `:70-72`；lint `:74-76`；构建应用 `:78-81` | 阻断 `release-pr`，即开不出发布 PR |
| `release-pr` | 同上 | 取码 `:90-94`；算版本 `:96-127`；建分支 `:129-133`；写元数据 `:135-145`；推分支 `:147-151`；开/改 PR `:153-171` | 发布链在源头断裂，只能改用手推 `release/*` 分支或 `workflow_dispatch` |
| `release-meta` | PR closed（带条件）/ 手动 | 全量取码 `:29-32`；解析版本 `:34-52`；打并推 tag `:54-63` | **阻断整条发布链**：`frontend`、`build`、`publish` 都 `needs` 它 |
| `frontend` | 依赖 release-meta | 按 tag 检出 `:70-73`；Bun 链 `:75-86`；上传产物 `:88-93` | 阻断 `build` |
| `build` | 依赖 release-meta + frontend | QuickJS 校验 `:148-163`；编译 `:165-175`；打包 `:177-191`；校验和 `:193-211`；上传 `:213-218` | 阻断 `publish`（`fail-fast: false`，单平台失败不牵连其余） |
| `publish` | 依赖 release-meta + build | 汇总产物 `:225-229`；创建 Release `:231-238` | 发布不产出，tag 已存在但无资产 |

**章节来源**
- [.github/workflows/ci.yml:18-201](file://.github/workflows/ci.yml#L18-L201)
- [.github/workflows/release-pr.yml:22-171](file://.github/workflows/release-pr.yml#L22-L171)
- [.github/workflows/release.yml:18-238](file://.github/workflows/release.yml#L18-L238)

## 详细组件分析

### ci.yml：门禁与契约校验

`ci.yml` 的 job 声明顺序与依赖顺序不一致：`backend-test`（`:18`）写在最前但 `needs: [frontend-test]`（`:21`），真正的首作业是文件末尾附近的 `frontend-test`（`:137`）。阅读时需按 `needs` 重建拓扑，不能按书写顺序理解。

```yaml
# .github/workflows/ci.yml:3-15（触发与并发，无敏感值）
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
```

`cancel-in-progress: true`（`:15`）意味着同一 ref 上的新 push 会掐掉旧运行；对 PR 是省资源，对 `push: main` 则可能把正在跑的 30 分钟全量测试打断。

后端测试的两条核心命令与本地口径完全一致：

```bash
# .github/workflows/ci.yml:76（Run go vet）
CGO_ENABLED=1 go vet -tags=quickjs ./...
# .github/workflows/ci.yml:79（Run Go tests）
CGO_ENABLED=1 go test -tags=quickjs -v -timeout=30m ./...
```

与 `README.md:431-433` 逐条对得上；差别是 CI 不跑 `README.md:435` 的 `go test -p 1 -count=1 -timeout=30m ./...` 串行回归口径。

`gofmt` 检查（`:32-39`）把 `gofmt -l .` 的输出当作失败条件，非空即 `::error::` 并 `exit 1`，因此格式化是硬性门禁。

**章节来源**
- [.github/workflows/ci.yml:3-15](file://.github/workflows/ci.yml#L3-L15)
- [.github/workflows/ci.yml:18-21](file://.github/workflows/ci.yml#L18-L21)
- [.github/workflows/ci.yml:32-39](file://.github/workflows/ci.yml#L32-L39)
- [.github/workflows/ci.yml:75-79](file://.github/workflows/ci.yml#L75-L79)
- [README.md:431-435](file://README.md#L431-L435)

### 契约校验：CI 反向守发布清单

`ci.yml:41-67` 的 `Check release workflow contract` 步骤是本仓库最有特色的一环：**用 CI 的 backend-test 去校验另一个 workflow 文件的文本与 YAML 结构**，防止有人把 `release.yml` 的 CGO/tag 改坏。它依赖 Runner 预装的 `ruby`（`:43`、`:46`）与 GNU `grep`。

| 断言 | 位置:行 | 判据 | 不满足时 |
|---|---|---|---|
| release.yml 可被 YAML 解析 | `ci.yml:43` | `YAML.parse_file` | ruby 抛错，步骤失败 |
| 走矩阵 runner | `ci.yml:44` | `grep -Fq 'runs-on: ${{ matrix.runner }}'` | `grep` 退出码 1 |
| runner 条目恰为 6 | `ci.yml:45` | `grep -cE '^[[:space:]]+runner:'` 结果 `-eq 6` | 测试表达式失败 |
| 存在 QuickJS 校验步骤 | `ci.yml:49` | 步骤名 `Verify native QuickJS backend` | `abort("missing native QuickJS verification step")` |
| 存在构建步骤 | `ci.yml:50` | 步骤名 `Build binary` | `abort("missing release build step")` |
| 校验步骤启用 cgo | `ci.yml:51` | `env.CGO_ENABLED == "1"` | abort 提示必须开 cgo |
| 校验步骤选 tag | `ci.yml:52` | run 文本含 `go list -tags=quickjs` | abort |
| 构建步骤启用 cgo | `ci.yml:53` | `env.CGO_ENABLED == "1"` | abort |
| 构建步骤选 tag | `ci.yml:54` | run 文本含 `go build -tags=quickjs` | abort |
| 全局禁 cgo 检测 | `ci.yml:56-59` | 不得出现 `CGO_ENABLED: '0'` | `::error::` + `exit 1` |
| tag 语法宽匹配 | `ci.yml:60-63` | `-tags(=|[[:space:]])+quickjs` | `::error::` + `exit 1` |
| cgo 源构建约束 | `ci.yml:64` | `quickjs_cgo.go` 含 `//go:build cgo && quickjs` | grep 失败 |
| stub 源构建约束 | `ci.yml:65` | `quickjs_stub.go` 含 `//go:build !cgo || !quickjs` | grep 失败 |
| 校验步骤名在文件中 | `ci.yml:66-67` | 同时含 `Verify native QuickJS backend` 与 `quickjs_cgo.go` | grep 失败 |

共 14 条断言：1 条只做 YAML 语法解析（`ci.yml:43`），6 条由内嵌 ruby 脚本以 `abort` 表达（`ci.yml:46-55`），其余 7 条由 `grep`/`test` 表达。被守护的真实文本在 `release.yml:148-163` 与 `release.yml:165-175`，两个源文件的构建约束分别是 `quickjs_cgo.go:1` 与 `quickjs_stub.go:1`。

**章节来源**
- [.github/workflows/ci.yml:41-67](file://.github/workflows/ci.yml#L41-L67)
- [.github/workflows/release.yml:148-175](file://.github/workflows/release.yml#L148-L175)
- [internal/waf/jsplugin/quickjs_cgo.go:1](file://internal/waf/jsplugin/quickjs_cgo.go#L1)
- [internal/waf/jsplugin/quickjs_stub.go:1](file://internal/waf/jsplugin/quickjs_stub.go#L1)

### 前端门禁与未纳入 CI 的契约脚本

`frontend-test`（`ci.yml:137-169`）只跑 `bun run typecheck`、`bun run lint`、`bun run build` 三条，对应 `frontend/package.json:12`、`:10`、`:8`。`package.json:13-22` 声明的 **10 个 `check:*` 契约脚本没有任何 workflow 调用**（全库 workflow 无 `check:` 字样），因此前端契约检查完全是人工口径。

```bash
# CI 实际执行（ci.yml:153 / :156 / :159 / :162）
bun install --frozen-lockfile
bun run typecheck
bun run lint
bun run build

# CI 未执行、仅本地的契约脚本（frontend/package.json:13-22，10 条 / 9 个文件）
bun run check:skip-path-contract
bun run check:auth-refresh-contract
bun run check:login-form-contract
bun run check:rule-pattern-roundtrip
bun run check:site-cache-contract
bun run check:site-challenge-contract
bun run check:site-protection-contract
bun run check:api-route-contract
bun run check:env-override-contract
```

`lint` 调的是裸 `eslint`（`package.json:10`）而非 `next lint`，与 Next 16 移除该子命令一致；`README.md:443-451` 只列了 8 条 `check:*`，遗漏 `check:i18n`（`package.json:13`）与 `check:env-override-contract`（`:22`）。

**章节来源**
- [.github/workflows/ci.yml:137-169](file://.github/workflows/ci.yml#L137-L169)
- [frontend/package.json:8-22](file://frontend/package.json#L8-L22)
- [README.md:443-451](file://README.md#L443-L451)

### 方言迁移作业

`dialect-migration`（`ci.yml:81-135`）是唯一的**服务型作业**，注释（`:82-86`）说明动机：SQLite 过于宽容，`TEXT` 列带 `DEFAULT`（MySQL Error 1101）与复合唯一索引键长超 3072 字节（MySQL Error 1071）只在真实 MySQL/PostgreSQL 上暴露。

```yaml
# .github/workflows/ci.yml:90-114（服务容器，口令已脱敏）
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: {占位}
          MYSQL_DATABASE: waf
        ports:
          - 3306:3306
        options: >-
          --health-cmd="mysqladmin ping -uroot -p{占位} --silent"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=12
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: {占位}
          POSTGRES_DB: waf
        ports:
          - 5432:5432
```

测试命令与主作业有两处实质差异：

```bash
# .github/workflows/ci.yml:135（Run dialect migration tests）
go test -v -timeout=10m -run TestAutoMigrateOnExternalDialect ./internal/store/
```

它**不带 `-tags=quickjs`，也不设 `CGO_ENABLED=1`**（对比 `ci.yml:79`），并把超时压到 10 分钟。含义是该用例只依赖数据库方言，不需要 QuickJS 后端；但一旦后续有人在该测试里引入 JS 插件路径，就会命中 stub 而静默失去覆盖。

DSN 通过 step 级 `env` 注入（`ci.yml:132-134`），变量名分别为 `MY_OPENWAF_TEST_MYSQL_DSN` 与 `MY_OPENWAF_TEST_POSTGRES_DSN`，账号口令即服务容器里的同一个占位口令。

**章节来源**
- [.github/workflows/ci.yml:81-135](file://.github/workflows/ci.yml#L81-L135)
- [go.mod:14](file://go.mod#L14)

### release-pr.yml：版本递增与 PR 自动化

`verify`（`:22-81`）把 `ci.yml` 的后端门禁与前端门禁合成单作业顺序执行，顺序值得注意：**前端 `typecheck`/`lint` 排在 Go 全量测试之后**（`:70-76` 在 `:67-68` 之后），与 `ci.yml` 里「前端先行、后端依赖产物」的次序相反。它自己用 `rm -rf` + `cp -r` 把 `frontend/out` 落进 `internal/core/adminweb/dist`（`:59-62`），因此不依赖 artifact 传递。

`release-pr`（`:83-171`）是版本策略的唯一实现处：

```bash
# .github/workflows/release-pr.yml:107-125（版本解析核心，逐字取自 workflow）
latest="$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"
if [ -z "$latest" ]; then
  VERSION="0.1.0"
else
  base="${latest#v}"
  major="${base%%.*}"
  rest="${base#*.}"
  minor="${rest%%.*}"
  patch="${rest#*.}"
  patch="${patch%%-*}"
  VERSION="${major}.${minor}.$((patch + 1))"
fi
TAG="v${VERSION}"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "::error::Tag already exists: $TAG"
  exit 1
fi
```

规则明确：手动 `version` 输入优先且必须匹配 `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`（`:101-106`）；否则取最新三位 tag 递增 patch；无任何 tag 时从 `0.1.0` 起。

分支与 PR 侧动作：`git checkout -B release/<tag>`（`:133`）→ 写 `.release.json`（含 `version`、`tag`、`commit` 三字段，`:137-143`）→ `git commit -m "chore: prepare release <tag>" || true`（`:145`，`|| true` 表示无变更也继续）→ 用 `--force-with-lease` 配远端预期 SHA 推送（`:149-151`）→ 用 `gh pr list/edit/create` 做「有则改、无则建」（`:161-171`）。令牌一律走 `secrets.GITHUB_TOKEN`，此处脱敏为 `{占位}`，不得出现在日志与文档。

```bash
# .github/workflows/release-pr.yml:149-151（幂等强推）
expected="$(git ls-remote --heads origin "refs/heads/release/${TAG}" | cut -f1)"
git push --force-with-lease="refs/heads/release/${TAG}:${expected}" \
  origin "refs/heads/release/${TAG}:refs/heads/release/${TAG}"
```

`--force-with-lease` 先把远端当前 SHA 取回来做条件，配合 `concurrency: release-pr` 且 `cancel-in-progress: false`（`:17-19`），保证并发触发的两个运行不会互相覆盖发布分支。

**章节来源**
- [.github/workflows/release-pr.yml:17-19](file://.github/workflows/release-pr.yml#L17-L19)
- [.github/workflows/release-pr.yml:22-81](file://.github/workflows/release-pr.yml#L22-L81)
- [.github/workflows/release-pr.yml:96-171](file://.github/workflows/release-pr.yml#L96-L171)

### release.yml：tag 闸门与产物矩阵

`release-meta` 的 `if` 是全链唯一准入条件（`:20-22`）：手动触发，或「PR 已合并 **且** head ref 以 `release/v` 开头」。二者皆不满足时该作业被跳过，下游三个 `needs` 它的作业连带不执行。

```mermaid
stateDiagram-v2
  state "PR 打开（CI 门禁）" as CI
  state "合并进 main" as Merged
  state "verify 全量通过" as Verify
  state "release/vX.Y.Z 分支与 PR 就绪" as RelPR
  state "release-meta 条件闸门" as Gate
  state "附注 tag 已推送" as Tagged
  state "六平台 build + 校验和" as Built
  state "GitHub Release 已发布" as Published
  state "闸门拒绝（作业跳过）" as Skipped
  CI --> Merged: 审查通过并合并
  Merged --> Verify: release-pr.yml 触发
  Verify --> RelPR: 版本解析 + 推分支
  RelPR --> Gate: 合并该 release PR
  Gate --> Tagged: merged 且 head ref 以 release/v 开头
  Gate --> Skipped: 其余情形
  Skipped --> RelPR: 手动 workflow_dispatch 指定 tag
  Tagged --> Built: frontend 产物就绪
  Built --> Published: publish 汇总产物
```

**图表来源**
- [.github/workflows/release.yml:20-22](file://.github/workflows/release.yml#L20-L22)
- [.github/workflows/release.yml:54-63](file://.github/workflows/release.yml#L54-L63)
- [.github/workflows/release.yml:65-68](file://.github/workflows/release.yml#L65-L68)
- [.github/workflows/release.yml:95-98](file://.github/workflows/release.yml#L95-L98)
- [.github/workflows/release.yml:220-223](file://.github/workflows/release.yml#L220-L223)
- [.github/workflows/release-pr.yml:129-151](file://.github/workflows/release-pr.yml#L129-L151)

打 tag 的两行细节是有意设计：`git tag -a -m "Release $TAG"`（`:62`）必须打**附注 tag**，注释（`:60-61`）解释「本地打标签失败同样停摆，避免空 tag 绕过附注签名要求」；推送用显式 refspec `refs/tags/$TAG:refs/tags/$TAG`（`:63`），目标 ref 已存在即失败，不做覆盖。

矩阵固定 6 个条目（`:102-126`），`fail-fast: false`（`:100`）使单平台失败不牵连其余：

| goos/goarch | runner | 扩展名 | 打包 | 校验和 | 产物名 |
|---|---|---|---|---|---|
| linux/amd64 | `ubuntu-24.04`（`:106`） | 无 | `tar.gz`（`:177-183`） | `sha256sum`（`:201`） | `my-openwaf-<ver>-linux-amd64.tar.gz` |
| linux/arm64 | `ubuntu-24.04-arm`（`:110`） | 无 | `tar.gz` | `sha256sum` | `...-linux-arm64.tar.gz` |
| darwin/amd64 | `macos-15-intel`（`:114`） | 无 | `tar.gz` | `shasum -a 256`（`:199`） | `...-darwin-amd64.tar.gz` |
| darwin/arm64 | `macos-14`（`:118`） | 无 | `tar.gz` | `shasum -a 256` | `...-darwin-arm64.tar.gz` |
| windows/amd64 | `windows-2022`（`:122`） | `.exe` | `Compress-Archive`（`:185-191`） | `Get-FileHash`（`:204-211`） | `...-windows-amd64.zip` |
| windows/arm64 | `windows-11-arm`（`:126`） | `.exe` | zip | `Get-FileHash` | `...-windows-arm64.zip` |

每个包内除二进制外固定附带 `README.md` 与 `LICENSE`（`:175`）；编译参数固定 `-trimpath -ldflags="-s -w"`（`:174`），与本地 `scripts/build.sh:13` 的裸编译不同，产物更小但不可直接对拍字节。

`publish`（`:220-238`）用 `merge-multiple: true` 把 6 个作业的产物拍平到 `dist/release`（`:225-229`），再交给 `softprops/action-gh-release@v2`（`:232`），`generate_release_notes: true`（`:237`）自动补变更记录；`prerelease` 取自 `is_prerelease` 输出，判据是版本号里存在 `-` 预发布段（`:48-52`）。

**章节来源**
- [.github/workflows/release.yml:18-63](file://.github/workflows/release.yml#L18-L63)
- [.github/workflows/release.yml:95-126](file://.github/workflows/release.yml#L95-L126)
- [.github/workflows/release.yml:165-218](file://.github/workflows/release.yml#L165-L218)
- [.github/workflows/release.yml:220-238](file://.github/workflows/release.yml#L220-L238)

### 作业配置项

| 配置项 | 位置:行 | 取值 | 说明 |
|---|---|---|---|
| `permissions.contents` | `ci.yml:10-11` | `read` | 门禁链只读 |
| `permissions.contents` | `release.yml:14-15` | `write` | 需推 tag 与 Release |
| `permissions.pull-requests` | `release-pr.yml:13-15` | `write` | 需建/改 PR |
| `concurrency.group` | `ci.yml:13-14` | `ci-${{ github.ref }}` | 按 ref 分组 |
| `cancel-in-progress` | `ci.yml:15` | `true` | 新提交掐旧运行 |
| `concurrency.group` | `release-pr.yml:17-18` | `release-pr` | 全局单组 |
| `cancel-in-progress` | `release-pr.yml:19` | `false` | 不允许打断发布分支准备 |
| `inputs.tag` | `release.yml:8-12` | 必填 string | 手动发布入口 |
| `inputs.version` | `release-pr.yml:6-11` | 可选 string | 留空自动升 patch |
| `strategy.fail-fast` | `release.yml:100` | `false` | 平台隔离 |
| `GITHUB_TOKEN` | `release-pr.yml:94`、`:155` | `{占位}` | Actions 内置令牌，禁止落日志 |
| `MY_OPENWAF_TEST_MYSQL_DSN` | `ci.yml:133` | `root:{占位}@tcp(127.0.0.1:3306)/waf?...` | 仅测试作业可见 |
| `MY_OPENWAF_TEST_POSTGRES_DSN` | `ci.yml:134` | `postgres://postgres:{占位}@127.0.0.1:5432/waf?sslmode=disable` | 同上 |
| `timeout-minutes` | 三个文件 | 未设置 | 全部走 Runner 默认值 |

最后一行是实测缺口：**10 个作业都没有 `timeout-minutes`**，30 分钟的测试作业若挂起会一直占用额度直到平台默认上限。

**章节来源**
- [.github/workflows/ci.yml:10-15](file://.github/workflows/ci.yml#L10-L15)
- [.github/workflows/ci.yml:131-134](file://.github/workflows/ci.yml#L131-L134)
- [.github/workflows/release-pr.yml:6-19](file://.github/workflows/release-pr.yml#L6-L19)
- [.github/workflows/release-pr.yml:94](file://.github/workflows/release-pr.yml#L94)
- [.github/workflows/release.yml:8-15](file://.github/workflows/release.yml#L8-L15)
- [.github/workflows/release.yml:100](file://.github/workflows/release.yml#L100)

## 依赖关系分析

### 内部依赖

```mermaid
graph LR
  A["actions/checkout@v4"] --> B["actions/setup-go@v5<br/>go-version-file: go.mod"]
  A --> C["oven-sh/setup-bun@v2<br/>bun-version 1.3.14"]
  C --> D["frontend-test / frontend job"]
  D --> E["upload-artifact<br/>frontend-out"]
  E --> F["download-artifact<br/>→ adminweb/dist"]
  B --> F
  F --> G["go vet / go test / go build"]
  G --> H["Verify native QuickJS backend"]
  H --> I["build matrix ×6"]
  I --> J["softprops/action-gh-release@v2"]
```

**图表来源**
- [.github/workflows/ci.yml:23-30](file://.github/workflows/ci.yml#L23-L30)
- [.github/workflows/ci.yml:147-150](file://.github/workflows/ci.yml#L147-L150)
- [.github/workflows/ci.yml:164-169](file://.github/workflows/ci.yml#L164-L169)
- [.github/workflows/ci.yml:185-189](file://.github/workflows/ci.yml#L185-L189)
- [.github/workflows/release.yml:139-143](file://.github/workflows/release.yml#L139-L143)
- [.github/workflows/release.yml:148-163](file://.github/workflows/release.yml#L148-L163)
- [.github/workflows/release.yml:231-232](file://.github/workflows/release.yml#L231-L232)
- [internal/core/adminweb/embed.go:12-13](file://internal/core/adminweb/embed.go#L12-L13)
- [go.mod:3](file://go.mod#L3)

`download-artifact` 落到的 `internal/core/adminweb/dist` 正是 `//go:embed all:dist`（`embed.go:12-13`）的目标目录，这是「后端作业必须等前端产物」的唯一技术原因，与本地必须跑 `scripts/build.sh:6-8` 同源。`setup-go` 用 `go-version-file: go.mod`（`ci.yml:29`、`release.yml:136`、`release-pr.yml:34`）取版本，实际解析为 `go.mod:3` 的 `1.27.2`。

**章节来源**
- [internal/core/adminweb/embed.go:12-13](file://internal/core/adminweb/embed.go#L12-L13)
- [go.mod:3](file://go.mod#L3)
- [scripts/build.sh:6-8](file://scripts/build.sh#L6-L8)
- [.github/workflows/ci.yml:26-30](file://.github/workflows/ci.yml#L26-L30)
- [.github/workflows/release.yml:133-137](file://.github/workflows/release.yml#L133-L137)

### 外部服务依赖

| 依赖 | 位置:行 | 用途 | 失败表现 |
|---|---|---|---|
| GitHub Runner：`ubuntu-latest` | `ci.yml:20`、`:88`、`:139`、`:173`；`release-pr.yml:24`、`:85`；`release.yml:23`、`:222` | 门禁与发布元数据 | 排队超时，作业不启动 |
| `ubuntu-24.04` / `ubuntu-24.04-arm` | `release.yml:67`、`:106`、`:110` | Linux 双架构产物 | 该两平台缺件 |
| `macos-15-intel` / `macos-14` | `release.yml:114`、`:118` | darwin 双架构 | 该两平台缺件 |
| `windows-2022` / `windows-11-arm` | `release.yml:122`、`:126` | 带 `.exe` 的 zip 包 | 该两平台缺件 |
| Runner 预装 `ruby` | `ci.yml:43`、`:46` | 解析并断言 release.yml | 契约步骤直接失败 |
| Runner 预装 GNU `grep`/`sha256sum`/`tar`/`shasum` | `ci.yml:44-67`、`release.yml:183`、`:199-201` | 断言与打包校验 | 平台缺工具即报错 |
| `actions/checkout@v4` | 全部作业首个步骤 | 取码（发布链需 `fetch-depth: 0`） | 取不到 tag 列表则版本解析退化 |
| `actions/setup-go@v5` | `ci.yml:27` 等 4 处 | Go 工具链与缓存 | 无法编译 |
| `oven-sh/setup-bun@v2` | `ci.yml:148`、`release.yml:76`、`release-pr.yml:38` | 固定 Bun `1.3.14` | 前端无法构建 |
| `actions/upload-artifact@v4` / `download-artifact@v4` | `ci.yml:164`、`:69`、`release.yml:88`、`:139`、`:213`、`:225` | 跨作业传前端树 | 后端 `//go:embed` 编译失败 |
| `mysql:8.0` / `postgres:16-alpine` 服务容器 | `ci.yml:92`、`:104` | 方言迁移 | 仅旁路作业失败 |
| `softprops/action-gh-release@v2` | `release.yml:232` | 创建 Release | 发布不出资产 |
| GitHub REST（`gh` CLI） | `release-pr.yml:161-171` | 查/改/建 PR | 发布 PR 开不出 |
| Docker Hub（镜像基础层） | `Dockerfile:2`、`:9`、`:17` | 镜像构建 | **CI 不触发**，仅人工构建时涉及 |

**章节来源**
- [.github/workflows/ci.yml:20-27](file://.github/workflows/ci.yml#L20-L27)
- [.github/workflows/ci.yml:69-72](file://.github/workflows/ci.yml#L69-L72)
- [.github/workflows/ci.yml:92-104](file://.github/workflows/ci.yml#L92-L104)
- [.github/workflows/ci.yml:148](file://.github/workflows/ci.yml#L148)
- [.github/workflows/ci.yml:164](file://.github/workflows/ci.yml#L164)
- [.github/workflows/release.yml:67-76](file://.github/workflows/release.yml#L67-L76)
- [.github/workflows/release.yml:102-126](file://.github/workflows/release.yml#L102-L126)
- [.github/workflows/release.yml:213-232](file://.github/workflows/release.yml#L213-L232)
- [.github/workflows/release-pr.yml:31-40](file://.github/workflows/release-pr.yml#L31-L40)
- [.github/workflows/release-pr.yml:161-171](file://.github/workflows/release-pr.yml#L161-L171)
- [Dockerfile:2-17](file://Dockerfile#L2-L17)

## 性能考虑

- **重复计算**：`ci.yml` 的 `backend-test`（`:79`）与 `release-pr.yml` 的 `verify`（`:68`）都是 `go test -tags=quickjs -v -timeout=30m ./...` 全量；两者都监听 `push: main`，一次合并要跑两遍 30 分钟全量。若要收敛，最小改动是让 `verify` 复用 `ci.yml` 已绿的运行结论，而不是新增缓存层。
- **产物传递代替重编**：前端只在根作业构建一次（`ci.yml:162`），其余 3 个后端作业靠 `download-artifact` 取 `frontend-out`（`:69-73`、`:125-129`、`:185-189`）。这是必要设计而非优化点——`//go:embed all:dist` 决定没有该目录就无法编译。
- **矩阵成本**：`release.yml` 的 6 平台各跑一次 `go build` + 一次 `go test ./internal/waf/jsplugin`（`:163`），且 macOS/Windows  runner 计费系数高于 Linux；`fail-fast: false`（`:100`）意味着最慢平台决定整体时长。
- **无 job 级超时**：三个文件都没有 `timeout-minutes`，挂起的测试只能依赖平台默认上限。加一个显式上限（如 35m，略高于 `-timeout=30m`）是最廉价的止损。
- **`-v` 全量输出**：`ci.yml:79` 与 `release-pr.yml:68` 都带 `-v`，532 个 `_test.go` 的日志会显著拖慢并增加日志体积，但这是当前唯一可回溯的失败定位手段，删除属高风险优化。
- **并发取消的双刃**：`ci.yml` 的 `cancel-in-progress: true`（`:15`）在 PR 高频推送时省额度；对 `push: main` 却可能取消掉一次即将完成的全量测试。

**章节来源**
- [.github/workflows/ci.yml:15](file://.github/workflows/ci.yml#L15)
- [.github/workflows/ci.yml:69-79](file://.github/workflows/ci.yml#L69-L79)
- [.github/workflows/ci.yml:125-129](file://.github/workflows/ci.yml#L125-L129)
- [.github/workflows/ci.yml:185-189](file://.github/workflows/ci.yml#L185-L189)
- [.github/workflows/release.yml:99-126](file://.github/workflows/release.yml#L99-L126)
- [.github/workflows/release.yml:163](file://.github/workflows/release.yml#L163)
- [.github/workflows/release-pr.yml:68](file://.github/workflows/release-pr.yml#L68)
- [internal/core/adminweb/embed.go:12-13](file://internal/core/adminweb/embed.go#L12-L13)

## 故障排查指南

```mermaid
flowchart TB
  S1{"backend-test 里<br/>release 契约步骤失败"} -->|YAML 解析错| R1["release.yml 缩进或键写坏<br/>对应 ci.yml:43"]:::r
  S1 -->|runner 计数≠6| R2["增删矩阵条目未同步断言<br/>ci.yml:45 要求恰为 6"]:::r
  S1 -->|QuickJS 断言 abort| R3["步骤名/CGO/tag 被改<br/>ci.yml:49-54"]:::r
  S1 -->|grep 无匹配| R4["源文件构建约束行被改<br/>ci.yml:64-65"]:::r
  S1 -->|否| S2{"dialect-migration 失败<br/>但主链绿"} -->|是| R5["MySQL 1101/1071 类方言问题<br/>ci.yml:82-86 注释列明"]:::w
  S2 -->|否| S3{"release 链没被触发"} -->|无 tag 作业| R6["PR head ref 未以 release/v 开头<br/>或 merged 为假，release.yml:20-22"]:::w
  S3 -->|tag 推送失败| R7["同名 tag 已存在，refspec 不覆盖<br/>release.yml:60-63"]:::e
  S3 -->|产物缺平台| R8["该平台作业失败，fail-fast=false 不牵连<br/>release.yml:100"]:::w
  classDef r fill:#fff4e6,stroke:#e8590c,color:#7a3400
  classDef w fill:#fff9db,stroke:#f59f00,color:#7a5b00
  classDef e fill:#ffe3e3,stroke:#e03131,color:#7d1a1a
```

**图表来源**
- [.github/workflows/ci.yml:43-65](file://.github/workflows/ci.yml#L43-L65)
- [.github/workflows/ci.yml:82-86](file://.github/workflows/ci.yml#L82-L86)
- [.github/workflows/release.yml:20-22](file://.github/workflows/release.yml#L20-L22)
- [.github/workflows/release.yml:60-63](file://.github/workflows/release.yml#L60-L63)
- [.github/workflows/release.yml:100](file://.github/workflows/release.yml#L100)

### 症状与处置

| 症状 | 根因 | 定位 | 处置 |
|---|---|---|---|
| 后端作业编译即失败 | 前端产物没取到，`//go:embed all:dist` 无目录 | `ci.yml:69-73` 是否成功；`frontend-test` 是否红 | 先修前端；`if-no-files-found: error`（`:169`）保证空产物早失败 |
| 契约步骤报 `missing native QuickJS verification step` | `release.yml` 步骤名被改动 | `ci.yml:49` | 恢复步骤名 `Verify native QuickJS backend`（`release.yml:148`） |
| 契约步骤报 `must enable cgo` | 有人把 env 改成 `CGO_ENABLED: '0'` | `ci.yml:51`、`:53`、`:56-59` | 恢复为 `'1'`；否则发布产物会静默用 stub |
| JS 插件在线上失效但 CI 绿 | 该二进制未带 `-tags=quickjs` 编译 | `quickjs_stub.go:1` 被选中 | 用 `release.yml:155-162` 同款 `go list` 自检 |
| 方言作业红、主作业绿 | 仅在 MySQL/PG 暴露的 schema 问题 | `ci.yml:131-135` | 按 `TEXT DEFAULT`、索引键长两类修迁移；主链不会因此停摆 |
| 合并 PR 后没开发布 PR | `verify` 失败 | `release-pr.yml:22-81` | 修测试；`release-pr` 有 `needs: [verify]`（`:86`） |
| 发布 PR 标题与提交不符 | `gh pr edit` 走了更新分支 | `release-pr.yml:167-170` | 同 tag 的开放 PR 会被原地改写，非重复创建 |
| tag 已存在但 Release 无资产 | `publish` 未跑或产物未上传 | `release.yml:213-218`、`:225-229` | tag 与发布解耦，需手动 `workflow_dispatch` 传 `tag` 重放 |
| Release PR 分支被覆盖 | 并发触发同一版本 | `release-pr.yml:17-19`、`:149-151` | `force-with-lease` + 不取消并发已兜住，检查远端预期 SHA 取回是否失败 |
| CI 全绿但镜像有问题 | 没有任何 workflow 构建镜像 | 三个文件无 docker 步骤 | 镜像需人工 `docker build`，口径见 `Dockerfile` |

**章节来源**
- [.github/workflows/ci.yml:49-73](file://.github/workflows/ci.yml#L49-L73)
- [.github/workflows/ci.yml:131-135](file://.github/workflows/ci.yml#L131-L135)
- [.github/workflows/ci.yml:164-169](file://.github/workflows/ci.yml#L164-L169)
- [.github/workflows/release.yml:148-162](file://.github/workflows/release.yml#L148-L162)
- [.github/workflows/release.yml:213-229](file://.github/workflows/release.yml#L213-L229)
- [.github/workflows/release-pr.yml:17-19](file://.github/workflows/release-pr.yml#L17-L19)
- [.github/workflows/release-pr.yml:86](file://.github/workflows/release-pr.yml#L86)
- [.github/workflows/release-pr.yml:149-170](file://.github/workflows/release-pr.yml#L149-L170)
- [internal/waf/jsplugin/quickjs_stub.go:1](file://internal/waf/jsplugin/quickjs_stub.go#L1)
- [Dockerfile:1-28](file://Dockerfile#L1-L28)

### 流水线覆盖缺口登记

| 缺口 | 证据 | 影响 |
|---|---|---|
| 10 个 `check:*` 前端契约脚本不进 CI | `frontend/package.json:13-22` 与三份 workflow 全文无 `check:` | 契约回归依赖人工执行 |
| 无镜像构建/推送作业 | 三份 workflow 无 `docker` 相关步骤 | `Dockerfile` 变更不受 CI 保护 |
| 无 WASM 重建作业 | 无 `make optimize`；`Makefile:20` 仅本地 | Rust 侧改坏要到人工重建才暴露 |
| 无 `timeout-minutes` | 三份 workflow 全文无该键 | 挂起作业占满默认时长 |
| 无独立 `e2e` 阶段 | 端到端用例仅 2 个，与单元同包（`*_e2e_test.go`） | 无专门发布前端到端验证 |
| `push: main` 双跑全量测试 | `ci.yml:4-5` 与 `release-pr.yml:4-5` | 成本翻倍，结论可能不一致 |

**章节来源**
- [frontend/package.json:13-22](file://frontend/package.json#L13-L22)
- [wasm-pow-solver/Makefile:20](file://wasm-pow-solver/Makefile#L20)
- [.github/workflows/ci.yml:4-5](file://.github/workflows/ci.yml#L4-L5)
- [.github/workflows/release-pr.yml:4-5](file://.github/workflows/release-pr.yml#L4-L5)
- [README.md:443-451](file://README.md#L443-L451)

## 结论

三条链分工清晰：`ci.yml` 是只读门禁（`permissions: contents: read`），`release-pr.yml` 写分支与 PR，`release.yml` 写 tag 与 Release。权限按最小化拆开，且用「`ci.yml` 校验 `release.yml`」的反向契约把最危险的 CGO/tag 退化堵在合并前——这是本流水线最值得保留的设计。

成果归纳：

- 10 个 job、14 条契约断言、6 平台矩阵、2 个服务容器，全部可由三份文件逐行复核。
- 门禁传递路径明确：`frontend-test` 是根，`release-meta` 是发布唯一闸门，`publish` 是唯一出口。
- 旁路属性同样明确：`dialect-migration` 与 `full-build` 无人依赖，失败不会阻断发布，需人工盯。
- 遵循 KISS：没有 reusable workflow、没有 matrix 之外的条件复用、没有第三方版本管理动作，版本递增用 12 行 shell 表达（`release-pr.yml:107-120`），符合 YAGNI。

遇到的问题与处置：本篇所有行号与断言均来自三份 workflow 原文逐行核对，`ci.yml:44` 的引号拼接与 `release.yml` 步骤名字符串匹配两处易误读，已在正文单独标注其失效方式。

下一步建议：为三个作业补 `timeout-minutes`；把 `check:*` 家族接入 `frontend-test`；若需要镜像交付，则新增独立作业而不是把 `docker build` 塞进 `build` 矩阵（矩阵里 6 平台各建一次镜像无意义）。

**章节来源**
- [docs/部署运维/构建脚本与工具链.md](file://docs/部署运维/构建脚本与工具链.md)
- [.github/workflows/ci.yml:10-15](file://.github/workflows/ci.yml#L10-L15)
- [.github/workflows/release-pr.yml:107-120](file://.github/workflows/release-pr.yml#L107-L120)

## 附录

### 命令口径速查（全部取自 workflow 原文）

```bash
# gofmt 硬门禁（ci.yml:34-38；release-pr.yml:44-48 同体）
files="$(gofmt -l .)"
if [ -n "$files" ]; then
  echo "::error::Go files are not formatted"
  echo "$files"
  exit 1
fi

# 后端静态检查与全量测试（ci.yml:76 / ci.yml:79）
CGO_ENABLED=1 go vet -tags=quickjs ./...
CGO_ENABLED=1 go test -tags=quickjs -v -timeout=30m ./...

# 方言迁移（ci.yml:135）
go test -v -timeout=10m -run TestAutoMigrateOnExternalDialect ./internal/store/

# QuickJS 后端选择自检（release.yml:155-163，逐字）
go_files="$(go list -tags=quickjs -f '{{join .GoFiles " "}}' ./internal/waf/jsplugin)"
case " $go_files " in
  *" quickjs_cgo.go "*) ;;
  *)
    echo "::error::QuickJS native backend was not selected: $go_files"
    exit 1
    ;;
esac
go test -tags=quickjs -count=1 ./internal/waf/jsplugin

# 发布构建与打包（release.yml:172-183，逐字；${{ }} 为 Actions 矩阵表达式）
mkdir -p dist/package
output="my-openwaf-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
go build -tags=quickjs -trimpath -ldflags="-s -w" -o "dist/package/$output" ./cmd
cp README.md LICENSE dist/package/
name="my-openwaf-${{ needs.release-meta.outputs.version }}-${{ matrix.goos }}-${{ matrix.goarch }}"
mkdir -p dist/artifacts
tar -C dist/package -czf "dist/artifacts/${name}.tar.gz" .

# 前端链与产物落位（ci.yml:153-162；release-pr.yml:60-62）
bun install --frozen-lockfile
bun run typecheck
bun run lint
bun run build
rm -rf internal/core/adminweb/dist
cp -r frontend/out internal/core/adminweb/dist
```

**章节来源**
- [.github/workflows/ci.yml:32-39](file://.github/workflows/ci.yml#L32-L39)
- [.github/workflows/ci.yml:75-79](file://.github/workflows/ci.yml#L75-L79)
- [.github/workflows/ci.yml:131-135](file://.github/workflows/ci.yml#L131-L135)
- [.github/workflows/ci.yml:152-162](file://.github/workflows/ci.yml#L152-L162)
- [.github/workflows/release.yml:154-183](file://.github/workflows/release.yml#L154-L183)
- [.github/workflows/release-pr.yml:59-62](file://.github/workflows/release-pr.yml#L59-L62)

### 事件与作业响应矩阵

| Git 事件 | `ci.yml` | `release-pr.yml` | `release.yml` | 净效果 |
|---|:--:|:--:|:--:|---|
| 向 main 提 PR | 全跑 | 不跑 | 不跑 | 门禁结论产生 |
| PR 合并（非 `release/v*`） | 全跑 | 全跑 | `release-meta` 跳过 | 只出测试结论，不出发布 |
| `release/v*` PR 合并 | 全跑 | 全跑 | 打 tag → 6 平台 → 发布 | 唯一完整交付路径 |
| `workflow_dispatch` 于 `release-pr.yml` | 不跑 | 两作业跑 | 不跑 | 可指定 `version` 造发布 PR |
| `workflow_dispatch` 于 `release.yml` | 不跑 | 不跑 | 四作业跑 | 指定 `tag` 重放发布 |
| 手动触发 `ci.yml` | 全跑 | 不跑 | 不跑 | 仅门禁复检 |

**章节来源**
- [.github/workflows/ci.yml:3-8](file://.github/workflows/ci.yml#L3-L8)
- [.github/workflows/release.yml:3-12](file://.github/workflows/release.yml#L3-L12)
- [.github/workflows/release.yml:20-22](file://.github/workflows/release.yml#L20-L22)
- [.github/workflows/release-pr.yml:3-11](file://.github/workflows/release-pr.yml#L3-L11)

### 与相邻文档的分工

| 主题 | 归属 |
|---|---|
| 本地三条构建链、WASM 工具链、诊断脚本 | [构建脚本与工具链](构建脚本与工具链.md) |
| 镜像运行、端口与卷编排 | [部署运维](部署运维.md) |
| 环境变量全集与校验语义 | [README 配置说明](../../README.md) |
| 开发流程与代码规范 | [开发者指南](../项目概述/开发者指南.md) |
| 测试资产规模与口径 | [构建脚本与工具链](构建脚本与工具链.md) 附录 |

**章节来源**
- [README.md:311-347](file://README.md#L311-L347)
- [docs/部署运维/构建脚本与工具链.md](file://docs/部署运维/构建脚本与工具链.md)
