# x01n-My-OpenWaf 项目分析

> GitHub：https://github.com/x01n/My-OpenWaf  
> 分析日期：2026-07-04

## 页面索引

| 页面 | 说明 |
|------|------|
| [技术栈](技术栈.md) | 后端（Go）与前端（Next.js）完整技术栈及依赖版本 |
| [工作原理](工作原理.md) | 控制面+数据面架构、请求处理流程、规则流水线、策略动作体系 |

## 参考笔记

- `docs/项目概述/技术架构.md` — 项目原生技术架构文档（详细组件分析）
- `docs/数据平面处理/请求处理流程.md` — 原生请求处理流程文档
- `docs/安全防护功能/安全防护功能.md` — 原生安全防护功能文档
- `docs/管理 API 系统/管理 API 系统.md` — 原生管理 API 文档
- `docs/前端管理界面/Next.js 架构设计/` — 原生前端架构文档

## 状态

- 技术栈：已确认（基于 `go.mod` + `frontend/package.json`）
- 工作原理：已确认（基于 `cmd/main.go` + `internal/app/server.go` + `internal/dataplane/handler.go` + `internal/core/engine/`）
