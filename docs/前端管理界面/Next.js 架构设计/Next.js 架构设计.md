# Next.js 架构设计

<cite>
**本文档引用的文件**
- [frontend/app/layout.tsx](file://frontend/app/layout.tsx)
- [frontend/app/(dashboard)/layout.tsx](file://frontend/app/(dashboard)/layout.tsx)
- [frontend/components/theme-provider.tsx](file://frontend/components/theme-provider.tsx)
- [frontend/components/auth-guard.tsx](file://frontend/components/auth-guard.tsx)
- [frontend/components/layout/sidebar.tsx](file://frontend/components/layout/sidebar.tsx)
- [frontend/components/layout/topbar.tsx](file://frontend/components/layout/topbar.tsx)
- [frontend/lib/api.ts](file://frontend/lib/api.ts)
- [frontend/lib/console.ts](file://frontend/lib/console.ts)
- [frontend/app/globals.css](file://frontend/app/globals.css)
- [frontend/next.config.mjs](file://frontend/next.config.mjs)
- [frontend/package.json](file://frontend/package.json)
- [docs/前端管理界面/Next.js 架构设计.md](file://docs/前端管理界面/Next.js 架构设计.md)
- [docs/前端管理界面/状态管理策略.md](file://docs/前端管理界面/状态管理策略.md)
</cite>

## 目录
1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构总览](#架构总览)
5. [详细组件分析](#详细组件分析)
6. [依赖关系分析](#依赖关系分析)
7. [性能考虑](#性能考虑)
8. [故障排除指南](#故障排除指南)
9. [结论](#结论)
10. [附录](#附录)

## 简介
本文件系统性梳理 My-OpenWaf 基于 Next.js 16 App Router 的前端架构设计，重点围绕根布局与仪表板布局的组织原则、主题提供器工作机制、路由守卫实现方式、全局状态管理策略，以及如何利用文件系统路由、动态路由与中间件功能。文档旨在帮助开发者快速理解并高效扩展前端控制台。

## 项目结构
前端采用 Next.js App Router 的目录约定，通过分组目录 `(dashboard)` 实现路由分层，配合共享的根布局与仪表板布局，形成清晰的层次化结构：
- 根布局：定义全局样式、字体变量、主题提供者与元数据
- 仪表板布局：封装侧边栏导航、顶部栏、权限守卫与通知组件
- 页面路由：以 `page.tsx` 作为入口，支持静态参数与动态参数
- 组件库：UI 组件、图表组件、工具函数与自定义 Hook

```mermaid
graph TB
subgraph "应用入口"
RootLayout["根布局<br/>frontend/app/layout.tsx"]
DashboardLayout["仪表板布局<br/>frontend/app/(dashboard)/layout.tsx"]
end
subgraph "页面路由"
HomePage["首页重定向<br/>frontend/app/page.tsx"]
DashboardPage["仪表板页面<br/>frontend/app/(dashboard)/dashboard/page.tsx"]
SitesPage["站点详情页<br/>frontend/app/(dashboard)/sites/[id]/page.tsx"]
LoginPage["登录页<br/>frontend/app/login/page.tsx"]
end
subgraph "共享组件"
AuthGuard["权限守卫<br/>frontend/components/auth-guard.tsx"]
Sidebar["侧边栏导航<br/>frontend/components/layout/sidebar.tsx"]
Topbar["顶部栏<br/>frontend/components/layout/topbar.tsx"]
ThemeProvider["主题提供者<br/>frontend/components/theme-provider.tsx"]
ApiLib["API 工具<br/>frontend/lib/api.ts"]
ConsoleNav["导航配置<br/>frontend/lib/console.ts"]
end
RootLayout --> DashboardLayout
DashboardLayout --> DashboardPage
DashboardLayout --> SitesPage
DashboardLayout --> LoginPage
DashboardLayout --> AuthGuard
DashboardLayout --> Sidebar
DashboardLayout --> Topbar
DashboardLayout --> ThemeProvider
DashboardPage --> ApiLib
SitesPage --> ApiLib
LoginPage --> ApiLib
DashboardPage --> ConsoleNav
SitesPage --> ConsoleNav
```

**图示来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/app/page.tsx:1-18](file://frontend/app/page.tsx#L1-L18)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)
- [frontend/app/login/page.tsx:1-76](file://frontend/app/login/page.tsx#L1-L76)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)
- [frontend/lib/console.ts:1-240](file://frontend/lib/console.ts#L1-L240)

**章节来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/app/page.tsx:1-18](file://frontend/app/page.tsx#L1-L18)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)
- [frontend/app/login/page.tsx:1-76](file://frontend/app/login/page.tsx#L1-L76)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)
- [frontend/lib/console.ts:1-240](file://frontend/lib/console.ts#L1-L240)

## 核心组件
- 根布局与主题系统
  - 根布局负责注入全局样式、字体变量与主题提供者，确保全站一致的主题体验与可访问性。
  - 主题提供者使用 next-themes，支持系统默认、明暗切换与热键快捷切换。
- 仪表板布局与导航
  - 仪表板布局整合侧边栏、顶部栏、权限守卫与通知组件，形成统一的控制台界面。
  - 侧边栏导航基于路径高亮与图标，支持折叠/展开与登出操作。
  - 顶部栏展示面包屑与用户下拉菜单，提供一致的操作入口。
- 权限与会话管理
  - 权限守卫在客户端检查访问令牌，未登录时重定向至登录页。
  - API 工具封装鉴权头、刷新令牌与错误处理，统一后端交互。
- 页面与数据渲染
  - 首页根据令牌存在与否重定向至仪表板或登录页。
  - 仪表板页面定时拉取数据并渲染图表，站点详情页支持动态路由参数。

**章节来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)
- [frontend/app/page.tsx:1-18](file://frontend/app/page.tsx#L1-L18)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)

## 架构总览
该应用采用"根布局 + 分组布局"的双层布局体系：
- 根布局负责全局样式与主题，为所有页面提供一致的外观与行为。
- 仪表板分组布局封装控制台专用 UI，包含权限校验与导航，子页面共享此上下文。
- 页面通过 `page.tsx` 作为入口，结合客户端与服务端能力实现不同渲染策略。

```mermaid
graph TB
Root["根布局<br/>app/layout.tsx"] --> HTML["HTML 根节点<br/>lang=zh-CN<br/>字体变量<br/>主题提供者"]
DashboardGroup["仪表板分组<br/>app/(dashboard)"] --> DashLayout["仪表板布局<br/>layout.tsx"]
DashLayout --> Auth["权限守卫<br/>AuthGuard"]
DashLayout --> Sidebar["侧边栏导航<br/>Sidebar"]
DashLayout --> Topbar["顶部栏<br/>Topbar"]
DashLayout --> Main["主内容区域<br/>children"]
Main --> Page["页面入口<br/>page.tsx"]
Page --> Data["数据获取与渲染<br/>Recharts 图表等"]
```

**图示来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)

## 详细组件分析

### 根布局与主题系统
- 字体加载：通过全局 CSS 注入无 FOUC 的字体变量，分别设置无衬线与等宽字体变量。
- 主题提供者：使用 next-themes 提供系统默认、明暗切换与热键切换（在非输入焦点时按 D 键切换）。
- 元数据：设置站点标题与描述，便于 SEO 与浏览器标签显示。
- 样式基线：全局 CSS 引入 Tailwind、动画与 shadcn 组件库样式，并定义深色/浅色主题变量。

```mermaid
classDiagram
class RootLayout {
+metadata
+fonts(Geist, Geist_Mono)
+ThemeProvider(children)
+html(lang, className)
}
class ThemeProvider {
+attribute="class"
+defaultTheme="system"
+enableSystem
+disableTransitionOnChange
+ThemeHotkey()
}
RootLayout --> ThemeProvider : "包裹"
```

**图示来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)

**章节来源**
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/app/globals.css:1-189](file://frontend/app/globals.css#L1-L189)

### 仪表板布局与导航
- 布局结构：左侧侧边栏 + 右侧主内容区，主内容区包含顶部栏与滚动内容区。
- 侧边栏导航：基于路由前缀高亮，支持折叠/展开与登出；图标与文案来自 Lucide。
- 顶部栏：展示当前页面的面包屑与用户下拉菜单，提供登出操作。
- 权限守卫：在进入仪表板布局前校验访问令牌，未登录则跳转登录页。

```mermaid
sequenceDiagram
participant U as "用户"
participant L as "仪表板布局"
participant G as "权限守卫"
participant S as "侧边栏导航"
participant T as "顶部栏"
U->>L : 访问仪表板路由
L->>G : 检查访问令牌
alt 未登录
G-->>U : 重定向到登录页
else 已登录
G-->>L : 渲染布局
L->>S : 渲染导航并高亮当前项
L->>T : 渲染顶部栏与面包屑
end
```

**图示来源**
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)

**章节来源**
- [frontend/app/(dashboard)/layout.tsx:1-52](file://frontend/app/(dashboard)/layout.tsx#L1-L52)
- [frontend/components/layout/sidebar.tsx:1-167](file://frontend/components/layout/sidebar.tsx#L1-L167)
- [frontend/components/layout/topbar.tsx:1-90](file://frontend/components/layout/topbar.tsx#L1-L90)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)

### 页面生命周期与渲染策略
- 首页重定向：根据是否存在访问令牌决定跳转至仪表板或登录页。
- 仪表板页面：使用客户端状态与定时器周期性拉取数据，渲染统计卡片与图表。
- 动态路由参数：站点详情页声明动态参数与静态参数生成，实际逻辑委托给客户端组件。

```mermaid
flowchart TD
Start(["进入页面"]) --> CheckToken["检查访问令牌"]
CheckToken --> |存在| RedirectDash["重定向到仪表板"]
CheckToken --> |不存在| RedirectLogin["重定向到登录页"]
RedirectDash --> RenderDash["渲染仪表板页面"]
RedirectLogin --> RenderLogin["渲染登录页"]
RenderDash --> Timer["定时器周期拉取数据"]
Timer --> UpdateUI["更新图表与统计"]
```

**图示来源**
- [frontend/app/page.tsx:1-18](file://frontend/app/page.tsx#L1-L18)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)

**章节来源**
- [frontend/app/page.tsx:1-18](file://frontend/app/page.tsx#L1-L18)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)

### 静态生成与动态路由
- 静态生成：站点详情页声明不生成任何静态参数，适合运行时动态构建。
- 动态路由参数：通过 `[id]` 定义动态段，支持运行时解析与客户端渲染。
- 路由配置：next.config.mjs 设置输出为静态导出、去除尾斜杠、禁用图片优化，适配本地部署与 CDN 场景。

```mermaid
flowchart LR
Route["路由匹配<br/>/sites/[id]"] --> Dynamic["动态参数解析<br/>[id]"]
Dynamic --> ClientComp["客户端组件渲染<br/>SiteDetailClient"]
StaticCfg["静态导出配置<br/>next.config.mjs"] --> Output["静态产物输出<br/>distDir/out"]
```

**图示来源**
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)
- [frontend/next.config.mjs:1-12](file://frontend/next.config.mjs#L1-L12)

**章节来源**
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)
- [frontend/next.config.mjs:1-12](file://frontend/next.config.mjs#L1-L12)

### 登录流程与鉴权
- 登录页：表单收集用户名与密码，调用登录接口并跳转仪表板。
- 鉴权流程：API 工具自动附加 Bearer 头，401 时尝试刷新令牌；仍失败则清除令牌并跳转登录。
- 会话存储：访问令牌持久化于模块闭包，避免刷新丢失。

```mermaid
sequenceDiagram
participant U as "用户"
participant LP as "登录页"
participant API as "API 工具"
participant BE as "后端"
participant LS as "浏览器存储"
U->>LP : 输入凭据并提交
LP->>API : 调用登录接口
API->>BE : POST /api/v1/auth/login
BE-->>API : 返回 access_token
API-->>LP : 写入 sessionStorage
LP-->>U : 跳转仪表板
Note over API,BE : 后续请求携带 Authorization 头
API->>BE : 请求受保护资源
alt 401 且有旧令牌
API->>BE : 刷新令牌
BE-->>API : 新 access_token
API->>LS : 更新存储
API->>BE : 重试原请求
else 401 且无旧令牌
API->>LS : 清除令牌
API-->>U : 跳转登录页
end
```

**图示来源**
- [frontend/app/login/page.tsx:1-76](file://frontend/app/login/page.tsx#L1-L76)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)

**章节来源**
- [frontend/app/login/page.tsx:1-76](file://frontend/app/login/page.tsx#L1-L76)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)

### 主题提供器工作机制
- 系统主题：使用 next-themes，默认"跟随系统"，禁用过渡动画以避免闪烁。
- 快捷键切换：提供键盘事件监听，仅在非编辑目标时生效，按 D 键切换深浅主题。
- 全局注入：在根布局中注入 Provider，确保全站生效。

```mermaid
flowchart TD
Start(["页面挂载"]) --> Listen["监听键盘事件"]
Listen --> CheckTarget{"是否处于输入目标？"}
CheckTarget --> |是| Ignore["忽略快捷键"]
CheckTarget --> |否| Toggle["切换主题"]
Toggle --> End(["完成"])
Ignore --> End
```

**图示来源**
- [frontend/components/theme-provider.tsx:37-69](file://frontend/components/theme-provider.tsx#L37-L69)

**章节来源**
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/app/layout.tsx:1-28](file://frontend/app/layout.tsx#L1-L28)

### 路由守卫实现方式
- 访问令牌检查：在客户端读取访问令牌，未登录时重定向至登录页。
- 会话过期处理：通过刷新令牌接口处理 401 情况，失败则清除令牌并跳转登录。
- 提示信息：根据 URL 参数 reason 展示相应的权限提示。

**章节来源**
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)

### 全局状态管理策略
- 主题状态：使用 next-themes 提供系统主题能力，默认"跟随系统"，禁用过渡动画以避免闪烁。
- 用户认证状态：访问令牌存储于模块闭包，避免 XSS 风险；刷新令牌使用 HttpOnly Cookie。
- 应用配置状态：从环境变量加载数据库驱动、DSN、数据目录、Redis、AdminBind、CVE/Bot/Drop 等参数。
- 本地状态：表单状态、对话框状态、组件内部状态通过 React 状态管理，避免不必要的重渲染。
- 数据缓存：响应缓存（内存分片 + LRU 风格淘汰，带 TTL 与后台清理）与快照缓存层（进程内 ristretto 缓存，用于不可变配置快照）。

**章节来源**
- [docs/前端管理界面/状态管理策略.md:1-427](file://docs/前端管理界面/状态管理策略.md#L1-L427)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/components/auth-guard.tsx:1-51](file://frontend/components/auth-guard.tsx#L1-L51)
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)

## 依赖关系分析
- 构建与运行时依赖：Next.js 16、React 19、Tailwind CSS 4、shadcn 组件库、Lucide 图标、Recharts 图表、next-themes 主题。
- 开发依赖：TypeScript、ESLint、Prettier、PostCSS、Tailwind 插件。
- 路径别名：通过 tsconfig.json 的 baseUrl 与 paths 将 `@/*` 映射到项目根目录，简化导入路径。

```mermaid
graph TB
Pkg["package.json 依赖"] --> Next["next@16"]
Pkg --> React["react@^19"]
Pkg --> Tailwind["tailwindcss@^4"]
Pkg --> Shadcn["shadcn"]
Pkg --> Icons["lucide-react"]
Pkg --> Charts["recharts"]
Pkg --> Themes["next-themes"]
Pkg --> DevDeps["开发依赖"]
TS["tsconfig.json 路径别名"] --> Alias["@/* -> ./*"]
```

**图示来源**
- [frontend/package.json:1-45](file://frontend/package.json#L1-L45)
- [frontend/tsconfig.json](file://frontend/tsconfig.json)

**章节来源**
- [frontend/package.json:1-45](file://frontend/package.json#L1-L45)
- [frontend/tsconfig.json](file://frontend/tsconfig.json)

## 性能考虑
- 字体与主题：根布局预加载字体变量，减少 FOUC；主题切换禁用过渡以避免闪烁。
- 图表渲染：仪表板页面使用响应式容器与轻量数据更新，避免不必要的重绘。
- 静态导出：next.config.mjs 配置静态导出，适合托管在 CDN 或静态服务器，降低运行时开销。
- 资源优化：禁用图片优化以简化构建流程，适用于内网或自托管场景。
- 前端状态：使用受控表单与最小化状态更新，避免不必要的重渲染；对高频交互使用防抖/节流。
- 后端缓存：响应缓存采用分片锁与后台清理，限制单条目大小，防止内存膨胀；快照缓存使用原子指针与 ristretto，按修订号隔离版本。

## 故障排除指南
- 登录后无法进入仪表板
  - 检查访问令牌是否写入 sessionStorage，确认登录接口返回值。
  - 排查权限守卫是否正确重定向至登录页。
- 401 未授权频繁出现
  - 确认刷新令牌接口可用，检查网络与跨域设置。
  - 避免在输入框中误触主题热键导致焦点被占用。
- 图表不显示或空白
  - 检查数据拉取接口与时间范围参数，确认定时器未被清理。
  - 确保 Recharts 依赖已安装且版本兼容。
- 主题切换无效
  - 检查键盘事件监听是否被输入框占用，确认快捷键触发条件。
  - 确认 next-themes 配置与全局 Provider 注入正常。

**章节来源**
- [frontend/lib/api.ts:1-150](file://frontend/lib/api.ts#L1-L150)
- [frontend/components/theme-provider.tsx:1-72](file://frontend/components/theme-provider.tsx#L1-L72)
- [frontend/app/(dashboard)/dashboard/page.tsx](file://frontend/app/(dashboard)/dashboard/page.tsx)

## 结论
该 Next.js 控制台通过清晰的 App Router 分层与共享组件，实现了统一的主题、导航与权限体系。根布局与仪表板布局分别承担全局样式与控制台上下文职责，页面路由结合静态导出与动态参数满足不同场景需求。配合完善的鉴权与错误处理机制，整体架构具备良好的可维护性与扩展性。

## 附录

### 路由配置示例与最佳实践
- 静态导出配置
  - 输出模式：静态导出
  - 构建目录：out
  - 图片优化：关闭
- 动态路由参数
  - 使用 `[param]` 定义动态段，页面声明动态参数与静态参数生成函数
- 最佳实践
  - 将通用 UI 组件置于共享目录，避免重复代码
  - 在仪表板布局中集中处理权限与导航，页面专注业务逻辑
  - 对高频数据使用定时器轮询，对一次性初始化使用 useEffect

**章节来源**
- [frontend/next.config.mjs:1-12](file://frontend/next.config.mjs#L1-L12)
- [frontend/app/(dashboard)/sites/[id]/page.tsx](file://frontend/app/(dashboard)/sites/[id]/page.tsx)