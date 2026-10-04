// Package core 承载进程级基础设施与 WAF 引擎：
//
//   - [My-OpenWaf/internal/core/action]:    WAF 动作类型（allow/block/log_only/challenge）
//   - [My-OpenWaf/internal/core/adminweb]:  内嵌的 Next.js 静态导出产物
//   - [My-OpenWaf/internal/core/database]:  打开 GORM 句柄（sqlite / mysql / postgres）
//   - [My-OpenWaf/internal/core/engine]:    顶层 WAF 处理引擎
//   - [My-OpenWaf/internal/core/health]:    存活 / 就绪 / 状态探针
//   - [My-OpenWaf/internal/core/lifecycle]: 多服务器启动 + 优雅关闭
//   - [My-OpenWaf/internal/core/pipeline]:  有序的请求处理阶段
//   - [My-OpenWaf/internal/core/redis]:     可选的 rueidis 客户端
//   - [My-OpenWaf/internal/core/rules]:     规则编译器、匹配器与阶段实现
//   - [My-OpenWaf/internal/core/sites]:     基于快照的虚拟主机解析器
//
// 引导配置与运行时装配位于 config.go / runtime.go。
// 领域持久化模型位于 [My-OpenWaf/internal/store]。
package core
