// Package sqlite 是 modernc.org/sqlite 的兼容适配层。
//
// github.com/glebarez/sqlite（GORM 方言）只依赖本模块的 Error 类型；
// 驱动实现改由 modernc.org/sqlite 提供。该版本会缓存编译后的 SQLite
// 语句句柄，避免 glebarez/go-sqlite v1.23.0 每次 Exec 都重新调用
// sqlite3_prepare_v2 的解析开销。
package sqlite

import modernc "modernc.org/sqlite"

// Error 是驱动错误的兼容别名：GORM sqlite 方言用 *Error 的类型断言
// 识别唯一键冲突（ErrDuplicatedKey）。
type Error = modernc.Error
