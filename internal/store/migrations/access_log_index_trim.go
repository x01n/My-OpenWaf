package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

var v14AccessLogTrimmedIndexes = []string{
	"idx_al_host",
	"idx_al_visitor_fusion_window",
	"idx_al_site_created",
}

/**
 * V14MigrateAccessLogIndexTrim 删除访问日志上无消费点的历史索引。
 *
 * GORM 的 AutoMigrate 只建索引、不删索引：模型标签里移除索引声明后，
 * 既有部署的库仍会保留旧索引，因此必须显式 DROP 才能让老库拿到同样的
 * 写入收益。DROP INDEX 只改元数据页并释放对应 B-tree，在 GB 级日志库上
 * 也是毫秒级操作，可留在启动关键路径。
 *
 * 从空库启动时这些索引从未存在，IF EXISTS 保证迁移幂等。
 *
 * @param db 日志库句柄。
 * @return 删除索引过程中的错误。
 */
func V14MigrateAccessLogIndexTrim(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("access_logs") {
		return nil
	}
	for _, index := range v14AccessLogTrimmedIndexes {
		if err := db.Exec("DROP INDEX IF EXISTS `" + index + "`").Error; err != nil {
			return fmt.Errorf("failed to drop access_logs index %s: %w", index, err)
		}
	}
	return nil
}
