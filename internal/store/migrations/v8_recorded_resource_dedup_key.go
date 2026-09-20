package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"gorm.io/gorm"
)

// v8DedupKeyBatchSize 是回填时每批读取的行数，避免大表一次性载入内存。
const v8DedupKeyBatchSize = 500

// recordedResourceDedupTable 描述加入 dedup_key 后的表结构。
//
// migrations 包不能 import store（store 反向依赖本包，会形成导入环），
// 故在此重复声明所需列。dedup_key 的类型与索引名必须与
// store.RecordedResource 保持一致。
type recordedResourceDedupTable struct {
	DedupKey string `gorm:"column:dedup_key;type:char(64);uniqueIndex:ux_recorded_res_dedup"`
}

func (recordedResourceDedupTable) TableName() string {
	return "recorded_resources"
}

/**
 * v8ComputeDedupKey 生成资源去重键。
 *
 * 必须与 store.ComputeDedupKey 的算法逐字节一致，否则迁移回填的值与运行时
 * 写入的值不匹配，会导致同一资源产生两行。分隔符用 \x00（URL 与 Host 中
 * 不会出现），避免相邻字段的边界歧义。
 */
func v8ComputeDedupKey(siteID uint, method, host, path, queryString string) string {
	h := sha256.New()
	var buf [20]byte
	h.Write(strconv.AppendUint(buf[:0], uint64(siteID), 10))
	for _, part := range []string{method, host, path, queryString} {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

/**
 * V8MigrateRecordedResourceDedupKey 把资源去重键从五列复合唯一索引改为定长摘要列。
 *
 * 动因：原索引建在 (site_id, method, host, path, query_string) 上，utf8mb4 下
 * path 与 query_string 各 2048 字符即 16384 字节，远超 MySQL 索引键 3072 字节
 * 上限（Error 1071），使 AutoMigrate 在 MySQL 上直接失败。数学上无法在不截断
 * 内容的前提下压进该上限，故改为对五列取 SHA-256 存入 char(64) 的 dedup_key。
 *
 * 步骤：加列 → 回填已有行 → 删旧索引。新唯一索引由随后的 AutoMigrate 创建，
 * 此时回填已完成、不会因重复值冲突。
 *
 * @param db GORM 句柄。
 * @return 迁移过程中的错误；表不存在时直接返回 nil。
 */
func V8MigrateRecordedResourceDedupKey(db *gorm.DB) error {
	if !db.Migrator().HasTable(&recordedResourceDedupTable{}) {
		return nil
	}

	if !db.Migrator().HasColumn(&recordedResourceDedupTable{}, "dedup_key") {
		if err := db.Migrator().AddColumn(&recordedResourceDedupTable{}, "DedupKey"); err != nil {
			return fmt.Errorf("failed to add recorded_resources.dedup_key: %w", err)
		}
	}

	if err := backfillDedupKeys(db); err != nil {
		return err
	}

	// 旧的五列复合索引不再需要，且在 MySQL 上本就无法建立。
	if db.Migrator().HasIndex(&recordedResourceTable{}, "ux_recorded_res_key") {
		if err := db.Migrator().DropIndex(&recordedResourceTable{}, "ux_recorded_res_key"); err != nil {
			return fmt.Errorf("failed to drop legacy recorded resource index: %w", err)
		}
	}

	return nil
}

/**
 * backfillDedupKeys 为尚无摘要的行计算并写入 dedup_key。
 *
 * 分批处理避免大表一次性载入内存。若历史数据中存在会映射到同一摘要的重复行
 * （旧索引缺失或被绕过时可能出现），保留 id 最小的一条并删除其余，否则
 * 后续创建唯一索引会失败。
 */
func backfillDedupKeys(db *gorm.DB) error {
	type row struct {
		ID          uint
		SiteID      uint
		Method      string
		Host        string
		Path        string
		QueryString string
	}

	seen := make(map[string]uint)
	for {
		var rows []row
		err := db.Table("recorded_resources").
			Select("id", "site_id", "method", "host", "path", "query_string").
			Where("dedup_key IS NULL OR dedup_key = ''").
			Order("id ASC").
			Limit(v8DedupKeyBatchSize).
			Scan(&rows).Error
		if err != nil {
			return fmt.Errorf("failed to scan recorded_resources for dedup backfill: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}

		for _, r := range rows {
			key := v8ComputeDedupKey(r.SiteID, r.Method, r.Host, r.Path, r.QueryString)
			if keeper, dup := seen[key]; dup {
				// 同一摘要已有保留行，删除当前重复行以免唯一索引创建失败。
				if err := db.Table("recorded_resources").Where("id = ?", r.ID).Delete(nil).Error; err != nil {
					return fmt.Errorf("failed to remove duplicate recorded_resource %d (kept %d): %w", r.ID, keeper, err)
				}
				continue
			}
			if err := db.Table("recorded_resources").
				Where("id = ?", r.ID).
				Update("dedup_key", key).Error; err != nil {
				return fmt.Errorf("failed to backfill dedup_key for recorded_resource %d: %w", r.ID, err)
			}
			seen[key] = r.ID
		}

		if len(rows) < v8DedupKeyBatchSize {
			return nil
		}
	}
}
