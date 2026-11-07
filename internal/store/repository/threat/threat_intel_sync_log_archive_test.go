package threat

import (
	"testing"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store/threatintel"
)

// TestThreatIntelSyncLogDeleteOlderThanDeletesInBatches 守护归档路径的分批删除。
//
// 同仓另外三个归档路径（security_event / access_log / drop_event）都是 5000 行一批、
// 批间 sleep 50ms，目的是避免单条超大 DELETE 在 SQLite 上长时间持有写锁，把数据面的
// 写入一起拖住。本仓库原先缺了这个骨架。
//
// 只断言「超期全删、未过期一条不删、计数正确」无法区分两种实现——单条 DELETE 与分批
// DELETE 删除的行集完全相同。所以这里额外统计 DELETE 语句条数：单条实现只发出 1 条，
// 分批实现在 12000 条过期记录上至少发出 3 条。
func TestThreatIntelSyncLogDeleteOlderThanDeletesInBatches(t *testing.T) {
	repo := newTISyncLogRepoForTest(t)
	now := time.Now()

	// 12000 条过期记录超过单批 5000 的两倍，确保循环至少走三轮。
	const expiredRows = 12000
	const keptRows = 7

	expiredAt := now.Add(-30 * 24 * time.Hour)
	rows := make([]threatintel.ThreatIntelSyncLog, 0, expiredRows+keptRows)
	for i := 0; i < expiredRows; i++ {
		rows = append(rows, threatintel.ThreatIntelSyncLog{
			FeedID: 1, FeedName: "expired", CreatedAt: expiredAt, StartedAt: expiredAt,
			Success: true, Trigger: "auto",
		})
	}
	for i := 0; i < keptRows; i++ {
		rows = append(rows, threatintel.ThreatIntelSyncLog{
			FeedID: 1, FeedName: "kept", CreatedAt: now, StartedAt: now,
			Success: true, Trigger: "auto",
		})
	}
	if err := repo.db.CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatalf("seed sync logs: %v", err)
	}

	// 显式写入的 CreatedAt 必须原样保留，否则保留策略本身无从验证。
	cutoff := now.Add(-7 * 24 * time.Hour)
	var seeded, seededExpired int64
	if err := repo.db.Model(&threatintel.ThreatIntelSyncLog{}).Count(&seeded).Error; err != nil {
		t.Fatalf("count seeded: %v", err)
	}
	if err := repo.db.Model(&threatintel.ThreatIntelSyncLog{}).Where("created_at < ?", cutoff).Count(&seededExpired).Error; err != nil {
		t.Fatalf("count seeded expired: %v", err)
	}
	if seeded != expiredRows+keptRows || seededExpired != expiredRows {
		t.Fatalf("seeded=%d/%d, want %d/%d; CreatedAt 未按预期落库",
			seeded, seededExpired, expiredRows+keptRows, expiredRows)
	}

	// 统计 DELETE 语句条数：单条无分批的实现只会发出 1 条。
	var deleteStatements int
	repo.db.Callback().Delete().Before("gorm:delete").Register(
		"test:count_threat_intel_sync_log_deletes", func(*gorm.DB) {
			deleteStatements++
		})

	deleted, err := repo.DeleteOlderThan(cutoff)
	if err != nil {
		t.Fatalf("delete older than: %v", err)
	}
	if deleted != expiredRows {
		t.Errorf("deleted = %d, want %d", deleted, expiredRows)
	}
	if deleteStatements < 3 {
		t.Errorf("DELETE statements = %d, want >= 3; 单条 DELETE 会在 SQLite 上长时间持写锁，归档必须分批",
			deleteStatements)
	}

	var remaining, remainingExpired int64
	if err := repo.db.Model(&threatintel.ThreatIntelSyncLog{}).Count(&remaining).Error; err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != keptRows {
		t.Errorf("remaining = %d, want %d; 未过期记录被误删", remaining, keptRows)
	}
	if err := repo.db.Model(&threatintel.ThreatIntelSyncLog{}).Where("created_at < ?", cutoff).Count(&remainingExpired).Error; err != nil {
		t.Fatalf("count remaining expired: %v", err)
	}
	if remainingExpired != 0 {
		t.Errorf("remaining expired = %d, want 0; 超期记录未删净", remainingExpired)
	}
}
