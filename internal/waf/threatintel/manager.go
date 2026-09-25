package threatintel

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const (
	// httpTimeout 单次拉取订阅源的整体超时。
	httpTimeout = 30 * time.Second
	// maxBodyBytes 限制单个订阅源响应体大小，防止 DoS（10 MiB）。
	maxBodyBytes = 10 * 1024 * 1024
	// loopInterval loop 检查各订阅源是否到期的轮询周期。
	loopInterval = time.Minute
)

/**
 * Manager 负责后台定时从各威胁情报订阅源拉取 IP/CIDR 列表，
 * 解析后全量替换对应 feed 在 IPListEntry 中的条目，并触发 snapshot 重建。
 *
 * 并发模型参考 cve.CVEFeedManager：以 mu 保护 syncing 集合，避免同一 feed 重复同步。
 */
type Manager struct {
	repo    *repository.ThreatIntelRepo
	logRepo *repository.ThreatIntelSyncLogRepo
	db      *gorm.DB
	log     *slog.Logger
	reload  func() error
	client  *http.Client

	stopCh   chan struct{}
	stopOnce sync.Once

	mu      sync.Mutex
	syncing map[uint]bool // 正在同步的 feedID 集合
}

// NewManager 构造威胁情报订阅管理器。reload 用于同步落库后触发 snapshot 重建。
func NewManager(db *gorm.DB, log *slog.Logger, reload func() error) *Manager {
	if log == nil {
		log = slog.Default()
	}
	if reload == nil {
		reload = func() error { return nil }
	}
	return &Manager{
		repo:    repository.NewThreatIntelRepo(db),
		logRepo: repository.NewThreatIntelSyncLogRepo(db),
		db:      db,
		log:     log,
		reload:  reload,
		client:  &http.Client{Timeout: httpTimeout},
		stopCh:  make(chan struct{}),
		syncing: make(map[uint]bool),
	}
}

// Start 完成建表并启动后台轮询循环。非阻塞。
func (m *Manager) Start() {
	if err := m.db.AutoMigrate(&store.ThreatIntelFeed{}); err != nil {
		m.log.Error("threatintel: 迁移 threat_intel_feeds 表失败", slog.String("error", err.Error()))
		return
	}
	go m.loop()
	m.log.Info("threatintel: 已启动", slog.Duration("check_interval", loopInterval))
}

// Stop 通知后台循环退出。
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		if m.stopCh != nil {
			close(m.stopCh)
		}
	})
}

// loop 每分钟检查一次，触发所有到达同步时间的启用订阅源。
func (m *Manager) loop() {
	ticker := time.NewTicker(loopInterval)
	defer ticker.Stop()
	// 启动时先跑一轮，尽快拉取一次到期的订阅源。
	m.syncDueFeeds()
	for {
		select {
		case <-ticker.C:
			m.syncDueFeeds()
		case <-m.stopCh:
			return
		}
	}
}

// syncDueFeeds 遍历启用的订阅源，对到期者触发同步。
func (m *Manager) syncDueFeeds() {
	feeds, err := m.repo.ListEnabled()
	if err != nil {
		m.log.Error("threatintel: 加载启用订阅源失败", slog.String("error", err.Error()))
		return
	}
	now := time.Now()
	for i := range feeds {
		f := feeds[i]
		if !m.isDue(f, now) {
			continue
		}
		if err := m.SyncFeed(f.ID); err != nil {
			m.log.Warn("threatintel: 订阅源同步失败",
				slog.Uint64("feed_id", uint64(f.ID)),
				slog.String("name", f.Name),
				slog.String("error", err.Error()))
		}
	}
}

// isDue 判断某订阅源是否已到达下次同步时间。
func (m *Manager) isDue(f store.ThreatIntelFeed, now time.Time) bool {
	interval := time.Duration(f.SyncInterval) * time.Second
	if interval <= 0 {
		interval = time.Hour
	}
	if f.LastSyncAt == nil {
		return true
	}
	return now.Sub(*f.LastSyncAt) >= interval
}

// SyncNow 手动立即同步指定订阅源（阻塞）。
func (m *Manager) SyncNow(feedID uint) error {
	return m.syncFeedInternal(feedID, "manual")
}

// SyncFeed 拉取单个订阅源 URL，解析为 IP 条目并全量替换，随后触发 reload。
// 同步失败会记录 LastError 但不 panic。
func (m *Manager) SyncFeed(feedID uint) error {
	return m.syncFeedInternal(feedID, "auto")
}

func (m *Manager) syncFeedInternal(feedID uint, trigger string) error {
	// 去重：同一 feed 正在同步时直接跳过。
	m.mu.Lock()
	if m.syncing[feedID] {
		m.mu.Unlock()
		return nil
	}
	m.syncing[feedID] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.syncing, feedID)
		m.mu.Unlock()
	}()

	started := time.Now()

	feed, err := m.repo.Get(feedID)
	if err != nil {
		return fmt.Errorf("加载订阅源: %w", err)
	}

	entries, fetchErr := m.fetchAndParse(feed)
	if fetchErr != nil {
		m.recordResult(feed, 0, fetchErr.Error())
		m.writeSyncLog(feed, trigger, started, 0, false, fetchErr.Error())
		return fetchErr
	}

	if err := m.repo.ReplaceFeedEntries(feed.ID, entries); err != nil {
		m.recordResult(feed, 0, "落库失败: "+err.Error())
		m.writeSyncLog(feed, trigger, started, 0, false, "落库失败: "+err.Error())
		return fmt.Errorf("替换订阅源条目: %w", err)
	}

	m.recordResult(feed, len(entries), "")
	m.writeSyncLog(feed, trigger, started, len(entries), true, "")
	m.log.Info("threatintel: 订阅源同步完成",
		slog.Uint64("feed_id", uint64(feed.ID)),
		slog.String("name", feed.Name),
		slog.Int("entries", len(entries)))

	if err := m.reload(); err != nil {
		m.log.Warn("threatintel: 同步后 reload 失败", slog.String("error", err.Error()))
	}
	return nil
}

// writeSyncLog 写入一条同步历史记录（失败不阻塞主流程，仅记警告日志）。
func (m *Manager) writeSyncLog(feed *store.ThreatIntelFeed, trigger string, started time.Time, entries int, success bool, errMsg string) {
	if m.logRepo == nil {
		return
	}
	finished := time.Now()
	rec := &store.ThreatIntelSyncLog{
		FeedID:       feed.ID,
		FeedName:     feed.Name,
		StartedAt:    started,
		FinishedAt:   finished,
		DurationMs:   finished.Sub(started).Milliseconds(),
		Success:      success,
		EntriesAdded: entries,
		Trigger:      trigger,
		Error:        truncate(errMsg, 1000),
	}
	if err := m.logRepo.Create(rec); err != nil {
		m.log.Warn("threatintel: 写入同步日志失败", slog.String("error", err.Error()))
	}
}

// fetchAndParse 拉取订阅源响应并解析为 IP 条目。
func (m *Manager) fetchAndParse(feed *store.ThreatIntelFeed) ([]store.IPListEntry, error) {
	req, err := http.NewRequest(http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("构建请求: %w", err)
	}
	// 可选认证头：仅当名称与值都非空时才附加，避免发出空头。
	if feed.AuthHeaderName != "" && feed.AuthHeaderValue != "" {
		req.Header.Set(feed.AuthHeaderName, feed.AuthHeaderValue)
	}
	// 声明支持 gzip，部分订阅源仅在收到该头时才返回压缩响应。
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅源返回状态 %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应: %w", err)
	}
	body, err := decompressBody(raw, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, err
	}
	return parseEntries(body, feed), nil
}

/**
 * decompressBody 按 Content-Encoding 解压响应正文。
 *
 * 支持 gzip（含 zlib 头包裹的 gzip 流，兼容某些不规范的订阅源）与
 * deflate/zlib（标准 zlib 流）。无编码声明或 x-gzip/其他未知编码时原样返回；
 * 声明了 gzip/deflate 但解压失败时如实返回错误，保证错误进入 LastError 而非
 * 静默吞掉并解析出空列表。
 */
func decompressBody(data []byte, encoding string) ([]byte, error) {
	encoding = strings.TrimSpace(strings.ToLower(encoding))
	switch {
	case encoding == "", encoding == "identity":
		return data, nil
	case encoding == "x-gzip":
		encoding = "gzip"
	}
	readAll := func(r io.Reader) ([]byte, error) {
		out, err := io.ReadAll(io.LimitReader(r, maxBodyBytes))
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	switch encoding {
	case "gzip":
		// 标准 gzip：gzip 头 + deflate。部分源会错误地用 zlib（2 字节头 + deflate）
		// 包裹 gzip 流；先按 zlib 探测首部，命中则走 zlib 路径。
		zr, zerr := zlib.NewReader(bytes.NewReader(data))
		if zerr == nil {
			if out, err := readAll(zr); err == nil {
				zr.Close()
				return out, nil
			}
			zr.Close()
		}
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("解压 gzip 响应失败: %w", err)
		}
		defer gr.Close()
		return readAll(gr)
	case "deflate", "zlib":
		// 先按标准 zlib 流（RFC 1950）解析；个别源会发裸 deflate（RFC 1951），
		// 标准流解析失败时回退到原始 deflate。
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err == nil {
			if out, rerr := readAll(zr); rerr == nil {
				zr.Close()
				return out, nil
			}
			zr.Close()
		}
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		out, err := readAll(fr)
		if err != nil {
			return nil, fmt.Errorf("解压 deflate 响应失败: %w", err)
		}
		return out, nil
	default:
		// 未知编码（如 br）不尝试猜测，原样交给解析器。
		return data, nil
	}
}

// recordResult 回写单次同步结果（时间、条目数、错误信息）。
func (m *Manager) recordResult(feed *store.ThreatIntelFeed, count int, errMsg string) {
	now := time.Now()
	feed.LastSyncAt = &now
	feed.LastError = truncate(errMsg, 500)
	feed.EntryCount = count
	if err := m.repo.Update(feed); err != nil {
		m.log.Warn("threatintel: 回写同步状态失败",
			slog.Uint64("feed_id", uint64(feed.ID)),
			slog.String("error", err.Error()))
	}
}

/**
 * parseEntries 按行解析订阅源正文，逐行 trim，跳过空行与 # 注释，
 * 支持行级切列（tab/空白分隔，取第一列），严格用 net.ParseIP / net.ParseCIDR
 * 校验，非法行跳过不整体失败。既有「每行一个 IP/CIDR」语义保持不变。
 * 每个合法条目继承 feed 的 Kind/Action/SiteID，并标记 FeedID 与来源备注。
 * 同一正文内的重复值会被去重。
 */
func parseEntries(body []byte, feed *store.ThreatIntelFeed) []store.IPListEntry {
	note := "来自订阅: " + feed.Name
	seen := make(map[string]struct{})
	var entries []store.IPListEntry

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 支持行内注释：从 trim 后的行首取第一列，无需手工逐字符切分。
		if hash := strings.IndexByte(line, '#'); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
			if line == "" {
				continue
			}
		}
		// 行级切列：按空白（空格/tab）切分后取第一列。既兼容「每行一个 IP/CIDR」，
		// 也兼容 "1.2.3.4/tab/备注" 的列式订阅源格式。
		if fields := strings.Fields(line); len(fields) > 0 {
			line = fields[0]
		}
		if !isValidIPOrCIDR(line) {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}

		fid := feed.ID
		entries = append(entries, store.IPListEntry{
			Kind:    store.IPListKind(feed.Kind),
			Value:   line,
			Note:    note,
			Enabled: true,
			Action:  feed.Action,
			SiteID:  feed.SiteID,
			FeedID:  &fid,
		})
	}
	return entries
}

// isValidIPOrCIDR 校验字符串是否为合法的单个 IP 或 CIDR 网段。
func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// truncate 将字符串按字节截断到 maxLen 以内，切点落在多字节字符中间时
// 回退到最近的 rune 起始字节，保证截断结果始终是合法 UTF-8。
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// UTF-8 续字节形如 0b10xxxxxx（(b & 0xC0) == 0x80）；回退越过所在 rune，
	// 直到切点处字节是某 rune 的起始字节。无需引入 unicode/utf8 依赖。
	for maxLen > 0 && s[maxLen]&0xC0 == 0x80 {
		maxLen--
	}
	return s[:maxLen]
}
