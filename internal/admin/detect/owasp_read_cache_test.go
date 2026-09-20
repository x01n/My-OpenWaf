package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/owasp"
)

type owaspReadSQLCounter struct {
	catalog atomic.Int64
	config  atomic.Int64
	policy  atomic.Int64
}

func registerOWASPReadSQLCounter(t *testing.T, db *gorm.DB) *owaspReadSQLCounter {
	t.Helper()
	counter := &owaspReadSQLCounter{}
	catalogType := reflect.TypeOf(store.OWASPRuleCatalog{})
	configType := reflect.TypeOf(store.PolicyOWASPRuleConfig{})
	policyType := reflect.TypeOf(store.Policy{})
	callbackName := "test:owasp-read-cache-query:" + t.Name()
	if err := db.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil {
			return
		}
		switch tx.Statement.Schema.ModelType {
		case catalogType:
			counter.catalog.Add(1)
		case configType:
			counter.config.Add(1)
		case policyType:
			counter.policy.Add(1)
		}
	}); err != nil {
		t.Fatalf("register OWASP query callback: %v", err)
	}
	return counter
}

func (c *owaspReadSQLCounter) reset() {
	c.catalog.Store(0)
	c.config.Store(0)
	c.policy.Store(0)
}

func TestOWASPReadSnapshotColdSingleflightAndWarmZeroDataSQL(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	sqlDB, err := repo.DB().DB()
	if err != nil {
		t.Fatalf("get SQL database: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	counter := registerOWASPReadSQLCounter(t, repo.DB())
	invalidateOWASPReadSnapshot(repo.DB(), 1)

	if owaspReadSnapshotTTL != 10*time.Second {
		t.Fatalf("snapshot TTL=%s want=10s", owaspReadSnapshotTTL)
	}
	if owaspReadSnapshotMaxEntries != 64 {
		t.Fatalf("snapshot max entries=%d want=64", owaspReadSnapshotMaxEntries)
	}

	const workers = 32
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			<-start
			snapshot, snapshotErr := getOWASPReadSnapshot(repo.DB(), 1)
			if snapshotErr != nil {
				errCh <- snapshotErr
				return
			}
			if len(snapshot.views) != len(owasp.BuiltinRuleDefinitions()) {
				errCh <- fmt.Errorf("snapshot rules=%d want=%d", len(snapshot.views), len(owasp.BuiltinRuleDefinitions()))
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errCh)
	for snapshotErr := range errCh {
		t.Fatal(snapshotErr)
	}
	if got := counter.catalog.Load(); got != 1 {
		t.Fatalf("cold concurrent catalog queries=%d want=1", got)
	}
	if got := counter.config.Load(); got != 1 {
		t.Fatalf("cold concurrent config queries=%d want=1", got)
	}

	counter.reset()
	if _, err := getOWASPReadSnapshot(repo.DB(), 1); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 0 {
		t.Fatalf("warm data queries=%d want=0", got)
	}
}

func TestOWASPReadSnapshotRetriesAfterDatabaseError(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	counter := registerOWASPReadSQLCounter(t, repo.DB())
	invalidateOWASPReadSnapshot(repo.DB(), 1)

	failFirst := atomic.Bool{}
	failFirst.Store(true)
	catalogType := reflect.TypeOf(store.OWASPRuleCatalog{})
	callbackName := "test:owasp-read-cache-transient:" + t.Name()
	if err := repo.DB().Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Schema != nil &&
			tx.Statement.Schema.ModelType == catalogType && failFirst.CompareAndSwap(true, false) {
			tx.AddError(errors.New("transient OWASP catalog failure"))
		}
	}); err != nil {
		t.Fatalf("register transient failure callback: %v", err)
	}

	if _, err := getOWASPReadSnapshot(repo.DB(), 1); err == nil {
		t.Fatal("first snapshot unexpectedly succeeded")
	}
	if _, err := getOWASPReadSnapshot(repo.DB(), 1); err != nil {
		t.Fatalf("retry snapshot: %v", err)
	}
	if got := counter.catalog.Load(); got != 2 {
		t.Fatalf("catalog retry queries=%d want=2", got)
	}
	if got := counter.config.Load(); got != 1 {
		t.Fatalf("config queries after successful retry=%d want=1", got)
	}
}

func TestOWASPReadSnapshotExpiryReloadsWithoutSleep(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	counter := registerOWASPReadSQLCounter(t, repo.DB())
	state := owaspSnapshotState(repo.DB(), 1)
	state.invalidate()
	if _, err := state.snapshot(repo.DB(), 1); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}

	state.mu.Lock()
	if state.entry == nil {
		state.mu.Unlock()
		t.Fatal("warm snapshot entry is nil")
	}
	state.entry.expiresAt = time.Now().Add(-time.Nanosecond)
	state.mu.Unlock()
	counter.reset()

	if _, err := state.snapshot(repo.DB(), 1); err != nil {
		t.Fatalf("expired snapshot reload: %v", err)
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 2 {
		t.Fatalf("expired snapshot data queries=%d want=2", got)
	}
}

func TestInvalidateOWASPReadSnapshotsClearsEveryPolicyForDatabase(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	states := []*owaspReadSnapshotState{
		owaspSnapshotState(repo.DB(), 1),
		owaspSnapshotState(repo.DB(), 2),
	}
	for i := range states {
		if _, err := states[i].snapshot(repo.DB(), uint(i+1)); err != nil {
			t.Fatalf("warm policy %d snapshot: %v", i+1, err)
		}
	}

	InvalidateOWASPReadSnapshots(repo.DB())
	for i := range states {
		states[i].mu.RLock()
		entry := states[i].entry
		states[i].mu.RUnlock()
		if entry != nil {
			t.Fatalf("policy %d snapshot remained cached after database-wide invalidation", i+1)
		}
	}
}

func TestOWASPReadSnapshotRegistryRemainsBounded(t *testing.T) {
	db := &gorm.DB{}
	keys := make([]owaspReadSnapshotKey, 0, owaspReadSnapshotMaxEntries+1)
	for policyID := uint(1); policyID <= owaspReadSnapshotMaxEntries+1; policyID++ {
		owaspSnapshotState(db, policyID)
		keys = append(keys, owaspReadSnapshotKey{db: db, policyID: policyID})
	}

	globalOWASPReadSnapshots.mu.Lock()
	got := len(globalOWASPReadSnapshots.entries)
	for i := range keys {
		delete(globalOWASPReadSnapshots.entries, keys[i])
	}
	globalOWASPReadSnapshots.mu.Unlock()
	if got > owaspReadSnapshotMaxEntries {
		t.Fatalf("snapshot registry entries=%d want<=%d", got, owaspReadSnapshotMaxEntries)
	}
}

// TestOWASPReadSnapshotInvalidationTargetsCurrentStateAfterRegistryChurn
// 验证键被淘汰并重新创建后，失效操作仍作用于当前注册状态。
func TestOWASPReadSnapshotInvalidationTargetsCurrentStateAfterRegistryChurn(t *testing.T) {
	db := &gorm.DB{}
	// 清理本测试可能留下的共享注册表项，避免影响其他测试。
	t.Cleanup(func() {
		globalOWASPReadSnapshots.mu.Lock()
		for key := range globalOWASPReadSnapshots.entries {
			if key.db == db {
				delete(globalOWASPReadSnapshots.entries, key)
			}
		}
		globalOWASPReadSnapshots.mu.Unlock()
	})

	oldState := owaspSnapshotState(db, 1)
	oldState.mu.Lock()
	oldState.entry = &owaspReadSnapshotEntry{expiresAt: time.Now().Add(time.Hour)}
	oldState.mu.Unlock()
	// 填满并超过注册表上限，确保 key=(db,1) 会被淘汰；随后重新创建同一键。
	for policyID := uint(2); policyID <= owaspReadSnapshotMaxEntries+2; policyID++ {
		owaspSnapshotState(db, policyID)
	}
	currentState := owaspSnapshotState(db, 1)
	if currentState == oldState {
		t.Fatal("registry churn did not replace the state for policy 1")
	}
	currentState.mu.Lock()
	currentState.entry = &owaspReadSnapshotEntry{expiresAt: time.Now().Add(time.Hour)}
	currentState.mu.Unlock()

	invalidateOWASPReadSnapshot(db, 1)
	currentState.mu.RLock()
	entry := currentState.entry
	currentState.mu.RUnlock()
	if entry != nil {
		t.Fatal("current replacement state remained cached after invalidation")
	}
}

func TestOWASPReadSnapshotReturnsDeepCopies(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	whitelist := `["/healthz","/metrics"]`
	if err := repo.DB().Create(&store.PolicyOWASPRuleConfig{
		PolicyID:  1,
		RuleID:    ruleID,
		Whitelist: &whitelist,
	}).Error; err != nil {
		t.Fatalf("create OWASP config: %v", err)
	}
	invalidateOWASPReadSnapshot(repo.DB(), 1)

	first, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	var viewIndex int
	for i := range first.views {
		if first.views[i].ID == ruleID {
			viewIndex = i
			break
		}
	}
	first.views[viewIndex].Description = "mutated"
	first.views[viewIndex].Whitelist[0] = "/mutated"
	first.views = append(first.views, owaspRuleView{ID: "mutated"})

	second, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if len(second.views) != len(owasp.BuiltinRuleDefinitions()) {
		t.Fatalf("cached rules=%d want=%d", len(second.views), len(owasp.BuiltinRuleDefinitions()))
	}
	for i := range second.views {
		if second.views[i].ID != ruleID {
			continue
		}
		if second.views[i].Description == "mutated" {
			t.Fatal("cached description was mutated by caller")
		}
		if len(second.views[i].Whitelist) != 2 || second.views[i].Whitelist[0] != "/healthz" {
			t.Fatalf("cached whitelist was mutated: %#v", second.views[i].Whitelist)
		}
		return
	}
	t.Fatalf("rule %q missing from cached snapshot", ruleID)
}

func TestOWASPListEmbedsEquivalentStatsAndWarmStatsSkipsDataSQL(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	counter := registerOWASPReadSQLCounter(t, repo.DB())
	invalidateOWASPReadSnapshot(repo.DB(), 1)

	listCtx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?policy_id=1&page=1&page_size=50&include_grouped=false")
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("list status=%d body=%s", listCtx.Response.StatusCode(), listCtx.Response.Body())
	}
	if got := counter.catalog.Load(); got != 1 {
		t.Fatalf("cold list catalog queries=%d want=1", got)
	}
	if got := counter.config.Load(); got != 1 {
		t.Fatalf("cold list config queries=%d want=1", got)
	}
	if got := counter.policy.Load(); got != 1 {
		t.Fatalf("cold list policy queries=%d want=1", got)
	}
	var listResponse struct {
		Stats owaspRuleStats `json:"stats"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}

	counter.reset()
	statsCtx := invokeOWASPGet(t, GetOWASPRuleStats(repo), "/api/v1/owasp-rules/stats?policy_id=1")
	if statsCtx.Response.StatusCode() != 200 {
		t.Fatalf("stats status=%d body=%s", statsCtx.Response.StatusCode(), statsCtx.Response.Body())
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 0 {
		t.Fatalf("warm stats data queries=%d want=0", got)
	}
	if got := counter.policy.Load(); got != 1 {
		t.Fatalf("warm stats policy queries=%d want=1", got)
	}
	var statsResponse owaspRuleStats
	if err := json.Unmarshal(statsCtx.Response.Body(), &statsResponse); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if !reflect.DeepEqual(listResponse.Stats, statsResponse) {
		t.Fatalf("embedded stats=%#v direct stats=%#v", listResponse.Stats, statsResponse)
	}
}

func TestOWASPListEmbeddedStatsMatchFilteredStatsEndpoint(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) == 0 {
		t.Fatal("expected OWASP rules")
	}
	query := strings.ToUpper(rules[0].RuleID)
	params := "policy_id=1&category=" + rules[0].Category + "&q=" + query
	listCtx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?"+params+"&page=1&page_size=1&include_grouped=false")
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("list status=%d body=%s", listCtx.Response.StatusCode(), listCtx.Response.Body())
	}
	var listResponse struct {
		Items []owaspRuleView `json:"items"`
		Total int             `json:"total"`
		Stats owaspRuleStats  `json:"stats"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listResponse.Total == 0 || listResponse.Stats.Total != listResponse.Total {
		t.Fatalf("filtered list total=%d embedded stats total=%d", listResponse.Total, listResponse.Stats.Total)
	}
	if len(listResponse.Items) > 1 {
		t.Fatalf("page_size=1 returned %d items", len(listResponse.Items))
	}

	statsCtx := invokeOWASPGet(t, GetOWASPRuleStats(repo), "/api/v1/owasp-rules/stats?"+params)
	if statsCtx.Response.StatusCode() != 200 {
		t.Fatalf("stats status=%d body=%s", statsCtx.Response.StatusCode(), statsCtx.Response.Body())
	}
	var statsResponse owaspRuleStats
	if err := json.Unmarshal(statsCtx.Response.Body(), &statsResponse); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if !reflect.DeepEqual(listResponse.Stats, statsResponse) {
		t.Fatalf("filtered embedded stats=%#v direct stats=%#v", listResponse.Stats, statsResponse)
	}
}

func TestOWASPReadSnapshotUpdateResetAndBatchInvalidateImmediately(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	counter := registerOWASPReadSQLCounter(t, repo.DB())
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) < 2 {
		t.Fatal("expected at least two OWASP rules")
	}
	firstID := firstOWASPRuleID(t)
	secondID := rules[0].RuleID
	if secondID == firstID {
		secondID = rules[1].RuleID
	}

	if _, err := getOWASPReadSnapshot(repo.DB(), 1); err != nil {
		t.Fatalf("warm initial snapshot: %v", err)
	}
	invokeOWASPUpdate(t, UpdateSingleOWASPRule(repo, func() error { return nil }), firstID, map[string]any{"enabled": false})
	counter.reset()
	afterUpdate, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("snapshot after update: %v", err)
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 2 {
		t.Fatalf("post-update data queries=%d want=2", got)
	}
	if viewEnabled(afterUpdate.views, firstID) {
		t.Fatalf("rule %q remained enabled after update", firstID)
	}

	resetCtx := invokeOWASPPost(t, ResetOWASPRuleOverride(repo, func() error { return nil }), "/api/v1/owasp-rules/"+firstID+"/reset", firstID, nil)
	if resetCtx.Response.StatusCode() != 200 {
		t.Fatalf("reset status=%d body=%s", resetCtx.Response.StatusCode(), resetCtx.Response.Body())
	}
	counter.reset()
	afterReset, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("snapshot after reset: %v", err)
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 2 {
		t.Fatalf("post-reset data queries=%d want=2", got)
	}
	if !viewEnabled(afterReset.views, firstID) {
		t.Fatalf("rule %q did not restore its enabled default after reset", firstID)
	}

	body, err := json.Marshal(map[string]any{
		"policy_id": 1,
		"rules": []map[string]any{{
			"id":      secondID,
			"enabled": false,
		}},
	})
	if err != nil {
		t.Fatalf("marshal batch body: %v", err)
	}
	batchCtx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }), "/api/v1/owasp-rules/batch-update", "", body)
	if batchCtx.Response.StatusCode() != 200 {
		t.Fatalf("batch status=%d body=%s", batchCtx.Response.StatusCode(), batchCtx.Response.Body())
	}
	counter.reset()
	afterBatch, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("snapshot after batch: %v", err)
	}
	if got := counter.catalog.Load() + counter.config.Load(); got != 2 {
		t.Fatalf("post-batch data queries=%d want=2", got)
	}
	if viewEnabled(afterBatch.views, secondID) {
		t.Fatalf("rule %q remained enabled after batch update", secondID)
	}
}

func viewEnabled(views []owaspRuleView, ruleID string) bool {
	for i := range views {
		if views[i].ID == ruleID {
			return views[i].Enabled
		}
	}
	return false
}

func TestSQLiteASCIILikeMatchesDatabaseSemantics(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	tests := []struct {
		pattern string
		value   string
	}{
		{pattern: "%SQLI%", value: "owasp:sqli:001"},
		{pattern: "%s_li%", value: "OWASP:SQLI:001"},
		{pattern: "%注入%", value: "SQL 注入检测"},
		{pattern: "%Ä%", value: "ä"},
		{pattern: "%\\%%", value: "value\\suffix"},
		{pattern: "%__", value: "a界"},
		{pattern: "%missing%", value: "owasp:xss:001"},
	}
	for _, test := range tests {
		var databaseResult int
		if err := repo.DB().Raw("SELECT ? LIKE ?", test.value, test.pattern).Scan(&databaseResult).Error; err != nil {
			t.Fatalf("evaluate SQLite LIKE for pattern %q: %v", test.pattern, err)
		}
		got := sqliteASCIILike(test.pattern, test.value)
		want := databaseResult == 1
		if got != want {
			t.Errorf("pattern=%q value=%q got=%v want=%v", test.pattern, test.value, got, want)
		}
	}
}

func TestOWASPLikeFilteringSelectsDatabaseSpecificSemantics(t *testing.T) {
	sqliteRepo := newSystemSettingsRepoForTest(t)
	if !usesSQLiteOWASPInMemoryLike(sqliteRepo.DB()) {
		t.Fatalf("dialect %q must use verified SQLite in-memory LIKE", sqliteRepo.DB().Dialector.Name())
	}

	postgresDB, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=127.0.0.1 user=openwaf dbname=openwaf sslmode=disable",
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run PostgreSQL: %v", err)
	}
	if usesSQLiteOWASPInMemoryLike(postgresDB) {
		t.Fatal("PostgreSQL must preserve its native LIKE and collation")
	}

	mysqlDB, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "openwaf:openwaf@tcp(127.0.0.1:3306)/openwaf",
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run MySQL: %v", err)
	}
	if usesSQLiteOWASPInMemoryLike(mysqlDB) {
		t.Fatal("MySQL must preserve its native LIKE and collation")
	}
}
