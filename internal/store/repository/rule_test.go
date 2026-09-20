package repository

import (
	"testing"

	"My-OpenWaf/internal/store"
)

func TestRuleRepoListFilteredActionIncludesLegacyAliasesAndTotal(t *testing.T) {
	db := newTestDB(t)
	repo := NewRuleRepo(db)
	items := []store.Rule{
		{Name: "canonical intercept", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/canonical", Action: store.ActionIntercept, Priority: 10},
		{Name: "legacy block", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/legacy", Action: store.ActionBlock, Priority: 20},
		{Name: "allow", PolicyID: 1, Phase: store.PhaseACL, Pattern: "allow_ip:192.0.2.1", Action: store.ActionAllow, Priority: 30},
		{Name: "other policy", PolicyID: 2, Phase: store.PhaseCustom, Pattern: "block_path:/other", Action: store.ActionIntercept, Priority: 40},
	}
	if err := db.Create(&items).Error; err != nil {
		t.Fatalf("create rules: %v", err)
	}

	policyID := uint(1)
	action := store.ActionIntercept
	got, total, err := repo.ListFiltered(0, 1, RuleFilter{PolicyID: &policyID, Action: &action})
	if err != nil {
		t.Fatalf("list filtered rules: %v", err)
	}
	if total != 2 || len(got) != 1 || got[0].Name != "canonical intercept" {
		t.Fatalf("expected paginated canonical and legacy intercept total, total=%d items=%+v", total, got)
	}
}
