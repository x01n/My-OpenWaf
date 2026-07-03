package rule

import (
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newRuleRepoForPriorityTest(t *testing.T) *repository.RuleRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Rule{}); err != nil {
		t.Fatalf("migrate rules: %v", err)
	}
	return repository.NewRuleRepo(db)
}

func TestValidatePersistedRulePriorityConflictRejectsDuplicateTuple(t *testing.T) {
	repo := newRuleRepoForPriorityTest(t)
	existing := store.Rule{
		Name:     "existing",
		PolicyID: 7,
		Phase:    store.PhaseCustom,
		Pattern:  "block_path:/admin",
		Action:   store.ActionIntercept,
		Priority: 10,
	}
	if err := repo.Create(&existing); err != nil {
		t.Fatalf("create existing rule: %v", err)
	}

	got, err := validatePersistedRulePriorityConflict(repo, &store.Rule{
		PolicyID: 7,
		Phase:    store.PhaseCustom,
		Priority: 10,
	}, 0)
	if err != nil {
		t.Fatalf("validatePersistedRulePriorityConflict() error = %v", err)
	}
	want := "priority 10 already exists in policy 7 phase custom (rule id 1)"
	if got != want {
		t.Fatalf("validatePersistedRulePriorityConflict() = %q, want %q", got, want)
	}
}

func TestValidatePersistedRulePriorityConflictAllowsDifferentPhase(t *testing.T) {
	repo := newRuleRepoForPriorityTest(t)
	existing := store.Rule{
		Name:     "existing acl",
		PolicyID: 7,
		Phase:    store.PhaseACL,
		Pattern:  "block_path:/admin",
		Action:   store.ActionIntercept,
		Priority: 10,
	}
	if err := repo.Create(&existing); err != nil {
		t.Fatalf("create existing rule: %v", err)
	}

	got, err := validatePersistedRulePriorityConflict(repo, &store.Rule{
		PolicyID: 7,
		Phase:    store.PhaseCustom,
		Priority: 10,
	}, 0)
	if err != nil {
		t.Fatalf("validatePersistedRulePriorityConflict() error = %v", err)
	}
	if got != "" {
		t.Fatalf("validatePersistedRulePriorityConflict() = %q, want empty", got)
	}
}

func TestValidateImportedRulePriorityConflictsRejectsDuplicateImportEntries(t *testing.T) {
	repo := newRuleRepoForPriorityTest(t)
	got, err := validateImportedRulePriorityConflicts(repo, []store.Rule{
		{PolicyID: 3, Phase: store.PhaseCustom, Priority: 100},
		{PolicyID: 3, Phase: store.PhaseCustom, Priority: 100},
	})
	if err != nil {
		t.Fatalf("validateImportedRulePriorityConflicts() error = %v", err)
	}
	want := "import rules at indexes 0 and 1 share priority 100 in policy 3 phase custom"
	if got != want {
		t.Fatalf("validateImportedRulePriorityConflicts() = %q, want %q", got, want)
	}
}
