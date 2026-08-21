package system

import (
	"testing"
	"time"

	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func TestRealtimeDashboardSnapshotKeepsClassificationAndVisitorFusionStats(t *testing.T) {
	configDB := newDashboardConfigDBForTest(t)
	logDB := newDashboardLogDBForTest(t)
	now := time.Now()

	accessLogs := []store.AccessLog{
		{
			RequestID:                       "human-request",
			WAFAction:                       "observe",
			CreatedAt:                       now,
			VisitorFusionClass:              "human",
			VisitorFusionEvidenceSufficient: true,
		},
		{
			RequestID:                       "bot-request",
			WAFAction:                       "observe",
			CreatedAt:                       now,
			VisitorFusionClass:              "bot",
			VisitorFusionEvidenceSufficient: true,
		},
		{
			RequestID:                       "intercept-request",
			WAFAction:                       "intercept",
			CreatedAt:                       now,
			VisitorFusionClass:              "unknown",
			VisitorFusionEvidenceSufficient: true,
		},
	}
	if err := logDB.Create(&accessLogs).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}
	if err := logDB.Create(&store.BotScoreLog{RequestID: "bot-request", CreatedAt: now}).Error; err != nil {
		t.Fatalf("seed bot score log: %v", err)
	}

	accessRepo := repository.NewAccessLogRepo(logDB)
	withAccessRepo := NewRealtimeHub(&DashboardDeps{
		Metrics:    dataplane.NewMetrics(),
		ConfigDB:   configDB,
		LogDB:      logDB,
		AccessRepo: accessRepo,
	}, nil, nil, nil, nil)
	withoutAccessRepo := NewRealtimeHub(&DashboardDeps{
		Metrics:  dataplane.NewMetrics(),
		ConfigDB: configDB,
		LogDB:    logDB,
	}, nil, nil, nil, nil)

	withSnapshot := BuildDashboardSnapshot(withAccessRepo.dashboard)
	withoutSnapshot := BuildDashboardSnapshot(withoutAccessRepo.dashboard)
	want := map[string]int64{
		"human_visits_24h":                        1,
		"bot_visits_24h":                          1,
		"unclassified_intercept_24h":              1,
		"visit_kind_total_24h":                    3,
		"visitor_fusion_https_released_total_24h": 3,
		"visitor_fusion_human_24h":                1,
		"visitor_fusion_bot_24h":                  1,
		"visitor_fusion_unknown_24h":              1,
	}
	for key, expected := range want {
		got, ok := withSnapshot[key].(int64)
		if !ok || got != expected {
			t.Errorf("injected dashboard %s = %#v, want %d", key, withSnapshot[key], expected)
		}
	}

	for _, key := range []string{
		"human_visits_24h",
		"bot_visits_24h",
		"unclassified_intercept_24h",
		"visit_kind_total_24h",
	} {
		if got, ok := withoutSnapshot[key].(int64); !ok || got != 0 {
			t.Errorf("dashboard without AccessRepo %s = %#v, want 0", key, withoutSnapshot[key])
		}
	}
	for _, key := range []string{
		"visitor_fusion_https_released_total_24h",
		"visitor_fusion_human_24h",
		"visitor_fusion_bot_24h",
		"visitor_fusion_unknown_24h",
	} {
		if withSnapshot[key] != withoutSnapshot[key] {
			t.Errorf("visitor-fusion stat %s changed without AccessRepo: with=%#v without=%#v", key, withSnapshot[key], withoutSnapshot[key])
		}
	}
}
