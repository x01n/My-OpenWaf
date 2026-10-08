package store

import (
	"reflect"
	"testing"

	cvestore "My-OpenWaf/internal/store/cve"
	"My-OpenWaf/internal/waf/cve"
)

// TestCVERuleModelsShareColumnSet 守护「同表双模型」的字段一致性。
//
// cve_rules 表由两个结构体映射：
//   - store.CVERuleRecord —— AutoMigrate 建表/加列的 schema 来源；
//   - cve.CVERuleModel    —— 运行时读写（feed 同步、目录装载）使用的模型。
//
// 二者 TableName() 均为 "cve_rules"。只在运行时模型上新增字段会出现
// 「INSERT 带了列名、但表中没有该列」的启动期失败（历史事故：References
// 只加在 CVERuleModel 上，导致全新部署在 CVE 目录装载时即报
// "table cve_rules has no column named references"）。
//
// 因此两个结构体的字段集必须逐名一致；本测试是这条约束的可执行载体。
func TestCVERuleModelsShareColumnSet(t *testing.T) {
	recordFields := structFieldNames(reflect.TypeOf(cvestore.CVERuleRecord{}))
	modelFields := structFieldNames(reflect.TypeOf(cve.CVERuleModel{}))

	for name := range modelFields {
		if !recordFields[name] {
			t.Errorf("cve.CVERuleModel 有字段 %q，但 store.CVERuleRecord 没有；"+
				"AutoMigrate 不会为 cve_rules 建出该列，运行时会报 column not found", name)
		}
	}
	for name := range recordFields {
		if !modelFields[name] {
			t.Errorf("store.CVERuleRecord 有字段 %q，但 cve.CVERuleModel 没有；"+
				"该列不会被运行时读写，属死列", name)
		}
	}

	if got := (cvestore.CVERuleRecord{}).TableName(); got != (cve.CVERuleModel{}).TableName() {
		t.Fatalf("两模型的表名不一致：CVERuleRecord=%q CVERuleModel=%q", got, (cve.CVERuleModel{}).TableName())
	}
}

// structFieldNames 返回结构体全部字段名的集合（不区分嵌入层级）。
func structFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names[t.Field(i).Name] = true
	}
	return names
}
