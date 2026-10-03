package utils

import "testing"

/**
 * TestSlicePage 锁定分类别 cap 分页切片语义:
 * 默认回落、cap 钳制、起始越界回空切片、尾页裁剪。
 */
func TestSlicePage(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	got := SlicePage(items, 1, 3, 20, 200)
	if len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("page1 size3 = %v", got)
	}
	got = SlicePage(items, 1, 0, 20, 200)
	if len(got) != 10 {
		t.Fatalf("zero size should fall back to def 20 covering all: %v", got)
	}
	got = SlicePage(items, 1, 500, 100, 500)
	if len(got) != 10 {
		t.Fatalf("cap 500 must return all items: %v", got)
	}
	got = SlicePage(items, 1, 999, 100, 500)
	if len(got) != 10 {
		t.Fatalf("size over cap must clamp to 500: %v", got)
	}
	got = SlicePage(items, 5, 3, 20, 200)
	if len(got) != 0 {
		t.Fatalf("start beyond len must return empty slice, got %v", got)
	}
	got = SlicePage(items, 4, 3, 20, 200)
	if len(got) != 1 || got[0] != 10 {
		t.Fatalf("tail page = %v", got)
	}
}
