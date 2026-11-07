package utils

import (
	"math"
	"strconv"
	"testing"
)

/**
 * TestPaginateBoundsExtremeInputs 锁定 Paginate 对极大输入的收敛行为。
 *
 * page 与 pageSize 都来自查询参数。改动前 page 只有下界校正，极大 page 会让
 * (page-1)*pageSize 溢出为负数：负 OFFSET 交给 SQL，调用方再把 offset+limit
 * 当切片边界时直接 panic（ListCVERules 的 views[offset:end] 即为此类）。
 * 本用例覆盖 page ∈ {0,1,2, 极大值} × pageSize ∈ {0,1,20,200,201, 极大值}
 * 的笛卡尔积，断言返回值始终可直接用于 OFFSET/LIMIT 与内存切分。
 */
func TestPaginateBoundsExtremeInputs(t *testing.T) {
	pages := []int{-5, 0, 1, 2, 3, 1000, math.MaxInt32, math.MaxInt}
	if strconv.IntSize == 64 {
		pages = append(pages, 1<<52)
	}
	sizes := []int{-1, 0, 1, 20, 50, 200, 201, 1000, math.MaxInt}

	for _, page := range pages {
		for _, pageSize := range sizes {
			offset, limit := Paginate(page, pageSize)

			if limit < 1 || limit > MaxPageSize {
				t.Fatalf("Paginate(%d, %d) limit = %d, want 1..%d", page, pageSize, limit, MaxPageSize)
			}
			if offset < 0 {
				t.Fatalf("Paginate(%d, %d) offset = %d, must not be negative", page, pageSize, offset)
			}
			// 调用方普遍自行计算 offset+limit（ListCVERules 的 end := offset + limit），
			// 上界必须为整页留余量，保证该加法同样不溢出。
			if offset > math.MaxInt-limit {
				t.Fatalf("Paginate(%d, %d) offset+limit overflows: offset=%d limit=%d", page, pageSize, offset, limit)
			}
			// 未能整页装下的末页，offset 必须仍落在可表示范围内。
			if offset%limit != 0 {
				t.Fatalf("Paginate(%d, %d) offset=%d is not a multiple of limit=%d", page, pageSize, offset, limit)
			}
			// 单调性：更大的 page 不允许算出更小的 offset（钳制只形成高位平台）。
			if page > 1 {
				smaller, _ := Paginate(page-1, pageSize)
				if offset < smaller {
					t.Fatalf("Paginate not monotone at page=%d size=%d: %d < %d", page, pageSize, offset, smaller)
				}
			}
		}
	}
}

/**
 * TestPaginateKeepsPreFixValues 锁定合法输入下的返回值与改动前逐 case 相同。
 *
 * 期望值逐行取自改动前实现的实测输出（未溢出的行），防止上界钳制误伤正常分页。
 * 表中数值用 int64 书写，超 32 位的行只在 64 位平台执行。
 */
func TestPaginateKeepsPreFixValues(t *testing.T) {
	cases := []struct {
		page, pageSize   int64
		wantOff, wantLim int64
		only64           bool
	}{
		{0, 0, 0, 20, false},
		{0, -1, 0, 20, false},
		{0, 1, 0, 1, false},
		{0, 20, 0, 20, false},
		{0, 200, 0, 200, false},
		{0, 201, 0, 200, false},
		{0, 1000, 0, 200, false},
		{-5, 0, 0, 20, false},
		{-5, 20, 0, 20, false},
		{-5, 201, 0, 200, false},
		{1, 0, 0, 20, false},
		{1, 1, 0, 1, false},
		{1, 20, 0, 20, false},
		{1, 200, 0, 200, false},
		{1, 201, 0, 200, false},
		{2, 1, 1, 1, false},
		{2, 20, 20, 20, false},
		{2, 50, 50, 50, false},
		{2, 200, 200, 200, false},
		{3, 1, 2, 1, false},
		{3, 20, 40, 20, false},
		{3, 50, 100, 50, false},
		{3, 200, 400, 200, false},
		{3, 201, 400, 200, false},
		{1000, 1, 999, 1, false},
		{1000, 20, 19980, 20, false},
		{1000, 50, 49950, 50, false},
		{1000, 200, 199800, 200, false},
		{2147483648, 1, 2147483647, 1, true},
		{2147483648, 20, 42949672940, 20, true},
		{2147483648, 50, 107374182350, 50, true},
		{2147483648, 200, 429496729400, 200, true},
		{4503599627370496, 1, 4503599627370495, 1, true},
		{4503599627370496, 20, 90071992547409900, 20, true},
		{4503599627370496, 50, 225179981368524750, 50, true},
		{4503599627370496, 200, 900719925474099000, 200, true},
	}

	for _, c := range cases {
		if c.only64 && strconv.IntSize != 64 {
			continue
		}
		offset, limit := Paginate(int(c.page), int(c.pageSize))
		if int64(offset) != c.wantOff || int64(limit) != c.wantLim {
			t.Errorf("Paginate(%d, %d) = (%d, %d), want (%d, %d)",
				c.page, c.pageSize, offset, limit, c.wantOff, c.wantLim)
		}
	}
}

/**
 * TestPaginateClampsOnlyAboveSafeDepth 锁定钳制边界本身。
 *
 * 断言钳制后仍指向「最后一个可表示的位置」，而不是把大 page 一律压回首页，
 * 并且钳制前允许的最大合法偏移不受影响。
 */
func TestPaginateClampsOnlyAboveSafeDepth(t *testing.T) {
	deepOffset, deepLimit := Paginate(math.MaxInt, 200)
	if deepLimit != 200 {
		t.Fatalf("deep page limit = %d, want 200", deepLimit)
	}
	if deepOffset < math.MaxInt/4 {
		t.Fatalf("deep page offset = %d, expected to stay near the representable ceiling", deepOffset)
	}
	// 同一输入重复计算必须稳定。
	if again, _ := Paginate(math.MaxInt, 200); again != deepOffset {
		t.Fatalf("deep page offset not stable: %d vs %d", deepOffset, again)
	}
	// 钳制阈值之内的深分页必须原样返回，不能被提前压平。
	safePage := (math.MaxInt - 200) / 200
	if got, _ := Paginate(safePage, 200); got != (safePage-1)*200 {
		t.Fatalf("in-range deep page was clamped: offset=%d want=%d", got, (safePage-1)*200)
	}
}

/**
 * TestSlicePageBoundsExtremeInputs 锁定 SlicePage 对极大输入的收敛行为。
 *
 * SlicePage 与 Paginate 同源：page 与 pageSize 来自请求参数，只有下界校正时，
 * 极大 page 会让 start=(page-1)*pageSize 溢出为负，items[start:end] 直接越界
 * （实测 page=MaxInt64, pageSize=200 触发 slice bounds out of range [:-200]）。
 * 断言任意输入下都只返回合法切片，绝不 panic。
 */
func TestSlicePageBoundsExtremeInputs(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	pages := []int{-5, 0, 1, 2, 5, 1000, math.MaxInt32, math.MaxInt}
	if strconv.IntSize == 64 {
		pages = append(pages, 1<<52)
	}
	sizes := []int{-1, 0, 1, 3, 10, 200, 500, math.MaxInt}
	defs := []int{20, 100}
	caps := []int{200, 500}

	for _, page := range pages {
		for _, pageSize := range sizes {
			for _, def := range defs {
				for _, limitCap := range caps {
					got := SlicePage(items, page, pageSize, def, limitCap)
					if len(got) > len(items) {
						t.Fatalf("SlicePage(page=%d size=%d def=%d cap=%d) returned %d items, more than input %d",
							page, pageSize, def, limitCap, len(got), len(items))
					}
					// 返回的必须是原切片里的连续子段：内部逐项 +1，且不越出源范围。
					for i := range got {
						if i > 0 && got[i] != got[i-1]+1 {
							t.Fatalf("SlicePage(page=%d size=%d def=%d cap=%d) not contiguous at %d: %v",
								page, pageSize, def, limitCap, i, got)
						}
						if got[i] < items[0] || got[i] > items[len(items)-1] {
							t.Fatalf("SlicePage(page=%d size=%d def=%d cap=%d) item[%d]=%d out of source range",
								page, pageSize, def, limitCap, i, got[i])
						}
					}
				}
			}
		}
	}
}

/**
 * TestSlicePageKeepsPreFixValues 锁定合法输入下与改动前逐 case 相同。
 *
 * 期望值取自改动前实现的实测输出，防止上界钳制误伤正常分页；同时覆盖既有
 * utils_pagination_test.go 之外的缺省回落与 cap 钳制组合。
 */
func TestSlicePageKeepsPreFixValues(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	cases := []struct {
		page, pageSize, def, limitCap int
		wantLen                       int
		wantFirst                     int
	}{
		{1, 3, 20, 200, 3, 1},
		{2, 3, 20, 200, 3, 4},
		{4, 3, 20, 200, 1, 10},
		{5, 3, 20, 200, 0, 0},
		{1, 0, 20, 200, 10, 1},
		{1, 0, 5, 200, 5, 1},
		{1, 999, 100, 500, 10, 1},
		{1, 201, 20, 200, 10, 1},
		{0, 3, 20, 200, 3, 1},
		{-5, 3, 20, 200, 3, 1},
		{math.MaxInt32, 20, 20, 200, 0, 0},
		// 深但未溢出的 page 必须仍落在原切片上，而不是被压回首页。
		{1 << 30, 1, 20, 200, 0, 0},
		{3, 3, 20, 200, 3, 7},
		{6, 2, 20, 200, 0, 0},
	}

	for _, c := range cases {
		got := SlicePage(items, c.page, c.pageSize, c.def, c.limitCap)
		if len(got) != c.wantLen {
			t.Errorf("SlicePage(page=%d size=%d def=%d cap=%d) len=%d, want %d",
				c.page, c.pageSize, c.def, c.limitCap, len(got), c.wantLen)
			continue
		}
		if c.wantLen > 0 && got[0] != c.wantFirst {
			t.Errorf("SlicePage(page=%d size=%d def=%d cap=%d) first=%d, want %d",
				c.page, c.pageSize, c.def, c.limitCap, got[0], c.wantFirst)
		}
	}
}

/**
 * TestSlicePageReturnsEmptyForNonPositivePageSize 锁定非正页长的收敛行为。
 *
 * def 与 cap 都由调用方给出，二者非正时切不出有意义的页；此处必须返回空切片
 * 而不是让后续的上界除法除以零。
 */
func TestSlicePageReturnsEmptyForNonPositivePageSize(t *testing.T) {
	items := []int{1, 2, 3}
	for _, c := range []struct {
		page, pageSize, def, limitCap int
	}{
		{1, 0, 0, 200},
		{1, 0, -1, 200},
		{1, 5, 20, 0},
		{1, 5, 20, -1},
		{math.MaxInt, 0, 0, 0},
	} {
		got := SlicePage(items, c.page, c.pageSize, c.def, c.limitCap)
		if len(got) != 0 {
			t.Fatalf("SlicePage(page=%d size=%d def=%d cap=%d) = %v, want empty",
				c.page, c.pageSize, c.def, c.limitCap, got)
		}
	}
}
