package utils

import (
	"math"
	"strconv"
)

// MaxPageSize 是 Paginate 允许的单页条数上限。
const MaxPageSize = 200

func UintPtr(v uint) *uint       { return &v }
func StringPtr(v string) *string { return &v }
func BoolPtr(v bool) *bool       { return &v }
func Int64Ptr(v int64) *int64    { return &v }

/**
 * Paginate 把请求页码换算为 SQL OFFSET/LIMIT。
 *
 * page 与 pageSize 都来自查询参数，只有下界校正不足以防溢出：pageSize 先钳到
 * 1..MaxPageSize，再把 page 钳到使 offset 与 offset+limit 都落在 int 可表示范围内。
 * 调用方常自行计算 offset+limit 后再切分内存切片，因此上界必须同时给 limit 留出余量，
 * 否则大 page 会让 offset 或 offset+limit 溢出为负数，产生负 OFFSET 与负切片边界。
 *
 * @param page 请求页码，小于 1 时回落为 1。
 * @param pageSize 请求每页条数，小于 1 时回落为 20，超过 MaxPageSize 时钳制。
 * @returns offset 与 limit，二者均非负且 offset+limit 不会溢出。
 */
func Paginate(page, pageSize int) (offset, limit int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	// 上界按本页条数留余量：钳制后 page-1 <= (MaxInt-pageSize)/pageSize，
	// 因此 offset <= MaxInt-pageSize，调用方随后算 offset+limit 也不会溢出。
	maxOffset := math.MaxInt - pageSize
	if page-1 > maxOffset/pageSize {
		page = maxOffset/pageSize + 1
	}
	return (page - 1) * pageSize, pageSize
}

/**
 * SlicePage 按页切分内存切片，页长上限由调用方按类别给出。
 *
 * 与 Paginate 同源：page 与 pageSize 来自请求参数，只有下界校正不足以防溢出。
 * 有效页长先收敛到 1..cap，再把 page 钳到使 start 与 start+pageSize 都落在 int
 * 可表示范围内；否则极大 page 会让 start 溢出为负数，items[start:end] 直接越界。
 *
 * @param items 待切分的内存切片。
 * @param page 请求页码，小于 1 时回落为 1。
 * @param pageSize 请求每页条数，小于 1 时回落为 def，超过 cap 时钳制。
 * @param def pageSize 缺省值，由调用方按数据类别给出。
 * @param cap 页长上限，由调用方按数据类别给出。
 * @returns 切分结果；页长非正或起始位置越界时返回空切片。
 */
func SlicePage[T any](items []T, page, pageSize, def, cap int) []T {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = def
	}
	if pageSize > cap {
		pageSize = cap
	}
	// def 与 cap 都由调用方给出，收敛后仍可能非正。此时切不出有意义的页，
	// 同时保证下面的上界除法不会除以零。
	if pageSize < 1 {
		return []T{}
	}
	// 上界与 Paginate 同口径：给整页留余量，保证 start 与 start+pageSize 不溢出。
	maxStart := math.MaxInt - pageSize
	if page-1 > maxStart/pageSize {
		page = maxStart/pageSize + 1
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func ParseUint(s string) (uint, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return uint(v), err
}

func ParseUintDefault(s string, def uint) uint {
	v, err := ParseUint(s)
	if err != nil {
		return def
	}
	return v
}
