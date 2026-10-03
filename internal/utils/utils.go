package utils

import "strconv"

func UintPtr(v uint) *uint       { return &v }
func StringPtr(v string) *string { return &v }
func BoolPtr(v bool) *bool       { return &v }
func Int64Ptr(v int64) *int64    { return &v }

func Paginate(page, pageSize int) (offset, limit int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return (page - 1) * pageSize, pageSize
}

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
