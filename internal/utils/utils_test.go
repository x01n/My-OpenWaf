package utils

import (
	"testing"
)

func TestUintPtr(t *testing.T) {
	v := uint(42)
	p := UintPtr(v)
	if p == nil {
		t.Fatal("UintPtr returned nil")
	}
	if *p != v {
		t.Fatalf("UintPtr: got %d, want %d", *p, v)
	}
	// 确认返回独立指针，不是原变量地址
	v = 99
	if *p != 42 {
		t.Fatal("UintPtr should return pointer to a copy, not to the original variable")
	}
}

func TestStringPtr(t *testing.T) {
	s := "hello"
	p := StringPtr(s)
	if p == nil {
		t.Fatal("StringPtr returned nil")
	}
	if *p != s {
		t.Fatalf("StringPtr: got %q, want %q", *p, s)
	}
	// 空字符串也应返回有效指针
	p2 := StringPtr("")
	if p2 == nil || *p2 != "" {
		t.Fatal("StringPtr(\"\") should return non-nil pointer to empty string")
	}
}

func TestBoolPtr(t *testing.T) {
	for _, b := range []bool{true, false} {
		p := BoolPtr(b)
		if p == nil {
			t.Fatalf("BoolPtr(%v) returned nil", b)
		}
		if *p != b {
			t.Fatalf("BoolPtr(%v): got %v", b, *p)
		}
	}
}

func TestInt64Ptr(t *testing.T) {
	for _, v := range []int64{0, -1, 1, 9223372036854775807, -9223372036854775808} {
		p := Int64Ptr(v)
		if p == nil {
			t.Fatalf("Int64Ptr(%d) returned nil", v)
		}
		if *p != v {
			t.Fatalf("Int64Ptr(%d): got %d", v, *p)
		}
	}
}

func TestPaginate(t *testing.T) {
	cases := []struct {
		page, pageSize   int
		wantOff, wantLim int
	}{
		{1, 20, 0, 20},
		{2, 20, 20, 20},
		{3, 10, 20, 10},
		// 默认值：page < 1 → 1
		{0, 20, 0, 20},
		{-5, 20, 0, 20},
		// 默认值：pageSize < 1 → 20
		{1, 0, 0, 20},
		{1, -1, 0, 20},
		// pageSize > 200 → 200
		{1, 201, 0, 200},
		{1, 200, 0, 200},
		// 边界：第二页，pageSize=1
		{2, 1, 1, 1},
	}

	for _, c := range cases {
		off, lim := Paginate(c.page, c.pageSize)
		if off != c.wantOff || lim != c.wantLim {
			t.Errorf("Paginate(%d, %d) = (%d, %d), want (%d, %d)",
				c.page, c.pageSize, off, lim, c.wantOff, c.wantLim)
		}
	}
}

func TestParseUint(t *testing.T) {
	v, err := ParseUint("42")
	if err != nil || v != 42 {
		t.Fatalf("ParseUint(\"42\") = %d, %v", v, err)
	}

	v, err = ParseUint("0")
	if err != nil || v != 0 {
		t.Fatalf("ParseUint(\"0\") = %d, %v", v, err)
	}

	_, err = ParseUint("")
	if err == nil {
		t.Fatal("ParseUint(\"\") should return error")
	}

	_, err = ParseUint("-1")
	if err == nil {
		t.Fatal("ParseUint(\"-1\") should return error for negative input")
	}

	_, err = ParseUint("abc")
	if err == nil {
		t.Fatal("ParseUint(\"abc\") should return error")
	}
}

func TestParseUintDefault(t *testing.T) {
	if v := ParseUintDefault("10", 5); v != 10 {
		t.Fatalf("ParseUintDefault(\"10\", 5) = %d, want 10", v)
	}

	if v := ParseUintDefault("", 7); v != 7 {
		t.Fatalf("ParseUintDefault(\"\", 7) = %d, want 7", v)
	}

	if v := ParseUintDefault("bad", 99); v != 99 {
		t.Fatalf("ParseUintDefault(\"bad\", 99) = %d, want 99", v)
	}

	if v := ParseUintDefault("0", 5); v != 0 {
		t.Fatalf("ParseUintDefault(\"0\", 5) = %d, want 0", v)
	}
}
