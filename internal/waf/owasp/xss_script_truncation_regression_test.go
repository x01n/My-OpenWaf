package owasp

import "testing"

func TestHarmlessInlineScriptHandlesTruncatedOpenTag(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"标签体内提前出现闭合标签", "<script </script>"},
		{"开标签带属性后提前闭合", "<script src=x</script>"},
		{"开标签内混入尖括号", "<script <</script>"},
		{"多处提前闭合", "<script a <script b</script>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("isHarmlessInlineScriptOnly(%q) panicked: %v", tc.input, r)
				}
			}()
			if got := isHarmlessInlineScriptOnly(tc.input); got {
				t.Fatalf("isHarmlessInlineScriptOnly(%q) = true, want false (截断的开标签不是合法元素)", tc.input)
			}
		})
	}
}

/**
 * TestHarmlessInlineScriptStillAcceptsCleanStructure 确认修复没有收紧正常放行面：
 * 完整闭合的纯外链元素与无载荷内联体仍应判为无害。
 */
func TestHarmlessInlineScriptStillAcceptsCleanStructure(t *testing.T) {
	cases := []string{
		`<script src="https://cdn.example.com/app.js"></script>`,
		`<script src="/assets/app.js"></script>`,
	}
	for _, in := range cases {
		if got := isHarmlessInlineScriptOnly(in); !got {
			t.Fatalf("isHarmlessInlineScriptOnly(%q) = false, want true", in)
		}
	}
}
