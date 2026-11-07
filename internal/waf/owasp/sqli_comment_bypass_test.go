package owasp

import "testing"

/**
 * TestSQLiCommentPaddingBypass 锁定「空块注释作空格」盲注家族的命中形态。
 *
 * 该家族把 SQL 语句里的空格全部换成空块注释（斜杠 星号 星号 斜杠），并用
 * `%%27` 之类非法百分号序列阻断严格解码。三条防线共同覆盖：
 *  1. normalizeBeforeSQLComments 的容错 URL 解码（非法序列不再中断整串）；
 *  2. normalizeSQLCommentsAsSpaces 的「注释垫空白」视图（and/or/like 两侧）；
 *  3. owasp:sqli:057-059（数字字面量与 like/in/构造函数比较的盲注形态）。
 *
 * 语料口径：/agc/timeclock.php 的 64 条黑样本子请求，修复前全量漏报。
 */
func TestSQLiCommentPaddingBypass(t *testing.T) {
	cases := []struct{ name, query string }{
		{
			name:  "select sleep 注释分隔",
			query: "referrer=welcome%27%29%29%3BseLEct%2F%2A%2A%2FSleEp%2810%29%23",
		},
		{
			name:  "and 数字 like 子查询",
			query: "referrer=welcome%27%29%2F%2A%2A%2FaND%2F%2A%2A%2F1859%2F%2A%2A%2FLike%2F%2A%2A%2F%28sElEct%2F%2A%2A%2FCOunT%28%2A%29%29",
		},
		{
			name:  "or 数字 in 子查询",
			query: "referrer=-5689%22%29%2F%2A%2A%2FoR%2F%2A%2A%2F2306%2F%2A%2A%2FiN%2F%2A%2A%2F%28SELEcT%2F%2A%2A%2F%28CHAr%28113%29",
		},
		{
			name:  "非法百分号序列 %%27",
			query: "referrer=-8049%%27%2F%2A%2A%2FoR%2F%2A%2A%2F9746%2F%2A%2A%2FliKe%2F%2A%2A%2F%28SeLecT",
		},
		{
			name:  "and 数字 like concat",
			query: "referrer=welcome%27%29%20and%201892%20like%20concat%28char%28113%29%2Bchar%28122%29%2C%28select%20%28case%20when%20%281892%20like%201892%29%20then%20char%2849%29%20end%29%29",
		},
		{
			name:  "and 数字 like benchmark",
			query: "referrer=agent&pl=%29%20and%209823%20like%20benchmark%2810000000%2Cmd5%280x66574244%29%29%20and%20%287507%20like%207507",
		},
		{
			name:  "rlike 子查询",
			query: "referrer=welcome%25%27%20rlike%20%28select%20%28case%20when%20%289863%20like%209863%29%20then%200x77656c636f6d65%20else%200x28%20end%29%29",
		},
		{
			name:  "and 数字 like convert",
			query: "referrer=welcome%22%20and%205023%20like%20convert%28int%2C%28select%20char%28113%29%2Bchar%28122%29%2B%28select%20%28case%20when%20%285023%20like%205023%29%20end%29%29%29",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := CheckOWASP("mid", "/agc/timeclock.php", tc.query, nil, nil)
			if !hasCategory(hits, CatSQLi) {
				t.Fatalf("query %q 应判为 SQLi，实际命中 %v", tc.query, hitIDs(hits))
			}
		})
	}
}

/**
 * TestSQLiCommentPaddingRejects 锁定「注释垫空白」与三条新规则的反例。
 *
 * 自然语言里的 `and 5 in stock`、普通 CSS/JS 注释、无 SQL 结构的键值对都
 * 必须放行；注释折叠本身不是判定依据。
 */
func TestSQLiCommentPaddingRejects(t *testing.T) {
	cases := []struct{ name, query string }{
		{name: "英文自然语言 and 数字 in", query: "q=red and 5 in stock"},
		{name: "英文自然语言 or 数字 in", query: "q=cat or 2 in cart"},
		{name: "普通键值对", query: "referrer=agent&pl=&pp=-4470"},
		{name: "无 SQL 结构的注释", query: "note=todo/**/later"},
		{name: "正常分页参数", query: "page=2&size=20&sort=desc"},
		{name: "含 like 的正常搜索", query: "q=select your favorite color"},
		{name: "rlike 无子查询", query: "q=name rlike pattern"},
		{name: "正常百分号编码", query: "q=100%25%20cotton"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := CheckOWASP("mid", "/search", tc.query, nil, nil)
			if hasCategory(hits, CatSQLi) {
				t.Fatalf("query %q 不应判为 SQLi，实际命中 %v", tc.query, hitIDs(hits))
			}
		})
	}
}

/**
 * TestUnescapeURLComponentTolerant 锁定容错解码的语义边界。
 *
 * 合法序列照常解码、非法序列只保留 `%` 后继续、query 语义的 '+' 转空格、
 * 解码产生的 '+' 不二次解释。
 */
func TestUnescapeURLComponentTolerant(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a%27b", "a'b"},
		{"%%27", "%'"},
		{"%2F%2A%2A%2F", "/**/"},
		{"a+b", "a b"},
		{"a%2Bb", "a+b"},
		{"%zz", "%zz"},
		{"tail%", "tail%"},
		{"%2527", "%27"},
	}
	for _, tc := range cases {
		if got := unescapeURLComponentTolerant(tc.in, true); got != tc.want {
			t.Errorf("unescapeURLComponentTolerant(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

/**
 * TestNormalizeSQLCommentsAsSpaces 锁定两种注释替换语义的差异。
 *
 * 删除语义用于拆字（sel 空注释 ect 还原为 select），垫空白语义用于 token
 * 分隔（引号 空注释 and 空注释 1 还原为 引号 and 1）。两者必须同时存在，
 * 任一单独实现都会留下完整的一类绕过面。
 */
func TestNormalizeSQLCommentsAsSpaces(t *testing.T) {
	if got := normalizeTarget("sel/**/ect", true); got != "select" {
		t.Errorf("删除语义: sel/**/ect = %q, want %q", got, "select")
	}
	if got := normalizeSQLCommentsAsSpaces("sel/**/ect", true); got != "sel ect" {
		t.Errorf("垫空白语义: sel/**/ect = %q, want %q", got, "sel ect")
	}
	if got := normalizeSQLCommentsAsSpaces("'/**/anD/**/1", true); got != "' and 1" {
		t.Errorf("垫空白语义: ' and 1 = %q", got)
	}
	// 串尾注释不得留下尾随空格。
	if got := normalizeSQLCommentsAsSpaces("1/**/", true); got != "1" {
		t.Errorf("尾随注释 = %q, want %q", got, "1")
	}
}

// hitIDs 提取命中规则 ID，供测试失败信息使用。
func hitIDs(hits []OWASPHit) []string {
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.RuleID)
	}
	return ids
}
