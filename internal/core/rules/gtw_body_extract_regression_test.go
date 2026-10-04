package rules

import (
	"strings"
	"testing"
)

/**
 * 本文件是 gotestwaf 剩余缺口修复线的请求体抽取专项回归，只断言
 * extractBodyTargets 的输出形态，不引用任何检测层包：
 *  1. community-rce-rawrequests：form-urlencoded 体 `cmd=127.0.0.1 && ls /etc`
 *     —— 按 & 拆分会把 `&&` 命令链切断，需保留整串目标。
 *  2. community-lfi-multipart：UNC 路径出现在 multipart 的 form name 位
 *     —— mime 解析对 quoted-string 做反转义（\\ → \），双反斜杠前缀被吞，
 *     需以 Content-Disposition 头部原文作为补充扫描目标。
 *  3. owasp-api rest：JSON 值内的 SQLi 短语需被完整抽出（含 \uXXXX 解码）。
 *
 * 检测层（哪条规则命中、命中分数）的断言在 internal/waf/owasp 包内，
 * 见 gtw_gap_regression_test.go。本包只负责「抽得全、抽得准、不过度抽取」，
 * 刻意不跨包调用检测引擎：两个包各自独立演进，避免测试互相拖红。
 */

// targetsContain 判断抽取结果中是否存在满足谓词的目标。
func targetsContain(targets []string, pred func(string) bool) bool {
	for _, tg := range targets {
		if pred(tg) {
			return true
		}
	}
	return false
}

// TestGTWBodyFormAndChainPreserved 覆盖 form-urlencoded 体中的 `&&` 命令链。
func TestGTWBodyFormAndChainPreserved(t *testing.T) {
	body := "cmd=127.0.0.1 && ls /etc"
	targets := extractBodyTargets([]byte(body), "application/x-www-form-urlencoded")

	// 整串必须作为目标保留：拆段后的 `" ls /etc"` 已无命令链上下文。
	if !targetsContain(targets, func(s string) bool { return s == body }) {
		t.Fatalf("form `&&` 命令链未保留整串目标，抽取结果 = %q", targets)
	}
	// 逐段抽取不得因新增整串分支而丢失（键名与值仍各自入库）。
	for _, want := range []string{"cmd", "127.0.0.1 ", " ls /etc"} {
		if !targetsContain(targets, func(s string) bool { return s == want }) {
			t.Fatalf("逐段目标 %q 丢失，抽取结果 = %q", want, targets)
		}
	}

	// `||` 同属命令链分隔符，整串同样保留。
	orBody := "filter=ready || render"
	orTargets := extractBodyTargets([]byte(orBody), "application/x-www-form-urlencoded")
	if !targetsContain(orTargets, func(s string) bool { return s == orBody }) {
		t.Fatalf("form `||` 链未保留整串目标，抽取结果 = %q", orTargets)
	}

	// 反例：不含 `&&`/`||` 的普通表单不得新增整串目标（分支足够窄）。
	plain := "name=alice&role=user"
	plainTargets := extractBodyTargets([]byte(plain), "application/x-www-form-urlencoded")
	if targetsContain(plainTargets, func(s string) bool { return s == plain }) {
		t.Fatalf("普通表单被误加整串目标，抽取结果 = %q", plainTargets)
	}
	for _, want := range []string{"alice", "name", "user", "role"} {
		if !targetsContain(plainTargets, func(s string) bool { return s == want }) {
			t.Fatalf("普通表单逐段目标 %q 丢失，抽取结果 = %q", want, plainTargets)
		}
	}
}

// TestGTWBodyMultipartRawDispositionName 覆盖 multipart form name 位的原始字节。
func TestGTWBodyMultipartRawDispositionName(t *testing.T) {
	const boundary = "bee3b1c4dbd3303d1f1b9a03ffd31afeaa"
	unc := `\\::1\c$\users\default\ntuser.dat`
	// mime 对 quoted-string 的反转义结果：双反斜杠前缀被吞成一个。
	unescaped := `\::1\c$\users\default\ntuser.dat`
	body := "--" + boundary + "\r\n" +
		"Content-disposition: form-data; name=\"" + unc + "\"\r\n" +
		"\r\n" +
		"Test\r\n" +
		"--" + boundary + "--\r\n"
	ct := "multipart/form-data; boundary=" + boundary

	targets := extractBodyTargets([]byte(body), ct)

	// 头部原文形态必须入库：依赖双反斜杠前缀的规则只在原文上匹配。
	if !targetsContain(targets, func(s string) bool { return s == unc }) {
		t.Fatalf("multipart form name 位原始双反斜杠形态未保留为扫描目标，抽取结果 = %q", targets)
	}
	// mime 解析形态同样保留，两种形态并存而不是互相取代。
	if !targetsContain(targets, func(s string) bool { return s == unescaped }) {
		t.Fatalf("multipart form name 位的 mime 解析形态丢失，抽取结果 = %q", targets)
	}
	// 值位内容不受影响。
	if !targetsContain(targets, func(s string) bool { return s == "Test" }) {
		t.Fatalf("multipart 字段值丢失，抽取结果 = %q", targets)
	}

	// 反例 1：良性 multipart 字段（含普通 name 与文件上传）不得被过度抽取：
	// 既不能把整行头部塞进目标，也不能凭空产生反斜杠变体。
	benignBody := "--" + boundary + "\r\n" +
		"Content-disposition: form-data; name=\"username\"\r\n" +
		"\r\n" +
		"alice\r\n" +
		"--" + boundary + "\r\n" +
		"Content-disposition: form-data; name=\"avatar\"; filename=\"photo.png\"\r\n" +
		"Content-Type: image/png\r\n" +
		"\r\n" +
		"fakepngbytes\r\n" +
		"--" + boundary + "--\r\n"
	benignTargets := extractBodyTargets([]byte(benignBody), ct)
	for _, tg := range benignTargets {
		if strings.ContainsAny(tg, "\\\r\n") || strings.Contains(tg, "Content-disposition") {
			t.Fatalf("良性 multipart 抽取结果含头部骨架或反斜杠，过度抽取：%q（全量 %q）", tg, benignTargets)
		}
	}
	for _, want := range []string{"username", "alice", "fakepngbytes"} {
		if !targetsContain(benignTargets, func(s string) bool { return s == want }) {
			t.Fatalf("良性 multipart 目标 %q 丢失，抽取结果 = %q", want, benignTargets)
		}
	}
	// 既有边界（生产代码 file part 分支在收内容前 continue）：file part 的
	// name 位不入库，只有其内容片段被抽。此处锁定该行为，防无意扩大范围。
	if targetsContain(benignTargets, func(s string) bool { return s == "avatar" }) {
		t.Fatalf("file part 的 name 位意外入库，抽取范围被扩大：%q", benignTargets)
	}

	// 反例 2：普通路径 form name 只以原文一种形态入库，不产生双反斜杠变体。
	plainPath := "uploads/2026/report.pdf"
	plainBody := "--" + boundary + "\r\n" +
		"Content-disposition: form-data; name=\"" + plainPath + "\"\r\n" +
		"\r\n" +
		"ok\r\n" +
		"--" + boundary + "--\r\n"
	plainTargets := extractBodyTargets([]byte(plainBody), ct)
	rawCount := 0
	for _, tg := range plainTargets {
		if tg == plainPath {
			rawCount++
		}
	}
	if rawCount != 1 {
		t.Fatalf("普通路径 form name 入库次数 = %d，期望 1（抽取结果 %q）", rawCount, plainTargets)
	}
}

// TestGTWBodyJSONUnionValue 覆盖 JSON 值内 SQLi 短语的抽取：\uXXXX 转义需还原。
func TestGTWBodyJSONUnionValue(t *testing.T) {
	// JSONRequest placeholder 的实际形态：值经 JSUnicode 编码（\u00XX 逐字符）。
	body := `{"test": true, "0123456789abcdef": "1e1 union select users from password"}`
	const want = "1e1 union select users from password"
	targets := extractBodyTargets([]byte(body), "application/json")
	if !targetsContain(targets, func(s string) bool { return s == want }) {
		t.Fatalf("JSON 值内 \\uXXXX 编码的短语未还原为 %q，抽取结果 = %q", want, targets)
	}
	// 键名同样入库（攻击者可在键名注入）。
	if !targetsContain(targets, func(s string) bool { return s == "0123456789abcdef" }) {
		t.Fatalf("JSON 键名未入库，抽取结果 = %q", targets)
	}

	// 反例：普通 JSON 业务字段只抽出叶子值与键名，不重复整串、不含转义残留。
	benign := `{"test": true, "name": "alice", "role": "user", "note": "thanks for your order"}`
	benignTargets := extractBodyTargets([]byte(benign), "application/json")
	for _, tg := range benignTargets {
		if strings.Contains(tg, "\\u") || strings.HasPrefix(tg, "{") {
			t.Fatalf("良性 JSON 抽取结果含转义残留或整串 JSON，过度抽取：%q（全量 %q）", tg, benignTargets)
		}
	}
	for _, want := range []string{"alice", "user", "thanks for your order", "name", "role", "note"} {
		if !targetsContain(benignTargets, func(s string) bool { return s == want }) {
			t.Fatalf("良性 JSON 目标 %q 丢失，抽取结果 = %q", want, benignTargets)
		}
	}
}
