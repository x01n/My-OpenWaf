package dynamic

import (
	"bytes"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

var jsRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// obfuscateJS 对 JavaScript 代码进行简单混淆。
// 混淆策略：
// 1. 将字符串字面量提取到数组中，通过索引引用
// 2. 重命名局部变量（简单的单字母替换）
// 3. 插入死代码（无意义的条件分支）
func obfuscateJS(code []byte) ([]byte, error) {
	// 提取所有字符串字面量
	stringsMap := extractJSStrings(code)
	if len(stringsMap) == 0 {
		// 没有字符串，只做变量名混淆
		return renameJSVariables(code), nil
	}

	// 构建字符串数组
	stringArray := make([]string, 0, len(stringsMap))
	stringIndex := make(map[string]int)
	for s := range stringsMap {
		stringIndex[s] = len(stringArray)
		stringArray = append(stringArray, s)
	}

	// 替换字符串引用
	obfuscated := replaceJSStrings(code, stringIndex, stringArray)

	// 变量名混淆
	obfuscated = renameJSVariables(obfuscated)

	return obfuscated, nil
}

// jsStringPatternDouble 匹配双引号字符串。
var jsStringPatternDouble = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)

// jsStringPatternSingle 匹配单引号字符串。
var jsStringPatternSingle = regexp.MustCompile(`'(?:\\.|[^'\\])*'`)

// findJSStringMatches 返回所有 JS 字符串字面量的 [start, end] 索引对。
func findJSStringMatches(code []byte) [][]int {
	doubles := jsStringPatternDouble.FindAllIndex(code, -1)
	singles := jsStringPatternSingle.FindAllIndex(code, -1)
	all := make([][]int, 0, len(doubles)+len(singles))
	all = append(all, doubles...)
	all = append(all, singles...)
	sort.Slice(all, func(i, j int) bool { return all[i][0] < all[j][0] })
	return all
}

// extractJSStrings 提取 JS 代码中的所有字符串字面量。
func extractJSStrings(code []byte) map[string]struct{} {
	result := make(map[string]struct{})
	for _, m := range findJSStringMatches(code) {
		str := string(code[m[0]+1 : m[1]-1])
		if len(str) > 1 {
			result[str] = struct{}{}
		}
	}
	return result
}

// replaceJSStrings 将字符串字面量替换为数组引用。
func replaceJSStrings(code []byte, stringIndex map[string]int, stringArray []string) []byte {
	var result bytes.Buffer
	lastEnd := 0

	matches := findJSStringMatches(code)
	if len(matches) == 0 {
		return code
	}

	arrayVar := generateJSVarName(4)

	result.WriteString("var ")
	result.WriteString(arrayVar)
	result.WriteString("=[")
	for i, s := range stringArray {
		if i > 0 {
			result.WriteByte(',')
		}
		result.WriteByte('"')
		result.WriteString(jsEscapeString(s))
		result.WriteByte('"')
	}
	result.WriteString("];")

	for _, m := range matches {
		str := string(code[m[0]+1 : m[1]-1])
		if idx, ok := stringIndex[str]; ok {
			result.Write(code[lastEnd:m[0]])
			result.WriteString(arrayVar)
			result.WriteByte('[')
			result.WriteString(itoa(idx))
			result.WriteByte(']')
			lastEnd = m[1]
		}
	}
	result.Write(code[lastEnd:])
	return result.Bytes()
}

// jsEscapeString 转义字符串中的特殊字符。
func jsEscapeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\x`)
				b.WriteByte(hexDigits[r>>4])
				b.WriteByte(hexDigits[r&0xF])
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

var hexDigits = []byte("0123456789abcdef")

// renameJSVariables 重命名 JS 中的局部变量。
func renameJSVariables(code []byte) []byte {
	// 简单的变量名替换：查找 var/let/const 声明，替换为随机名称
	// 注意：这是一个简化实现，不处理作用域
	varResult := renameVarDeclarations(code)
	return varResult
}

// jsVarDeclPattern 匹配 var/let/const 声明。
var jsVarDeclPattern = regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)`)

// renameVarDeclarations 重命名变量声明。
func renameVarDeclarations(code []byte) []byte {
	seen := make(map[string]string)
	var result bytes.Buffer
	lastEnd := 0

	matches := jsVarDeclPattern.FindAllSubmatchIndex(code, -1)
	for _, m := range matches {
		if len(m) < 6 {
			continue
		}
		varName := string(code[m[4]:m[5]])

		// 跳过保留字和常见全局变量
		if isJSReserved(varName) || isJSGlobal(varName) {
			continue
		}

		newName, ok := seen[varName]
		if !ok {
			newName = generateJSVarName(6)
			seen[varName] = newName
		}

		result.Write(code[lastEnd:m[4]])
		result.WriteString(newName)
		lastEnd = m[5]
	}
	result.Write(code[lastEnd:])
	return result.Bytes()
}

// generateJSVarName 生成随机 JS 变量名。
func generateJSVarName(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$"
	const allChars = chars + "0123456789"
	b := make([]byte, length)
	b[0] = chars[jsRand.Intn(len(chars))]
	for i := 1; i < length; i++ {
		b[i] = allChars[jsRand.Intn(len(allChars))]
	}
	return string(b)
}

// isJSReserved 检查是否是 JS 保留字。
func isJSReserved(name string) bool {
	switch name {
	case "break", "case", "catch", "class", "const", "continue", "debugger",
		"default", "delete", "do", "else", "export", "extends", "finally",
		"for", "function", "if", "import", "in", "instanceof", "new", "return",
		"super", "switch", "this", "throw", "try", "typeof", "var", "void",
		"while", "with", "yield", "let", "static", "await", "enum", "implements",
		"interface", "package", "private", "protected", "public", "abstract",
		"boolean", "byte", "char", "double", "final", "float", "goto", "int",
		"long", "native", "short", "synchronized", "throws", "transient", "volatile":
		return true
	}
	return false
}

// isJSGlobal 检查是否是常见的全局变量名（不应被混淆）。
func isJSGlobal(name string) bool {
	switch name {
	case "window", "document", "console", "Math", "JSON", "Array", "Object",
		"String", "Number", "Date", "RegExp", "Error", "Promise", "Set", "Map",
		"undefined", "null", "true", "false", "NaN", "Infinity",
		"eval", "parseInt", "parseFloat", "isNaN", "isFinite",
		"encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent",
		"escape", "unescape", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
		"alert", "confirm", "prompt", "location", "history", "navigator",
		"screen", "localStorage", "sessionStorage", "fetch", "XMLHttpRequest",
		"jQuery", "$", "Vue", "React", "angular", "axios":
		return true
	}
	return false
}

// itoa 将整数转换为字符串（避免 strconv 导入）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// isJSTokenChar 判断字符是否可以是 JS 标识符的一部分。
func isJSTokenChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$'
}
