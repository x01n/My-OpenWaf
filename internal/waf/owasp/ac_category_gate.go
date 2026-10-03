package owasp

import (
	"sync"

	"My-OpenWaf/internal/ac"
)

var jndiUnicodeEscQ = string([]byte{92, 117, 48, 48, 50, 52, 92, 117, 48, 48, 55})

// 族 token。
const (
	famSSRF int32 = iota
	famPathTrav
	famXXE
	famLDAP
	famNoSQLi
	famTemplate
	famJNDI
	famCRLF
	famDeser
	famEL
	famGraphQL
	famCount // 非 token；族循环上界
)

type acFamilyNeedles struct {
	name      string
	orNeedles []string // 纯 OR 判定字面量（族自动机）
	andLeft   []string // AND 链左臂（模板族：constructor）
	andRight  []string // AND 链右臂（模板族：{{|${|<%）
	gateOnly  []string // 只进总表的必要条件字面
}

var owaspACFamilies = [famCount]acFamilyNeedles{
	famSSRF: {
		// hasSSRFIndicator（owasp_extended.go，19 条纯 OR）
		name: "ssrf",
		orNeedles: []string{
			"://", "169.254.169.254", "metadata.google", "100.100.100.200",
			"x-aws-ec2-metadata", "localhost", "127.0.", "127.1", "::ffff:", "::1",
			"0x7f", "0x7f000001", "0x0a0a0a0a", "unix:", "0177.0",
			".nip.io", ".xip.io", ".sslip.io", "2130706433",
		},
	},
	famPathTrav: {
		// hasPathTravIndicator（owasp.go，11 条纯 OR）
		name: "path_trav",
		orNeedles: []string{
			"..", "%2e%2e", "%252e", "%252f", "etc/", "/proc/",
			"win.ini", "boot.ini", "..;", "web-inf", "meta-inf",
			"c$", "admin$", "ipc$",
		},
	},
	famXXE: {
		name: "xxe",
		orNeedles: []string{
			"<!doctype", "<!entity", "!entity", "xsi:", " system ",
			" public ", "xi:include", "xs:include", "xs:import",
			"xs:schemalocation", "file://", "expect://", "php://",
		},
		gateOnly: []string{"%"},
	},
	famLDAP: {
		name: "ldap",
		orNeedles: []string{
			")(", "objectclass", ")(|", ")(&",
			// LDAP 属性 OID（userPassword 2.5.13.18 / uniqueMember
			// 2.5.4.31 等 LDAP-X.500 标准属性值）；纯数字加点的形态
			// 只出现在 OID/版本号语境，误报极低。
			"2.5.13.18",
		},
	},
	famNoSQLi: {
		name: "nosqli",
		orNeedles: []string{
			"$where", "$ne", "$gt", "$lt", "$gte", "$lte", "$regex",
			"$or", "$and", "$exists", "$lookup", "$function", "$accumulator",
			"$match", "/_all_docs", "/_find", "/_view/", "allow filtering",
			"evalsha", "eval ", "this.",
			// HTML 实体转义后的 $or（&#36; 形态经实体解码还原，$apos;or
			// 半实体形态则原样保留），配合 nosql:005 的 `$or[:[]` 需在
			// 门内可见。只在实体上下文（$apos;）出现，非转义输入不会拼出。
			"$apos;or",
			"injection.", "new date",
		},
	},
	famTemplate: {
		// hasTemplateInjectionIndicator（owasp_extended.go，14 条纯 OR +
		// AND 链 constructor && ({{|${|<%)；三条括号标记也是纯 OR 项）
		name: "template",
		orNeedles: []string{
			"{{", "${", "<%", "__class__", "__proto__", "__subclasses__",
			"__builtins__", "__import__", "getclass(", "java.lang.",
			"process.env", "{php}", "$self.", "{dede:", "#{",
		},
		andLeft:  []string{"constructor"},
		andRight: []string{"{{", "${", "<%"},
	},
	famJNDI: {
		// hasJNDIIndicator（owasp_extended.go，8 条纯 OR；末条为 12 字节
		// ASCII 序列，用 jndiUnicodeEscQ 构建（见其注释））
		name: "jndi",
		orNeedles: []string{
			"jndi:", "${lower", "${upper", "${env:", "${sys:", "${java:",
			"${base64:", jndiUnicodeEscQ,
		},
	},
	famCRLF: {
		name: "crlf",
		orNeedles: []string{
			"%0d", "%0a", "\r", "\n", "set-cookie:", "location:", "content-type:",
			"rcpt to:", "capability", "fetch",
		},
	},
	famDeser: {
		// hasDeserializationIndicator（owasp_extended.go，18 条 Contains
		// 纯 OR，含 Java 序列化魔数（0xAC 0xED 0x00 0x05 四字节），
		// 另外两条 PHP 序列化状态机由网关在回放层原样调用，
		// "o:"/"s:" 是它们的必要条件字面）
		name: "deser",
		orNeedles: []string{
			"\xac\xed\x00\x05", "aced0005", "ro0ab", "ysoserial", "aaeaaad//", "nd_func",
			"objectinputstream", "xstream", "<sorted-set", "<tree-map",
			"<dynamic-proxy", "java.util", "javax.", "jdk.",
			"com.sun.org.apache.xalan", "org.apache.commons.collections",
			"readobject", "deserializ",
		},
		gateOnly: []string{"o:", "s:"},
	},
	famEL: {
		name: "el",
		orNeedles: []string{
			"#{t(", "${t(", "${", "java.lang.", "getclass()", "getruntime",
			"getdeclaredmethods", "#rt", "@java.", "#context", "%{#",
			"new java.", "newjava.",
			// YAML 反序列化 RCE 载荷头（!!python/object/new:exec 等）：
			// 该类文本形态归 EL 族拦（owasp:el:014）。!! 双叹号缩写词在自然
			// 语言与常见 URL/form 输入中不出现，误报可忽略，防总表负短路。
			"!!",
		},
	},
	famGraphQL: {
		// hasGraphQLIndicator（owasp_extended.go，4 条纯 OR）
		name: "graphql",
		orNeedles: []string{
			"__schema", "__type", "__typename", "introspectionquery",
		},
	},
}

var (
	acGlobalM  *ac.Matcher           // 总表：全部字面量（OR + AND 两臂 + gateOnly）
	acFamM     [famCount]*ac.Matcher // 每族 OR 判定自动机
	acAndLM    [famCount]*ac.Matcher // 每族 AND 左臂自动机（仅模板族非空）
	acAndRM    [famCount]*ac.Matcher // 每族 AND 右臂自动机（仅模板族非空）
	acInitOnce sync.Once
)

// acInit 构建上述全部自动机。空 needle 跳过（历史坑：root 恒命中）。
func acInit() {
	acInitOnce.Do(func() {
		gb := ac.NewBuilder()
		addAll := func(m *ac.Builder, qs []string) {
			for _, q := range qs {
				if q == "" {
					continue
				}
				m.AddPattern(q)
			}
		}
		for fam := int32(0); fam < famCount; fam++ {
			f := &owaspACFamilies[fam]
			addAll(gb, f.orNeedles)
			// AND 两臂（当前仅模板族配置）。
			if len(f.andLeft) > 0 || len(f.andRight) > 0 {
				lb := ac.NewBuilder()
				addAll(lb, f.andLeft)
				acAndLM[fam] = lb.Build()
				rb := ac.NewBuilder()
				addAll(rb, f.andRight)
				acAndRM[fam] = rb.Build()
				addAll(gb, f.andLeft)
				addAll(gb, f.andRight)
			}
			// 必要条件门只进总表。
			addAll(gb, f.gateOnly)
			if len(f.orNeedles) > 0 {
				fb := ac.NewBuilder()
				addAll(fb, f.orNeedles)
				acFamM[fam] = fb.Build()
			}
		}
		acGlobalM = gb.Build()
	})
}

func hasACIndicator(fam int32, s string) bool {
	acInit()
	if !acGlobalM.MatchAny(s) {
		return false
	}
	switch fam {
	case famXXE:
		// 10 条 Contains || reParamEntityChain（"% 必要条件门已保证正则
		// 可命中的输入不被总表负短路）。
		if m := acFamM[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		return reParamEntityChain.MatchString(s)
	case famDeser:
		// 17 条 Contains || PHP 状态机 ×2（"o:"/"s:" 必要门保底）。
		if m := acFamM[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		return hasPHPSerializedObjectIndicator(s) || hasPHPSerializedStringPairIndicator(s)
	default:
		if m := acFamM[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		// 模板族 AND 链：constructor ∧ ({{|${|<%)，按原短路顺序回放。
		if acAndLM[fam] != nil && acAndRM[fam] != nil {
			return acAndLM[fam].MatchAny(s) && acAndRM[fam].MatchAny(s)
		}
		return false
	}
}
