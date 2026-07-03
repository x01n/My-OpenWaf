package rules

import (
	"encoding/json"
	"net"
	"strings"

	"My-OpenWaf/internal/tlsmeta"
)

type compoundPattern struct {
	Op        string            `json:"op"`
	Kind      string            `json:"kind"`
	Arg       string            `json:"arg"`
	Children  []compoundPattern `json:"children"`
	If        *compoundPattern  `json:"if"`
	Then      *compoundPattern  `json:"then"`
	Else      *compoundPattern  `json:"else"`
	Window    int64             `json:"window"`
	Threshold int64             `json:"threshold"`
	Duration  int64             `json:"duration"`
}

// ValidatePattern performs syntax and semantic validation for a persisted rule
// pattern. It accepts both simple DSL and JSON compound conditions.
func ValidatePattern(pattern string) (kind, arg string, errs []string) {
	kind, arg = ParsePattern(strings.TrimSpace(pattern))
	if kind == "" {
		return "", "", []string{"pattern must start with a supported matcher prefix or be a valid JSON compound condition"}
	}
	return kind, arg, validateParsedPattern(kind, arg)
}

func validateParsedPattern(kind, arg string) []string {
	if kind == "compound" {
		return validateCompoundPattern(arg)
	}
	if err := validateSimplePattern(kind, arg); err != "" {
		return []string{err}
	}
	return nil
}

func validateCompoundPattern(raw string) []string {
	var cond compoundPattern
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return []string{"compound JSON is invalid"}
	}
	return validateCompoundNode(cond)
}

func validateCompoundNode(cond compoundPattern) []string {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
	case "and", "or":
		if len(cond.Children) == 0 {
			return []string{"compound condition requires at least one child"}
		}
		return validateCompoundChildren(cond.Children)
	case "not":
		if len(cond.Children) == 0 {
			return []string{"not condition requires at least one child"}
		}
		return validateCompoundChildren(cond.Children[:1])
	case "if", "if_else", "ifelse":
		if cond.If == nil || cond.Then == nil {
			return []string{"if condition requires both if and then branches"}
		}
		errs := append(validateCompoundNode(*cond.If), validateCompoundNode(*cond.Then)...)
		if cond.Else != nil {
			errs = append(errs, validateCompoundNode(*cond.Else)...)
		}
		return errs
	case "cc_rate":
		if len(cond.Children) == 0 {
			return []string{"cc_rate condition requires at least one child"}
		}
		return validateCompoundChildren(cond.Children[:1])
	default:
		if cond.If != nil && cond.Then != nil {
			errs := append(validateCompoundNode(*cond.If), validateCompoundNode(*cond.Then)...)
			if cond.Else != nil {
				errs = append(errs, validateCompoundNode(*cond.Else)...)
			}
			return errs
		}
		if cond.Kind == "" {
			return []string{"compound leaf must define kind"}
		}
		if err := validateSimplePattern(cond.Kind, cond.Arg); err != "" {
			return []string{err}
		}
		return nil
	}
}

func validateCompoundChildren(children []compoundPattern) []string {
	errs := make([]string, 0)
	for _, child := range children {
		errs = append(errs, validateCompoundNode(child)...)
	}
	return errs
}

func validateSimplePattern(kind, arg string) string {
	switch kind {
	case "allow_ip", "block_ip":
		if _, _, err := net.ParseCIDR(arg); err == nil {
			return ""
		}
		if net.ParseIP(strings.TrimSpace(arg)) == nil {
			return "IP/CIDR matcher requires a valid IP address or CIDR"
		}
	case "block_path_regex", "block_query_regex", "block_user_agent_regex", "header_order_regex", "full_url_regex":
		if _, err := cachedCompile(arg); err != nil {
			return "pattern uses an invalid regular expression"
		}
	case "block_header_regex", "header_regex":
		_, pattern := splitHeaderArg(arg)
		if _, err := cachedCompile(pattern); err != nil {
			return "pattern uses an invalid regular expression"
		}
	case "query_param_regex":
		_, pattern, ok := strings.Cut(arg, ":")
		if !ok {
			return "query_param_regex requires param:regex format"
		}
		if _, err := cachedCompile(pattern); err != nil {
			return "pattern uses an invalid regular expression"
		}
	case "block_body_regex", "body_regex":
		if _, err := cachedCompile(arg); err != nil {
			return "pattern uses an invalid regular expression"
		}
	case "block_body_json_path":
		_, pattern := splitHeaderArg(arg)
		if pattern != "" {
			if _, err := cachedCompile(pattern); err != nil {
				return "pattern uses an invalid regular expression"
			}
		}
	case "block_multipart":
		if arg != "" {
			if _, err := cachedCompile(arg); err != nil {
				return "pattern uses an invalid regular expression"
			}
		}
	case "tls_version":
		if tlsmeta.NormalizeRuntimeVersionToken(arg) == "" {
			return "tls_version requires a supported TLS version token"
		}
	case "tls_cipher_suite", "tls_cipher_suites":
		values := make(map[string]struct{})
		for _, token := range strings.Split(arg, ",") {
			normalized := normalizeTLSCipherSuiteToken(token)
			if normalized == "" {
				continue
			}
			values[normalized] = struct{}{}
		}
		if len(values) == 0 {
			return "tls_cipher_suites requires at least one valid cipher suite token"
		}
	}
	return ""
}
