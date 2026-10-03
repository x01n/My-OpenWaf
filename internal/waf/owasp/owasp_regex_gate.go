package owasp

import "strings"

type owaspPatternGate struct {
	musts []string
}

// passes 判定单条门：musts 全部出现即真。
func (g owaspPatternGate) passes(s string) bool {
	for _, m := range g.musts {
		if !strings.Contains(s, m) {
			return false
		}
	}
	return true
}

var owaspPatternGates = map[string]owaspPatternGate{
	"owasp:xxe:004":     {musts: []string{"%", ";"}},
	"owasp:ldap:004":    {musts: []string{"(|", "*", "="}},
	"owasp:nosql:014":   {musts: []string{"$", "{"}},
	"owasp:ssti:015":    {musts: []string{"{", ":", "("}},
	"owasp:ssti:016":    {musts: []string{"{", ":", "(", "}"}},
	"owasp:jndi:003":    {musts: []string{"${", "}"}},
	"owasp:graphql:006": {musts: []string{"query", ":"}},
	"owasp:graphql:007": {musts: []string{"@", "(", "if", ":", "$"}},
}

func owaspPatternGatePass(p owaspPattern, s string) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	if g, ok := owaspPatternGates[p.id]; ok {
		return g.passes(s)
	}
	return true
}
