package roles

import (
	"strings"
)

// Mapper converts IdP claim values into local RBAC role names.
type Mapper struct {
	Claim        string
	StaticMap    map[string]string // IdP value → local role
	DefaultRoles []string
}

func NewMapper(claim, roleMapCSV, defaultRolesCSV string) *Mapper {
	if claim == "" {
		claim = "groups"
	}
	m := &Mapper{
		Claim:        claim,
		StaticMap:    parseKVMap(roleMapCSV),
		DefaultRoles: splitCSV(defaultRolesCSV),
	}
	if len(m.DefaultRoles) == 0 {
		m.DefaultRoles = []string{"user"}
	}
	return m
}

// MapClaimValues maps raw IdP group/role strings to local roles.
// If StaticMap is empty, claim values are used as local role names as-is.
// If no roles result, DefaultRoles is returned.
func (m *Mapper) MapClaimValues(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(r string) {
		r = strings.TrimSpace(r)
		if r == "" {
			return
		}
		if _, ok := seen[r]; ok {
			return
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}

	if len(m.StaticMap) == 0 {
		for _, v := range values {
			add(v)
		}
	} else {
		for _, v := range values {
			if local, ok := m.StaticMap[v]; ok {
				add(local)
			}
		}
	}

	if len(out) == 0 {
		for _, r := range m.DefaultRoles {
			add(r)
		}
	}
	return out
}

func parseKVMap(csv string) map[string]string {
	out := make(map[string]string)
	for _, part := range splitCSV(csv) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
