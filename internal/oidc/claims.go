package oidc

import (
	"fmt"
	"strings"
)

func claimString(claims map[string]any, key string) string {
	v, ok := claims[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func claimStringSlice(claims map[string]any, key string) []string {
	if key == "resource_access.*.roles" {
		return resourceAccessRoles(claims)
	}
	if strings.Contains(key, ".") {
		if v := walkClaimPath(claims, key); v != nil {
			return flattenStringSlice(v)
		}
		return nil
	}
	v, ok := claims[key]
	if !ok || v == nil {
		return nil
	}
	return flattenStringSlice(v)
}

func walkClaimPath(claims map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var cur any = claims
	for _, part := range parts {
		if part == "*" {
			return cur
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func resourceAccessRoles(claims map[string]any) []string {
	raw, ok := claims["resource_access"].(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, client := range raw {
		for _, role := range flattenStringSlice(client) {
			if _, ok := seen[role]; ok {
				continue
			}
			seen[role] = struct{}{}
			out = append(out, role)
		}
	}
	return out
}

func flattenStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			appendStringSlice(&out, item)
		}
		return out
	case []string:
		return t
	case map[string]any:
		if roles, ok := t["roles"]; ok {
			return flattenStringSlice(roles)
		}
		var out []string
		for _, item := range t {
			appendStringSlice(&out, item)
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		parts := strings.Fields(t)
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	default:
		s := strings.TrimSpace(fmt.Sprint(t))
		if s == "" {
			return nil
		}
		return []string{s}
	}
}

func appendStringSlice(out *[]string, item any) {
	switch t := item.(type) {
	case map[string]any:
		if roles, ok := t["roles"]; ok {
			*out = append(*out, flattenStringSlice(roles)...)
			return
		}
		s := strings.TrimSpace(fmt.Sprint(t))
		if s != "" {
			*out = append(*out, s)
		}
	default:
		s := strings.TrimSpace(fmt.Sprint(item))
		if s != "" {
			*out = append(*out, s)
		}
	}
}
