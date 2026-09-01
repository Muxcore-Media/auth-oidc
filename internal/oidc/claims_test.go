package oidc

import (
	"testing"

	"github.com/Muxcore-Media/auth-oidc/internal/roles"
)

func TestClaimStringSliceFlat(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"admin", "user"},
	}
	raw := claimStringSlice(claims, "groups")
	if len(raw) != 2 || raw[0] != "admin" {
		t.Fatalf("flat groups=%v", raw)
	}
	mapper := roles.NewMapper("groups", "", "user")
	mapped := mapper.MapClaimValues(raw)
	if len(mapped) != 2 {
		t.Fatalf("mapped=%v", mapped)
	}
}

func TestClaimStringSliceDotted(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"admin", "offline_access"},
		},
	}
	raw := claimStringSlice(claims, "realm_access.roles")
	if len(raw) != 2 || raw[0] != "admin" {
		t.Fatalf("dotted roles=%v", raw)
	}
}

func TestClaimStringSliceResourceAccess(t *testing.T) {
	claims := map[string]any{
		"resource_access": map[string]any{
			"muxcore": map[string]any{
				"roles": []any{"manage-account"},
			},
			"other": map[string]any{
				"roles": []any{"view-profile"},
			},
		},
	}
	raw := claimStringSlice(claims, "resource_access.*.roles")
	if len(raw) != 2 {
		t.Fatalf("resource_access roles=%v", raw)
	}
}
