package roles

import "testing"

func TestMapPassthrough(t *testing.T) {
	m := NewMapper("groups", "", "")
	got := m.MapClaimValues([]string{"admin", "viewer"})
	if len(got) != 2 || got[0] != "admin" || got[1] != "viewer" {
		t.Fatalf("got %v", got)
	}
}

func TestMapStatic(t *testing.T) {
	m := NewMapper("groups", "muxcore-admins=admin,muxcore-users=user", "viewer")
	got := m.MapClaimValues([]string{"muxcore-admins", "other"})
	if len(got) != 1 || got[0] != "admin" {
		t.Fatalf("got %v", got)
	}
	got = m.MapClaimValues([]string{"unknown"})
	if len(got) != 1 || got[0] != "viewer" {
		t.Fatalf("default got %v", got)
	}
}
