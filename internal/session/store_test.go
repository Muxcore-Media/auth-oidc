package session

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateGetDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := New(context.Background(), filepath.Join(dir, "sessions.db"), time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sess, err := s.Create(context.Background(), "uid-1", "alice", []string{"admin", "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(sess.Token) != 64 {
		t.Fatalf("token len=%d want 64 (sha256 hex)", len(sess.Token))
	}

	got, err := s.Get(context.Background(), sess.Token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != "uid-1" || got.Username != "alice" {
		t.Fatalf("identity mismatch: %+v", got)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "admin" {
		t.Fatalf("roles=%v", got.Roles)
	}

	id, err := s.Identity(context.Background(), "uid-1")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Username != "alice" {
		t.Fatalf("identity username=%q", id.Username)
	}

	s.Delete(context.Background(), sess.Token)
	if _, err := s.Get(context.Background(), sess.Token); err == nil {
		t.Fatal("expected miss after delete")
	}
}

func TestExpired(t *testing.T) {
	dir := t.TempDir()
	s, err := New(context.Background(), filepath.Join(dir, "sessions.db"), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sess, err := s.Create(context.Background(), "u", "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := s.Get(context.Background(), sess.Token); err == nil {
		t.Fatal("expected expired")
	}
}

func TestRevokeDropsIdentity(t *testing.T) {
	dir := t.TempDir()
	s, err := New(context.Background(), filepath.Join(dir, "sessions.db"), time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sess, err := s.Create(context.Background(), "uid-1", "alice", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Identity(context.Background(), "uid-1"); err != nil {
		t.Fatalf("Identity before revoke: %v", err)
	}
	s.Revoke(context.Background(), sess.Token)
	if _, err := s.Identity(context.Background(), "uid-1"); err == nil {
		t.Fatal("identity should be removed after last session revoked")
	}
}

func TestRevokeKeepsIdentityWithOtherSession(t *testing.T) {
	dir := t.TempDir()
	s, err := New(context.Background(), filepath.Join(dir, "sessions.db"), time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	s1, err := s.Create(context.Background(), "uid-1", "alice", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := s.Create(context.Background(), "uid-1", "alice", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	s.Revoke(context.Background(), s1.Token)
	if _, err := s.Identity(context.Background(), "uid-1"); err != nil {
		t.Fatal("identity should remain while another session exists")
	}
	s.Revoke(context.Background(), s2.Token)
	if _, err := s.Identity(context.Background(), "uid-1"); err == nil {
		t.Fatal("identity should be removed after all sessions revoked")
	}
}

func TestDurableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.db")
	s1, err := New(context.Background(), path, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sess, err := s1.Create(context.Background(), "uid", "dave", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	token := sess.Token
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := New(context.Background(), path, time.Hour)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	got, err := s2.Get(context.Background(), token)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Username != "dave" {
		t.Fatalf("username=%q", got.Username)
	}
}
