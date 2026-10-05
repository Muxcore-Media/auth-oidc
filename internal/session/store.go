package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const DefaultTTL = 24 * time.Hour

// Session is an opaque bearer session with embedded identity.
type Session struct {
	ExpiresAt time.Time
	Token     string
	UserID    string
	Username  string
	Roles     []string
}

// Identity is the last-known profile for a subject (for Can without a token).
type Identity struct {
	UserID   string
	Username string
	Roles    []string
}

// Store holds opaque sessions in SQLite.
type Store struct {
	db  *sql.DB
	mu  sync.Mutex
	ttl time.Duration
}

func New(ctx context.Context, path string, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, ttl: ttl}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			token      TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			username   TEXT NOT NULL DEFAULT '',
			roles      TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS identities (
			user_id  TEXT PRIMARY KEY,
			username TEXT NOT NULL DEFAULT '',
			roles    TEXT NOT NULL DEFAULT '[]'
		)`,
	}
	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, userID, username string, roles []string) (*Session, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id required")
	}
	token, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	rolesCopy := append([]string(nil), roles...)
	rolesJSON, _ := json.Marshal(rolesCopy)
	expiresAt := time.Now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (token, user_id, username, roles, expires_at) VALUES (?, ?, ?, ?, ?)`,
		token, userID, username, string(rolesJSON), expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO identities (user_id, username, roles) VALUES (?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, roles = excluded.roles`,
		userID, username, string(rolesJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("upsert identity: %w", err)
	}
	return &Session{
		Token:     token,
		UserID:    userID,
		Username:  username,
		Roles:     rolesCopy,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Store) Get(ctx context.Context, token string) (*Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, user_id, username, roles, expires_at FROM sessions WHERE token = ?`,
		token,
	)
	var sess Session
	var rolesJSON, expiresAt string
	if err := row.Scan(&sess.Token, &sess.UserID, &sess.Username, &rolesJSON, &expiresAt); err != nil {
		return nil, fmt.Errorf("session not found")
	}
	if err := json.Unmarshal([]byte(rolesJSON), &sess.Roles); err != nil {
		slog.Warn("corrupt roles data for session", "token", token[:min(8, len(token))], "error", err)
		sess.Roles = nil
	}
	sess.ExpiresAt = parseTime(expiresAt)
	if sess.ExpiresAt.IsZero() {
		slog.Warn("session has unparseable expiration, treating as expired", "token", token[:min(8, len(token))])
		s.Delete(ctx, token)
		return nil, fmt.Errorf("session expired")
	}
	if time.Now().After(sess.ExpiresAt) {
		s.Delete(ctx, token)
		return nil, fmt.Errorf("session expired")
	}
	return &sess, nil
}

func (s *Store) Identity(ctx context.Context, userID string) (*Identity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, username, roles FROM identities WHERE user_id = ?`,
		userID,
	)
	var id Identity
	var rolesJSON string
	if err := row.Scan(&id.UserID, &id.Username, &rolesJSON); err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := json.Unmarshal([]byte(rolesJSON), &id.Roles); err != nil {
		slog.Warn("corrupt roles data for identity", "user_id", userID, "error", err)
		id.Roles = nil
	}
	return &id, nil
}

func (s *Store) Delete(ctx context.Context, token string) {
	s.Revoke(ctx, token)
}

// Revoke deletes a session and drops the identity row when no sessions remain.
func (s *Store) Revoke(ctx context.Context, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID := s.deleteSessionLocked(ctx, token)
	if userID != "" {
		s.cleanupIdentityIfNoSessionsLocked(ctx, userID)
	}
}

func (s *Store) deleteSessionLocked(ctx context.Context, token string) string {
	row := s.db.QueryRowContext(ctx, `SELECT user_id FROM sessions WHERE token = ?`, token)
	var userID string
	if err := row.Scan(&userID); err != nil {
		return ""
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return userID
}

func (s *Store) cleanupIdentityIfNoSessionsLocked(ctx context.Context, userID string) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = ?`, userID).Scan(&count); err != nil || count > 0 {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM identities WHERE user_id = ?`, userID)
}

func (s *Store) Count(ctx context.Context) int {
	_ = s.CleanupExpired(ctx)
	var count int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, time.Now().Format(time.RFC3339)).Scan(&count)
	return count
}

func (s *Store) CleanupExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Format(time.RFC3339))
	return err
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", s)
		if err != nil {
			slog.Warn("failed to parse timestamp", "value", s, "error", err)
			return time.Time{}
		}
	}
	return t
}
