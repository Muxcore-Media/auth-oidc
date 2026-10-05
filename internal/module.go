package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	manifest "github.com/Muxcore-Media/auth-oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/policy"
	"github.com/Muxcore-Media/auth-oidc/internal/redirectallow"
	"github.com/Muxcore-Media/auth-oidc/internal/roles"
	"github.com/Muxcore-Media/auth-oidc/internal/server"
	"github.com/Muxcore-Media/auth-oidc/internal/session"
	"github.com/Muxcore-Media/auth-oidc/internal/webapp"
	"github.com/Muxcore-Media/core/pkg/contracts"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
)

type Module struct {
	grpcLis              net.Listener
	httpLis              net.Listener
	flow                 oidc.Flow
	grpcSrv              *grpc.Server
	httpSrv              *http.Server
	webHandler           *webapp.Handler
	sessions             *session.Store
	authSrv              *server.AuthServer
	sighupCh             chan os.Signal
	sighupStop           chan struct{}
	sighupDone           chan struct{}
	cleanupStop          chan struct{}
	cleanupDone          chan struct{}
	id                   string
	clientID             string
	grpcAddr             string
	httpAddr             string
	dbPath               string
	policyFile           string
	issuer               string
	allowedRedirectHosts string
	clientSecret         string
	redirectURL          string
	scopes               string
	rolesClaim           string
	roleMap              string
	defaultRoles         string
	sessionTTL           time.Duration
	cfgMu                sync.RWMutex
}

// Config holds module settings. Non-empty fields override environment.
type Config struct {
	// Flow overrides the OIDC provider (tests).
	Flow                 oidc.Flow
	RedirectURL          string
	RoleMap              string
	DBPath               string
	PolicyFile           string
	Issuer               string
	ClientID             string
	HTTPAddr             string
	Scopes               string
	ClientSecret         string
	RolesClaim           string
	ID                   string
	DefaultRoles         string
	AllowedRedirectHosts string
	GRPCAddr             string
	SessionTTL           time.Duration
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "auth-oidc"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = os.Getenv("AUTH_OIDC_GRPC_ADDR")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = os.Getenv("AUTH_OIDC_HTTP_ADDR")
	}
	if cfg.DBPath == "" {
		cfg.DBPath = os.Getenv("AUTH_OIDC_DB_PATH")
	}
	if cfg.PolicyFile == "" {
		cfg.PolicyFile = os.Getenv("AUTH_OIDC_POLICY_FILE")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = os.Getenv("AUTH_OIDC_ISSUER")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = firstEnv("AUTH_OIDC_CLIENT_ID", "CLIENT_ID")
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = firstEnv("AUTH_OIDC_CLIENT_SECRET", "CLIENT_SECRET")
	}
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = firstEnv("AUTH_OIDC_REDIRECT_URL", "REDIRECT_URL")
	}
	if cfg.Scopes == "" {
		cfg.Scopes = os.Getenv("AUTH_OIDC_SCOPES")
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = firstEnv("AUTH_OIDC_ROLES_CLAIM", "ROLES_CLAIM")
	}
	if cfg.RoleMap == "" {
		cfg.RoleMap = os.Getenv("AUTH_OIDC_ROLE_MAP")
	}
	if cfg.DefaultRoles == "" {
		cfg.DefaultRoles = os.Getenv("AUTH_OIDC_DEFAULT_ROLES")
	}
	if cfg.AllowedRedirectHosts == "" {
		cfg.AllowedRedirectHosts = os.Getenv("AUTH_ALLOWED_REDIRECT_HOSTS")
	}

	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9410"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":9412"
	}
	if cfg.PolicyFile == "" {
		cfg.PolicyFile = "policies.yaml"
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "groups"
	}
	if cfg.DBPath == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			cfg.DBPath = "auth-oidc.db"
		} else {
			cfg.DBPath = filepath.Join(home, ".muxcore", "auth-oidc.db")
		}
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = parseDurationEnv("AUTH_OIDC_SESSION_TTL", session.DefaultTTL)
	}

	redirectallow.SetExtraHosts(cfg.AllowedRedirectHosts)

	return &Module{
		id:                   cfg.ID,
		grpcAddr:             cfg.GRPCAddr,
		httpAddr:             cfg.HTTPAddr,
		dbPath:               cfg.DBPath,
		policyFile:           cfg.PolicyFile,
		issuer:               cfg.Issuer,
		clientID:             cfg.ClientID,
		clientSecret:         cfg.ClientSecret,
		redirectURL:          cfg.RedirectURL,
		scopes:               cfg.Scopes,
		rolesClaim:           cfg.RolesClaim,
		roleMap:              cfg.RoleMap,
		defaultRoles:         cfg.DefaultRoles,
		allowedRedirectHosts: cfg.AllowedRedirectHosts,
		sessionTTL:           cfg.SessionTTL,
		flow:                 cfg.Flow,
	}
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Auth OIDC",
		Version:      modulesdk.ManifestVersion(manifest.ManifestJSON),
		Roles:        []string{"security"},
		Description:  "OIDC authentication and authorization provider",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityAuth, contracts.CapabilityAuthorizer, contracts.CapabilityIdentity, "settings"},
		HTTPAddr:     m.httpAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	if dir := filepath.Dir(m.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create db dir: %w", err)
		}
	}

	var err error
	m.sessions, err = session.New(ctx, m.dbPath, m.sessionTTL)
	if err != nil {
		return fmt.Errorf("init sessions: %w", err)
	}

	pol, err := m.loadPolicy()
	if err != nil {
		return err
	}
	m.authSrv = server.New(m.sessions, pol)

	if m.flow == nil {
		if m.issuer == "" || m.clientID == "" || m.redirectURL == "" {
			slog.Warn("OIDC IdP unset; module starts but login soft-fails until AUTH_OIDC_ISSUER, AUTH_OIDC_CLIENT_ID, and AUTH_OIDC_REDIRECT_URL are set (default stacks use auth-local)")
			m.flow = oidc.Disabled{}
		} else {
			flow, perr := m.buildProvider(ctx)
			if perr != nil {
				return fmt.Errorf("init oidc: %w", perr)
			}
			m.flow = flow
		}
	}

	var lc net.ListenConfig
	m.grpcLis, err = lc.Listen(ctx, "tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC %s: %w", m.grpcAddr, err)
	}
	m.httpLis, err = lc.Listen(ctx, "tcp", m.httpAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP %s: %w", m.httpAddr, err)
	}
	m.webHandler = webapp.New(m.sessions, m.authSrv, m.flow)
	slog.Info("auth-oidc initialized",
		"grpc", m.grpcAddr,
		"http", m.httpAddr,
		"db", m.dbPath,
		"issuer", m.issuer,
		"redirect", m.redirectURL,
		"policy", m.policyFile,
		"roles_claim", m.rolesClaim,
		"session_ttl", m.sessionTTL,
	)
	return nil
}

func (m *Module) buildProvider(ctx context.Context) (oidc.Flow, error) {
	mapper := roles.NewMapper(m.rolesClaim, m.roleMap, m.defaultRoles)
	return oidc.NewProvider(ctx, oidc.Config{
		Issuer:       m.issuer,
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		RedirectURL:  m.redirectURL,
		Scopes:       splitScopes(m.scopes),
		Mapper:       mapper,
	})
}

func splitScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m *Module) loadPolicy() (*policy.Policy, error) {
	pol, err := policy.Load(m.policyFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			slog.Warn("policy file missing; using builtin default roles",
				"file", m.policyFile)
			return policy.Builtin(), nil
		}
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if pol.RoleCount() == 0 {
		slog.Warn("policy file has no roles — all Can() checks deny",
			"file", m.policyFile)
	} else {
		slog.Info("RBAC policy loaded", "file", m.policyFile, "roles", pol.RoleCount())
	}
	return pol, nil
}

func (m *Module) ReloadPolicy() error {
	if m.authSrv == nil {
		return fmt.Errorf("not initialized")
	}
	pol, err := policy.Load(m.policyFile)
	if err != nil {
		return err
	}
	m.authSrv.SetPolicy(pol)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.grpcSrv = grpc.NewServer()
	m.authSrv.RegisterWithGRPC(m.grpcSrv)
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)
	go func() {
		slog.Info("auth-oidc gRPC started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.grpcLis); err != nil {
			slog.Error("auth-oidc gRPC error", "error", err)
		}
	}()

	mux := http.NewServeMux()
	m.webHandler.RegisterRoutes(mux)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(m.authSrv.Metrics(r.Context())))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := m.Health(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"unhealthy","reason":%q}`, err.Error())
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	m.httpSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("auth-oidc HTTP started", "addr", m.httpAddr)
		if err := m.httpSrv.Serve(m.httpLis); err != nil && err != http.ErrServerClosed {
			slog.Error("auth-oidc HTTP error", "error", err)
		}
	}()

	cleanupStop := make(chan struct{})
	cleanupDone := make(chan struct{})
	m.cleanupStop = cleanupStop
	m.cleanupDone = cleanupDone
	// The cleanup loop outlives Start; keep ctx values but not its cancellation.
	bg := context.WithoutCancel(ctx)
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupStop:
				return
			case <-ticker.C:
				if m.sessions != nil {
					_ = m.sessions.CleanupExpired(bg)
				}
			}
		}
	}()

	sighupCh := make(chan os.Signal, 1)
	sighupStop := make(chan struct{})
	sighupDone := make(chan struct{})
	m.sighupCh = sighupCh
	m.sighupStop = sighupStop
	m.sighupDone = sighupDone
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		defer close(sighupDone)
		for {
			select {
			case <-sighupCh:
				slog.Info("SIGHUP received — reloading RBAC policy")
				if err := m.ReloadPolicy(); err != nil {
					slog.Error("policy reload failed", "error", err)
				}
			case <-sighupStop:
				return
			}
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.cleanupStop != nil {
		close(m.cleanupStop)
		if m.cleanupDone != nil {
			<-m.cleanupDone
		}
	}
	if m.sighupStop != nil {
		select {
		case <-m.sighupStop:
		default:
			close(m.sighupStop)
		}
		if m.sighupDone != nil {
			<-m.sighupDone
		}
	}
	if m.sighupCh != nil {
		signal.Stop(m.sighupCh)
	}
	if m.webHandler != nil {
		m.webHandler.Stop()
	}
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	if m.httpSrv != nil {
		_ = m.httpSrv.Shutdown(ctx)
	}
	if m.sessions != nil {
		_ = m.sessions.Close()
	}
	slog.Info("auth-oidc stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.sessions == nil || m.flow == nil {
		return fmt.Errorf("not initialized")
	}
	if !m.IdPConfigured() {
		return fmt.Errorf("OIDC IdP soft-disabled (set AUTH_OIDC_ISSUER, AUTH_OIDC_CLIENT_ID, AUTH_OIDC_REDIRECT_URL)")
	}
	if err := m.flow.HealthCheck(ctx); err != nil {
		return fmt.Errorf("IdP unreachable: %w", err)
	}
	return nil
}

// IdPConfigured reports whether a live OIDC IdP is wired (false when soft-disabled).
func (m *Module) IdPConfigured() bool {
	return oidc.IsConfigured(m.flow)
}

func (m *Module) HTTPAddr() string {
	if m.httpLis != nil {
		return m.httpLis.Addr().String()
	}
	return m.httpAddr
}

func (m *Module) GRPCAddr() string {
	if m.grpcLis != nil {
		return m.grpcLis.Addr().String()
	}
	return m.grpcAddr
}

func (m *Module) AuthServer() *server.AuthServer {
	return m.authSrv
}

func (m *Module) Sessions() *session.Store {
	return m.sessions
}
