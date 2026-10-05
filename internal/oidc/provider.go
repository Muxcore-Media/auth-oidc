package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Muxcore-Media/auth-oidc/internal/roles"
)

// ErrNotConfigured is returned when OIDC IdP settings are unset.
// The module still starts; login soft-fails until issuer/client/redirect are set.
var ErrNotConfigured = errors.New("OIDC IdP not configured (set AUTH_OIDC_ISSUER, AUTH_OIDC_CLIENT_ID, AUTH_OIDC_REDIRECT_URL)")

const discoveryTimeout = 15 * time.Second

// IsConfigured reports whether f can drive a real login redirect.
// Flows that omit Configured() are treated as configured (e.g. Fake, Provider).
func IsConfigured(f Flow) bool {
	if f == nil {
		return false
	}
	if c, ok := f.(interface{ Configured() bool }); ok {
		return c.Configured()
	}
	return true
}

// AuthParams carries PKCE verifier and OIDC nonce for a single auth attempt.
type AuthParams struct {
	PKCEVerifier string
	Nonce        string
}

// Disabled is a Flow used when IdP env/config is unset. Login soft-fails.
type Disabled struct{}

func (Disabled) Configured() bool { return false }

func (Disabled) AuthCodeURL(state string, _ AuthParams) string { return "" }

func (Disabled) Exchange(ctx context.Context, code string, _ AuthParams) (*Identity, error) {
	return nil, ErrNotConfigured
}

func (Disabled) EndSessionURL(postLogoutRedirectURI string) string { return "" }

func (Disabled) HealthCheck(ctx context.Context) error { return ErrNotConfigured }

// Identity is the normalized subject after a successful code exchange.
type Identity struct {
	Subject  string
	Username string
	Email    string
	Roles    []string
}

// Flow starts the auth-code redirect and exchanges the callback code.
type Flow interface {
	AuthCodeURL(state string, params AuthParams) string
	Exchange(ctx context.Context, code string, params AuthParams) (*Identity, error)
	EndSessionURL(postLogoutRedirectURI string) string
	HealthCheck(ctx context.Context) error
}

// Config for a real OIDC provider.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Mapper       *roles.Mapper
}

// Provider implements Flow against a discovery-capable IdP.
type Provider struct {
	oauth2             oauth2.Config
	verifier           *oidc.IDTokenVerifier
	mapper             *roles.Mapper
	issuer             string
	endSessionEndpoint string
}

func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("issuer, client_id, and redirect_url are required")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()
	}
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	mapper := cfg.Mapper
	if mapper == nil {
		mapper = roles.NewMapper("groups", "", "user")
	}
	endSession, err := fetchEndSessionEndpoint(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery metadata: %w", err)
	}
	return &Provider{
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       scopes,
		},
		verifier:           p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		mapper:             mapper,
		issuer:             strings.TrimSuffix(cfg.Issuer, "/"),
		endSessionEndpoint: endSession,
	}, nil
}

func fetchEndSessionEndpoint(ctx context.Context, issuer string) (string, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("well-known status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var meta struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", err
	}
	return meta.EndSessionEndpoint, nil
}

func (p *Provider) AuthCodeURL(state string, params AuthParams) string {
	opts := []oauth2.AuthCodeOption{}
	if params.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", params.Nonce))
	}
	if params.PKCEVerifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(params.PKCEVerifier))
	}
	return p.oauth2.AuthCodeURL(state, opts...)
}

func (p *Provider) Exchange(ctx context.Context, code string, params AuthParams) (*Identity, error) {
	opts := []oauth2.AuthCodeOption{}
	if params.PKCEVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(params.PKCEVerifier))
	}
	tok, err := p.oauth2.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("id_token missing from token response")
	}
	idTok, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if params.Nonce != "" {
		var nonceClaims struct {
			Nonce string `json:"nonce"`
		}
		if err := idTok.Claims(&nonceClaims); err != nil {
			return nil, fmt.Errorf("parse nonce: %w", err)
		}
		if nonceClaims.Nonce != params.Nonce {
			return nil, fmt.Errorf("nonce mismatch")
		}
	}

	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	username := claimString(claims, "preferred_username")
	if username == "" {
		username = claimString(claims, "email")
	}
	if username == "" {
		username = idTok.Subject
	}

	rawRoles := claimStringSlice(claims, p.mapper.Claim)
	return &Identity{
		Subject:  idTok.Subject,
		Username: username,
		Email:    claimString(claims, "email"),
		Roles:    p.mapper.MapClaimValues(rawRoles),
	}, nil
}

func (p *Provider) EndSessionURL(postLogoutRedirectURI string) string {
	if p.endSessionEndpoint == "" {
		return ""
	}
	u, err := url.Parse(p.endSessionEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	q.Set("client_id", p.oauth2.ClientID)
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *Provider) HealthCheck(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()
	}
	_, err := fetchEndSessionEndpoint(ctx, p.issuer)
	return err
}

// Fake is a test double implementing Flow.
type Fake struct {
	AuthURL    string
	Identity   *Identity
	Err        error
	LastCode   string
	LastState  string
	LastParams AuthParams
}

func (f *Fake) AuthCodeURL(state string, params AuthParams) string {
	f.LastState = state
	f.LastParams = params
	if f.AuthURL == "" {
		return "https://idp.example/auth?state=" + state
	}
	return f.AuthURL + "?state=" + state
}

func (f *Fake) Exchange(ctx context.Context, code string, params AuthParams) (*Identity, error) {
	f.LastCode = code
	f.LastParams = params
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Identity == nil {
		return &Identity{Subject: "sub", Username: "user", Roles: []string{"user"}}, nil
	}
	return f.Identity, nil
}

func (f *Fake) EndSessionURL(postLogoutRedirectURI string) string {
	if postLogoutRedirectURI == "" {
		return "https://idp.example/logout"
	}
	return "https://idp.example/logout?post_logout_redirect_uri=" + url.QueryEscape(postLogoutRedirectURI)
}

func (f *Fake) HealthCheck(ctx context.Context) error { return nil }
