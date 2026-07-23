package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Muxcore-Media/auth-oidc/internal/roles"
)

// Identity is the normalized subject after a successful code exchange.
type Identity struct {
	Subject  string
	Username string
	Email    string
	Roles    []string
}

// Flow starts the auth-code redirect and exchanges the callback code.
type Flow interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*Identity, error)
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
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	mapper   *roles.Mapper
}

func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("issuer, client_id, and redirect_url are required")
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
	return &Provider{
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       scopes,
		},
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		mapper:   mapper,
	}, nil
}

func (p *Provider) AuthCodeURL(state string) string {
	return p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (p *Provider) Exchange(ctx context.Context, code string) (*Identity, error) {
	tok, err := p.oauth2.Exchange(ctx, code)
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
	v, ok := claims[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		parts := strings.Split(t, " ")
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

// Fake is a test double implementing Flow.
type Fake struct {
	AuthURL   string
	Identity  *Identity
	Err       error
	LastCode  string
	LastState string
}

func (f *Fake) AuthCodeURL(state string) string {
	f.LastState = state
	if f.AuthURL == "" {
		return "https://idp.example/auth?state=" + state
	}
	return f.AuthURL + "?state=" + state
}

func (f *Fake) Exchange(ctx context.Context, code string) (*Identity, error) {
	f.LastCode = code
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Identity == nil {
		return &Identity{Subject: "sub", Username: "user", Roles: []string{"user"}}, nil
	}
	return f.Identity, nil
}
