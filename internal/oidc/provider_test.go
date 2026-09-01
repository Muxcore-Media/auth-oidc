package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/roles"
)

func TestProviderPKCEAndNonce(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	nonce := "test-nonce-123"
	state := "state-abc"
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			issuer := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/auth",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"end_session_endpoint":                    issuer + "/logout",
				"response_types_supported":                []string{"code"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case r.URL.Path == "/jwks":
			n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
					"n": n,
					"e": "AQAB",
				}},
			})
		case r.URL.Path == "/auth":
			if r.URL.Query().Get("code_challenge") != challenge {
				t.Errorf("code_challenge=%q want %q", r.URL.Query().Get("code_challenge"), challenge)
			}
			if r.URL.Query().Get("nonce") != nonce {
				t.Errorf("nonce=%q", r.URL.Query().Get("nonce"))
			}
			redirectURI := r.URL.Query().Get("redirect_uri")
			u, _ := url.Parse(redirectURI)
			q := u.Query()
			q.Set("code", "auth-code-1")
			q.Set("state", state)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
		case r.URL.Path == "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.FormValue("code_verifier") != verifier {
				t.Errorf("code_verifier=%q", r.FormValue("code_verifier"))
			}
			claims := jwt.MapClaims{
				"sub":                "user-1",
				"preferred_username": "alice",
				"nonce":              nonce,
				"groups":             []string{"admin"},
				"iss":                "http://" + r.Host,
				"aud":                "test-client",
				"exp":                time.Now().Add(time.Hour).Unix(),
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = "test"
			idToken, err := tok.SignedString(priv)
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at",
				"token_type":   "Bearer",
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	ctx := context.Background()
	p, err := oidc.NewProvider(ctx, oidc.Config{
		Issuer:      srv.URL,
		ClientID:    "test-client",
		RedirectURL: srv.URL + "/cb",
		Mapper:      roles.NewMapper("groups", "", "user"),
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	params := oidc.AuthParams{PKCEVerifier: verifier, Nonce: nonce}
	authURL := p.AuthCodeURL(state, params)
	if !strings.Contains(authURL, "code_challenge=") {
		t.Fatalf("AuthCodeURL missing PKCE: %s", authURL)
	}

	ident, err := p.Exchange(ctx, "auth-code-1", params)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ident.Username != "alice" || len(ident.Roles) != 1 || ident.Roles[0] != "admin" {
		t.Fatalf("identity=%+v", ident)
	}
	if end := p.EndSessionURL("http://app/logout"); !strings.Contains(end, "/logout") {
		t.Fatalf("EndSessionURL=%q", end)
	}
}
