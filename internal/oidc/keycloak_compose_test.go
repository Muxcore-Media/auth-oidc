package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"golang.org/x/oauth2"
)

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	return lis.Addr().(*net.TCPAddr).Port
}

func deployDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "deploy")
}

// TestKeycloakComposeDiscovery starts local Keycloak via Docker Compose and
// verifies OIDC discovery, PKCE auth-code login as alice/alice, and groups claim.
// Skips when Docker is unavailable.
// TestKeycloakComposeDiscovery is opt-in: it starts a real Keycloak via
// `docker compose`, which is slow and unavailable on CI runners. Set
// AUTH_OIDC_KEYCLOAK_TEST=1 to run it (docker must be available).
func TestKeycloakComposeDiscovery(t *testing.T) {
	if os.Getenv("AUTH_OIDC_KEYCLOAK_TEST") != "1" {
		t.Skip("skipping Keycloak docker compose test; set AUTH_OIDC_KEYCLOAK_TEST=1 to enable")
	}
	if !dockerAvailable() {
		t.Skip("docker not available; Fake IdP unit tests cover login; see deploy/docker-compose.yml for local Keycloak (Authentik also fine)")
	}

	dir := deployDir(t)
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); err != nil {
		t.Fatalf("compose file: %v", err)
	}

	port := freePort(t)
	project := fmt.Sprintf("auth-oidc-kc-%d", port)
	env := append(os.Environ(),
		fmt.Sprintf("KEYCLOAK_HOST_PORT=%d", port),
		fmt.Sprintf("COMPOSE_PROJECT_NAME=%s", project),
	)

	up := exec.Command("docker", "compose", "-f", composeFile, "up", "-d", "--wait", "--wait-timeout", "120")
	up.Dir = dir
	up.Env = env
	if out, err := up.CombinedOutput(); err != nil {
		t.Logf("compose up --wait: %v\n%s\nfalling back to up -d + poll", err, out)
		up2 := exec.Command("docker", "compose", "-f", composeFile, "up", "-d")
		up2.Dir = dir
		up2.Env = env
		if out2, err2 := up2.CombinedOutput(); err2 != nil {
			t.Fatalf("docker compose up: %v\n%s", err2, out2)
		}
	}
	t.Cleanup(func() {
		down := exec.Command("docker", "compose", "-f", composeFile, "down", "-v", "--remove-orphans")
		down.Dir = dir
		down.Env = env
		_ = down.Run()
	})

	issuer := fmt.Sprintf("http://127.0.0.1:%d/realms/muxcore", port)
	wellKnown := issuer + "/.well-known/openid-configuration"
	deadline := time.Now().Add(2 * time.Minute)
	var meta map[string]any
	for {
		resp, err := http.Get(wellKnown)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &meta) == nil {
				if _, ok := meta["authorization_endpoint"].(string); ok {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("keycloak not ready at %s after 2m (last err=%v)", wellKnown, err)
		}
		time.Sleep(2 * time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", freePort(t))
	p, err := oidc.NewProvider(ctx, oidc.Config{
		Issuer:       issuer,
		ClientID:     "muxcore",
		ClientSecret: "muxcore-test-secret",
		RedirectURL:  redirectURL,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	verifier := oauth2.GenerateVerifier()
	state := "test-state"
	params := oidc.AuthParams{PKCEVerifier: verifier, Nonce: "nonce-kc-test"}
	authURL := p.AuthCodeURL(state, params)
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("AuthCodeURL parse: %v", err)
	}
	if !strings.Contains(u.Path, "/protocol/openid-connect/auth") && !strings.Contains(authURL, "openid-connect") {
		t.Fatalf("AuthCodeURL=%q missing keycloak authorize path", authURL)
	}
	if u.Query().Get("client_id") != "muxcore" {
		t.Fatalf("client_id=%q", u.Query().Get("client_id"))
	}
	if u.Query().Get("state") != state {
		t.Fatalf("state=%q", u.Query().Get("state"))
	}
	if u.Query().Get("code_challenge") == "" {
		t.Fatal("expected PKCE code_challenge")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	loginPage, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	body, _ := io.ReadAll(loginPage.Body)
	_ = loginPage.Body.Close()
	if loginPage.StatusCode != http.StatusOK {
		t.Fatalf("login page status=%d body=%s", loginPage.StatusCode, body)
	}
	formAction := extractFormAction(string(body))
	if formAction == "" {
		t.Fatal("login form action not found")
	}
	if !strings.HasPrefix(formAction, "http") {
		formAction = strings.TrimSuffix(loginPage.Request.URL.Scheme+"://"+loginPage.Request.URL.Host, "") + formAction
		if strings.HasPrefix(formAction, "://") {
			base := fmt.Sprintf("http://127.0.0.1:%d", port)
			formAction = base + extractFormAction(string(body))
		}
	}
	if !strings.HasPrefix(formAction, "http") {
		formAction = fmt.Sprintf("http://127.0.0.1:%d%s", port, extractFormAction(string(body)))
	}

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice")
	loginResp, err := client.PostForm(formAction, form)
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	finalURL := loginResp.Request.URL.String()
	_ = loginResp.Body.Close()

	if !strings.HasPrefix(finalURL, redirectURL) {
		// Keycloak may redirect through an intermediate consent page; follow once more.
		if loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusSeeOther {
			loc := loginResp.Header.Get("Location")
			if loc != "" {
				follow, err := client.Get(loc)
				if err == nil {
					finalURL = follow.Request.URL.String()
					_ = follow.Body.Close()
				}
			}
		}
	}
	cbURL, err := url.Parse(finalURL)
	if err != nil || !strings.HasPrefix(cbURL.String(), redirectURL) {
		t.Fatalf("expected callback redirect to %s got %q", redirectURL, finalURL)
	}
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in callback URL %q", finalURL)
	}
	if cbURL.Query().Get("state") != state {
		t.Fatalf("state=%q", cbURL.Query().Get("state"))
	}

	ident, err := p.Exchange(ctx, code, params)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ident.Username != "alice" {
		t.Fatalf("username=%q", ident.Username)
	}
	if len(ident.Roles) == 0 || ident.Roles[0] != "user" {
		t.Fatalf("roles=%v want user from groups mapper", ident.Roles)
	}
}

var formActionRE = regexp.MustCompile(`action="([^"]+)"`)

func extractFormAction(html string) string {
	m := formActionRE.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.ReplaceAll(m[1], "&amp;", "&")
}

func TestDisabledExchange(t *testing.T) {
	d := oidc.Disabled{}
	if d.Configured() {
		t.Fatal("Disabled should not be configured")
	}
	if oidc.IsConfigured(nil) {
		t.Fatal("nil Flow should not be configured")
	}
	if oidc.IsConfigured(d) {
		t.Fatal("Disabled should not be configured via IsConfigured")
	}
	if d.AuthCodeURL("s", oidc.AuthParams{}) != "" {
		t.Fatal("Disabled AuthCodeURL should be empty")
	}
	_, err := d.Exchange(context.Background(), "x", oidc.AuthParams{})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Exchange err=%v", err)
	}
}
