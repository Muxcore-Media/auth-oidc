package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
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
	defer lis.Close()
	return lis.Addr().(*net.TCPAddr).Port
}

func deployDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/oidc → repo root → deploy
	return filepath.Join(filepath.Dir(file), "..", "..", "deploy")
}

// TestKeycloakComposeDiscovery starts local Keycloak via Docker Compose and
// verifies OIDC discovery + AuthCodeURL. Skips when Docker is unavailable —
// Fake IdP unit tests cover login without a live issuer.
func TestKeycloakComposeDiscovery(t *testing.T) {
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
		// --wait may fail on older compose; fall back to up -d + poll.
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
			resp.Body.Close()
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, oidc.Config{
		Issuer:       issuer,
		ClientID:     "muxcore",
		ClientSecret: "muxcore-test-secret",
		RedirectURL:  "http://127.0.0.1:9412/oidc/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	authURL := p.AuthCodeURL("test-state")
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
	if u.Query().Get("state") != "test-state" {
		t.Fatalf("state=%q", u.Query().Get("state"))
	}
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
	if d.AuthCodeURL("s") != "" {
		t.Fatal("Disabled AuthCodeURL should be empty")
	}
	_, err := d.Exchange(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Exchange err=%v", err)
	}
}
