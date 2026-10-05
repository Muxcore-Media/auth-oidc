package webapp_test

import (
	"net/url"
	"testing"

	"github.com/Muxcore-Media/auth-oidc/internal/webapp"
)

func TestSafeRedirectPublicHosts(t *testing.T) {
	t.Setenv("ADMIN_UI_PUBLIC_URL", "https://admin.zem.systems")
	t.Setenv("MEDIA_UI_PUBLIC_URL", "https://mux.zem.systems")

	req, _ := url.Parse("http://auth.zem.systems:9412/login")
	got := webapp.SafeRedirectForTest(req, "https://admin.zem.systems/auth/callback")
	if got != "https://admin.zem.systems/auth/callback" {
		t.Fatalf("admin redirect=%q", got)
	}
	got = webapp.SafeRedirectForTest(req, "https://mux.zem.systems/home")
	if got != "https://mux.zem.systems/home" {
		t.Fatalf("mux redirect=%q", got)
	}
	got = webapp.SafeRedirectForTest(req, "https://evil.example/phish")
	if got != "/" {
		t.Fatalf("evil redirect=%q want /", got)
	}
}

func TestSafeRedirectLocalDev(t *testing.T) {
	req, _ := url.Parse("http://127.0.0.1:9412/login")
	got := webapp.SafeRedirectForTest(req, "http://127.0.0.1:8082/auth/callback")
	if got != "http://127.0.0.1:8082/auth/callback" {
		t.Fatalf("127.0.0.1:8082 redirect=%q", got)
	}
	got = webapp.SafeRedirectForTest(req, "http://127.0.0.1:5173/auth/callback")
	if got != "http://127.0.0.1:5173/auth/callback" {
		t.Fatalf("127.0.0.1:5173 redirect=%q", got)
	}
}

func TestSafeRedirectRejectsHostSmuggling(t *testing.T) {
	req, _ := url.Parse("http://127.0.0.1:9412/login")
	for _, in := range []string{"//evil.example/x", `/\evil.example`, "javascript://localhost:8082/%0aalert(1)"} {
		if got := webapp.SafeRedirectForTest(req, in); got != "/" {
			t.Fatalf("redirect %q = %q, want /", in, got)
		}
	}
	if got := webapp.SafeRedirectForTest(req, "/library?x=1"); got != "/library?x=1" {
		t.Fatalf("same-origin path rewritten: %q", got)
	}
}
