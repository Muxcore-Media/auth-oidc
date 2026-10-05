package webapp_test

import (
	"net/http/httptest"
	"testing"

	"github.com/Muxcore-Media/auth-oidc/internal/webapp"
)

// Server-side requests carry the host in r.Host, not r.URL.Host; same-host
// absolute redirects must be accepted based on it.
func TestSafeRedirectUsesRequestHost(t *testing.T) {
	req := httptest.NewRequest("GET", "http://auth.example.com/login", nil)
	if req.URL.Host != "" {
		// httptest fills URL.Host for absolute targets; mimic a real server request.
		req.URL.Host = ""
	}
	got := webapp.SafeRedirectForHostForTest(req.Host, "https://auth.example.com/after")
	if got != "https://auth.example.com/after" {
		t.Fatalf("same-host redirect rejected: got %q", got)
	}
	if got := webapp.SafeRedirectForHostForTest(req.Host, "https://evil.example/x"); got != "/" {
		t.Fatalf("foreign host accepted: got %q", got)
	}
}
