package redirectallow

import (
	"testing"
)

func TestHostAllowed(t *testing.T) {
	t.Setenv("AUTH_ALLOWED_REDIRECT_HOSTS", "vault.lan:8082")
	t.Setenv("ADMIN_UI_PUBLIC_URL", "https://admin.zem.systems")
	SetExtraHosts("")

	if !HostAllowed("auth.zem.systems", "admin.zem.systems") {
		t.Fatal("ADMIN_UI_PUBLIC_URL host should be allowed")
	}
	if !HostAllowed("127.0.0.1:9412", "vault.lan:8082") {
		t.Fatal("AUTH_ALLOWED_REDIRECT_HOSTS should be allowed")
	}
	if HostAllowed("auth.zem.systems", "evil.example") {
		t.Fatal("evil.example should be denied")
	}

	SetExtraHosts("custom.example:443")
	if !HostAllowed("auth.zem.systems", "custom.example:443") {
		t.Fatal("SetExtraHosts should be allowed")
	}
}
