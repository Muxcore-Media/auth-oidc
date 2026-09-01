package internal

import (
	"testing"

	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
)

func TestSettings_PreInit(t *testing.T) {
	m := NewModule(Config{
		Issuer:       "https://idp.example",
		ClientID:     "mux",
		ClientSecret: "sekret",
		RedirectURL:  "http://localhost/cb",
	})
	defs := m.Settings()
	by := map[string]string{}
	for _, d := range defs {
		by[d.Key] = d.Value
	}
	if by["issuer"] != "https://idp.example" {
		t.Fatalf("issuer=%q", by["issuer"])
	}
	if by["client_secret"] != modulesdk.MaskSecret("x") {
		t.Fatalf("secret not masked: %q", by["client_secret"])
	}
	if err := m.UpdateSetting("roles_claim", "groups"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("client_secret", modulesdk.MaskSecret("x")); err != nil {
		t.Fatal(err)
	}
	if m.Settings()[0].Key != "issuer" {
		t.Fatal("unexpected settings order")
	}
	info := m.Info()
	if info.Version != "0.1.2" {
		t.Fatalf("version=%q", info.Version)
	}
	if info.HTTPAddr != ":9412" {
		t.Fatalf("HTTPAddr=%q want :9412", info.HTTPAddr)
	}
	found := false
	for _, c := range info.Capabilities {
		if c == "settings" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected settings capability")
	}
}
