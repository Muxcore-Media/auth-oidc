package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/Muxcore-Media/core/sdk/go/module/netguard"
)

func TestValidateIssuer(t *testing.T) {
	if err := ValidateIssuer(""); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://idp.example/realms/muxcore",
		"http://127.0.0.1:8080/realms/household",
		"http://authentik:9000/application/o/muxcore/",
	} {
		if err := ValidateIssuer(raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/",
		"file:///etc/passwd",
	} {
		if err := ValidateIssuer(raw); !errors.Is(err, netguard.ErrBlocked) {
			t.Fatalf("%s: err=%v", raw, err)
		}
	}
}

func TestNewProviderRejectsMetadataIssuer(t *testing.T) {
	_, err := NewProvider(context.Background(), Config{
		Issuer:      "http://169.254.169.254",
		ClientID:    "c",
		RedirectURL: "http://127.0.0.1/cb",
	})
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("err=%v", err)
	}
}
