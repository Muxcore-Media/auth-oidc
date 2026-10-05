package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-oidc/internal/policy"
	"github.com/Muxcore-Media/auth-oidc/internal/server"
)

func peerCtx(cn string, verified bool) context.Context {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	st := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if verified {
		st.VerifiedChains = [][]*x509.Certificate{{cert}}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: st}})
}

func TestExtractIdentityCallerID(t *testing.T) {
	store := testStore(t)
	sess, err := store.Create(context.Background(), "sub-1", "bob", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(store, policy.Builtin())
	req := &authv1.ExtractIdentityRequest{CallerId: "downloader"}

	// Spoofed CallerId, no TLS peer.
	r, _ := srv.ExtractIdentity(context.Background(), req)
	if r.Found || r.Id != "" {
		t.Fatalf("spoofed caller accepted: %+v", r)
	}
	// Unverified chain, matching CN.
	if r, _ = srv.ExtractIdentity(peerCtx("downloader", false), req); r.Found {
		t.Fatalf("unverified peer accepted: %+v", r)
	}
	// Verified peer, CN mismatch.
	if r, _ = srv.ExtractIdentity(peerCtx("other", true), req); r.Found {
		t.Fatalf("CN mismatch accepted: %+v", r)
	}
	// Verified peer, CN match.
	r, _ = srv.ExtractIdentity(peerCtx("downloader", true), req)
	if !r.Found || r.Id != "downloader" || r.Kind != "service" {
		t.Fatalf("verified peer rejected: %+v", r)
	}
	// User token unchanged, and a spoofed CallerId alongside does not override it.
	r, _ = srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{Token: sess.Token, CallerId: "admin-ui"})
	if !r.Found || r.Id != "sub-1" || r.Kind != "user" {
		t.Fatalf("user identity=%+v", r)
	}
	// Bad token + spoofed CallerId.
	if r, _ = srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{Token: "bad", CallerId: "x"}); r.Found {
		t.Fatalf("bad token + caller accepted: %+v", r)
	}
}
