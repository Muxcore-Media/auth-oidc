package server_test

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-oidc/internal/policy"
	"github.com/Muxcore-Media/auth-oidc/internal/server"
	"github.com/Muxcore-Media/auth-oidc/internal/session"
)

func testStore(t *testing.T) *session.Store {
	t.Helper()
	s, err := session.New(context.Background(), filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestValidateRevokeExtractCan(t *testing.T) {
	store := testStore(t)
	sess, err := store.Create(context.Background(), "sub-1", "bob", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(store, policy.Builtin())
	ctx := context.Background()

	v, err := srv.Validate(ctx, &authv1.ValidateRequest{Token: sess.Token})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.UserId != "sub-1" || v.Username != "bob" {
		t.Fatalf("validate=%+v", v)
	}

	id, err := srv.ExtractIdentity(ctx, &authv1.ExtractIdentityRequest{Token: sess.Token})
	if err != nil {
		t.Fatal(err)
	}
	if !id.Found || id.Id != "sub-1" {
		t.Fatalf("identity=%+v", id)
	}

	can, err := srv.Can(ctx, &authv1.CanRequest{UserId: "sub-1", Action: "manage", Resource: "modules"})
	if err != nil {
		t.Fatal(err)
	}
	if !can.Allowed {
		t.Fatalf("admin should be allowed: %+v", can)
	}

	_, err = srv.Revoke(ctx, &authv1.RevokeRequest{Token: sess.Token})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := srv.Validate(ctx, &authv1.ValidateRequest{Token: sess.Token})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Valid {
		t.Fatal("expected invalid after revoke")
	}
}

func TestCanDeniedAfterRevoke(t *testing.T) {
	store := testStore(t)
	sess, err := store.Create(context.Background(), "sub-1", "bob", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(store, policy.Builtin())
	ctx := context.Background()

	can, err := srv.Can(ctx, &authv1.CanRequest{UserId: "sub-1", Action: "manage", Resource: "modules"})
	if err != nil {
		t.Fatal(err)
	}
	if !can.Allowed {
		t.Fatalf("admin should be allowed before revoke: %+v", can)
	}

	_, err = srv.Revoke(ctx, &authv1.RevokeRequest{Token: sess.Token})
	if err != nil {
		t.Fatal(err)
	}
	can2, err := srv.Can(ctx, &authv1.CanRequest{UserId: "sub-1", Action: "manage", Resource: "modules"})
	if err != nil {
		t.Fatal(err)
	}
	if can2.Allowed {
		t.Fatalf("Can should deny after last session revoked: %+v", can2)
	}
}

func TestUnimplementedUserCRUD(t *testing.T) {
	store := testStore(t)
	srv := server.New(store, policy.Builtin())
	_, err := srv.CreateUser(context.Background(), &authv1.CreateUserRequest{Username: "x", Password: "y"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code=%v err=%v", status.Code(err), err)
	}
	_, err = srv.EnableTOTP(context.Background(), &authv1.EnableTOTPRequest{UserId: "x"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("totp code=%v", status.Code(err))
	}
}
