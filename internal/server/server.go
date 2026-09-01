package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-oidc/internal/policy"
	"github.com/Muxcore-Media/auth-oidc/internal/session"
)

// AuthServer implements AuthService: Validate/Revoke/ExtractIdentity/Can.
// User CRUD, TOTP, and WebAuthn return Unimplemented.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	sessions     *session.Store
	policy       *policy.Policy
	validateOK   atomic.Int64
	validateFail atomic.Int64
}

func New(sessions *session.Store, p *policy.Policy) *AuthServer {
	return &AuthServer{sessions: sessions, policy: p}
}

func (s *AuthServer) RegisterWithGRPC(srv *grpc.Server) {
	authv1.RegisterAuthServiceServer(srv, s)
}

func (s *AuthServer) SetPolicy(p *policy.Policy) {
	if p == nil {
		return
	}
	if s.policy != nil {
		s.policy.Replace(p)
	} else {
		s.policy = p
	}
	slog.Info("RBAC policy reloaded")
}

func (s *AuthServer) Metrics() string {
	var b strings.Builder
	b.WriteString("# HELP auth_validate_ok_total Successful Validate calls\n")
	b.WriteString("# TYPE auth_validate_ok_total counter\n")
	fmt.Fprintf(&b, "auth_validate_ok_total %d\n", s.validateOK.Load())
	b.WriteString("# HELP auth_validate_fail_total Failed Validate calls\n")
	b.WriteString("# TYPE auth_validate_fail_total counter\n")
	fmt.Fprintf(&b, "auth_validate_fail_total %d\n", s.validateFail.Load())
	if s.sessions != nil {
		b.WriteString("# HELP auth_sessions_active Current active sessions\n")
		b.WriteString("# TYPE auth_sessions_active gauge\n")
		fmt.Fprintf(&b, "auth_sessions_active %d\n", s.sessions.Count())
	}
	return b.String()
}

func (s *AuthServer) Authenticate(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	return &authv1.AuthenticateResponse{
		Authenticated: false,
		Error:         "use HTTP OIDC login flow; direct Authenticate is unsupported",
	}, nil
}

func (s *AuthServer) Validate(ctx context.Context, req *authv1.ValidateRequest) (*authv1.ValidateResponse, error) {
	sess, err := s.sessions.Get(req.Token)
	if err != nil {
		s.validateFail.Add(1)
		return &authv1.ValidateResponse{Valid: false, Error: "invalid or expired token"}, nil
	}
	s.validateOK.Add(1)
	return &authv1.ValidateResponse{
		Valid:    true,
		UserId:   sess.UserID,
		Username: sess.Username,
		Roles:    sess.Roles,
	}, nil
}

func (s *AuthServer) Revoke(ctx context.Context, req *authv1.RevokeRequest) (*authv1.RevokeResponse, error) {
	s.sessions.Revoke(req.Token)
	return &authv1.RevokeResponse{}, nil
}

func (s *AuthServer) Can(ctx context.Context, req *authv1.CanRequest) (*authv1.CanResponse, error) {
	id, err := s.sessions.Identity(req.UserId)
	if err != nil {
		return &authv1.CanResponse{Allowed: false, Reason: "user not found"}, nil
	}
	var allowed bool
	var reason string
	if s.policy != nil {
		allowed, reason = s.policy.IsAllowed(id.Roles, req.Action, req.Resource)
	} else {
		allowed, reason = false, "no policy loaded"
	}
	return &authv1.CanResponse{Allowed: allowed, Reason: reason}, nil
}

func (s *AuthServer) ExtractIdentity(ctx context.Context, req *authv1.ExtractIdentityRequest) (*authv1.ExtractIdentityResponse, error) {
	if req.Token == "" && req.CallerId == "" {
		return &authv1.ExtractIdentityResponse{Found: false}, nil
	}
	if req.Token != "" {
		sess, err := s.sessions.Get(req.Token)
		if err == nil {
			return &authv1.ExtractIdentityResponse{
				Found: true,
				Id:    sess.UserID,
				Kind:  "user",
				Roles: sess.Roles,
			}, nil
		}
	}
	if req.CallerId != "" {
		return &authv1.ExtractIdentityResponse{
			Found: true,
			Id:    req.CallerId,
			Kind:  "service",
			Roles: []string{"module"},
		}, nil
	}
	return &authv1.ExtractIdentityResponse{Found: false}, nil
}

func (s *AuthServer) CreateUser(ctx context.Context, req *authv1.CreateUserRequest) (*authv1.CreateUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "user management is handled by the IdP")
}

func (s *AuthServer) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "user management is handled by the IdP")
}

func (s *AuthServer) ListUsers(ctx context.Context, req *authv1.ListUsersRequest) (*authv1.ListUsersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "user management is handled by the IdP")
}

func (s *AuthServer) SetPassword(ctx context.Context, req *authv1.SetPasswordRequest) (*authv1.SetPasswordResponse, error) {
	return nil, status.Error(codes.Unimplemented, "user management is handled by the IdP")
}

func (s *AuthServer) SetRoles(ctx context.Context, req *authv1.SetRolesRequest) (*authv1.SetRolesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "roles come from IdP claims")
}

func (s *AuthServer) EnableTOTP(ctx context.Context, req *authv1.EnableTOTPRequest) (*authv1.EnableTOTPResponse, error) {
	return nil, status.Error(codes.Unimplemented, "TOTP is handled by the IdP")
}

func (s *AuthServer) DisableTOTP(ctx context.Context, req *authv1.DisableTOTPRequest) (*authv1.DisableTOTPResponse, error) {
	return nil, status.Error(codes.Unimplemented, "TOTP is handled by the IdP")
}

func (s *AuthServer) TOTPStatus(ctx context.Context, req *authv1.TOTPStatusRequest) (*authv1.TOTPStatusResponse, error) {
	return nil, status.Error(codes.Unimplemented, "TOTP is handled by the IdP")
}

func (s *AuthServer) VerifyTOTPSetup(ctx context.Context, req *authv1.VerifyTOTPSetupRequest) (*authv1.VerifyTOTPSetupResponse, error) {
	return nil, status.Error(codes.Unimplemented, "TOTP is handled by the IdP")
}

func (s *AuthServer) ListWebAuthnCredentials(ctx context.Context, req *authv1.ListWebAuthnCredentialsRequest) (*authv1.ListWebAuthnCredentialsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "WebAuthn is handled by the IdP")
}

func (s *AuthServer) DeleteWebAuthnCredential(ctx context.Context, req *authv1.DeleteWebAuthnCredentialRequest) (*authv1.DeleteWebAuthnCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "WebAuthn is handled by the IdP")
}

func (s *AuthServer) BeginAdminRegistration(ctx context.Context, req *authv1.BeginAdminRegistrationRequest) (*authv1.BeginAdminRegistrationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "WebAuthn is handled by the IdP")
}

func (s *AuthServer) CompleteAdminRegistration(ctx context.Context, req *authv1.CompleteAdminRegistrationRequest) (*authv1.CompleteAdminRegistrationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "WebAuthn is handled by the IdP")
}

func (s *AuthServer) CreateAPIToken(ctx context.Context, req *authv1.CreateAPITokenRequest) (*authv1.CreateAPITokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "API tokens are not supported in auth-oidc")
}

func (s *AuthServer) ListAPITokens(ctx context.Context, req *authv1.ListAPITokensRequest) (*authv1.ListAPITokensResponse, error) {
	return nil, status.Error(codes.Unimplemented, "API tokens are not supported in auth-oidc")
}

func (s *AuthServer) DeleteAPIToken(ctx context.Context, req *authv1.DeleteAPITokenRequest) (*authv1.DeleteAPITokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "API tokens are not supported in auth-oidc")
}
