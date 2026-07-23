package main

import (
	"flag"
	"log/slog"
	"os"

	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"

	"github.com/Muxcore-Media/auth-oidc/internal"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer URL (AUTH_OIDC_ISSUER)")
	clientID := flag.String("client-id", "", "OIDC client ID (AUTH_OIDC_CLIENT_ID)")
	clientSecret := flag.String("client-secret", "", "OIDC client secret (AUTH_OIDC_CLIENT_SECRET)")
	redirectURL := flag.String("redirect-url", "", "OIDC redirect URL (AUTH_OIDC_REDIRECT_URL)")
	policyFile := flag.String("policy-file", "", "RBAC policy YAML path (AUTH_OIDC_POLICY_FILE)")
	grpcAddr := flag.String("grpc-addr", "", "gRPC listen address (AUTH_OIDC_GRPC_ADDR)")
	httpAddr := flag.String("http-addr", "", "HTTP listen address (AUTH_OIDC_HTTP_ADDR)")
	rolesClaim := flag.String("roles-claim", "", "IdP claim for roles/groups (AUTH_OIDC_ROLES_CLAIM)")
	roleMap := flag.String("role-map", "", "IdP=local role map CSV (AUTH_OIDC_ROLE_MAP)")
	flag.Parse()

	mod := internal.NewModule(internal.Config{
		Issuer:       *issuer,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *redirectURL,
		PolicyFile:   *policyFile,
		GRPCAddr:     *grpcAddr,
		HTTPAddr:     *httpAddr,
		RolesClaim:   *rolesClaim,
		RoleMap:      *roleMap,
	})
	insecure := os.Getenv("MUXCORE_INSECURE_DISABLE_TLS") == "true" || os.Getenv("MUXCORE_GRPC_INSECURE") == "true"
	if err := modulesdk.Run(modulesdk.Config{
		Module:   mod,
		Insecure: insecure,
	}); err != nil {
		slog.Error("module exited", "error", err)
		os.Exit(1)
	}
}
