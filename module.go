package authoidc

import (
	"context"

	"github.com/Muxcore-Media/core/pkg/contracts"
)

func init() {
	contracts.Register(func(deps contracts.ModuleDeps) contracts.Module {
		return &Module{}
	})
}

type Module struct{}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           "auth-oidc",
		Name:         "OIDC/SSO Auth Provider",
		Version:      "0.1.0",
		Description:  "OpenID Connect and OAuth2 authentication supporting Google, GitHub, Authelia, Authentik, Keycloak.",
		Author:       "MuxCore",
		Kinds:        []contracts.ModuleKind{contracts.ModuleKindAuth},
		Capabilities: []string{"auth.oidc", "auth.sso"},
	}
}

func (m *Module) Init(ctx context.Context) error  { return nil }
func (m *Module) Start(ctx context.Context) error  { return nil }
func (m *Module) Stop(ctx context.Context) error   { return nil }
func (m *Module) Health(ctx context.Context) error { return nil }
