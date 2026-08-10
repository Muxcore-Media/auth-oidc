package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/roles"
	"github.com/Muxcore-Media/core/pkg/contracts"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "issuer",
			Label:       "OIDC Issuer",
			Type:        contracts.SettingTypeString,
			Value:       m.issuer,
			Description: "IdP issuer URL (AUTH_OIDC_ISSUER)",
			Group:       "OIDC",
		},
		{
			Key:         "client_id",
			Label:       "Client ID",
			Type:        contracts.SettingTypeString,
			Value:       m.clientID,
			Description: "OAuth client ID (AUTH_OIDC_CLIENT_ID)",
			Group:       "OIDC",
		},
		{
			Key:         "client_secret",
			Label:       "Client Secret",
			Type:        contracts.SettingTypeSecret,
			Value:       modulesdk.MaskSecret(m.clientSecret),
			Description: "OAuth client secret (AUTH_OIDC_CLIENT_SECRET)",
			Group:       "OIDC",
		},
		{
			Key:         "redirect_url",
			Label:       "Redirect URL",
			Type:        contracts.SettingTypeString,
			Value:       m.redirectURL,
			Description: "OIDC callback URL (AUTH_OIDC_REDIRECT_URL)",
			Group:       "OIDC",
		},
		{
			Key:         "roles_claim",
			Label:       "Roles Claim",
			Type:        contracts.SettingTypeString,
			Value:       m.rolesClaim,
			Default:     "groups",
			Description: "ID token claim for roles (AUTH_OIDC_ROLES_CLAIM)",
			Group:       "OIDC",
		},
		{
			Key:         "role_map",
			Label:       "Role Map",
			Type:        contracts.SettingTypeString,
			Value:       m.roleMap,
			Description: "IdP→MuxCore role map (AUTH_OIDC_ROLE_MAP)",
			Group:       "OIDC",
		},
		{
			Key:         "default_roles",
			Label:       "Default Roles",
			Type:        contracts.SettingTypeString,
			Value:       m.defaultRoles,
			Description: "Fallback roles when claim empty (AUTH_OIDC_DEFAULT_ROLES)",
			Group:       "OIDC",
		},
		{
			Key:         "policy_file",
			Label:       "Policy File",
			Type:        contracts.SettingTypeString,
			Value:       m.policyFile,
			Default:     "policies.yaml",
			Description: "RBAC policy YAML path (AUTH_OIDC_POLICY_FILE); reloads live",
			Group:       "RBAC",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "issuer", "AUTH_OIDC_ISSUER":
		return m.applyOIDC(func() { m.issuer = value })
	case "client_id", "AUTH_OIDC_CLIENT_ID", "CLIENT_ID":
		return m.applyOIDC(func() { m.clientID = value })
	case "client_secret", "AUTH_OIDC_CLIENT_SECRET", "CLIENT_SECRET":
		if value == "" || value == modulesdk.MaskSecret("x") {
			return nil
		}
		return m.applyOIDC(func() { m.clientSecret = value })
	case "redirect_url", "AUTH_OIDC_REDIRECT_URL", "REDIRECT_URL":
		return m.applyOIDC(func() { m.redirectURL = value })
	case "roles_claim", "AUTH_OIDC_ROLES_CLAIM", "ROLES_CLAIM":
		if value == "" {
			value = "groups"
		}
		return m.applyOIDC(func() { m.rolesClaim = value })
	case "role_map", "AUTH_OIDC_ROLE_MAP":
		return m.applyOIDC(func() { m.roleMap = value })
	case "default_roles", "AUTH_OIDC_DEFAULT_ROLES":
		return m.applyOIDC(func() { m.defaultRoles = value })
	case "policy_file", "AUTH_OIDC_POLICY_FILE":
		if value == "" {
			return fmt.Errorf("policy_file must not be empty")
		}
		m.cfgMu.Lock()
		m.policyFile = value
		m.cfgMu.Unlock()
		if m.authSrv == nil {
			return nil
		}
		return m.ReloadPolicy()
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

func (m *Module) applyOIDC(mutate func()) error {
	m.cfgMu.Lock()
	mutate()
	issuer := m.issuer
	clientID := m.clientID
	clientSecret := m.clientSecret
	redirectURL := m.redirectURL
	rolesClaim := m.rolesClaim
	roleMap := m.roleMap
	defaultRoles := m.defaultRoles
	m.cfgMu.Unlock()

	if m.webHandler == nil {
		return nil
	}
	// Tests inject Fake flow via Config.Flow — skip live IdP discovery.
	if _, ok := m.flow.(*oidc.Fake); ok {
		return nil
	}
	if issuer == "" || clientID == "" || redirectURL == "" {
		flow := oidc.Disabled{}
		m.flow = flow
		m.webHandler.SetFlow(flow)
		return nil
	}
	mapper := roles.NewMapper(rolesClaim, roleMap, defaultRoles)
	flow, err := oidc.NewProvider(context.Background(), oidc.Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Mapper:       mapper,
	})
	if err != nil {
		return fmt.Errorf("reinit oidc: %w", err)
	}
	m.flow = flow
	m.webHandler.SetFlow(flow)
	return nil
}
