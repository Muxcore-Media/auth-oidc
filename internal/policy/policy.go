package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const BuiltinYAML = `roles:
  admin:
    permissions: ["*"]
  manager:
    permissions:
      - "media.*"
      - "storage.*"
      - "modules.read"
      - "modules.manage"
  user:
    permissions:
      - "media.request"
      - "media.view"
      - "media.search"
  viewer:
    permissions:
      - "media.view"
      - "media.search"
`

func Builtin() *Policy {
	p, err := Parse([]byte(BuiltinYAML))
	if err != nil {
		panic("policy.Builtin: " + err.Error())
	}
	return p
}

type Config struct {
	Roles map[string]RoleConfig `yaml:"roles"`
}

type RoleConfig struct {
	Permissions []string `yaml:"permissions"`
}

type Policy struct {
	roles map[string][]string
	mu    sync.RWMutex
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Policy, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	p := &Policy{roles: make(map[string][]string)}
	for name, rc := range cfg.Roles {
		p.roles[name] = rc.Permissions
	}
	return p, nil
}

func (p *Policy) IsAllowed(userRoles []string, action, resource string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, userRole := range userRoles {
		perms, ok := p.roles[userRole]
		if !ok {
			continue
		}
		for _, perm := range perms {
			if perm == "*" {
				return true, ""
			}
			if matchPermission(perm, action, resource) {
				return true, ""
			}
		}
	}
	return false, "insufficient permissions"
}

func (p *Policy) RoleCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.roles)
}

func (p *Policy) Replace(src *Policy) {
	src.mu.RLock()
	roles := make(map[string][]string, len(src.roles))
	for k, v := range src.roles {
		perms := make([]string, len(v))
		copy(perms, v)
		roles[k] = perms
	}
	src.mu.RUnlock()

	p.mu.Lock()
	p.roles = roles
	p.mu.Unlock()
}

func matchPermission(perm, action, resource string) bool {
	if perm == "*" {
		return true
	}
	dot := strings.IndexByte(perm, '.')
	if dot < 0 {
		return perm == resource && action == "*"
	}
	permResource := perm[:dot]
	permAction := perm[dot+1:]

	if permResource != "*" && permResource != resource {
		return false
	}
	if permAction != "*" && permAction != action {
		return false
	}
	return true
}
