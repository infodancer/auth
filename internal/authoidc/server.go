package authoidc

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/infodancer/auth/domain"
	"github.com/infodancer/auth/passwd"
)

// domainEntry holds the runtime state for a configured domain.
type domainEntry struct {
	name    string
	agent   *passwd.Agent
	clients []ClientConfig
}

// Server is the auth-oidc HTTP server.
type Server struct {
	cfg     *Config
	keys    *keyStore
	store   *memStore
	domains map[string]*domainEntry
}

// New builds a Server from cfg, loading/generating keypairs and auth agents for
// every domain referenced in the client list.
func New(cfg *Config) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		keys:    newKeyStore(),
		store:   newMemStore(),
		domains: make(map[string]*domainEntry),
	}

	seen := make(map[string]struct{})
	for _, c := range cfg.Clients {
		if _, ok := seen[c.Domain]; ok {
			continue
		}
		seen[c.Domain] = struct{}{}
		if err := s.loadDomain(c.Domain); err != nil {
			return nil, fmt.Errorf("domain %s: %w", c.Domain, err)
		}
	}

	return s, nil
}

func (s *Server) loadDomain(name string) error {
	cfgPath := filepath.Join(s.cfg.Server.DomainDataPath, name, "config.toml")
	dc, err := domain.LoadDomainConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load domain config: %w", err)
	}

	domainDir := filepath.Join(s.cfg.Server.DomainDataPath, name)
	passwdPath := filepath.Join(domainDir, dc.Auth.CredentialBackend)
	keyDir := filepath.Join(domainDir, dc.Auth.KeyBackend)

	agent, err := passwd.NewAgent(passwdPath, keyDir)
	if err != nil {
		return fmt.Errorf("passwd agent: %w", err)
	}

	if err := s.keys.LoadOrGenerate(name, s.cfg.Server.DataDir); err != nil {
		_ = agent.Close()
		return fmt.Errorf("load keys: %w", err)
	}

	var clients []ClientConfig
	for _, c := range s.cfg.Clients {
		if c.Domain == name {
			clients = append(clients, c)
		}
	}

	s.domains[name] = &domainEntry{
		name:    name,
		agent:   agent,
		clients: clients,
	}
	return nil
}

// Close releases resources held by all domain agents.
func (s *Server) Close() error {
	for _, de := range s.domains {
		_ = de.agent.Close()
	}
	return nil
}

// Handler returns the root HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /{domain}/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /{domain}/.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /{domain}/authorize", s.authorize)
	mux.HandleFunc("POST /{domain}/login", s.login)
	mux.HandleFunc("POST /{domain}/token", s.token)
	mux.HandleFunc("GET /{domain}/userinfo", s.userinfo)
	mux.HandleFunc("POST /{domain}/logout", s.logout)

	return mux
}

// issuerBase returns the OIDC issuer string for the given domain.
func issuerBase(r *http.Request, domainName string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/" + domainName
}

// domainFor validates the domain path value and returns its entry.
func (s *Server) domainFor(w http.ResponseWriter, r *http.Request) (*domainEntry, bool) {
	name := r.PathValue("domain")
	de, ok := s.domains[name]
	if !ok {
		http.Error(w, "unknown domain", http.StatusNotFound)
		return nil, false
	}
	return de, true
}

// clientFor finds a registered client by ID within a domain entry.
func (s *Server) clientFor(de *domainEntry, clientID string) (*ClientConfig, bool) {
	for i := range de.clients {
		if de.clients[i].ID == clientID {
			return &de.clients[i], true
		}
	}
	return nil, false
}

// validRedirectURI reports whether uri is registered for the client.
func validRedirectURI(client *ClientConfig, uri string) bool {
	for _, u := range client.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
