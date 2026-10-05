package webapp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
	"golang.org/x/oauth2"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/redirectallow"
	"github.com/Muxcore-Media/auth-oidc/internal/server"
	"github.com/Muxcore-Media/auth-oidc/internal/session"
)

type codeEntry struct {
	expiresAt time.Time
	sessToken string
}

type stateEntry struct {
	expiresAt    time.Time
	redirect     string
	pkceVerifier string
	nonce        string
}

// Handler serves the auth-local-compatible browser login contract.
type Handler struct {
	flow     oidc.Flow
	sessions *session.Store
	authSrv  *server.AuthServer
	codes    map[string]*codeEntry
	states   map[string]*stateEntry
	stopCh   chan struct{}
	flowMu   sync.RWMutex
	codesMu  sync.Mutex
	stateMu  sync.Mutex
}

func New(sessions *session.Store, authSrv *server.AuthServer, flow oidc.Flow) *Handler {
	h := &Handler{
		sessions: sessions,
		authSrv:  authSrv,
		flow:     flow,
		codes:    make(map[string]*codeEntry),
		states:   make(map[string]*stateEntry),
		stopCh:   make(chan struct{}),
	}
	go h.cleanup()
	return h
}

// SetFlow swaps the OIDC provider used by login/callback (live settings updates).
func (h *Handler) SetFlow(flow oidc.Flow) {
	h.flowMu.Lock()
	h.flow = flow
	h.flowMu.Unlock()
}

func (h *Handler) getFlow() oidc.Flow {
	h.flowMu.RLock()
	defer h.flowMu.RUnlock()
	return h.flow
}

func (h *Handler) Stop() {
	close(h.stopCh)
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/oidc/callback", h.callbackHandler)
	mux.HandleFunc("/login/exchange", h.exchangeHandler)
	mux.HandleFunc("/logout", h.logoutHandler)
	mux.HandleFunc("/session/validate", h.validateHandler)
	mux.HandleFunc("/session/revoke", h.revokeHandler)
}

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !oidc.IsConfigured(h.getFlow()) {
		http.Error(w, "OIDC IdP not configured", http.StatusServiceUnavailable)
		return
	}
	redirect := safeRedirect(r.Host, r.URL.Query().Get("redirect"))
	state, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pkceVerifier := oauth2.GenerateVerifier()
	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.stateMu.Lock()
	h.states[state] = &stateEntry{
		redirect:     redirect,
		pkceVerifier: pkceVerifier,
		nonce:        nonce,
		expiresAt:    time.Now().Add(10 * time.Minute),
	}
	h.stateMu.Unlock()
	params := oidc.AuthParams{PKCEVerifier: pkceVerifier, Nonce: nonce}
	http.Redirect(w, r, h.getFlow().AuthCodeURL(state, params), http.StatusFound)
}

func (h *Handler) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !oidc.IsConfigured(h.getFlow()) {
		http.Error(w, "OIDC IdP not configured", http.StatusServiceUnavailable)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		slog.Warn("oidc callback error", "error", errParam, "description", desc)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "code and state required", http.StatusBadRequest)
		return
	}

	h.stateMu.Lock()
	entry, ok := h.states[state]
	if ok {
		delete(h.states, state)
	}
	h.stateMu.Unlock()
	if !ok || time.Now().After(entry.expiresAt) {
		http.Error(w, "invalid or expired state", http.StatusUnauthorized)
		return
	}

	params := oidc.AuthParams{PKCEVerifier: entry.pkceVerifier, Nonce: entry.nonce}
	ident, err := h.getFlow().Exchange(r.Context(), code, params)
	if err != nil {
		slog.Warn("oidc exchange failed", "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	sess, err := h.sessions.Create(r.Context(), ident.Subject, ident.Username, ident.Roles)
	if err != nil {
		slog.Error("create session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.redirectWithCode(w, r, sess.Token, entry.redirect)
}

func (h *Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token != "" {
		if h.authSrv != nil {
			_, _ = h.authSrv.Revoke(r.Context(), &authv1.RevokeRequest{Token: token})
		} else {
			h.sessions.Revoke(r.Context(), token)
		}
	}
	postLogout := safeRedirect(r.Host, r.URL.Query().Get("redirect"))
	if postLogout == "/" {
		postLogout = ""
	}
	if endURL := h.getFlow().EndSessionURL(postLogout); endURL != "" {
		// endURL is the IdP's end_session_endpoint from OIDC discovery (operator-configured issuer), not user input.
		http.Redirect(w, r, endURL, http.StatusFound) //nolint:gosec // G710: IdP-provided end-session URL from discovery, not request-controlled
		return
	}
	if postLogout != "" {
		http.Redirect(w, r, postLogout, http.StatusFound) //nolint:gosec // G710: postLogout was validated by safeRedirect (same-origin path or allow-listed host)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Handler) exchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	sessToken, ok := h.consumeCode(req.Code)
	if !ok {
		http.Error(w, "invalid or expired code", http.StatusUnauthorized)
		return
	}

	sess, err := h.sessions.Get(r.Context(), sessToken)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":    sess.Token,
		"user_id":  sess.UserID,
		"username": sess.Username,
		"roles":    sess.Roles,
	})
}

func (h *Handler) validateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if h.authSrv == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	resp, err := h.authSrv.Validate(r.Context(), &authv1.ValidateRequest{Token: req.Token})
	if err != nil {
		http.Error(w, "validate failed", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if !resp.GetValid() {
		w.WriteHeader(http.StatusUnauthorized)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"valid":    resp.GetValid(),
		"user_id":  resp.GetUserId(),
		"username": resp.GetUsername(),
		"roles":    resp.GetRoles(),
		"error":    resp.GetError(),
	})
}

func (h *Handler) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if h.authSrv == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.authSrv.Revoke(r.Context(), &authv1.RevokeRequest{Token: req.Token}); err != nil {
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h *Handler) redirectWithCode(w http.ResponseWriter, r *http.Request, sessToken, redirect string) {
	code := h.generateCode(sessToken)
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	http.Redirect(w, r, redirect+sep+"code="+code, http.StatusSeeOther)
}

func (h *Handler) generateCode(sessToken string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := hex.EncodeToString(b)
	h.codesMu.Lock()
	h.codes[code] = &codeEntry{
		sessToken: sessToken,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	h.codesMu.Unlock()
	return code
}

func (h *Handler) consumeCode(code string) (string, bool) {
	h.codesMu.Lock()
	defer h.codesMu.Unlock()
	entry, ok := h.codes[code]
	if !ok {
		return "", false
	}
	delete(h.codes, code)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.sessToken, true
}

func (h *Handler) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			h.codesMu.Lock()
			for k, v := range h.codes {
				if now.After(v.expiresAt) {
					delete(h.codes, k)
				}
			}
			h.codesMu.Unlock()
			h.stateMu.Lock()
			for k, v := range h.states {
				if now.After(v.expiresAt) {
					delete(h.states, k)
				}
			}
			h.stateMu.Unlock()
		}
	}
}

// safeRedirect accepts same-origin paths and absolute http(s) URLs whose host is
// allowed for requestHost (the incoming request's Host header).
func safeRedirect(requestHost, redirect string) string {
	if redirect == "" {
		return "/"
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		return "/"
	}
	if !parsed.IsAbs() {
		// Only same-origin paths are acceptable. A scheme-relative target
		// ("//evil.example") or one using backslashes ("/\evil.example") is
		// treated as a host by browsers and would be an open redirect.
		if parsed.Host != "" || strings.Contains(redirect, `\`) {
			return "/"
		}
		return redirect
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "/"
	}
	if redirectallow.HostAllowed(requestHost, parsed.Host) {
		return redirect
	}
	return "/"
}

// SafeRedirectForHostForTest exposes safeRedirect for unit tests.
func SafeRedirectForHostForTest(requestHost, redirect string) string {
	return safeRedirect(requestHost, redirect)
}

// SafeRedirectForTest exposes safeRedirect for unit tests.
func SafeRedirectForTest(r *url.URL, redirect string) string {
	return safeRedirect(r.Host, redirect)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
