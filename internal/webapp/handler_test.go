package webapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
	"github.com/Muxcore-Media/auth-oidc/internal/policy"
	"github.com/Muxcore-Media/auth-oidc/internal/server"
	"github.com/Muxcore-Media/auth-oidc/internal/session"
	"github.com/Muxcore-Media/auth-oidc/internal/webapp"
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

func TestLoginCallbackExchange(t *testing.T) {
	fake := &oidc.Fake{
		Identity: &oidc.Identity{
			Subject:  "sub-42",
			Username: "alice",
			Roles:    []string{"admin"},
		},
	}
	store := testStore(t)
	authSrv := server.New(store, policy.Builtin())
	h := webapp.New(store, authSrv, fake)
	defer h.Stop()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/login?redirect="+url.QueryEscape("http://localhost:8082/callback"), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login status=%d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("missing state in %s", loc)
	}

	cb := httptest.NewRequest(http.MethodGet, "/oidc/callback?code=idp-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	mux.ServeHTTP(cbRec, cb)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status=%d body=%s", cbRec.Code, cbRec.Body.String())
	}
	if fake.LastCode != "idp-code" {
		t.Fatalf("exchange code=%q", fake.LastCode)
	}
	redir := cbRec.Header().Get("Location")
	ru, err := url.Parse(redir)
	if err != nil {
		t.Fatal(err)
	}
	oneTime := ru.Query().Get("code")
	if oneTime == "" {
		t.Fatalf("missing one-time code in %s", redir)
	}
	if !strings.HasPrefix(redir, "http://localhost:8082/callback") {
		t.Fatalf("redirect=%s", redir)
	}

	body, _ := json.Marshal(map[string]string{"code": oneTime})
	ex := httptest.NewRequest(http.MethodPost, "/login/exchange", bytes.NewReader(body))
	ex.Header.Set("Content-Type", "application/json")
	exRec := httptest.NewRecorder()
	mux.ServeHTTP(exRec, ex)
	if exRec.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", exRec.Code, exRec.Body.String())
	}
	var resp struct {
		Token    string   `json:"token"`
		UserID   string   `json:"user_id"`
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
	}
	if err := json.NewDecoder(exRec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" || len(resp.Token) != 64 {
		t.Fatalf("token=%q", resp.Token)
	}
	if resp.UserID != "sub-42" || resp.Username != "alice" {
		t.Fatalf("resp=%+v", resp)
	}
	if len(resp.Roles) != 1 || resp.Roles[0] != "admin" {
		t.Fatalf("roles=%v", resp.Roles)
	}

	ex2 := httptest.NewRequest(http.MethodPost, "/login/exchange", bytes.NewReader(body))
	ex2.Header.Set("Content-Type", "application/json")
	ex2Rec := httptest.NewRecorder()
	mux.ServeHTTP(ex2Rec, ex2)
	if ex2Rec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse status=%d", ex2Rec.Code)
	}

	sess, err := store.Get(context.Background(), resp.Token)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if sess.Username != "alice" {
		t.Fatalf("sess=%+v", sess)
	}

	valBody, _ := json.Marshal(map[string]string{"token": resp.Token})
	valReq := httptest.NewRequest(http.MethodPost, "/session/validate", bytes.NewReader(valBody))
	valReq.Header.Set("Content-Type", "application/json")
	valRec := httptest.NewRecorder()
	mux.ServeHTTP(valRec, valReq)
	if valRec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", valRec.Code, valRec.Body.String())
	}
	var valResp struct {
		Valid    bool   `json:"valid"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(valRec.Body).Decode(&valResp); err != nil {
		t.Fatal(err)
	}
	if !valResp.Valid || valResp.Username != "alice" {
		t.Fatalf("validate=%+v", valResp)
	}

	revBody, _ := json.Marshal(map[string]string{"token": resp.Token})
	revReq := httptest.NewRequest(http.MethodPost, "/session/revoke", bytes.NewReader(revBody))
	revReq.Header.Set("Content-Type", "application/json")
	revRec := httptest.NewRecorder()
	mux.ServeHTTP(revRec, revReq)
	if revRec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", revRec.Code)
	}
	if _, err := store.Get(context.Background(), resp.Token); err == nil {
		t.Fatal("expected miss after revoke")
	}
}

func TestExchangeBadCode(t *testing.T) {
	store := testStore(t)
	h := webapp.New(store, server.New(store, policy.Builtin()), &oidc.Fake{})
	defer h.Stop()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/login/exchange", io.NopCloser(strings.NewReader(`{"code":"nope"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}
