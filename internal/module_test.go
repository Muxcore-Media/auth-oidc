package internal_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Muxcore-Media/auth-oidc/internal"
	"github.com/Muxcore-Media/auth-oidc/internal/oidc"
)

func TestModuleLoginValidateRoundTrip(t *testing.T) {
	fake := &oidc.Fake{
		Identity: &oidc.Identity{
			Subject:  "oidc-sub",
			Username: "carol",
			Roles:    []string{"user"},
		},
	}
	mod := internal.NewModule(internal.Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		DBPath:     filepath.Join(t.TempDir(), "oidc.db"),
		PolicyFile: "/nonexistent-auth-oidc-policy.yaml",
		Flow:       fake,
	})
	ctx := context.Background()
	if err := mod.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := mod.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mod.Stop(ctx)

	httpBase := "http://" + mod.HTTPAddr()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(httpBase + "/login?redirect=" + url.QueryEscape("http://localhost:8082/cb"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login=%d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	cb, err := client.Get(httpBase + "/oidc/callback?code=abc&state=" + state)
	if err != nil {
		t.Fatal(err)
	}
	cb.Body.Close()
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback=%d", cb.StatusCode)
	}
	ru, _ := url.Parse(cb.Header.Get("Location"))
	code := ru.Query().Get("code")

	exReq, _ := http.NewRequest(http.MethodPost, httpBase+"/login/exchange", strings.NewReader(`{"code":"`+code+`"}`))
	exReq.Header.Set("Content-Type", "application/json")
	ex, err := client.Do(exReq)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Body.Close()
	body, _ := io.ReadAll(ex.Body)
	if ex.StatusCode != http.StatusOK {
		t.Fatalf("exchange=%d body=%s", ex.StatusCode, body)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	conn, err := grpc.NewClient(mod.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := authv1.NewAuthServiceClient(conn)
	v, err := auth.Validate(ctx, &authv1.ValidateRequest{Token: payload.Token})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Username != "carol" {
		t.Fatalf("validate=%+v", v)
	}
}
