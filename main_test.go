package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setupTest(t *testing.T, upstream *httptest.Server) *http.ServeMux {
	t.Helper()
	var err error
	signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID = computeKeyID(&signingKey.PublicKey)

	cfg = config{
		Upstream:     upstream.URL,
		Issuer:       "https://test.exe.xyz/_oidc",
		ClientID:     "testapp",
		ClientSecret: "testsecret",
	}

	// Clear state.
	codes = pendingMap[authCode]{}
	tokens = pendingMap[tokenInfo]{}

	mux := http.NewServeMux()
	mux.HandleFunc("/_oidc/.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("/_oidc/authorize", handleAuthorize)
	mux.HandleFunc("/_oidc/token", handleToken)
	mux.HandleFunc("/_oidc/userinfo", handleUserInfo)
	mux.HandleFunc("/_oidc/jwks", handleJWKS)
	return mux
}

func TestDiscovery(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_oidc/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}

	if doc["issuer"] != cfg.Issuer {
		t.Errorf("issuer = %v, want %v", doc["issuer"], cfg.Issuer)
	}
	if doc["authorization_endpoint"] != cfg.Issuer+"/authorize" {
		t.Errorf("authorization_endpoint = %v", doc["authorization_endpoint"])
	}
}

func TestAuthorizeRedirectsToLoginWhenNoHeader(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/_oidc/authorize?redirect_uri=http://app/callback&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/__exe.dev/login?") {
		t.Errorf("location = %q, want /__exe.dev/login?...", loc)
	}
}

func TestAuthorizeIssuesCode(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	req, _ := http.NewRequest("GET", srv.URL+"/_oidc/authorize?redirect_uri=http://app/callback&state=xyz&nonce=n1", nil)
	req.Header.Set("X-Exedev-Email", "alice@example.com")
	req.Header.Set("X-Exedev-Userid", "usr_alice")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	if loc.Host != "app" || loc.Path != "/callback" {
		t.Errorf("redirect to %v, want http://app/callback", loc)
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("state = %q, want xyz", loc.Query().Get("state"))
	}
	if loc.Query().Get("code") == "" {
		t.Error("missing code")
	}
}

func TestFullOIDCFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Step 1: Authorize.
	req, _ := http.NewRequest("GET", srv.URL+"/_oidc/authorize?redirect_uri=http://app/callback&state=s1&nonce=n1&response_type=code", nil)
	req.Header.Set("X-Exedev-Email", "bob@test.com")
	req.Header.Set("X-Exedev-Userid", "usr_bob")

	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}

	// Step 2: Exchange code for tokens (client_secret_post).
	tokenResp, err := http.PostForm(srv.URL+"/_oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://app/callback"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status = %d: %s", tokenResp.StatusCode, body)
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		t.Fatal(err)
	}

	if tokenData.AccessToken == "" {
		t.Error("empty access_token")
	}
	if tokenData.IDToken == "" {
		t.Error("empty id_token")
	}
	if tokenData.TokenType != "bearer" {
		t.Errorf("token_type = %q", tokenData.TokenType)
	}

	// Verify the id_token.
	verifyIDToken(t, tokenData.IDToken, "bob@test.com", "usr_bob", "n1")

	// Step 3: UserInfo.
	uiReq, _ := http.NewRequest("GET", srv.URL+"/_oidc/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		t.Fatal(err)
	}
	defer uiResp.Body.Close()

	var userInfo map[string]any
	if err := json.NewDecoder(uiResp.Body).Decode(&userInfo); err != nil {
		t.Fatal(err)
	}
	if userInfo["email"] != "bob@test.com" {
		t.Errorf("userinfo email = %q", userInfo["email"])
	}
	if userInfo["sub"] != "usr_bob" {
		t.Errorf("userinfo sub = %q", userInfo["sub"])
	}
	groups, ok := userInfo["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "admin" {
		t.Errorf("userinfo groups = %v", userInfo["groups"])
	}
}

func TestTokenWithBasicAuth(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Authorize.
	req, _ := http.NewRequest("GET", srv.URL+"/_oidc/authorize?redirect_uri=http://app/cb&state=s", nil)
	req.Header.Set("X-Exedev-Email", "carol@test.com")
	req.Header.Set("X-Exedev-Userid", "usr_carol")
	resp, _ := noFollow.Do(req)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	// Exchange with Basic auth.
	tokenReq, _ := http.NewRequest("POST", srv.URL+"/_oidc/token",
		strings.NewReader(url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {"http://app/cb"},
		}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("status = %d: %s", tokenResp.StatusCode, body)
	}
}

func TestTokenBadClientSecret(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/_oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"whatever"},
		"client_id":     {cfg.ClientID},
		"client_secret": {"wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestCodeExpiry(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Manually store an expired code.
	codes.m.Store("expired-code", pendingEntry[authCode]{
		Value:  authCode{Email: "old@test.com", UserID: "usr_old"},
		Expiry: time.Now().Add(-time.Second),
	})

	resp, err := http.PostForm(srv.URL+"/_oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"expired-code"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCodeSingleUse(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Authorize.
	req, _ := http.NewRequest("GET", srv.URL+"/_oidc/authorize?redirect_uri=http://app/cb&state=s", nil)
	req.Header.Set("X-Exedev-Email", "dan@test.com")
	req.Header.Set("X-Exedev-Userid", "usr_dan")
	resp, _ := noFollow.Do(req)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	post := func() int {
		resp, err := http.PostForm(srv.URL+"/_oidc/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {cfg.ClientID},
			"client_secret": {cfg.ClientSecret},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if s := post(); s != 200 {
		t.Fatalf("first use: status %d", s)
	}
	if s := post(); s != 400 {
		t.Errorf("second use: status %d, want 400", s)
	}
}

func TestJWKS(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_oidc/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
		t.Errorf("key = %+v", k)
	}
	if k.Kid != keyID {
		t.Errorf("kid = %q, want %q", k.Kid, keyID)
	}
}

func TestUserInfoNoToken(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_oidc/userinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthorizeNoRedirectURI(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	mux := setupTest(t, upstream)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/_oidc/authorize?state=s", nil)
	req.Header.Set("X-Exedev-Email", "test@test.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// verifyIDToken parses and verifies a JWT id_token against the signing key.
func verifyIDToken(t *testing.T, tokenStr, wantEmail, wantSub, wantNonce string) {
	t.Helper()

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token has %d parts, want 3", len(parts))
	}

	// Verify signature.
	unsigned := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}

	hash := sha256.Sum256([]byte(unsigned))
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(&signingKey.PublicKey, hash[:], r, s) {
		t.Fatal("id_token signature verification failed")
	}

	// Verify claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}

	if claims["iss"] != cfg.Issuer {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["email"] != wantEmail {
		t.Errorf("email = %v, want %v", claims["email"], wantEmail)
	}
	if claims["sub"] != wantSub {
		t.Errorf("sub = %v, want %v", claims["sub"], wantSub)
	}
	if wantNonce != "" && claims["nonce"] != wantNonce {
		t.Errorf("nonce = %v, want %v", claims["nonce"], wantNonce)
	}
	if claims["aud"] != cfg.ClientID {
		t.Errorf("aud = %v, want %v", claims["aud"], cfg.ClientID)
	}
}
