package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	signingKey *ecdsa.PrivateKey
	keyID      string

	codes  pendingMap[authCode]
	tokens pendingMap[tokenInfo]

	cfg config
)

type config struct {
	Listen       string
	Upstream     string
	Issuer       string
	ClientID     string
	ClientSecret string
}

type authCode struct {
	Email  string
	UserID string
	Nonce  string
}

type tokenInfo struct {
	Email  string
	UserID string
}

func main() {
	flag.StringVar(&cfg.Listen, "listen", envOr("LISTEN", ":8000"), "listen address")
	flag.StringVar(&cfg.Upstream, "upstream", os.Getenv("UPSTREAM"), "upstream URL to proxy to")
	flag.StringVar(&cfg.Issuer, "issuer", os.Getenv("ISSUER"), "OIDC issuer URL")
	flag.StringVar(&cfg.ClientID, "client-id", os.Getenv("CLIENT_ID"), "OIDC client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", os.Getenv("CLIENT_SECRET"), "OIDC client secret")
	flag.Parse()

	if cfg.Upstream == "" {
		log.Fatal("--upstream is required")
	}
	if cfg.Issuer == "" {
		log.Fatal("--issuer is required")
	}
	if cfg.ClientID == "" {
		log.Fatal("--client-id is required")
	}
	if cfg.ClientSecret == "" {
		log.Fatal("--client-secret is required")
	}

	var err error
	signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generating signing key: %v", err)
	}
	keyID = computeKeyID(&signingKey.PublicKey)

	go sweepLoop()

	upstreamURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Fatalf("parsing upstream URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/_oidc/.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("/_oidc/authorize", handleAuthorize)
	mux.HandleFunc("/_oidc/token", handleToken)
	mux.HandleFunc("/_oidc/userinfo", handleUserInfo)
	mux.HandleFunc("/_oidc/jwks", handleJWKS)
	mux.Handle("/", proxy)

	log.Printf("exe-oidc-proxy listening on %s, upstream %s, issuer %s", cfg.Listen, cfg.Upstream, cfg.Issuer)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Fatal(err)
	}
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                cfg.Issuer,
		"authorization_endpoint":                 cfg.Issuer + "/authorize",
		"token_endpoint":                         cfg.Issuer + "/token",
		"userinfo_endpoint":                      cfg.Issuer + "/userinfo",
		"jwks_uri":                               cfg.Issuer + "/jwks",
		"response_types_supported":               []string{"code"},
		"subject_types_supported":                []string{"public"},
		"id_token_signing_alg_values_supported":  []string{"ES256"},
		"scopes_supported":                       []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported":  []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                       []string{"sub", "email", "iss", "aud", "exp", "iat", "nonce"},
		"grant_types_supported":                  []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-Exedev-Email")
	userID := r.Header.Get("X-Exedev-Userid")

	if email == "" {
		// Not authenticated — bounce through exe.dev login.
		// Reconstruct the full authorize URL so we come back here after login.
		loginURL := "/__exe.dev/login?redirect=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	code := randomString(32)
	codes.Store(code, authCode{Email: email, UserID: userID, Nonce: nonce}, 60*time.Second)

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Authenticate the client via post body or basic auth.
	if !authenticateClient(r) {
		w.Header().Set("WWW-Authenticate", "Basic")
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	ac, ok := codes.LoadAndDelete(code)
	if !ok {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	accessToken := randomString(32)
	tokens.Store(accessToken, tokenInfo{Email: ac.Email, UserID: ac.UserID}, 24*time.Hour)

	now := time.Now()
	idToken := jwtToken{
		Header: jwtHeader{Alg: "ES256", Typ: "JWT", Kid: keyID},
		Claims: map[string]any{
			"iss":   cfg.Issuer,
			"sub":   ac.UserID,
			"aud":   cfg.ClientID,
			"email": ac.Email,
			"iat":   now.Unix(),
			"exp":   now.Add(24 * time.Hour).Unix(),
		},
	}
	if ac.Nonce != "" {
		idToken.Claims["nonce"] = ac.Nonce
	}

	signed, err := idToken.Sign(signingKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"id_token":     signed,
		"token_type":   "bearer",
		"expires_in":   86400,
	})
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken := extractBearerToken(r)
	if accessToken == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	info, ok := tokens.Load(accessToken)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":   info.UserID,
		"email": info.Email,
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &signingKey.PublicKey
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "EC",
			"crv": "P-256",
			"use": "sig",
			"kid": keyID,
			"alg": "ES256",
			"x":   base64URLEncode(pub.X.Bytes(), 32),
			"y":   base64URLEncode(pub.Y.Bytes(), 32),
		}},
	})
}

// authenticateClient checks client credentials from POST body or Basic auth.
func authenticateClient(r *http.Request) bool {
	// Try POST body first.
	if r.FormValue("client_id") == cfg.ClientID && r.FormValue("client_secret") == cfg.ClientSecret {
		return true
	}
	// Try Basic auth.
	if user, pass, ok := r.BasicAuth(); ok {
		return user == cfg.ClientID && pass == cfg.ClientSecret
	}
	return false
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- JWT signing (no dependencies) ---

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtToken struct {
	Header jwtHeader
	Claims map[string]any
}

func (t *jwtToken) Sign(key *ecdsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	unsigned := base64url(headerJSON) + "." + base64url(claimsJSON)

	hash := sha256.Sum256([]byte(unsigned))
	sigR, sigS, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}

	// ECDSA signature for ES256: r || s, each 32 bytes, big-endian.
	sig := make([]byte, 64)
	rBytes := sigR.Bytes()
	sBytes := sigS.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return unsigned + "." + base64url(sig), nil
}

func base64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLEncode encodes a big-endian integer as base64url, zero-padded to size bytes.
func base64URLEncode(b []byte, size int) string {
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return base64url(padded)
}

func computeKeyID(pub *ecdsa.PublicKey) string {
	h := sha256.New()
	h.Write(pub.X.Bytes())
	h.Write(pub.Y.Bytes())
	return base64url(h.Sum(nil)[:8])
}

// --- Pending map with expiry ---

type pendingEntry[T any] struct {
	Value  T
	Expiry time.Time
}

type pendingMap[T any] struct {
	m sync.Map
}

func (p *pendingMap[T]) Store(key string, val T, ttl time.Duration) {
	p.m.Store(key, pendingEntry[T]{Value: val, Expiry: time.Now().Add(ttl)})
}

func (p *pendingMap[T]) Load(key string) (T, bool) {
	v, ok := p.m.Load(key)
	if !ok {
		var zero T
		return zero, false
	}
	e := v.(pendingEntry[T])
	if time.Now().After(e.Expiry) {
		p.m.Delete(key)
		var zero T
		return zero, false
	}
	return e.Value, true
}

func (p *pendingMap[T]) LoadAndDelete(key string) (T, bool) {
	v, ok := p.m.LoadAndDelete(key)
	if !ok {
		var zero T
		return zero, false
	}
	e := v.(pendingEntry[T])
	if time.Now().After(e.Expiry) {
		var zero T
		return zero, false
	}
	return e.Value, true
}

func (p *pendingMap[T]) Sweep() {
	now := time.Now()
	p.m.Range(func(key, value any) bool {
		if e, ok := value.(pendingEntry[T]); ok && now.After(e.Expiry) {
			p.m.Delete(key)
		}
		return true
	})
}

func sweepLoop() {
	for {
		time.Sleep(time.Minute)
		codes.Sweep()
		tokens.Sweep()
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64url(b)
}
