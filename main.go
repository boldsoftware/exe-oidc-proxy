package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
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

	// RedirectURIs is the set of redirection endpoints the client is
	// registered to use, matched exactly (RFC 6749 §3.1.2.2). When empty,
	// any redirect URI on the issuer's own origin is accepted, which covers
	// the common case: this proxy fronts a single app served from the same
	// hostname it issues tokens for.
	RedirectURIs []string
}

type authCode struct {
	Email       string
	UserID      string
	Nonce       string
	RedirectURI string
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
	redirectURIs := flag.String("redirect-uri", os.Getenv("REDIRECT_URI"), "comma-separated list of registered redirect URIs (default: any URI on the issuer's origin)")
	flag.Parse()

	for _, u := range strings.Split(*redirectURIs, ",") {
		if u = strings.TrimSpace(u); u != "" {
			cfg.RedirectURIs = append(cfg.RedirectURIs, u)
		}
	}

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

	// checkRedirectURI falls back to the issuer's origin, so an issuer that
	// doesn't parse would silently reject every authorization request.
	origin, err := issuerOrigin()
	if err != nil {
		log.Fatalf("parsing issuer URL: %v", err)
	}

	// A registered redirect URI that can't pass checkRedirectURI's syntactic
	// gates can never match, so it would silently reject every authorization
	// request that names it.
	for _, u := range cfg.RedirectURIs {
		if _, err := checkRedirectURI(u); err != nil {
			log.Fatalf("registered redirect URI %q: %v", u, err)
		}
	}

	if len(cfg.RedirectURIs) > 0 {
		log.Printf("redirect URIs: %s", strings.Join(cfg.RedirectURIs, ", "))
	} else {
		log.Printf("redirect URIs: any on %s", originOf(origin))
	}

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
		"authorization_endpoint":                cfg.Issuer + "/authorize",
		"token_endpoint":                        cfg.Issuer + "/token",
		"userinfo_endpoint":                     cfg.Issuer + "/userinfo",
		"jwks_uri":                              cfg.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "email", "iss", "aud", "exp", "iat", "nonce"},
		"grant_types_supported":                 []string{"authorization_code"},
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
	responseMode := r.URL.Query().Get("response_mode")

	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	// An unregistered redirect URI is reported to the user agent, never
	// redirected to (RFC 6749 §4.1.2.1): redirecting would hand the
	// authorization code to whoever supplied the URI.
	u, err := checkRedirectURI(redirectURI)
	if err != nil {
		log.Printf("authorize: rejecting redirect_uri %q for %s: %v", redirectURI, email, err)
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	code := randomString(32)
	codes.Store(code, authCode{Email: email, UserID: userID, Nonce: nonce, RedirectURI: redirectURI}, 60*time.Second)

	// Build the response parameters. A query component already present on
	// the redirect URI is retained (RFC 6749 §3.1.2): in query mode the
	// response parameters merge into it, in fragment mode it rides along
	// untouched.
	params := url.Values{}
	if responseMode != "fragment" {
		params = u.Query()
	}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	if responseMode == "fragment" {
		// u.String() re-escapes u.Fragment, which would double-encode the
		// already-encoded parameters; append the fragment directly instead.
		http.Redirect(w, r, u.String()+"#"+params.Encode(), http.StatusFound)
		return
	}
	u.RawQuery = params.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// issuerOrigin returns the scheme and host of the configured issuer, which is
// the default origin that redirect URIs must belong to.
func issuerOrigin() (*url.URL, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("issuer %q is not an absolute URL", cfg.Issuer)
	}
	return u, nil
}

// checkRedirectURI parses raw and reports whether the client is registered to
// use it. With -redirect-uri set, raw must match one of the registered values
// exactly; otherwise it must sit on the issuer's own origin.
func checkRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("unparsable: %w", err)
	}
	// RFC 6749 §3.1.2: the redirection endpoint must be an absolute URI and
	// must not carry a fragment (the server owns the fragment in the
	// response_mode=fragment case).
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("not an absolute URI")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, fmt.Errorf("carries a fragment")
	}

	if len(cfg.RedirectURIs) > 0 {
		for _, want := range cfg.RedirectURIs {
			if raw == want {
				return u, nil
			}
		}
		return nil, fmt.Errorf("not a registered redirect URI")
	}

	origin, err := issuerOrigin()
	if err != nil {
		return nil, err
	}
	if got, want := originOf(u), originOf(origin); got != want {
		return nil, fmt.Errorf("origin %s is not the issuer's origin %s", got, want)
	}
	return u, nil
}

// originOf renders u's scheme and authority in a comparable form: lowercased,
// with the scheme's default port dropped, so that https://host and
// https://host:443 compare equal. Folding is ASCII-only: Unicode look-alike
// hosts (İ.example) reach browsers as distinct punycode origins, so they must
// not compare equal here.
func originOf(u *url.URL) string {
	scheme := lowerASCII(u.Scheme)
	host := lowerASCII(u.Host)
	if h, port, err := net.SplitHostPort(host); err == nil {
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			host = h
		}
	}
	return scheme + "://" + host
}

// lowerASCII lowercases ASCII letters only, leaving other runes untouched.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
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

	// RFC 6749 §10.6: the redirect URI presented here must be the one the
	// code was issued to. Clients that omit it are tolerated for
	// compatibility -- client authentication above is the real gate, and
	// the code only ever reached a URI that passed checkRedirectURI.
	if got := r.FormValue("redirect_uri"); got != "" && got != ac.RedirectURI {
		log.Printf("token: redirect_uri %q does not match the one the code was issued to", got)
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	accessToken := randomString(32)
	tokens.Store(accessToken, tokenInfo{Email: ac.Email, UserID: ac.UserID}, 24*time.Hour)
	log.Printf("token: issued access token for %s", ac.Email)

	// Derive a display name from email
	name := ac.Email
	if idx := strings.Index(ac.Email, "@"); idx > 0 {
		name = ac.Email[:idx]
	}

	now := time.Now()
	idToken := jwtToken{
		Header: jwtHeader{Alg: "ES256", Typ: "JWT", Kid: keyID},
		Claims: map[string]any{
			"iss":                cfg.Issuer,
			"sub":                ac.UserID,
			"aud":                cfg.ClientID,
			"email":              ac.Email,
			"name":               name,
			"preferred_username": name,
			"groups":             []string{"admin"},
			"iat":                now.Unix(),
			"exp":                now.Add(24 * time.Hour).Unix(),
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
	// Also check query parameter and form body (some clients send it there)
	if accessToken == "" {
		accessToken = r.URL.Query().Get("access_token")
	}
	if accessToken == "" {
		r.ParseForm()
		accessToken = r.FormValue("access_token")
	}
	if accessToken == "" {
		log.Printf("userinfo: no access token in header, query, or form")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	info, ok := tokens.Load(accessToken)
	if !ok {
		log.Printf("userinfo: unknown access token")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Derive a display name from email (part before @)
	name := info.Email
	if idx := strings.Index(info.Email, "@"); idx > 0 {
		name = info.Email[:idx]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":                info.UserID,
		"email":              info.Email,
		"name":               name,
		"preferred_username": name,
		"groups":             []string{"admin"},
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
	// Try POST body first. PostFormValue ignores the URL query: a secret
	// there would land in access logs and intermediaries.
	if credsMatch(r.PostFormValue("client_id"), r.PostFormValue("client_secret")) {
		return true
	}
	// Try Basic auth.
	if user, pass, ok := r.BasicAuth(); ok {
		return credsMatch(user, pass)
	}
	return false
}

// credsMatch reports whether id and secret are the configured client
// credentials, without leaking how far they matched through timing.
func credsMatch(id, secret string) bool {
	idOK := constantTimeEqual(id, cfg.ClientID)
	secretOK := constantTimeEqual(secret, cfg.ClientSecret)
	return idOK && secretOK
}

// constantTimeEqual compares digests rather than the strings themselves so
// that the comparison leaks neither content nor length.
func constantTimeEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	// Handle both "Bearer" and "bearer" (case-insensitive)
	if len(auth) > 7 && strings.EqualFold(auth[:6], "bearer") && auth[6] == ' ' {
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
