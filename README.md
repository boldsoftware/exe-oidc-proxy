# exe-oidc-proxy

A minimal reverse proxy that acts as an OpenID Connect identity provider,
using [exe.dev](https://exe.dev)'s authentication headers as the source of truth.

When an app (Plane, Zulip, Gitea, etc.) initiates an OIDC login, the browser
is redirected to this proxy's authorization endpoint. Because the proxy sits
behind exe.dev's HTTPS proxy, the `X-ExeDev-Email` and `X-ExeDev-UserID`
headers are already present — so the OIDC flow completes instantly with zero
user interaction.

## Architecture

```
User → exe.dev proxy (adds X-ExeDev-Email/X-ExeDev-UserID)
     → exe-oidc-proxy (port 8000)
       ├── OIDC IdP endpoints (/_oidc/*)
       └── reverse proxy → upstream app (e.g. Plane on :3000)
```

## Install

```
go install github.com/boldsoftware/exe-oidc-proxy@latest
```

## Usage

```
exe-oidc-proxy \
  -listen :8000 \
  -upstream http://localhost:3000 \
  -issuer https://myvm.exe.xyz/_oidc \
  -client-id myapp \
  -client-secret mysecret
```

All flags can also be set via environment variables:

| Flag | Env | Description |
|------|-----|-------------|
| `-listen` | `LISTEN` | Address to listen on (default `:8000`) |
| `-upstream` | `UPSTREAM` | URL of the upstream app to proxy to |
| `-issuer` | `ISSUER` | OIDC issuer URL (your VM's public URL + `/_oidc`) |
| `-client-id` | `CLIENT_ID` | OIDC client ID the app will use |
| `-client-secret` | `CLIENT_SECRET` | OIDC client secret the app will use |
| `-redirect-uri` | `REDIRECT_URI` | Comma-separated list of redirect URIs the app is allowed to use |

## Redirect URIs

The authorization endpoint only redirects to a URI the app is registered to
use. By default that means any URI on the issuer's own origin, which is what
the architecture above produces: the app is served from the same hostname the
proxy issues tokens for. If the app's callback lives somewhere else, register
it explicitly:

```
exe-oidc-proxy ... -redirect-uri https://myapp.example/auth/callback
```

Registered URIs are matched exactly, and setting `-redirect-uri` replaces the
issuer-origin default rather than adding to it: once the list exists, list
every callback the app uses, including ones on the issuer's own origin.

An unregistered `redirect_uri` gets a 400 and no redirect -- redirecting would
hand the authorization code to whoever supplied the URI.

## How it works

1. App has no session → redirects browser to `/_oidc/authorize`
2. exe.dev's proxy has already added `X-ExeDev-Email` to the request
3. The authorize endpoint reads the header, generates an auth code, and
   redirects back to the app's callback URL instantly
4. App exchanges the code for tokens at `/_oidc/token`
5. App verifies the id_token using keys from `/_oidc/jwks`
6. User is logged in

If the user isn't authenticated yet (no `X-ExeDev-Email` header), the
authorize endpoint redirects to `/__exe.dev/login` first.

## OIDC endpoints

| Path | Description |
|------|-------------|
| `/_oidc/.well-known/openid-configuration` | Discovery document |
| `/_oidc/authorize` | Authorization endpoint |
| `/_oidc/token` | Token endpoint |
| `/_oidc/userinfo` | UserInfo endpoint |
| `/_oidc/jwks` | JSON Web Key Set |

## License

MIT
