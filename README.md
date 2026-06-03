# OAuth 2.0 Demo Server

A minimal but complete OAuth 2.0 Authorization Server for testing consumer applications. Supports the full Authorization Code flow, PKCE, token refresh, introspection, and revocation.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 discovery metadata |
| GET | `/oauth/authorize` | Authorization endpoint (login form) |
| POST | `/oauth/token` | Token endpoint (code → tokens) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| GET 🔒 | `/api/me` | Protected user info |
| GET 🔒 | `/api/data` | Protected dummy resource list |
| POST 🔒 | `/api/data` | Protected dummy resource create |

## Local Development

```bash
cp .env.example .env
npm install
npm start
# Server: http://localhost:3000
```

## Authorization Code Flow — Step by Step

### 1. Redirect your user to the authorization endpoint

```
GET http://localhost:3000/oauth/authorize
  ?client_id=demo-client-id
  &redirect_uri=http://localhost:8080/callback
  &response_type=code
  &scope=openid profile api:read
  &state=YOUR_RANDOM_STATE
```

The user sees a login form. Demo credentials:
- **alice** / password123 (role: admin)
- **bob** / password123 (role: user)

### 2. Handle the callback

Your app receives a redirect to:
```
http://localhost:8080/callback?code=<auth_code>&state=YOUR_RANDOM_STATE
```

Always verify `state` matches what you sent.

### 3. Exchange the code for tokens

```bash
curl -X POST http://localhost:3000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=<auth_code>" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
```

Response:
```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<UUID>",
  "scope": "openid profile api:read"
}
```

### 4. Call a protected endpoint

```bash
curl http://localhost:3000/api/data \
  -H "Authorization: Bearer <access_token>"
```

### 5. Refresh the access token

```bash
curl -X POST http://localhost:3000/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<refresh_token>" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
```

## PKCE Support

Add these parameters to the `/oauth/authorize` request:
- `code_challenge=<BASE64URL(SHA256(code_verifier))>`
- `code_challenge_method=S256`

Then include `code_verifier` in the `/oauth/token` request.

## Deploying to Render.com

1. Push this repo to GitHub.
2. In Render: **New → Web Service** → connect your repo.
3. Set:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Add **Environment Variables** in the Render dashboard:

| Variable | Value |
|----------|-------|
| `PORT` | (Render sets this automatically) |
| `BASE_URL` | `https://your-service-name.onrender.com` |
| `JWT_SECRET` | A long random string |
| `CLIENT_ID` | Your desired client ID |
| `CLIENT_SECRET` | Your desired client secret |
| `REDIRECT_URIS` | Your app's callback URL(s), comma-separated |

> **Important:** `BASE_URL` must match the public Render URL — it's embedded in JWT `iss` claims and the discovery document.

## Registering Additional Clients

Edit the `CLIENTS` object in `server.js` or extend it to load from environment variables.

## Notes

- Auth codes expire after **5 minutes** (one-time use)
- Access tokens are **JWTs**, valid for **1 hour**
- Refresh tokens **rotate** on each use
- All state is **in-memory** — resets on restart (fine for demos)
