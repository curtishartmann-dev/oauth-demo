require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const swaggerUi = require("swagger-ui-express");
const yaml = require("js-yaml");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─── Config (override via environment variables) ───────────────────────────
const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET || "demo-secret-change-in-production";
const BASE_URL    = process.env.BASE_URL || `http://localhost:${PORT}`;


// ─── Load OpenAPI spec ────────────────────────────────────────────────────
const specPath = path.join(__dirname, 'openapi.yaml');
let openApiSpec = {};
if (fs.existsSync(specPath)) {
  openApiSpec = yaml.load(fs.readFileSync(specPath, 'utf8'));
}

// ─── Registered demo clients (extend as needed) ───────────────────────────
const CLIENTS = {
  [process.env.CLIENT_ID || "demo-client-id"]: {
    secret:       process.env.CLIENT_SECRET || "demo-client-secret",
    redirectUris: (process.env.REDIRECT_URIS || "http://localhost:8080/callback").split(",").map(s => s.trim()),
    name:         "Demo Application",
  },
};

// ─── Demo users ────────────────────────────────────────────────────────────
const USERS = {
  alice: { password: "password123", name: "Alice Demo", email: "alice@demo.com", role: "admin" },
  bob:   { password: "password123", name: "Bob Demo",   email: "bob@demo.com",   role: "user"  },
};

// ─── In-memory stores (resets on restart — fine for demo) ─────────────────
const authCodes    = new Map(); // code -> { clientId, userId, redirectUri, expiresAt, scope }
const refreshTokens = new Map(); // token -> { clientId, userId, scope }

// ─── Helpers ───────────────────────────────────────────────────────────────
function generateAccessToken(userId, clientId, scope) {
  return jwt.sign(
    { sub: userId, client_id: clientId, scope, type: "access" },
    JWT_SECRET,
    { expiresIn: "1h", issuer: BASE_URL, jwtid: uuidv4() }
  );
}

function verifyAccessToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthorized", error_description: "Missing Bearer token" });
  try {
    req.tokenPayload = jwt.verify(token, JWT_SECRET, { issuer: BASE_URL });
    next();
  } catch (e) {
    res.status(401).json({ error: "invalid_token", error_description: e.message });
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  DISCOVERY  —  GET /.well-known/oauth-authorization-server
// ══════════════════════════════════════════════════════════════════════════
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer:                 BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint:         `${BASE_URL}/oauth/token`,
    userinfo_endpoint:      `${BASE_URL}/api/me`,
    jwks_uri:               `${BASE_URL}/.well-known/jwks.json`,
    response_types_supported:        ["code"],
    grant_types_supported:           ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    scopes_supported:       ["openid", "profile", "email", "api:read", "api:write"],
  });
});

// ══════════════════════════════════════════════════════════════════════════
//  AUTHORIZATION ENDPOINT  —  GET /oauth/authorize
//  Renders a simple login form; submits to POST /oauth/authorize
// ══════════════════════════════════════════════════════════════════════════
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, response_type, scope = "openid profile", state, code_challenge, code_challenge_method } = req.query;

  // Validate client
  const client = CLIENTS[client_id];
  if (!client) return res.status(400).send(errorPage("Unknown client_id"));
  if (response_type !== "code") return res.status(400).send(errorPage("Only response_type=code is supported"));
  if (redirect_uri && !client.redirectUris.includes(redirect_uri))
    return res.status(400).send(errorPage("redirect_uri not registered for this client"));

  const effectiveRedirect = redirect_uri || client.redirectUris[0];

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — OAuth Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: white; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.12); padding: 40px; width: 380px; }
    .logo { text-align: center; margin-bottom: 24px; }
    .logo span { font-size: 28px; font-weight: 700; color: #FF6900; }
    h1 { font-size: 18px; color: #1a1a2e; text-align: center; margin-bottom: 6px; }
    .app-name { text-align: center; font-size: 13px; color: #666; margin-bottom: 28px; }
    .scope-box { background: #f8f9ff; border: 1px solid #e0e4ff; border-radius: 8px; padding: 14px 16px; margin-bottom: 24px; }
    .scope-box p { font-size: 12px; color: #444; margin-bottom: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }
    .scope-box ul { list-style: none; }
    .scope-box li { font-size: 13px; color: #333; padding: 2px 0; }
    .scope-box li::before { content: "✓ "; color: #22c55e; font-weight: 700; }
    label { display: block; font-size: 13px; font-weight: 600; color: #333; margin-bottom: 6px; }
    input[type=text], input[type=password] { width: 100%; padding: 10px 14px; border: 1.5px solid #ddd; border-radius: 8px; font-size: 14px; transition: border-color .2s; margin-bottom: 16px; }
    input:focus { outline: none; border-color: #FF6900; }
    .hint { font-size: 11px; color: #888; margin-top: -12px; margin-bottom: 16px; }
    button { width: 100%; padding: 12px; background: #FF6900; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: opacity .2s; }
    button:hover { opacity: .88; }
    .deny { margin-top: 10px; background: transparent; color: #888; border: 1.5px solid #ddd; }
    .deny:hover { background: #f8f8f8; opacity: 1; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo"><span>OAuth Demo</span></div>
    <h1>Sign in to continue</h1>
    <p class="app-name"><strong>${client.name}</strong> is requesting access</p>
    <div class="scope-box">
      <p>Permissions requested</p>
      <ul>
        ${scope.split(" ").map(s => `<li>${s}</li>`).join("")}
      </ul>
    </div>
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${effectiveRedirect}">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ""}">
      <input type="hidden" name="code_challenge" value="${code_challenge || ""}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}">
      <label for="username">Username</label>
      <input id="username" type="text" name="username" placeholder="alice or bob" autocomplete="username" required>
      <p class="hint">Demo users: alice / bob — password: password123</p>
      <label for="password">Password</label>
      <input id="password" type="password" name="password" autocomplete="current-password" required>
      <button type="submit">Authorize &amp; Sign In</button>
      <button type="button" class="deny" onclick="window.location='${effectiveRedirect}?error=access_denied&state=${state || ""}'">Deny</button>
    </form>
  </div>
</body>
</html>`);
});

// ══════════════════════════════════════════════════════════════════════════
//  AUTHORIZATION ENDPOINT (POST)  —  Validate credentials, issue code
// ══════════════════════════════════════════════════════════════════════════
app.post("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, scope, state, username, password, code_challenge, code_challenge_method } = req.body;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).send(errorPage("Unknown client_id"));

  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).send(errorPage("Invalid username or password", true));
  }

  const code = uuidv4();
  authCodes.set(code, {
    clientId:    client_id,
    userId:      username,
    redirectUri: redirect_uri,
    scope:       scope || "openid profile",
    expiresAt:   Date.now() + 5 * 60 * 1000, // 5-minute TTL
    codeChallenge:       code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
  });

  const params = new URLSearchParams({ code, ...(state && { state }) });
  res.redirect(`${redirect_uri}?${params}`);
});

// ══════════════════════════════════════════════════════════════════════════
//  TOKEN ENDPOINT  —  POST /oauth/token
//  Supports: authorization_code, refresh_token
// ══════════════════════════════════════════════════════════════════════════
app.post("/oauth/token", (req, res) => {
  // Accept credentials from body OR Basic auth header
  let clientId, clientSecret;
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    [clientId, clientSecret] = decoded.split(":");
  } else {
    clientId     = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = CLIENTS[clientId];
  if (!client || client.secret !== clientSecret) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const { grant_type, code, redirect_uri, refresh_token, code_verifier } = req.body;

  // ── authorization_code ──
  if (grant_type === "authorization_code") {
    const stored = authCodes.get(code);
    if (!stored || stored.expiresAt < Date.now()) {
      return res.status(400).json({ error: "invalid_grant", error_description: "Code expired or not found" });
    }
    if (stored.clientId !== clientId) {
      return res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
    }
    if (redirect_uri && stored.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
    }

    // PKCE check (if challenge was supplied at /authorize)
    if (stored.codeChallenge) {
      if (!code_verifier) return res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
      const crypto = require("crypto");
      const digest = crypto.createHash("sha256").update(code_verifier).digest("base64url");
      if (digest !== stored.codeChallenge) {
        return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      }
    }

    authCodes.delete(code); // one-time use

    const accessToken  = generateAccessToken(stored.userId, clientId, stored.scope);
    const newRefresh   = uuidv4();
    refreshTokens.set(newRefresh, { clientId, userId: stored.userId, scope: stored.scope });

    return res.json({
      access_token:  accessToken,
      token_type:    "Bearer",
      expires_in:    3600,
      refresh_token: newRefresh,
      scope:         stored.scope,
    });
  }

  // ── refresh_token ──
  if (grant_type === "refresh_token") {
    const stored = refreshTokens.get(refresh_token);
    if (!stored || stored.clientId !== clientId) {
      return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token not found or expired" });
    }

    refreshTokens.delete(refresh_token); // rotate

    const accessToken = generateAccessToken(stored.userId, clientId, stored.scope);
    const newRefresh  = uuidv4();
    refreshTokens.set(newRefresh, { clientId, userId: stored.userId, scope: stored.scope });

    return res.json({
      access_token:  accessToken,
      token_type:    "Bearer",
      expires_in:    3600,
      refresh_token: newRefresh,
      scope:         stored.scope,
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// ══════════════════════════════════════════════════════════════════════════
//  PROTECTED: User Info  —  GET /api/me
// ══════════════════════════════════════════════════════════════════════════
app.get("/api/me", verifyAccessToken, (req, res) => {
  const user = USERS[req.tokenPayload.sub];
  if (!user) return res.status(404).json({ error: "user_not_found" });
  res.json({
    sub:       req.tokenPayload.sub,
    name:      user.name,
    email:     user.email,
    role:      user.role,
    client_id: req.tokenPayload.client_id,
    scope:     req.tokenPayload.scope,
  });
});

// ══════════════════════════════════════════════════════════════════════════
//  PROTECTED: Dummy API  —  GET /api/data
// ══════════════════════════════════════════════════════════════════════════
app.get("/api/data", verifyAccessToken, (req, res) => {
  res.json({
    message:   "You successfully called a protected endpoint!",
    timestamp: new Date().toISOString(),
    user:      req.tokenPayload.sub,
    scope:     req.tokenPayload.scope,
    items: [
      { id: 1, name: "Widget Alpha",   status: "active",   value: 1200 },
      { id: 2, name: "Widget Beta",    status: "inactive", value: 450  },
      { id: 3, name: "Widget Gamma",   status: "active",   value: 3800 },
      { id: 4, name: "Widget Delta",   status: "pending",  value: 750  },
    ],
  });
});

// ══════════════════════════════════════════════════════════════════════════
//  PROTECTED: Dummy POST  —  POST /api/data
// ══════════════════════════════════════════════════════════════════════════
app.post("/api/data", verifyAccessToken, (req, res) => {
  res.status(201).json({
    message:   "Resource created (demo — nothing actually persisted)",
    received:  req.body,
    id:        uuidv4(),
    timestamp: new Date().toISOString(),
    user:      req.tokenPayload.sub,
  });
});

// ══════════════════════════════════════════════════════════════════════════
//  TOKEN INTROSPECTION  —  POST /oauth/introspect  (RFC 7662)
// ══════════════════════════════════════════════════════════════════════════
app.post("/oauth/introspect", (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ active: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: BASE_URL });
    res.json({ active: true, sub: payload.sub, scope: payload.scope, client_id: payload.client_id, exp: payload.exp, iat: payload.iat });
  } catch {
    res.json({ active: false });
  }
});

// ══════════════════════════════════════════════════════════════════════════
//  TOKEN REVOCATION  —  POST /oauth/revoke  (RFC 7009)
// ══════════════════════════════════════════════════════════════════════════
app.post("/oauth/revoke", (req, res) => {
  const { token } = req.body;
  if (token) refreshTokens.delete(token);
  res.status(200).json({ message: "Token revoked (if it existed)" });
});

// ══════════════════════════════════════════════════════════════════════════
//  HOME  —  shows a quick reference card
// ══════════════════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>OAuth 2.0 Demo Server</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 60px auto; padding: 0 20px; color: #222; }
    h1 { color: #FF6900; }
    h2 { margin-top: 32px; border-bottom: 2px solid #eee; padding-bottom: 6px; }
    code, pre { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    pre { padding: 14px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 14px; }
    th { background: #f8f8f8; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
    .get { background: #dbeafe; color: #1d4ed8; }
    .post { background: #dcfce7; color: #166534; }
    .lock { color: #f59e0b; }
  </style>
</head>
<body>
  <h1>⚡ OAuth 2.0 Demo Server</h1>
  <p>Running at <strong>${BASE_URL}</strong></p>

  <h2>Endpoints</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Description</th></tr>
    <tr><td><span class="badge get">GET</span></td><td><code>/.well-known/oauth-authorization-server</code></td><td>Discovery metadata (RFC 8414)</td></tr>
    <tr><td><span class="badge get">GET</span></td><td><code>/oauth/authorize</code></td><td>Authorization endpoint — login form</td></tr>
    <tr><td><span class="badge post">POST</span></td><td><code>/oauth/token</code></td><td>Token endpoint — exchange code for tokens</td></tr>
    <tr><td><span class="badge post">POST</span></td><td><code>/oauth/introspect</code></td><td>Token introspection (RFC 7662)</td></tr>
    <tr><td><span class="badge post">POST</span></td><td><code>/oauth/revoke</code></td><td>Token revocation (RFC 7009)</td></tr>
    <tr><td><span class="badge get">GET</span> <span class="lock">🔒</span></td><td><code>/api/me</code></td><td>User info (requires Bearer token)</td></tr>
    <tr><td><span class="badge get">GET</span> <span class="lock">🔒</span></td><td><code>/api/data</code></td><td>Protected dummy resource list</td></tr>
    <tr><td><span class="badge post">POST</span> <span class="lock">🔒</span></td><td><code>/api/data</code></td><td>Protected dummy resource create</td></tr>
  </table>

  <h2>Demo Credentials</h2>
  <table>
    <tr><th>Client ID</th><td><code>${Object.keys(CLIENTS)[0]}</code></td></tr>
    <tr><th>Client Secret</th><td><code>${CLIENTS[Object.keys(CLIENTS)[0]].secret}</code></td></tr>
    <tr><th>Users</th><td><code>alice</code> / <code>bob</code> — password: <code>password123</code></td></tr>
    <tr><th>Redirect URIs</th><td>${CLIENTS[Object.keys(CLIENTS)[0]].redirectUris.map(u => `<code>${u}</code>`).join(", ")}</td></tr>
  </table>

  <h2>Quick Start — Authorization Code Flow</h2>
  <pre>1. Redirect user to:
   ${BASE_URL}/oauth/authorize
     ?client_id=demo-client-id
     &redirect_uri=http://localhost:8080/callback
     &response_type=code
     &scope=openid profile api:read
     &state=random-state-value

2. After login, your callback receives: ?code=&lt;code&gt;&state=&lt;state&gt;

3. Exchange the code:
   POST ${BASE_URL}/oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=&lt;code&gt;
   &redirect_uri=http://localhost:8080/callback
   &client_id=demo-client-id
   &client_secret=demo-client-secret

4. Call a protected endpoint:
   GET ${BASE_URL}/api/data
   Authorization: Bearer &lt;access_token&gt;</pre>
</body>
</html>`);
});

// ══════════════════════════════════════════════════════════════════════════
//  OPENAPI SPEC  —  GET /openapi.yaml  and  GET /openapi.json
// ══════════════════════════════════════════════════════════════════════════
app.get("/openapi.yaml", (req, res) => {
  const spec = buildSpec();
  res.setHeader("Content-Type", "text/yaml");
  res.send(yaml.dump(spec));
});

app.get("/openapi.json", (req, res) => {
  res.json(buildSpec());
});

// ══════════════════════════════════════════════════════════════════════════
//  SWAGGER UI  —  GET /docs
// ══════════════════════════════════════════════════════════════════════════
app.use("/docs", swaggerUi.serve, (req, res, next) => {
  swaggerUi.setup(buildSpec(), {
    customSiteTitle: "OAuth 2.0 Demo — API Docs",
    swaggerOptions: {
      persistAuthorization: true,
      tryItOutEnabled: true,
    },
  })(req, res, next);
});

function buildSpec() {
  if (!openApiSpec || !openApiSpec.info) return { openapi: "3.0.3", info: { title: "OAuth 2.0 Demo", version: "1.0.0" }, paths: {} };
  return { ...openApiSpec, servers: [{ url: BASE_URL, description: "This server" }] };
}

// ─── Error helper ──────────────────────────────────────────────────────────
function errorPage(msg, showBack = false) {
  return `<!DOCTYPE html><html><body style="font-family:system-ui;text-align:center;padding:60px">
  <h2 style="color:#e11d48">Error</h2><p>${msg}</p>
  ${showBack ? `<a href="javascript:history.back()">← Go back</a>` : ""}
  </body></html>`;
}

app.listen(PORT, () => {
  console.log(`OAuth 2.0 Demo Server running on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Discovery: ${BASE_URL}/.well-known/oauth-authorization-server`);
});
