# rest-api-mcp

> A Model Context Protocol (MCP) server for authenticated REST APIs.  
> Drop it into any project, point it at your API, and let AI agents call endpoints — with **auto-login**, **2FA support**, **Swagger spec fetch**, and **fuzzy endpoint search** — all without writing a single line of auth code.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Tools](#tools)
  - [search_endpoints](#search_endpoints)
  - [request](#request)
  - [fetch_spec](#fetch_spec)
  - [inspect_login](#inspect_login)
- [Authentication Flows](#authentication-flows)
  - [Standard login](#standard-login)
  - [Login with extra credentials](#login-with-extra-credentials)
  - [Two-factor authentication (2FA)](#two-factor-authentication-2fa)
- [Multi-API Setup](#multi-api-setup)
- [VS Code mcp.json Examples](#vs-code-mcpjson-examples)
- [How It Works](#how-it-works)
- [Environment Variables Reference](#environment-variables-reference)
- [Troubleshooting](#troubleshooting)

---

## Features

| Capability | Description |
|---|---|
| **Auto-login** | Logs in automatically before every request; re-logins when token expires |
| **Token caching** | 20-second TTL cache — survives rapid sequential calls |
| **Auto-discovery** | Finds the login endpoint by scanning the Swagger spec (no config needed) |
| **Auto token detection** | Tries 9 common token paths (`data.access_token`, `accessToken`, `token`, …) |
| **AI-driven token detection** | `inspect_login` tool exposes raw responses + heuristic suggestions so the AI can pick the exact token path |
| **2FA / OTP support** | Two-step auth: login → verify-otp, session identifiers forwarded automatically |
| **Custom session fields** | Override hardcoded session candidates via `verify_session_fields` in `request()` |
| **Extra login fields** | `source`, `userRole`, `channel`, `device_id` — any field, via JSON env var |
| **Fuzzy endpoint search** | Find endpoints by keyword across path, summary, description, tags, operationId |
| **Swagger spec fetch** | Retrieve and inspect the full OpenAPI spec |
| **SSL bypass** | Optional for staging/dev environments with self-signed certs |
| **Response truncation** | Configurable size limit to keep responses in context |

---

## Installation

### Option A — Use via npx (recommended)

No installation needed. Add this to your project's `.vscode/mcp.json` and VS Code will download and run the package automatically:

```json
{
  "command": "npx",
  "args": ["-y", "rest-api-mcp"]
}
```

This always uses the latest published version from npm. See [VS Code mcp.json Examples](#vs-code-mcpjson-examples) for a full config.

### Option B — Use locally (for development / offline)

```bash
git clone https://github.com/Muhammed-AbdelGhany/rest_api_mcp
cd rest_api_mcp
npm install && npm run build
```

Then point VS Code at the local build:

```json
{
  "command": "node",
  "args": ["/path/to/rest_api_mcp/build/index.js"]
}
```

---

## Quick Start

Add this to your project's `.vscode/mcp.json`:

```json
{
  "servers": {
    "my-api": {
      "command": "npx",
      "args": ["-y", "rest-api-mcp"],
      "env": {
        "REST_BASE_URL": "https://api.example.com/api/v1",
        "API_EMAIL": "user@example.com",
        "API_PASSWORD": "yourpassword",
        "API_SWAGGER_URL": "https://api.example.com/docs-json"
      }
    }
  }
}
```

That's it. The agent can now:
1. Search for endpoints by keyword
2. Call any endpoint with automatic authentication
3. Fetch the full OpenAPI spec for schema inspection

---

## Configuration

All configuration is done via environment variables in `mcp.json`. No code changes required.

### Minimum required

| Variable | Description |
|---|---|
| `REST_BASE_URL` | Base URL of the API (no trailing slash) |
| `API_EMAIL` | Login email |
| `API_PASSWORD` | Login password |

### Strongly recommended

| Variable | Description |
|---|---|
| `API_SWAGGER_URL` | OpenAPI/Swagger JSON URL — enables `fetch_spec`, `search_endpoints`, and auto-login-endpoint discovery |

### Optional

See [Environment Variables Reference](#environment-variables-reference) for the full list.

---

## Tools

### `search_endpoints`

Fuzzy-search the API spec by keyword. Returns matching endpoints with method, path, summary, tags, and required parameters. **Use this before `request` when you don't know the exact path.**

**Input:**

| Field | Type | Required | Description |
|---|---|---|---|
| `query` | string | ✅ | Keywords to search for |
| `limit` | number | ❌ | Max results (default: 10) |

**Example — Find order-related endpoints:**

```
search_endpoints("orders list customer")
```

**Response:**

```
Found 6 match(es) for "orders list customer", showing top 5:

1. GET /customers/{id}/orders
   Summary: List all orders for a customer
   Tags: Orders, Customers
   Required params: path:id

2. GET /orders
   Summary: List orders with optional filters
   Tags: Orders
   Required params: query:status, query:page

3. POST /orders/search
   Summary: Search orders by multiple criteria
   Tags: Orders
   Required params: body
...
```

---

### `request`

Make an authenticated API call. Handles login automatically — re-logins transparently if the token is expired.

**Input:**

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | ✅ | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `endpoint` | string | ✅ | Path relative to `REST_BASE_URL`, e.g. `/users/profile` |
| `body` | object | ❌ | Request body for POST/PUT/PATCH |
| `headers` | object | ❌ | Extra headers to merge |
| `skip_auth` | boolean | ❌ | Set `true` to skip the `Authorization` header |
| `token_path` | string | ❌ | Dot-notation path to the token in the login/verify response (e.g. `data.result.accessToken`). Overrides auto-detection and is **cached** for re-logins. |
| `verify_session_fields` | object | ❌ | Map of verify-body field names → dot-notation paths in the step-1 login response. Example: `{"sessionId": "data.result.sessionId"}`. Overrides hardcoded candidates and is **cached** for re-logins. |

**Response shape:**

```json
{
  "status": 200,
  "statusText": "OK",
  "timing_ms": 312,
  "login_data": { ... },
  "response": { ... }
}
```

> **`login_data`** contains the full login response — useful for IDs like `userId`, `orgId`, `tenantId` returned at login that you need for subsequent requests.

**Example — GET current user profile:**

```
request("GET", "/users/me")
```

**Example — POST with filters:**

```
request("POST", "/orders/search", {
  "status": "pending",
  "from": "2025-01-01",
  "limit": 20
})
```

**Example — PATCH to update a resource:**

```
request("PATCH", "/products/42", {
  "price": 9.99,
  "inStock": true
})
```

**Example — Public endpoint (no auth):**

```
request("GET", "/health", skip_auth=true)
```

**Example — Custom token path (when auto-detection fails):**

```
request("GET", "/orders", token_path="result.data.jwtToken")
```

**Example — Custom 2FA session fields:**

```
request("GET", "/orders",
  token_path="data.result.accessToken",
  verify_session_fields={"sessionId": "data.result.sessionId", "requestToken": "data.result.requestToken"}
)
```

---

### `inspect_login`

Performs the login flow (and optional 2FA verify) and returns the **raw server responses** without extracting a token. Also returns **heuristic suggestions** for:
- Token paths (fields that look like JWTs or long auth strings)
- Session fields (fields that look like session identifiers for 2FA verify)

Use this when auto-detection fails so the AI can identify the correct `token_path` and `verify_session_fields` to pass to `request()`.

**No input required.**

**Example — when `request()` fails with "Could not find token":**

```
inspect_login()
```

**Response:**

```json
{
  "step1": { "status": 200, "data": { "result": { "customJwt": "eyJ...", "sessionId": "abc" } } },
  "step2": null,
  "token_suggestions": [
    { "path": "result.customJwt", "value_preview": "eyJhbGciOiJIUzI1Ni...", "confidence": 4 }
  ],
  "session_field_suggestions": [
    { "path": "result.sessionId", "key": "sessionId", "value_preview": "abc" }
  ],
  "note": "Use token_path and verify_session_fields in your next request() call."
}
```

Then call `request()` with the AI-discovered path:

```
request("GET", "/orders", token_path="result.customJwt")
```

The server **caches** the AI-provided `token_path` and `verify_session_fields` so re-logins (after token expiry) use them automatically.

---

### `fetch_spec`

Fetch the full OpenAPI/Swagger JSON spec for schema inspection, DTO discovery, or understanding available endpoints.

**Input:**

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | ❌ | Override spec URL. Falls back to `API_SWAGGER_URL` env var |

**Example:**

```
fetch_spec()
```

Returns the raw OpenAPI JSON (truncated to `REST_RESPONSE_SIZE_LIMIT` if large).

---

## Authentication Flows

### Standard login

The most common case — email + password, token returned directly.

```json
{
  "REST_BASE_URL": "https://api.example.com/api/v1",
  "API_EMAIL": "user@example.com",
  "API_PASSWORD": "secret",
  "API_SWAGGER_URL": "https://api.example.com/docs-json"
}
```

The server auto-discovers the login endpoint by scanning the Swagger spec for the first `POST` path containing `"login"`. Override if needed:

```json
"API_LOGIN_ENDPOINT": "/auth/sign-in"
```

---

### Login with extra credentials

Some APIs require fields beyond `email` and `password` in the login request body — for example a `role` to specify what type of user is logging in, a `source` to indicate which client platform is making the request, a `channel`, a `tenantId`, etc.

Set `API_LOGIN_CREDENTIALS` to a **JSON object string** containing any extra fields you need. They are merged into the login POST body alongside `email` and `password`:

```json
"API_LOGIN_CREDENTIALS": "{\"role\": \"admin\"}"
```

What gets sent to the login endpoint:

```json
{
  "email": "admin@acme.com",
  "password": "secret",
  "role": "admin"
}
```

Multiple extra fields work the same way:

```json
"API_LOGIN_CREDENTIALS": "{\"role\": \"viewer\", \"source\": \"web\", \"tenantId\": \"acme\"}"
```

What gets sent:

```json
{
  "email": "viewer@acme.com",
  "password": "secret",
  "role": "viewer",
  "source": "web",
  "tenantId": "acme"
}
```

> **Note:** The field names are entirely up to your API. Check its Swagger spec or docs to see what the login endpoint accepts.

---

### Two-factor authentication (2FA)

Some APIs require a second verification step after the initial login — the server returns a one-time code to the user's email or phone, and you must submit it to a separate endpoint to receive the actual JWT.

**Flow:**

```
Step 1 — Login
  POST /auth/login  { email, password }
  ← 200: { session_token: "tmp_abc", message: "OTP sent to email" }

Step 2 — Verify OTP
  POST /auth/verify-otp  { email, otp: "482019", session_token: "tmp_abc" }
  ← 200: { accessToken: "eyJhbGci..." }
```

The three env vars that drive this:

```json
"API_VERIFY_ENDPOINT": "/auth/verify-otp",
"API_OTP": "482019",
"API_LOGIN_CREDENTIALS": "{\"platform\": \"web\"}"
```

**`API_VERIFY_ENDPOINT`** — The path of the second step. When this is set, the server automatically performs both steps before attaching a token to your request.

**`API_OTP`** — The OTP value to submit. For staging environments this is usually a fixed test code provided by the API team. For production you'd need to retrieve the live code from your email and set it here.

**Session carry-forward** — Session identifiers returned by login step 1 (e.g. `session_token`, `requestId`, `temp_token`, `nonce`, `transactionId`) are **automatically detected and forwarded** to the verify endpoint. You do not need to configure this manually.

The full body sent to the verify endpoint looks like:

```json
{
  "email": "user@acme.com",
  "otp": "482019",
  "session_token": "tmp_abc"   ← auto-carried from step 1
}
```

**`API_VERIFY_CREDENTIALS`** — If your verify endpoint requires extra fields that aren't session identifiers or the OTP, add them here:

```json
"API_VERIFY_CREDENTIALS": "{\"client_id\": \"web-app\"}"
```

What gets sent:

```json
{
  "email": "user@acme.com",
  "otp": "482019",
  "session_token": "tmp_abc",
  "client_id": "web-app"    ← from API_VERIFY_CREDENTIALS
}
```

---

## Multi-API Setup

Run multiple independent server instances — one per API — in the same `mcp.json`. Each instance runs its own auth session, token cache, and spec cache independently.

In this example, `shop-api` uses a simple role-based login and `analytics-api` uses 2FA:

```json
{
  "servers": {
    "shop-api": {
      "command": "npx",
      "args": ["-y", "rest-api-mcp"],
      "env": {
        "REST_BASE_URL": "https://api.acme-shop.com/v1",
        "API_EMAIL": "admin@acme-shop.com",
        "API_PASSWORD": "s3cr3t",
        "API_LOGIN_CREDENTIALS": "{\"role\": \"admin\"}",
        "API_SWAGGER_URL": "https://api.acme-shop.com/docs-json"
      }
    },
    "analytics-api": {
      "command": "npx",
      "args": ["-y", "rest-api-mcp"],
      "env": {
        "REST_BASE_URL": "https://analytics.acme.com/api/v2",
        "API_EMAIL": "analyst@acme.com",
        "API_PASSWORD": "s3cr3t",
        "API_LOGIN_ENDPOINT": "/auth/sign-in",
        "API_VERIFY_ENDPOINT": "/auth/verify-otp",
        "API_OTP": "482019",
        "API_SWAGGER_URL": "https://analytics.acme.com/openapi.json"
      }
    }
  }
}
```

---

## VS Code mcp.json Examples

### Minimal

```json
{
  "servers": {
    "my-api": {
      "command": "npx",
      "args": ["-y", "rest-api-mcp"],
      "env": {
        "REST_BASE_URL": "https://api.example.com/v1",
        "API_EMAIL": "user@example.com",
        "API_PASSWORD": "secret"
      }
    }
  }
}
```

### Full (all options)

```json
{
  "servers": {
    "my-api": {
      "command": "npx",
      "args": ["-y", "rest-api-mcp"],
      "env": {
        "REST_BASE_URL": "https://api.example.com/v1",
        "REST_ENABLE_SSL_VERIFY": "false",
        "REST_RESPONSE_SIZE_LIMIT": "150000",
        "API_EMAIL": "user@example.com",
        "API_PASSWORD": "secret",
        "API_LOGIN_ENDPOINT": "/auth/login",
        "API_LOGIN_CREDENTIALS": "{\"source\":\"mobile\"}",
        "API_VERIFY_ENDPOINT": "/auth/verify-otp",
        "API_OTP": "123456",
        "API_VERIFY_CREDENTIALS": "{\"device_id\":\"abc\"}",
        "API_TOKEN_PATH": "data.access_token",
        "API_SWAGGER_URL": "https://api.example.com/docs-json"
      }
    }
  }
}
```

---

## How It Works

```
Agent says: "show me pending orders"
     │
     ▼
search_endpoints("orders pending list")
     │  Fetches Swagger spec, scores every endpoint by keyword match
     │  Returns: GET /orders  ← best match
     ▼
request("GET", "/orders?status=pending")
     │
     ├─ Token cache valid? ──yes──► attach Bearer token
     │
     └─ Cache expired/empty?
           │
           ├─ Step 1: POST /auth/login  {email, password, ...LOGIN_CREDENTIALS}
           │          ◄── 200: {data: {access_token: "eyJ..."}}
           │
           ├─ [if VERIFY_ENDPOINT set]
           │   Step 2: POST /auth/verify-otp  {email, otp, ...session_tokens}
           │            ◄── 200: {accessToken: "eyJ..."}
           │
           ├─ Auto-detect token path from response (or use AI-provided token_path)
           ├─ Cache token for 20s
           └─ attach Bearer token
     │
     ▼
GET /orders?status=pending
     Authorization: Bearer eyJ...
     ◄── 200: {total: 47, data: [{id: 1, status: "pending", ...}, ...]}
```

**When auto-detection fails:**
```
request("GET", "/orders")  ← "Could not find token"
     │
     ▼
inspect_login()
     │  Returns raw login response + token/session suggestions
     ▼
request("GET", "/orders", token_path="data.result.jwt")
     │  Token path cached for future re-logins
     ▼
✅ Success
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `REST_BASE_URL` | ✅ | — | Base API URL, no trailing slash |
| `API_EMAIL` | ✅* | — | Login email (*required for authenticated endpoints) |
| `API_PASSWORD` | ✅* | — | Login password |
| `API_SWAGGER_URL` | — | — | OpenAPI JSON URL for `fetch_spec`, `search_endpoints`, and login auto-discovery |
| `API_LOGIN_ENDPOINT` | — | auto-discovered | Override login path, e.g. `/auth/sign-in` |
| `API_LOGIN_CREDENTIALS` | — | — | JSON object of extra fields merged into the login POST body alongside `email`/`password`. Use for `role`, `source`, `tenantId`, etc. Example: `{"role":"admin"}` |
| `API_VERIFY_ENDPOINT` | — | — | Path of the 2FA/OTP verify step. Setting this enables two-step auth. Example: `/auth/verify-otp` |
| `API_OTP` | — | — | The OTP code to submit to `API_VERIFY_ENDPOINT`. On staging this is typically a fixed test code. |
| `API_VERIFY_CREDENTIALS` | — | — | JSON object of extra fields merged into the verify POST body, beyond the auto-carried session identifiers and OTP. Example: `{"client_id":"web-app"}` |
| `API_TOKEN_PATH` | — | auto-detected | Dot-path to token in login/verify response, e.g. `data.access_token` |
| `REST_ENABLE_SSL_VERIFY` | — | `true` | Set `false` to skip TLS cert validation (dev/staging only) |
| `REST_RESPONSE_SIZE_LIMIT` | — | `100000` | Max response characters before truncation |

**Auto-detected token paths (tried in order):**
`data.access_token` · `access_token` · `data.token` · `token` · `data.accessToken` · `accessToken` · `data.data.access_token` · `result.access_token` · `result.token`

If none match, use `inspect_login()` to discover the correct path and pass it via `token_path`.

**Auto-forwarded session fields (2FA step 1 → step 2):**
`session_token` · `sessionToken` · `session` · `request_id` · `requestId` · `temp_token` · `tempToken` · `verification_token` · `verificationToken` · `challenge` · `nonce` · `transaction_id` · `transactionId`

Override these via `verify_session_fields` when the API uses non-standard session field names.

---

## Troubleshooting

**Login failed: Could not find token**  
The login response uses an unusual token path. Use `inspect_login()` to see the raw response and heuristic suggestions, then pass the correct path to `request()`:
```
inspect_login()                    ← see suggestions
request("GET", "/orders", token_path="result.data.jwt")
```
Alternatively, set `API_TOKEN_PATH` explicitly in env:
```json
"API_TOKEN_PATH": "result.data.jwt"
```

**2FA verify fails with 401**  
The verify endpoint may need the OTP as a different field name. Use `API_VERIFY_CREDENTIALS`:
```json
"API_VERIFY_CREDENTIALS": "{\"code\": \"123456\"}"
```
And leave `API_OTP` unset if the field name isn't `otp`.

**search_endpoints returns no matches**  
- Make sure `API_SWAGGER_URL` is set and reachable
- Try broader keywords: `"inventory"` instead of `"getInventory"`
- The spec may be truncated — use `fetch_spec` to check

**SSL errors on staging**  
```json
"REST_ENABLE_SSL_VERIFY": "false"
```

**Response truncated**  
Increase the limit:
```json
"REST_RESPONSE_SIZE_LIMIT": "500000"
```

---

## License

MIT
