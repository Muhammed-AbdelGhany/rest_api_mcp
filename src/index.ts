#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { type AxiosRequestConfig } from "axios";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import https from "https";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Config from env ────────────────────────────────────────────────────────────
const BASE_URL = process.env.REST_BASE_URL;
const LOGIN_ENDPOINT_OVERRIDE = process.env.API_LOGIN_ENDPOINT; // optional — auto-discovered if not set
const EMAIL = process.env.API_EMAIL;
const PASSWORD = process.env.API_PASSWORD;
const TOKEN_PATH_OVERRIDE = process.env.API_TOKEN_PATH;         // optional — auto-detected if not set
const SWAGGER_URL = process.env.API_SWAGGER_URL;
const LOGIN_CREDENTIALS_JSON = process.env.API_LOGIN_CREDENTIALS; // optional JSON — extra login fields, e.g. {"userRole":"manager","source":"mobile"}
const VERIFY_ENDPOINT = process.env.API_VERIFY_ENDPOINT;          // optional — 2FA verify endpoint, e.g. /auth/verify-otp
const OTP = process.env.API_OTP;                                // optional — OTP value for 2FA
const VERIFY_EXTRA_JSON = process.env.API_VERIFY_CREDENTIALS;    // optional JSON — extra verify body fields
const RESPONSE_SIZE_LIMIT = parseInt(process.env.REST_RESPONSE_SIZE_LIMIT ?? "100000");
const SSL_VERIFY = process.env.REST_ENABLE_SSL_VERIFY !== "false";

if (!BASE_URL) throw new Error("REST_BASE_URL env var is required");

// ── Token cache ────────────────────────────────────────────────────────────────
interface TokenCache {
  token: string;
  expiresAt: number;
  loginData: Record<string, unknown>;
}
let tokenCache: TokenCache | null = null;
const TOKEN_TTL_MS = 20_000; // 20s — safe margin for short-lived tokens

// ── Discovered values cache ────────────────────────────────────────────────────
let discoveredLoginEndpoint: string | null = null;
let discoveredTokenPath: string | null = null;

// ── Helpers ────────────────────────────────────────────────────────────────────
function getNestedValue(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((curr, key) => {
    if (curr && typeof curr === "object") return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

function httpsAgent() {
  return SSL_VERIFY ? undefined : new https.Agent({ rejectUnauthorized: false });
}

function truncate(data: unknown): unknown {
  const str = typeof data === "string" ? data : JSON.stringify(data);
  if (str.length <= RESPONSE_SIZE_LIMIT) {
    try { return JSON.parse(str); } catch { return str; }
  }
  return str.slice(0, RESPONSE_SIZE_LIMIT) + `\n\n[TRUNCATED: ${str.length} chars total, ${RESPONSE_SIZE_LIMIT} returned]`;
}

// ── Auto-discover login endpoint from Swagger spec ─────────────────────────────
async function discoverLoginEndpoint(): Promise<string> {
  if (LOGIN_ENDPOINT_OVERRIDE) return LOGIN_ENDPOINT_OVERRIDE;
  if (discoveredLoginEndpoint) return discoveredLoginEndpoint;
  if (!SWAGGER_URL) return "/auth/login"; // fallback

  try {
    const res = await axios.get(SWAGGER_URL, { httpsAgent: httpsAgent() });
    const paths: Record<string, unknown> = res.data?.paths ?? {};

    // Priority: exact "login" path > path containing "login" > fallback
    const candidates = Object.entries(paths)
      .filter(([, methods]) => typeof methods === "object" && methods !== null && "post" in methods)
      .map(([path]) => path.replace(/^.*\/api\/[^/]+/, "")); // strip base prefix like /service/api/v1

    const exact = candidates.find(p => p.toLowerCase().endsWith("/login"));
    const contains = candidates.find(p => p.toLowerCase().includes("login"));
    discoveredLoginEndpoint = exact ?? contains ?? "/auth/login";
  } catch {
    discoveredLoginEndpoint = "/auth/login";
  }

  return discoveredLoginEndpoint;
}

// ── Auto-detect token path from login response ─────────────────────────────────
const TOKEN_PATH_CANDIDATES = [
  "data.access_token",
  "access_token",
  "data.token",
  "token",
  "data.accessToken",
  "accessToken",
  "data.data.access_token",
  "result.access_token",
  "result.token",
];

function detectTokenPath(responseData: unknown): string | null {
  if (TOKEN_PATH_OVERRIDE) return TOKEN_PATH_OVERRIDE;
  if (discoveredTokenPath) return discoveredTokenPath;

  for (const path of TOKEN_PATH_CANDIDATES) {
    const value = getNestedValue(responseData, path);
    if (typeof value === "string" && value.length > 10) {
      discoveredTokenPath = path;
      return path;
    }
  }
  return null;
}

// Session-identifier fields that may appear in a step-1 login response and must
// be forwarded to the 2FA verify endpoint so the server can match the session.
const SESSION_FIELD_CANDIDATES = [
  "session_token", "sessionToken", "session",
  "request_id",   "requestId",
  "temp_token",   "tempToken",
  "verification_token", "verificationToken",
  "challenge",    "nonce",
  "transaction_id", "transactionId",
];

// ── Login (supports optional 2FA) ─────────────────────────────────────────────
async function login(): Promise<TokenCache> {
  if (!EMAIL || !PASSWORD) throw new Error("API_EMAIL and API_PASSWORD env vars are required for authenticated requests");

  const loginEndpoint = await discoverLoginEndpoint();

  // ── Step 1: initial login ──────────────────────────────────────────────────
  const loginBody: Record<string, unknown> = { email: EMAIL, password: PASSWORD };

  // Merge extra login credentials (userRole, source, channel, device_id, etc.)
  if (LOGIN_CREDENTIALS_JSON) {
    try { Object.assign(loginBody, JSON.parse(LOGIN_CREDENTIALS_JSON)); }
    catch { throw new Error(`API_LOGIN_CREDENTIALS is not valid JSON: ${LOGIN_CREDENTIALS_JSON}`); }
  }

  const step1 = await axios.post(`${BASE_URL}${loginEndpoint}`, loginBody, {
    headers: { "Content-Type": "application/json" },
    httpsAgent: httpsAgent(),
    validateStatus: () => true,
  });

  if (step1.status >= 400) {
    throw new Error(`Login returned ${step1.status}: ${JSON.stringify(step1.data).slice(0, 300)}`);
  }

  // ── Step 2: 2FA OTP verify (optional) ─────────────────────────────────────
  let finalData: unknown = step1.data;

  if (VERIFY_ENDPOINT) {
    const verifyBody: Record<string, unknown> = {};

    // Always include the OTP and the email (most verify endpoints need both)
    if (OTP)   verifyBody.otp   = OTP;
    if (EMAIL) verifyBody.email = EMAIL;

    // Auto-carry session identifiers from step-1 response (top-level and data.*)
    for (const field of SESSION_FIELD_CANDIDATES) {
      const val =
        getNestedValue(step1.data, field) ??
        getNestedValue(step1.data, `data.${field}`);
      if (typeof val === "string" && val.length > 0) {
        verifyBody[field] = val;
      }
    }

    // Merge any extra verify fields
    if (VERIFY_EXTRA_JSON) {
      try { Object.assign(verifyBody, JSON.parse(VERIFY_EXTRA_JSON)); }
      catch { throw new Error(`API_VERIFY_CREDENTIALS is not valid JSON: ${VERIFY_EXTRA_JSON}`); }
    }

    const step2 = await axios.post(`${BASE_URL}${VERIFY_ENDPOINT}`, verifyBody, {
      headers: { "Content-Type": "application/json" },
      httpsAgent: httpsAgent(),
      validateStatus: () => true,
    });

    if (step2.status >= 400) {
      throw new Error(`2FA verify returned ${step2.status}: ${JSON.stringify(step2.data).slice(0, 300)}`);
    }

    finalData = step2.data;
  }

  // ── Extract token ──────────────────────────────────────────────────────────
  const tokenPath = detectTokenPath(finalData);
  if (!tokenPath) {
    throw new Error(
      `Could not find token in ${VERIFY_ENDPOINT ? "verify" : "login"} response. ` +
      `Tried paths: ${TOKEN_PATH_CANDIDATES.join(", ")}. ` +
      `Response: ${JSON.stringify(finalData).slice(0, 500)}. ` +
      `Set API_TOKEN_PATH env var explicitly.`
    );
  }

  const token = getNestedValue(finalData, tokenPath) as string;

  const cache: TokenCache = {
    token,
    expiresAt: Date.now() + TOKEN_TTL_MS,
    loginData: finalData as Record<string, unknown>,
  };
  tokenCache = cache;
  return cache;
}

async function getToken(): Promise<TokenCache> {
  if (tokenCache && Date.now() < tokenCache.expiresAt) return tokenCache;
  return login();
}


// ── MCP Server ─────────────────────────────────────────────────────────────────
const server = new Server(
  { name: "rest-api-mcp", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {} } }
);

// ── Resources ──────────────────────────────────────────────────────────────────
const GUIDE_URI = "guide://workflow";
let guideContent = "";
try {
  guideContent = readFileSync(join(__dirname, "..", "guide.md"), "utf-8");
} catch {
  guideContent = "Guide file not found.";
}

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: GUIDE_URI,
      name: "Implementation Workflow Guide",
      description: "Step-by-step guide for implementing a REST API endpoint in Flutter using this MCP server",
      mimeType: "text/markdown",
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
  if (req.params.uri === GUIDE_URI) {
    return { contents: [{ uri: GUIDE_URI, mimeType: "text/markdown", text: guideContent }] };
  }
  throw new Error(`Unknown resource: ${req.params.uri}`);
});

// ── Tools ──────────────────────────────────────────────────────────────────────
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch_spec",
      description: "Fetches the OpenAPI/Swagger JSON spec for this API. Use this to discover endpoint paths, HTTP methods, and request body schemas before calling request().",
      inputSchema: {
        type: "object",
        properties: {
          url: {
            type: "string",
            description: "Override the spec URL. If omitted, uses API_SWAGGER_URL env var.",
          },
        },
      },
    },
    {
      name: "search_endpoints",
      description:
        "Fuzzy-search the API spec by keyword. Use this when you don't know the exact path. " +
        "Searches across path, HTTP method, summary, description, tags, and operationId. " +
        "Returns matching endpoints with their method, full path, summary, and required parameters.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "Keywords to search for, e.g. 'packs search' or 'inspector shipments' or 'verify otp'",
          },
          limit: {
            type: "number",
            description: "Max results to return (default 10)",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "request",
      description:
        "Makes an authenticated API call. Handles login automatically — if the token is expired it re-logins transparently. Returns the full response body plus login_data (which contains IDs like pharmacyId returned from login).",
      inputSchema: {
        type: "object",
        properties: {
          method: {
            type: "string",
            enum: ["GET", "POST", "PUT", "PATCH", "DELETE"],
            description: "HTTP method",
          },
          endpoint: {
            type: "string",
            description: "API path, e.g. /Incident/getMyForms/0/10",
          },
          body: {
            type: "object",
            description: "Request body for POST/PUT/PATCH",
          },
          headers: {
            type: "object",
            description: "Additional headers to include",
          },
          skip_auth: {
            type: "boolean",
            description: "Set true to skip the Authorization header (e.g. for public endpoints)",
          },
        },
        required: ["method", "endpoint"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  // ── search_endpoints ────────────────────────────────────────────────────────
  if (name === "search_endpoints") {
    const query = (args?.query as string ?? "").toLowerCase();
    const limit = (args?.limit as number | undefined) ?? 10;
    const specUrl = SWAGGER_URL;

    if (!specUrl) {
      return { content: [{ type: "text", text: "Error: API_SWAGGER_URL env var is not set." }] };
    }
    if (!query.trim()) {
      return { content: [{ type: "text", text: "Error: query is required." }] };
    }

    try {
      const res = await axios.get(specUrl, { httpsAgent: httpsAgent() });
      const paths: Record<string, Record<string, unknown>> = res.data?.paths ?? {};
      const keywords = query.split(/\s+/).filter(Boolean);

      // Strip the spec's base prefix (e.g. /service/api/v1) from each path
      // so the returned paths match what request() expects.
      const specBasePaths = Object.keys(paths);
      const basePrefix = (() => {
        // Find the longest common prefix segment up to /api/vN
        const m = specBasePaths[0]?.match(/^(\/[^/]+\/api\/v\d+)/);
        return m ? m[1] : "";
      })();

      type EndpointHit = { method: string; path: string; summary: string; tags: string[]; params: string[]; score: number };
      const hits: EndpointHit[] = [];

      for (const [rawPath, methods] of Object.entries(paths)) {
        const cleanPath = rawPath.replace(basePrefix, "") || rawPath;
        for (const [method, op] of Object.entries(methods as Record<string, unknown>)) {
          if (["get","post","put","patch","delete"].indexOf(method) === -1) continue;
          const operation = op as Record<string, unknown>;
          const summary    = String(operation.summary    ?? "");
          const description = String(operation.description ?? "");
          const operationId = String(operation.operationId ?? "");
          const tags        = (operation.tags as string[] | undefined ?? []).join(" ");
          const haystack    = [cleanPath, rawPath, method, summary, description, operationId, tags]
                                .join(" ").toLowerCase();

          // Score = how many keywords match
          const score = keywords.reduce((acc, kw) => acc + (haystack.includes(kw) ? 1 : 0), 0);
          if (score === 0) continue;

          // Collect required params for context
          const paramList: string[] = [];
          for (const p of (operation.parameters as Array<Record<string,unknown>> | undefined ?? [])) {
            if (p.required) paramList.push(`${p.in}:${p.name}`);
          }
          if (operation.requestBody) paramList.push("body");

          hits.push({
            method: method.toUpperCase(),
            path: cleanPath,
            summary: summary || operationId,
            tags: operation.tags as string[] ?? [],
            params: paramList,
            score,
          });
        }
      }

      // Sort by score desc, then path length asc (shorter = more direct)
      hits.sort((a, b) => b.score - a.score || a.path.length - b.path.length);
      const top = hits.slice(0, limit);

      if (top.length === 0) {
        return { content: [{ type: "text", text: `No endpoints matched "${query}". Try different keywords.` }] };
      }

      const lines = top.map((h, i) =>
        `${i + 1}. ${h.method} ${h.path}` +
        (h.summary ? `\n   Summary: ${h.summary}` : "") +
        (h.tags.length ? `\n   Tags: ${h.tags.join(", ")}` : "") +
        (h.params.length ? `\n   Required params: ${h.params.join(", ")}` : "")
      );

      return {
        content: [{
          type: "text",
          text: `Found ${hits.length} match(es) for "${query}", showing top ${top.length}:\n\n` + lines.join("\n\n"),
        }],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error searching spec: ${msg}` }] };
    }
  }

  // ── fetch_spec ──────────────────────────────────────────────────────────────
  if (name === "fetch_spec") {
    const specUrl = (args?.url as string | undefined) ?? SWAGGER_URL;
    if (!specUrl) {
      return { content: [{ type: "text", text: "Error: No spec URL provided and API_SWAGGER_URL env var is not set." }] };
    }

    try {
      const res = await axios.get(specUrl, { httpsAgent: httpsAgent() });
      const spec = truncate(res.data);
      return {
        content: [
          {
            type: "text",
            text: typeof spec === "string" ? spec : JSON.stringify(spec, null, 2),
          },
        ],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error fetching spec: ${msg}` }] };
    }
  }

  // ── request ─────────────────────────────────────────────────────────────────
  if (name === "request") {
    const method = (args?.method as string).toUpperCase();
    const endpoint = args?.endpoint as string;
    const body = args?.body as Record<string, unknown> | undefined;
    const extraHeaders = (args?.headers as Record<string, string> | undefined) ?? {};
    const skipAuth = (args?.skip_auth as boolean | undefined) ?? false;

    let authHeaders: Record<string, string> = {};
    let loginData: Record<string, unknown> = {};

    if (!skipAuth) {
      try {
        const cache = await getToken();
        authHeaders = { Authorization: `Bearer ${cache.token}` };
        loginData = cache.loginData as Record<string, unknown>;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text", text: `Login failed: ${msg}` }] };
      }
    }

    const config: AxiosRequestConfig = {
      method,
      url: `${BASE_URL}${endpoint}`,
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
        ...extraHeaders,
      },
      data: body,
      httpsAgent: httpsAgent(),
      validateStatus: () => true, // never throw on HTTP error codes
    };

    const start = Date.now();
    try {
      const res = await axios(config);
      const timing = Date.now() - start;
      const responseBody = truncate(res.data);

      const result = {
        status: res.status,
        statusText: res.statusText,
        timing_ms: timing,
        login_data: loginData,
        response: responseBody,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Request failed: ${msg}` }] };
    }
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
});

// ── Start ──────────────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
