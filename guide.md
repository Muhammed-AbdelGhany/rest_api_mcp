# REST API MCP — Workflow Guide

This MCP server provides two tools for working with any authenticated REST API:

- **`fetch_spec`** — fetches the OpenAPI/Swagger JSON spec for the configured API
- **`request`** — makes an authenticated API call (auto-login handled internally)

---

## Workflow

### Step 1 — Fetch the Swagger spec

Call `fetch_spec` with no arguments.
Find the target endpoint in the returned spec. Extract:
- HTTP method
- Full path
- Every request body field and its type

---

### Step 2 — Call the target endpoint

Call `request` with:
- `method`: from Step 1
- `endpoint`: from Step 1
- `body`: built from the spec fields — use sensible defaults for filters (e.g. wide date ranges, status = first enum value)

The server handles login automatically. Any IDs returned from login (e.g. `userId`, `orgId`) are available via the `login_data` field in the response.
