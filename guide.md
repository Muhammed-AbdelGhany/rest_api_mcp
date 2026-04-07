# REST API MCP — Workflow Guide

This MCP server provides two tools for working with any authenticated REST API:

- **`fetch_spec`** — fetches the OpenAPI/Swagger JSON spec for the configured API
- **`request`** — makes an authenticated API call (auto-login handled internally)

---

## How to implement an API endpoint in Flutter

### STRICT EXECUTION ORDER — do not skip any step, do not ask questions

---

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

The server handles login automatically. Any IDs returned from login (e.g. `pharmacyId`, `userId`) are available via the `login_data` field in the response.

---

### Step 3 — Implement the Flutter feature

Using the **live response** from Step 2, implement following `rules.md`:

1. **Model** — Dart `fromJson`/`toJson` for every field in the response
2. **Remote Data Source** — API call using Dio
3. **Repository** — interface + implementation
4. **Use Case** — single responsibility
5. **Cubit** — state management
6. **UI** — only if explicitly requested
