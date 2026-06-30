---
title: Dashboard
summary: The dashboard service serves the embedded admin UI, authenticates dashboard API calls with a dashboard token, proxies service APIs, and manages local or S3-backed asset uploads.
topics: [dashboard, services, asset-management]
sources:
  - id: dashboard-main
    type: file
    path: services/dashboard/cmd/dashboard/main.go
    note: Implements static serving, dashboard auth, API proxying, asset upload/list/delete/purge, and local/S3 asset stores.
  - id: dashboard-tests
    type: file
    path: services/dashboard/cmd/dashboard/main_test.go
    note: Verifies proxy behavior, dashboard auth, CDN fetch, asset operations, purge, traversal rejection, and S3 mode.
  - id: static-index
    type: file
    path: services/dashboard/cmd/dashboard/static/index.html
    note: Provides the embedded dashboard HTML title and UI shell.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Wires dashboard to control, edge, inference, origin data, and optional S3 settings.
status: active
verified: 2026-06-30
---

The dashboard service is a backend-for-frontend and static UI server. It embeds files from `services/dashboard/cmd/dashboard/static/`, listens on port `3000`, requires `X-AstraCDN-Dashboard-Token` for API routes, and forwards authenticated calls to [[control-plane]], [[edge-service]], and [[inference-service]] [@dashboard-main].

## Auth Boundary

Dashboard API routes require the dashboard token unless the configured access token is empty. The default access token is `DASHBOARD_ACCESS_TOKEN`, falling back to `ASTRACDN_API_KEY` [@dashboard-main]. Tests verify unauthenticated rejection and authenticated access [@dashboard-tests].

When proxying upstream service APIs, dashboard removes the dashboard token header. If the caller has not supplied `Authorization` or `X-AstraCDN-API-Key`, dashboard injects `Authorization: Bearer <ASTRACDN_API_KEY>` for upstream access [@dashboard-main]. Tests verify it preserves caller auth when supplied [@dashboard-tests].

## Proxy Routes

Dashboard forwards:

- `/api/control/...` to the control base URL after stripping `/api/control`.
- `/api/edge/...` to the edge base URL after stripping `/api/edge`.
- `/api/inference/...` to the inference base URL after stripping `/api/inference`.
- `/api/cdn/fetch` to edge with an explicit Host header and a required `/edge/...` path [@dashboard-main].

`/api/cdn/fetch` is a controlled CDN preview endpoint. It accepts only GET/HEAD, requires a valid host and `/edge/` path, forwards to edge, and returns status, cache headers, content type, body preview, and selected origin/cache headers [@dashboard-main].

## Asset Management

Dashboard owns the administrative asset flow described in [[asset-management-flow]]. It supports local filesystem and S3-compatible stores, enforces upload size limits, rejects path traversal, lists folders, deletes objects, reports storage mode without secrets, and calls control to purge affected edge paths after upload/delete unless disabled [@dashboard-main].

Local compose mounts `./data/origin` into the origin container as read-only and points dashboard at the same host path, so dashboard writes files that origin later serves [@compose].

## Static UI

The service embeds `static/index.html`, `static/app.js`, and `static/styles.css` into the Go binary. Smoke tests check that the served HTML includes `AstraCDN Control Deck`, which is a useful canary that the embedded UI route is intact [@static-index].

## Related Pages

Read [[asset-management-flow]] for upload/delete/purge behavior and [[security-and-auth]] before changing dashboard token or upstream auth handling.
