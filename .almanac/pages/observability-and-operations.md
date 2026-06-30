---
title: Observability And Operations
summary: AstraCDN operations rely on health/readiness endpoints, Prometheus metrics, cache analytics snapshots, edge health reporting, database migrations, smoke tests, and cloud verification scripts.
topics: [operations, observability, deployment]
sources:
  - id: edge-main
    type: file
    path: services/edge/cmd/edge/main.go
    note: Implements edge health, readiness, metrics, cache analytics, health push, and analytics snapshot push.
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements control health, readiness, metrics, edge health, cache analytics persistence/export, and audit logs.
  - id: inference-main
    type: file
    path: services/inference/cmd/inference/main.go
    note: Implements inference health, readiness, metrics, cache counters, and provider latency metrics.
  - id: smoke
    type: file
    path: scripts/smoke-test.sh
    note: Defines the local end-to-end verification workflow.
  - id: cloud-verify
    type: file
    path: scripts/cloud-verify.sh
    note: Defines production/cloud verification checks.
  - id: migrate
    type: file
    path: scripts/db-migrate.sh
    note: Defines database migration operations.
status: active
verified: 2026-06-30
---

Operational visibility in AstraCDN is built into service endpoints and scripts rather than a separate observability service. Edge, control, and inference expose `/health`, `/ready`, and `/metrics`; edge and control also exchange edge health and cache analytics snapshots [@edge-main] [@control-main] [@inference-main].

## Health And Readiness

`/health` is a liveness-style process check. `/ready` checks dependencies and returns unavailable when required dependencies are missing. Tests explicitly cover missing-dependency readiness failures for edge, control, and inference.

Edge can also register/push health to control using `EDGE_NODE_ID`, `EDGE_PUBLIC_URL`, and capabilities. Control's `/v1/edge/health` combines registered node data with latest analytics observations and marks health based on a staleness window [@control-main].

## Metrics And Analytics

Edge metrics include cache hits by memory/Redis/miss, rate-limit blocks, WAF blocks, invalidations, invalidation failures, and cache fill latency. `/v1/cache/analytics` returns JSON cache analytics with host and route dimensions [@edge-main].

Control metrics include rate-limit blocks and cache invalidation counters. It persists cache analytics snapshots, can render snapshots as Prometheus text, and has export paths for OTLP and JSONL warehouse sinks [@control-main].

Inference metrics include exact cache hits, semantic cache hits, misses, rate-limit blocks, and provider latency [@inference-main].

## Smoke Test

`scripts/smoke-test.sh` is the broadest executable specification in the repo. It resets compose volumes, starts the stack with mock inference, enables CORS, domain verification bypass, billing webhook signing, edge domain validation, WAF, delivery headers, redirects, route limits, signed cookies, Brotli, segmented cache, and image transforms, then verifies dashboard, API keys, tenants, billing, routes, cache behavior, purge, inference, and ingress flows [@smoke].

Because the smoke test exercises cross-service behavior, it is the best verification command after changes that touch service contracts, compose wiring, auth, cache events, or dashboard proxy behavior.

## Database Operations

`scripts/db-migrate.sh` supports `up`, `status`, and `validate`. It can connect through `DATABASE_URL`, discrete Postgres env vars, or `podman exec` into a configured psql container. It validates filenames and applied checksums before applying pending migrations [@migrate].

## Cloud Verification

`scripts/cloud-verify.sh` requires `CONTROL_URL`, `CDN_URL`, `DASHBOARD_URL`, `CDN_HOST`, and `ASTRACDN_API_KEY`. It checks control readiness, dashboard health, CDN readiness, a CDN probe path with Host header, control edge health API, and Kubernetes rollout status when `kubectl` is available [@cloud-verify].

## Related Pages

Read [[deployment-topology]] for where these scripts fit into local, Kubernetes, and OpenTofu workflows. Read [[data-model]] before modifying migrations.
