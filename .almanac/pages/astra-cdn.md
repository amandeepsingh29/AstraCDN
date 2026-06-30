---
title: AstraCDN
summary: AstraCDN is this repository's self-hosted CDN and WAF platform, composed of Go services for edge delivery, control-plane configuration, dashboard operations, inference, and origin assets.
topics: [architecture, product, services]
sources:
  - id: readme
    type: file
    path: README.md
    note: Describes the product intent, local stack, service roles, and advertised workflows.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Shows the runnable local topology and service wiring.
  - id: openapi
    type: file
    path: api/openapi.yaml
    note: Defines the exposed local API surface across edge, control, and inference.
  - id: schema
    type: file
    path: db/schema.sql
    note: Defines the current durable control-plane state model.
status: active
verified: 2026-06-30
---

AstraCDN is a self-hosted CDN control and delivery stack. In this checkout it is implemented as five Go service binaries plus infrastructure manifests: [[edge-service]], [[control-plane]], [[dashboard]], [[origin-service]], and [[inference-service]]. The product claim is broader than a caching proxy: the project combines cache delivery, route configuration, WAF and rate-limit rules, custom domains, asset upload, billing/RBAC foundations, telemetry, and deployment templates [@readme].

The codebase uses service boundaries rather than shared internal packages. Each service is a `package main` binary under `services/<name>/cmd/<name>/`, so cross-service contracts are HTTP APIs, Postgres tables, Redis keys, NATS subjects, environment variables, and deployment manifests rather than imported Go interfaces [@compose].

## Runtime Shape

The local stack is the clearest operational map:

- Dashboard runs on port `3000` and is the browser/admin entry point.
- Edge runs on port `8080` and serves `/edge/...` CDN requests plus cache analytics.
- Control runs on port `8081` and persists routes, domains, API keys, edge health, billing, audit logs, and cache operations.
- Inference runs on port `8082` and exposes `/v1/infer` with exact and semantic caching.
- Origin runs on port `9000` and serves local or S3-backed assets for the edge to fetch.
- Postgres, Redis, and NATS are required infrastructure for durable control state, shared cache/prompt cache, and pub/sub control events [@compose].

The OpenAPI contract intentionally describes only edge, control, and inference service APIs. Dashboard and origin are operational surfaces, but not part of the published OpenAPI contract in this checkout [@openapi].

## Main Flows

The central product flow is [[cdn-delivery-flow]]: a client requests `/edge/...`, edge matches route/domain config from control, applies access/security/delivery rules, reads memory or Redis cache, and fills from origin on miss. Control-side changes propagate through route polling and NATS config events.

The main operations flow is [[cache-invalidation-and-prewarm]]: dashboard or API callers create invalidation/prewarm records in control, control publishes NATS events, edge nodes apply them, and edge reports delivery acknowledgements.

The main admin flow is [[asset-management-flow]]: dashboard writes uploaded assets to local disk or S3-compatible storage, returns an edge path, and calls control to purge affected cache entries.

## Project Invariants

Current code makes Postgres the source of truth for configured origins, routes, domains, API keys, tenants, billing accounts, billing webhook events, route rule versions, cache invalidations, cache prewarm jobs, edge nodes, cache analytics snapshots, and audit logs. Edge caches and local in-memory structures are runtime projections of that control state rather than authoritative configuration [@schema].

The README references a `docs/` directory that is not present in this checkout. Treat current code, tests, deployment manifests, `api/openapi.yaml`, and `db/schema.sql` as the evidence for present behavior.

## Read Next

Start with [[system-architecture]] for the service graph, then read [[control-plane]] and [[edge-service]] for the two core subsystems. Use [[data-model]] when changing persistence, [[deployment-topology]] when changing runtime composition, and [[security-and-auth]] when touching API keys, signed URLs, WAF, CORS, or production defaults.
