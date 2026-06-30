---
title: System Architecture
summary: AstraCDN is a service-oriented Go platform where control persists configuration, edge projects and applies it, dashboard fronts admin operations, origin supplies assets, and inference provides a cached AI sidecar API.
topics: [architecture, services]
sources:
  - id: compose
    type: file
    path: podman-compose.yml
    note: Defines local service dependencies, ports, and environment wiring.
  - id: openapi
    type: file
    path: api/openapi.yaml
    note: Defines the documented HTTP API surfaces for edge, control, and inference.
  - id: readme
    type: file
    path: README.md
    note: Provides the project-level architecture description.
status: active
verified: 2026-06-30
---

The AstraCDN architecture has one durable control plane and several runtime surfaces. [[control-plane]] owns persistent CDN configuration and operational records in Postgres. [[edge-service]] reads and applies that configuration while serving client traffic. [[dashboard]] wraps control, edge, inference, and asset operations behind a dashboard token. [[origin-service]] is the bundled origin implementation for local files or S3-compatible object storage. [[inference-service]] is adjacent to the CDN path and exposes AI inference with Redis-backed prompt caching [@compose].

## Service Responsibilities

| Service | Role | Primary state |
| --- | --- | --- |
| Edge | CDN request handler, cache, WAF, signing, compression, transformations, invalidation consumer | Memory cache, Redis cache, control route projection |
| Control | API and source of truth for origins, routes, domains, keys, tenants, billing, events, analytics | Postgres, NATS publishing |
| Dashboard | Static admin UI, authenticated API proxy, asset upload/list/delete/purge | Local/S3 asset backend, upstream APIs |
| Origin | Example origin and asset server | Local asset directory or S3 bucket |
| Inference | Cached inference API with multiple providers | Redis prompt cache, memory semantic cache |
| Ingress | Caddy HTTPS/HTTP3 terminator for local edge traffic | Caddy data/config volumes |

The repo keeps these services independent at build/runtime boundaries. Shared behavior such as observability middleware, CORS handling, rate limiting, and secure config validation is repeated in service files instead of centralized in a common package.

## Infrastructure Dependencies

Postgres is required by control. The local compose stack initializes it from `db/schema.sql`; the migration script applies versioned SQL under `db/migrations/` for managed upgrades [@compose].

Redis is used by edge for distributed cache and by inference for prompt cache. Edge also keeps a memory cache, so local cache behavior can differ between single-process and multi-edge runs.

NATS is the event bus between control and edge. Control publishes invalidation, prewarm, and config-change events; edge subscribes when `NATS_URL` is configured.

## API Boundaries

`api/openapi.yaml` documents the edge, control, and inference APIs, with separate server URLs for ports `8080`, `8081`, and `8082` [@openapi]. The dashboard APIs are not in the OpenAPI contract; they are a local UI/backend-for-frontend layer that forwards to documented service APIs and adds asset operations.

## Local Versus Production Shape

The local stack uses compose profiles for optional MinIO object storage and a second edge node. Kubernetes manifests under `deploy/k8s/base/` express the same core services for cluster deployment. OpenTofu does not provision a full cloud; it generates regional edge manifests and a DNS routing plan consumed by provider-specific infrastructure [@compose].

## Related Pages

Read [[deployment-topology]] for compose, Kubernetes, and OpenTofu details. Read [[data-model]] for the Postgres contract. Read [[observability-and-operations]] for health, readiness, metrics, smoke tests, and migration operations.
