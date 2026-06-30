---
title: Getting Started
summary: Start here to navigate the AstraCDN wiki by reading the core service graph first, then following focused pages for delivery, control, data, security, operations, and deployment work.
topics: [navigation]
sources:
  - id: wiki-build
    type: note
    note: Synthesized from the initial Almanac build over the repository on 2026-06-30.
status: active
verified: 2026-06-30
---

This wiki is the project-memory layer for [[astra-cdn]]. It is not setup documentation; it is the map a future agent should read before changing the CDN, control plane, dashboard, data model, or deployment wiring.

## First Read

Read these pages in order:

1. [[astra-cdn]] for the product and repo-level mental model.
2. [[system-architecture]] for service responsibilities and runtime dependencies.
3. [[control-plane]] for the persistent source of truth and API surface.
4. [[edge-service]] for the delivery data plane.
5. [[cdn-delivery-flow]] for how a request moves through route policy, cache, origin fill, and telemetry.

## Common Work Areas

For database, migrations, or persistence changes, read [[data-model]] and then [[control-plane]]. The schema page explains table ownership, uniqueness constraints, and migration rules.

For cache freshness, purge, surrogate keys, or warmup changes, read [[cache-invalidation-and-prewarm]], [[edge-service]], and [[origin-service]].

For dashboard upload, asset listing, delete, S3 mode, or public asset URL behavior, read [[dashboard]] and [[asset-management-flow]].

For auth, WAF, signed URLs, signed cookies, billing webhook signatures, CORS, or rate limits, read [[security-and-auth]] before editing service handlers.

For inference work, read [[inference-service]]. It is part of the local platform and dashboard proxy surface, but it is not on the CDN delivery path.

For local stack, Kubernetes, OpenTofu, smoke tests, migrations, or cloud checks, read [[deployment-topology]] and [[observability-and-operations]].

## Current Evidence Boundaries

The first wiki pass is grounded in current repo files: Go service entrypoints and tests, `db/schema.sql`, migrations, `api/openapi.yaml`, compose, Kubernetes manifests, OpenTofu, scripts, and the README. The README references a `docs/` directory that is not present in this checkout, so code, tests, schema, and deployment manifests should be treated as current truth for behavior.

## Dense Clusters

The core CDN cluster is [[control-plane]], [[edge-service]], [[cdn-delivery-flow]], [[cache-invalidation-and-prewarm]], and [[data-model]].

The asset cluster is [[dashboard]], [[asset-management-flow]], and [[origin-service]].

The operations cluster is [[deployment-topology]], [[observability-and-operations]], and [[security-and-auth]].
