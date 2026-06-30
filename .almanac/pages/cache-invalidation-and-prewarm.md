---
title: Cache Invalidation And Prewarm
summary: Cache invalidation and prewarm are persisted control-plane operations that fan out to edge nodes over NATS and are acknowledged back per invalidation delivery.
topics: [flows, caching, control-plane, edge]
sources:
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements cache invalidation/prewarm handlers, persistence, NATS publishing, delivery recording, and metrics.
  - id: edge-main
    type: file
    path: services/edge/cmd/edge/main.go
    note: Implements NATS subscribers, invalidation application, prewarm fetching, and delivery acknowledgements.
  - id: schema
    type: file
    path: db/schema.sql
    note: Defines cache operation and delivery tables.
  - id: edge-tests
    type: file
    path: services/edge/cmd/edge/main_test.go
    note: Verifies invalidation modes, host scoping, surrogate tags, prewarm, and acknowledgement retries.
  - id: control-tests
    type: file
    path: services/control/cmd/control/main_test.go
    note: Verifies cache operation validation, persistence, rate limiting, and delivery list/record behavior.
status: active
verified: 2026-06-30
---

Cache invalidation and prewarm are control-plane operations with edge-side effects. [[control-plane]] persists the requested operation, publishes a NATS event, and exposes delivery/operation APIs. [[edge-service]] consumes the event, mutates cache state or warms paths, and reports delivery status back to control [@control-main] [@edge-main].

## Invalidation Modes

Invalidation accepts exactly one mode per request:

- `keys`: purge exact cache keys.
- `prefixes`: purge cache entries matching prefixes.
- `tags`: purge entries indexed by surrogate key tags [@schema].

Control rejects ambiguous invalidation requests, including mixed tags with other modes. Tests cover ambiguous keys/prefixes, ambiguous tags, host-scoped invalidation, and surrogate-tag persistence [@control-tests].

## Host Scope

Invalidations can include `host`. Edge applies host scoping so an invalidation for one host does not purge cache entries for another host. Tests verify exact-key host isolation and prefix host isolation [@edge-tests].

## Surrogate Keys

Surrogate-key invalidation depends on edge indexing the origin response `Surrogate-Key` header when storing cache entries. Later tag invalidation purges entries with matching tags. The origin service emits surrogate keys for local assets and a smoke endpoint, which makes the behavior testable across local asset flows [@edge-tests].

## Prewarm

Prewarm jobs contain a host and list of `/edge/...` paths. Edge receives the event and fetches each path through its own delivery path so successful prewarm requests populate cache using normal route/origin behavior [@edge-main]. Control validates paths and persists jobs in `cache_prewarm_jobs` [@schema].

## Delivery Acknowledgements

For invalidations, edge posts delivery status back to `/v1/cache/invalidation-deliveries` with invalidation ID, node ID, status, and optional error message. The database primary key is `(invalidation_id, node_id)`, so delivery status is per invalidation per edge node [@schema].

Edge retries transient acknowledgement failures according to `EDGE_INVALIDATION_ACK_ATTEMPTS` and `EDGE_INVALIDATION_ACK_BACKOFF`; tests verify retry behavior [@edge-tests].

## Operational Implication

A successful control API response means the operation was accepted and recorded, not that every edge has already applied it. For production verification, inspect invalidation delivery rows, edge metrics, and edge-node health.

## Related Pages

Read [[asset-management-flow]] for dashboard-triggered purge behavior after upload/delete. Read [[observability-and-operations]] for smoke-test and metrics coverage.
