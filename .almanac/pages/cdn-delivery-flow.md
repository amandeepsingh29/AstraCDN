---
title: CDN Delivery Flow
summary: CDN delivery starts at /edge requests, combines route/domain config from control with edge-local cache and security policy, fills from origin, and records cache telemetry.
topics: [flows, edge, caching]
sources:
  - id: edge-main
    type: file
    path: services/edge/cmd/edge/main.go
    note: Implements the delivery path and route/cache/security behavior.
  - id: edge-tests
    type: file
    path: services/edge/cmd/edge/main_test.go
    note: Verifies delivery behavior across cache hits, misses, range, revalidation, rules, domain validation, and transformations.
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements route/origin/domain APIs consumed by edge.
status: active
verified: 2026-06-30
---

The CDN delivery flow is the core runtime path of [[astra-cdn]]. A request to `/edge/...` enters [[edge-service]], which resolves route policy from [[control-plane]], uses cache where legal, fetches from [[origin-service]] when needed, and updates cache metrics [@edge-main].

## Route Resolution

Control stores origins, routes, and domains. A route binds `host + path_prefix` to an origin and policy fields such as cache mode, TTL, stale-while-revalidate, delivery rules, WAF rules, and rate-limit rules [@control-main]. Edge periodically fetches this route/domain state and matches requests by host and longest relevant path prefix [@edge-main].

When domain validation is enabled, the request host must be present in the edge's domain projection. Tests verify both rejection of unconfigured domains and acceptance of configured domains [@edge-tests].

## Cache Decision

Edge caches GET and HEAD-style delivery responses when the route policy and origin headers allow it. `cache_mode=origin` follows origin cache headers, `override` can cache without origin cache headers using route TTL, and `bypass` skips cache [@edge-tests].

Cache keys isolate hosts and include path/query details. `Vary` is honored by storing and looking up variant keys; `Vary: *` is not cached. Requests with `Authorization` are not cached by default, and private/no-store responses are not reused as public cache entries [@edge-tests].

## Miss Fill And Revalidation

On a miss, edge fetches from the matched origin. Request coalescing can collapse concurrent misses for the same key so only one origin fill happens. Tests verify coalescing with concurrent cache misses [@edge-tests].

Stale entries can be revalidated using ETag or Last-Modified. Edge can serve stale-if-error inside the allowed window when origin revalidation fails, and rejects that behavior outside the window [@edge-tests].

## Response Mutation

Delivery rules can set headers, remove headers, or return redirects based on path prefixes. These rules can come from global environment config or control-plane route config. Tests cover both static and route-derived delivery headers and redirects [@edge-tests].

Compression and image transformation happen in the delivery path. Edge supports gzip and Brotli for eligible responses, avoids compressing range responses, and can cache transformed image variants [@edge-tests].

## Telemetry

Edge records cache results by layer and can break analytics down by host and route. `/v1/cache/analytics` returns JSON, `/metrics` exposes Prometheus text, and periodic snapshot publishing posts cache analytics to control when configured [@edge-main].

## Read Next

Read [[edge-service]] for implementation boundaries, [[data-model]] for route/domain storage, and [[observability-and-operations]] for metrics and smoke-test coverage.
