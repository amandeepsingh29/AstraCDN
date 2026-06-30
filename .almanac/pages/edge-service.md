---
title: Edge Service
summary: The edge service is the CDN data plane that serves /edge requests, applies control-plane route policy, caches responses in memory/Redis, transforms and compresses content, and consumes cache/config events.
topics: [edge, services, caching]
sources:
  - id: edge-main
    type: file
    path: services/edge/cmd/edge/main.go
    note: Implements edge request handling, caching, route config refresh, NATS subscriptions, WAF, signing, compression, transforms, metrics, and health publishing.
  - id: edge-tests
    type: file
    path: services/edge/cmd/edge/main_test.go
    note: Verifies cache, route, WAF, signing, compression, range, segmented cache, transform, invalidation, metrics, and control integration behavior.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Shows edge runtime environment defaults and local dependencies.
status: active
verified: 2026-06-30
---

The edge service is AstraCDN's data plane. It listens on port `8080`, serves `/edge/...`, keeps local memory cache, optionally uses Redis, fetches misses from origin URLs, applies route and security policy, and reports health/analytics to [[control-plane]] [@edge-main].

## Request Pipeline

For an edge request, the service:

1. Applies observability and CORS middleware.
2. Optionally validates that the request host is configured in the control-plane domain projection.
3. Finds the best route by host and path prefix, using control-plane route config when enabled.
4. Applies WAF rules, signed URL checks, signed cookie checks, global/scoped rate limits, redirects, and delivery header rules.
5. Builds a cache key that isolates host, path, query, image-transform variants, and `Vary` dimensions where applicable.
6. Looks for fresh entries in memory and Redis.
7. Revalidates stale entries with ETag or Last-Modified when allowed.
8. Fetches from origin, origin shield, or failover origins on miss.
9. Stores cacheable responses and writes HIT/MISS/STALE style headers [@edge-main].

Tests cover host isolation, `Vary` behavior, no-cache/private handling, authorization bypass for caching, stale-if-error windows, revalidation, range serving, HEAD cache behavior, route override/bypass cache policies, and route-derived delivery/security rules [@edge-tests].

## Control Projection

Edge does not write route configuration. Its `routeConfigStore` fetches `/v1/routes` and `/v1/domains` from control using `CONTROL_BASE_URL` and `CONTROL_API_KEY`, refreshes periodically, and can refresh on NATS config-change events [@edge-main]. If control projection is unavailable, the edge still has environment-based defaults such as `ORIGIN_BASE_URL`, global WAF rules, response headers, redirects, and rate limits.

Domain validation is controlled by `EDGE_DOMAIN_VALIDATION_ENABLED`. Local compose defaults it to false; the smoke test enables it to verify configured-domain behavior [@compose].

## Cache Layers

Memory cache is always used when an `edgeServer` has one. Redis cache is configured with `REDIS_ADDR` in the local stack and gives cache sharing across edge processes. Metrics distinguish memory hits, Redis hits, and misses [@edge-main].

Large object support can stream origin responses and cache segments when `EDGE_LARGE_OBJECT_STREAMING_ENABLED` and `EDGE_SEGMENTED_CACHE_ENABLED` are active. Segment keys use a dedicated separator and tests verify that a large origin response can be streamed and then served from segmented cache [@edge-tests].

Surrogate-key invalidation is supported by indexing the `Surrogate-Key` response header at store time and invalidating by tag later. Tests cover surrogate-key indexing and tag invalidation [@edge-tests].

## Origin Fetching

The primary origin comes from the matched route's origin base URL when route config supplies one, otherwise `ORIGIN_BASE_URL`. Edge can also use origin shield URLs and failover origins. Tests cover retries on 5xx, backup failover, origin shield use, and fallback when origin shield fails [@edge-tests].

Edge strips signing parameters from the forwarded origin query so signed URL mechanics do not leak into origin cache identity or application handling [@edge-tests].

## Media And Compression

Edge can gzip or Brotli compress compressible responses when enabled and the client accepts it. Range responses are not gzip-compressed. Image transform support can resize/convert/cache image variants and is controlled by `EDGE_IMAGE_TRANSFORM_*` environment variables [@edge-tests].

## Events And Reporting

When NATS is configured, edge subscribes to cache invalidation, prewarm, and config-change events. It applies invalidations by keys, prefixes, or surrogate tags, runs prewarm fetches, and acknowledges invalidation delivery back to control with retries [@edge-main].

Edge can periodically publish cache analytics snapshots and health registration to control. The health registration uses `EDGE_NODE_ID`, `EDGE_PUBLIC_URL`, and capabilities; analytics include hit/miss totals, host/route dimensions, and cache fill latency [@edge-main].

## Related Pages

Read [[cdn-delivery-flow]] for end-to-end request behavior, [[cache-invalidation-and-prewarm]] for event-driven cache operations, and [[security-and-auth]] for WAF, signed URLs, signed cookies, rate limiting, and secure config constraints.
