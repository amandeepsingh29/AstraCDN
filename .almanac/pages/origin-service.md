---
title: Origin Service
summary: The origin service is the bundled origin implementation that serves smoke endpoints and /assets objects from local disk or S3-compatible storage for edge cache fills.
topics: [origin, services, asset-management]
sources:
  - id: origin-main
    type: file
    path: services/origin/cmd/origin/main.go
    note: Implements origin routes, local/S3 asset storage, range forwarding, SigV4 signing, surrogate keys, and graceful server config.
  - id: origin-tests
    type: file
    path: services/origin/cmd/origin/main_test.go
    note: Verifies local file assets, range requests, missing assets, S3 assets, range forwarding, and request signing.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Wires origin local storage and optional S3 environment.
status: active
verified: 2026-06-30
---

The origin service is a bundled origin for local development, smoke tests, and simple asset hosting. It listens on port `9000`, serves `/assets/...` from local disk or S3-compatible object storage, and provides synthetic smoke endpoints used by edge tests and scripts [@origin-main].

## Local Assets

Local mode serves files from `ORIGIN_ASSET_DIR`, defaulting to `/var/lib/astra-cdn/origin` in containers. It uses `http.ServeContent`, so file-backed assets support HTTP range requests and validators from file metadata [@origin-main]. Tests verify file serving, range support, and missing-file 404 behavior [@origin-tests].

## S3 Assets

S3 mode is selected with `ORIGIN_STORAGE_MODE=s3`. The service builds object URLs from endpoint, bucket, region, prefix, and path-style settings. If access key and secret are configured, it signs outbound object requests with AWS Signature V4. It forwards range-related request headers and copies object response headers back to clients [@origin-main]. Tests verify S3-backed serving, range forwarding, and signed requests [@origin-tests].

## Smoke Endpoints

The service also exposes:

- `/large-object-smoke`: fixed-size binary response for large-object/segmented-cache checks.
- `/image-smoke.png`: generated PNG for image transform checks.
- `/surrogate-smoke`: text response with `Surrogate-Key: smoke-tag release-2026`.
- All other paths: text responses with ETag and Last-Modified support [@origin-main].

These endpoints make [[cdn-delivery-flow]] and [[cache-invalidation-and-prewarm]] behavior testable without external services.

## Surrogate Keys

For `/assets/...`, origin computes surrogate keys from the asset path and sets the `Surrogate-Key` header when tags exist. Edge indexes this header when caching, enabling tag invalidation later [@origin-main].

## Related Pages

Read [[asset-management-flow]] for how dashboard writes origin assets, and [[edge-service]] for how edge fetches origin responses and caches them.
