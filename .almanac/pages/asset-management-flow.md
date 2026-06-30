---
title: Asset Management Flow
summary: Dashboard asset management writes objects to local disk or S3, returns edge-facing /edge/assets paths, and triggers control-plane cache purges for changed objects.
topics: [flows, dashboard, origin, asset-management]
sources:
  - id: dashboard-main
    type: file
    path: services/dashboard/cmd/dashboard/main.go
    note: Implements upload, list, delete, storage status, purge, path sanitization, and S3/local stores.
  - id: dashboard-tests
    type: file
    path: services/dashboard/cmd/dashboard/main_test.go
    note: Verifies asset upload/delete/list/purge behavior, traversal rejection, max size, and S3 store usage.
  - id: origin-main
    type: file
    path: services/origin/cmd/origin/main.go
    note: Serves local and S3-backed /assets paths for edge origin fetches.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Shows local shared asset directory and optional MinIO profile.
status: active
verified: 2026-06-30
---

The asset management flow connects [[dashboard]], [[origin-service]], [[edge-service]], and [[control-plane]]. Dashboard writes an asset into the origin storage backend, returns an `/edge/assets/...` path and public URL, and asks control to invalidate that path so edge will fetch the new object [@dashboard-main].

## Local Storage Flow

In local mode, dashboard writes uploaded files under `DASHBOARD_ASSET_DIR`, defaulting to `data/origin`. The example origin serves from `ORIGIN_ASSET_DIR`; compose maps the same host directory into the origin container, so uploaded dashboard files become origin files [@compose].

Origin serves these files under `/assets/...`. Edge clients request `/edge/assets/...`; edge strips/forwards the path to origin according to its origin URL handling [@origin-main].

## S3 Storage Flow

Dashboard and origin can both use S3-compatible object storage. Dashboard writes objects with AWS Signature V4 when credentials are configured, lists/deletes via S3 APIs, and reports S3 mode without exposing secrets. Origin fetches the same object keys from S3 and forwards range/metadata headers [@dashboard-main] [@origin-main].

The compose `object-storage` profile starts MinIO and a bucket initializer. `make up-minio` wires both dashboard and origin to the MinIO bucket through environment variables [@compose].

## Purge Contract

Dashboard's upload and delete paths call `purgeAsset`, which posts a cache invalidation request to control for the edge path. Tests verify upload-triggered purge, delete-triggered purge, explicit purge, and skip-purge behavior for delete [@dashboard-tests].

This means successful upload/delete is not purely a storage operation. It is also expected to update CDN freshness through [[cache-invalidation-and-prewarm]].

## Path Safety

Dashboard sanitizes asset names and rejects traversal attempts in upload, list, delete, and purge flows. Origin also cleans `/assets/...` paths and rejects missing or traversal-like paths before opening local files or S3 objects [@dashboard-tests] [@origin-main].

## Related Pages

Read [[origin-service]] for storage backend behavior and [[cache-invalidation-and-prewarm]] for the purge fanout path.
