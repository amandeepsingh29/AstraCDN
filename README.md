# AstraCDN

AstraCDN is a self-hosted CDN project for serving images, videos, and files
through an edge caching layer.

- Built a self-hosted CDN to serve images, videos, and files through an edge cache.
- Added a dashboard and control plane to manage routes, tenants, cache purge/prewarm, signed URLs, rate limits, and security rules.
- Runs locally with Podman using MinIO/S3, Redis, NATS, and PostgreSQL, with support for multi-edge deployment later.

This repository is being built in small phases. The current target is a minimal local stack with:

- Go edge service
- Go control service
- Go inference service
- Go dashboard service
- PostgreSQL
- Redis
- NATS
- Podman Compose local deployment

## Local Development

Prerequisites:

- Podman
- `podman-compose`
- Go, if running services directly outside containers

Start the local stack:

```sh
make up
```

Stop the local stack:

```sh
make down
```

Reset local persisted data:

```sh
make reset-data
```

Remove local project containers/orphans and built service images:

```sh
make clean
make clean-images
```

Run the local smoke/integration test:

```sh
make smoke
```

Run local hot-path benchmarks:

```sh
make bench
```

Health checks:

```sh
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health
curl http://localhost:3000/health
```

Open the local dashboard:

```sh
open http://localhost:3000
```

The dashboard API proxy is protected by `DASHBOARD_ACCESS_TOKEN`. For local
development it defaults to `ASTRACDN_API_KEY`, so the default unlock token is
`astracdn-local-dev-key`.
Use the Domains panel to create CDN hostnames, copy the required DNS TXT
ownership value, and run verification through the dashboard control-plane
proxy. Local smoke tests bypass external DNS, but normal environments must add
the TXT record before a domain becomes active.
Use the Create route panel to create basic routes or attach common advanced
rules: response header injection, WAF path blocking, and route-scoped rate
limits. Empty advanced fields are ignored.
Use the Route rule versions panel to inspect recent delivery, WAF, and
rate-limit rule changes for safer route rollout review.

Serve your own local assets:

```sh
mkdir -p data/origin/assets
cp /path/to/photo.jpg data/origin/assets/photo.jpg
curl -H 'Host: cdn.localhost' http://localhost:8080/edge/assets/photo.jpg
```

The example origin mounts `data/origin` read-only and serves it under
`/assets/*`. The dashboard can also upload files into the same local asset
directory from the "Upload photo or video" panel. Uploaded files are shown in
the local asset inventory and returned as `/edge/assets/...` paths that can be
tested immediately in the CDN tester. The inventory can also delete local
assets and publish a cache purge for the deleted edge path. Re-uploading the
same asset path also publishes a purge so edge caches refresh to the new file.
Asset upload and inventory responses include a `public_url` built from
`DASHBOARD_PUBLIC_CDN_BASE_URL`, which defaults locally to
`http://cdn.localhost:8080`. Use the inventory Purge action to invalidate a
single asset without deleting the origin file.

For production-style media delivery, the example origin and dashboard can use
an S3-compatible object store instead of local disk by setting
`ORIGIN_STORAGE_MODE=s3` and `DASHBOARD_STORAGE_MODE=s3` plus the matching
S3 endpoint, bucket, prefix, and credentials. Range requests, object metadata
headers, CDN surrogate keys, dashboard upload/list/delete, and dashboard purge
actions continue to work through the edge. The dashboard exposes the current
asset backend in the upload panel and through `GET /api/assets/storage`. Use
the asset inventory filter to narrow large local directories or S3 prefixes by
folder and result limit. Asset Test, Purge, and Delete actions use the
inventory panel's selected CDN host, so custom domains are supported without
editing code. Asset Prewarm uses the same selected host and asks the control
plane to fill edge cache for the selected object. The inventory can also
prewarm or purge all currently loaded rows after applying a folder and limit
filter.

API contract:

- `api/openapi.yaml`

Curl examples:

- `docs/curl-examples.md`

Production readiness notes:

- `docs/tenant-rbac-billing.md`
- `docs/local-minio-multi-edge.md`
- `docs/global-edge-network.md`
- `docs/live-cloud-deployment.md`
- `docs/production-deployment.md`
- `deploy/opentofu/README.md`

Local HTTPS/dev certificate guide:

- `docs/local-https.md`

Kubernetes deployment skeleton:

- `deploy/k8s/README.md`
- `docs/image-build-publish.md`
- `docs/deployment-checklist.md`
- `docs/production-tls.md`
- `docs/production-runbook.md`
- `docs/slo.md`
- `docs/backup-restore.md`
- `docs/database-migrations.md`
- `docs/advanced-cdn-backlog.md`

## Service Ports

- Edge: `8080`
- Edge ingress HTTPS/HTTP3: `8443` TCP and UDP
- Control: `8081`
- Inference: `8082`
- Dashboard: `3000`
- PostgreSQL: `5432`
- Redis: `6379`
- NATS: `4222`
