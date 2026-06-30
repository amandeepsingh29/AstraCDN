---
title: Data Model
summary: AstraCDN's durable model is a Postgres schema for CDN config, edge fleet state, cache operations, analytics snapshots, API keys, tenants, billing, audit logs, and schema migration bookkeeping.
topics: [data-model, postgres, control-plane]
sources:
  - id: schema
    type: file
    path: db/schema.sql
    note: Defines the current full schema loaded by local Postgres.
  - id: migrations
    type: file
    path: db/migrations/
    note: Contains ordered migration files from initial schema through billing webhook events.
  - id: migrate-script
    type: file
    path: scripts/db-migrate.sh
    note: Defines migration validation, status, and application behavior.
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements application reads/writes against the schema.
status: active
verified: 2026-06-30
---

The AstraCDN durable data model lives in Postgres and is owned by [[control-plane]]. Local compose initializes a database from `db/schema.sql`, while managed upgrades use ordered files under `db/migrations/` plus `scripts/db-migrate.sh` [@schema] [@migrate-script].

## Schema Areas

CDN configuration:

- `cdn_origins`: named origin base URLs plus origin headers.
- `cdn_routes`: host/path route bindings to origins, cache policy, delivery rules, WAF rules, and route-scoped rate limits.
- `cdn_domains`: custom hosts, route associations, TLS mode, DNS TXT challenge fields, verification status, and verification time.
- `route_rule_versions`: append-only version history for delivery/WAF/rate-limit rule snapshots per route [@schema].

Edge and cache operations:

- `edge_nodes`: registered edge node addresses, capabilities, status, and last-seen time.
- `cache_invalidations`: accepted invalidation requests by mode and values.
- `cache_prewarm_jobs`: accepted prewarm requests.
- `cache_invalidation_deliveries`: per-node invalidation application status.
- `cache_analytics_snapshots`: edge-reported request totals, layer/host/route dimensions, and cache-fill latency [@schema].

Access, tenant, and billing:

- `api_keys`: hashed API keys, names, scopes, revocation timestamp, and creation time.
- `tenants`: tenant identity and lifecycle status.
- `tenant_users`: tenant-scoped users with role and lifecycle status.
- `billing_accounts`: one billing account per tenant.
- `billing_webhook_events`: deduplicated webhook event records keyed by provider and event ID [@schema].

Operational bookkeeping:

- `control_audit_logs`: actor, action, resource type/ID, request ID, remote address, metadata, and creation time.
- `service_events`: generic service event table present in schema but not a central flow in the current inspected code.
- `schema_migrations`: migration ledger with version, description, checksum, and applied timestamp [@schema].

## Migrations

Migration filenames must match `NNN_description.sql`. The migration script computes a SHA-256 checksum for each file, rejects checksum drift for already-applied migrations, wraps each pending migration in a transaction, and inserts the ledger row after the SQL body succeeds [@migrate-script].

`db/schema.sql` includes the current full schema plus `schema_migrations` rows for known migrations. Keep it aligned with migrations because compose uses it for fresh local database initialization, while existing deployments rely on migrations.

## Constraints That Matter

`cdn_routes` is unique on `(host, path_prefix)`, so route upsert behavior is keyed by those fields. `cdn_domains.host` is unique. `billing_accounts.tenant_id` is unique, making billing one account per tenant. `billing_webhook_events` is unique on `(provider, event_id)`, which is the duplicate replay guard for billing webhooks [@schema].

`cache_invalidations.mode` currently allows `keys`, `prefixes`, and `tags`. Migration `011_surrogate_key_invalidation.sql` exists specifically to replace the earlier check constraint that only allowed keys and prefixes [@migrations].

## Related Pages

Read [[control-plane]] for handlers and persistence methods, [[cache-invalidation-and-prewarm]] for cache operation tables, and [[security-and-auth]] for API key and billing webhook records.
