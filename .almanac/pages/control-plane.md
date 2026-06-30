---
title: Control Plane
summary: The control service is AstraCDN's Postgres-backed API for origins, routes, domains, API keys, tenants, billing, edge health, cache operations, analytics snapshots, and audit logs.
topics: [control-plane, services, data-model]
sources:
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements control HTTP handlers, persistence methods, auth, NATS publishing, metrics, and exports.
  - id: control-tests
    type: file
    path: services/control/cmd/control/main_test.go
    note: Verifies validation, auth, persistence, billing, analytics, audit, and cache operation behavior.
  - id: schema
    type: file
    path: db/schema.sql
    note: Defines current durable tables used by control.
  - id: openapi
    type: file
    path: api/openapi.yaml
    note: Documents the public control API contract.
status: active
verified: 2026-06-30
---

The control plane is the source of truth for AstraCDN configuration and operational records. It exposes `/v1/...` APIs on port `8081`, writes Postgres records, publishes NATS events to edge nodes, exports metrics, and records audit logs for mutating operations [@control-main].

## API Surface

Control handlers cover:

- CDN configuration: `/v1/origins`, `/v1/routes`, `/v1/domains`, `/v1/domains/verify`, `/v1/route-rule-versions`.
- Access: `/v1/api-keys`, `/v1/api-keys/revoke`.
- Tenant and commercial foundations: `/v1/tenants`, `/v1/rbac/users`, `/v1/billing/accounts`, `/v1/billing/webhooks`, `/v1/billing/webhook-events`.
- Edge fleet and telemetry: `/v1/edge/register`, `/v1/edge/nodes`, `/v1/edge/health`, `/v1/analytics/cache-snapshots`, `/v1/analytics/cache-snapshots/prometheus`.
- Cache operations: `/v1/cache/invalidate`, `/v1/cache/prewarm`, `/v1/cache/invalidation-deliveries` [@control-main].

The OpenAPI file documents this as the control API server at `http://localhost:8081` [@openapi].

## Persistence Contract

Control writes the tables described in [[data-model]]. The important configuration tables are `cdn_origins`, `cdn_routes`, and `cdn_domains`; operational tables include `edge_nodes`, `cache_invalidations`, `cache_prewarm_jobs`, `cache_invalidation_deliveries`, `cache_analytics_snapshots`, `control_audit_logs`, and `route_rule_versions`; commercial/access tables include `api_keys`, `tenants`, `tenant_users`, `billing_accounts`, and `billing_webhook_events` [@schema].

Routes are upserted by `(host, path_prefix)` and include `cache_mode`, `cache_ttl_seconds`, `stale_while_revalidate_seconds`, `delivery_rules`, `waf_rules`, and `rate_limit_rules`. After route rule changes, control records version rows and publishes config-change events, so route edits affect both future API reads and edge projections [@control-main].

## Event Publishing

Control publishes cache invalidation, cache prewarm, and config-changed events through NATS when configured. The cache operation APIs persist a database record first, then publish the event for edge nodes. Edge nodes later report per-node invalidation delivery status back to `/v1/cache/invalidation-deliveries` [@control-main].

This makes cache operations auditable even when event delivery or edge application fails. Do not treat a created invalidation row as proof that every edge applied it; use delivery rows and edge metrics for that.

## Auth And Scopes

Control accepts a static `ASTRACDN_API_KEY`/bearer token path and persisted API keys. Persisted keys are hashed in Postgres, can be revoked, and carry scopes; tests cover wildcard support and legacy empty scopes [@control-tests]. Dashboard-created keys are one-time secrets in responses and only hashes are stored.

Mutating handlers call `requireAuth` with required scopes where applicable. The static configured API key is broad administrative access; persisted scoped keys are the path for narrower access.

## Billing And Webhooks

Billing is deliberately minimal but durable. Each tenant can have one billing account. Billing webhooks can update account status by provider customer ID and are deduplicated by `(provider, event_id)` in `billing_webhook_events` [@schema]. When `CONTROL_BILLING_WEBHOOK_SECRET` is configured, webhook requests must include a valid HMAC signature; tests verify valid signatures, invalid payloads, duplicate replay, and event listing [@control-tests].

## Observability

Control exposes `/health`, `/ready`, and `/metrics`. Readiness checks dependencies such as the database and returns unavailable when required dependencies are missing. Metrics include rate-limit blocks and cache invalidation counters, and analytics snapshots can be exported to Prometheus-style output, OTLP, or a JSONL warehouse sink depending on configuration [@control-main].

## Related Pages

Read [[cdn-delivery-flow]] to see how edge consumes control records. Read [[cache-invalidation-and-prewarm]] for the event-driven cache operations. Read [[security-and-auth]] before changing auth, signatures, CORS, or production defaults.
