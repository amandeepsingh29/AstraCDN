---
title: Security And Auth
summary: AstraCDN security spans dashboard tokens, static and persisted control API keys, billing webhook HMACs, signed edge URLs/cookies, WAF rules, CORS, rate limits, and production secure-config checks.
topics: [security, auth, edge, control-plane]
sources:
  - id: control-main
    type: file
    path: services/control/cmd/control/main.go
    note: Implements control auth, persisted API keys, scopes, billing webhook signature checks, CORS, rate limiting, and secure config validation.
  - id: edge-main
    type: file
    path: services/edge/cmd/edge/main.go
    note: Implements edge signed URLs, signed cookies, WAF, CORS, rate limits, and secure config validation.
  - id: dashboard-main
    type: file
    path: services/dashboard/cmd/dashboard/main.go
    note: Implements dashboard token auth and upstream API credential injection.
  - id: inference-main
    type: file
    path: services/inference/cmd/inference/main.go
    note: Implements inference API key auth, rate limiting, and secure provider config validation.
  - id: tests
    type: file
    path: services/
    note: Service tests verify auth, CORS, WAF, signing, rate limiting, webhook signatures, and secure config behavior.
status: active
verified: 2026-06-30
---

AstraCDN security is distributed across services. There is no single auth package; each service implements its own middleware and validators. Changes in this area must account for dashboard token auth, control API keys/scopes, edge request signing, WAF/rate limits, billing webhook signatures, and production config checks [@control-main] [@edge-main] [@dashboard-main] [@inference-main].

## Dashboard Token

Dashboard API routes require `X-AstraCDN-Dashboard-Token` unless `DASHBOARD_ACCESS_TOKEN` resolves to an empty value. By default, dashboard uses `ASTRACDN_API_KEY` as both upstream API key and dashboard token in local development [@dashboard-main].

Dashboard strips the dashboard token before proxying upstream. It injects `Authorization: Bearer <ASTRACDN_API_KEY>` only when the caller did not already supply `Authorization` or `X-AstraCDN-API-Key` [@dashboard-main].

## Control API Keys

Control supports a static configured API key and persisted API keys. Persisted keys are generated as one-time `ak_...` secrets, stored as hashes, can carry scopes, and can be revoked. Scope checks support wildcard behavior and legacy empty scopes per tests [@control-main].

The static configured key is broad administrative access. Persisted scoped keys are the safer integration surface for callers that only need subsets like control writes or edge reads.

## Billing Webhook Signatures

When `CONTROL_BILLING_WEBHOOK_SECRET` is set, billing webhook requests must include `X-AstraCDN-Billing-Signature` with a `sha256=` HMAC over the request body. Webhook events are deduplicated by provider and event ID after successful processing [@control-main].

## Edge Access Controls

Edge can enforce signed URLs and signed cookies. Signed URL validation uses an expiry and HMAC secret; edge strips signing query params before forwarding to origin. Signed cookies protect configured path prefixes with a cookie name and HMAC secret [@edge-main].

WAF rules can block methods, path prefixes, headers containing configured substrings, and exact/CIDR IPs. Route-level WAF rules from control can apply alongside or instead of environment-level edge defaults depending on matched route behavior [@edge-main].

Rate limiting exists at several layers: edge global rate limit by client identity, edge route-scoped rate limits, control API limits, and inference API limits. Tests verify that limit buckets separate client IPs or API keys as appropriate [@tests].

## CORS

Edge, control, and inference each implement CORS middleware controlled by `CORS_*` environment variables. Tests cover allowed preflight behavior and edge rejection for disallowed preflights [@tests].

## Secure Config Checks

Control, edge, and inference validate production-sensitive defaults. Tests verify rejection of production defaults in control, rejection of short edge signing secrets, rejection of disabled edge rate limits outside local mode, and rejection of missing OpenAI credentials outside local mode unless the mock inference provider is used [@tests].

## Related Pages

Read [[control-plane]] for persisted API keys and billing webhooks, [[edge-service]] for signed delivery and WAF mechanics, and [[dashboard]] for dashboard auth/proxy behavior.
