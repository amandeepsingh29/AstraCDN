---
title: Inference Service
summary: The inference service exposes a cached /v1/infer API with mock, OpenAI-compatible, OpenAI Responses, and Ollama providers, Redis exact caching, optional semantic caching, streaming, auth, rate limiting, and metrics.
topics: [inference, services, ai]
sources:
  - id: inference-main
    type: file
    path: services/inference/cmd/inference/main.go
    note: Implements inference API, providers, exact and semantic cache, streaming, auth, rate limiting, metrics, and secure config validation.
  - id: inference-tests
    type: file
    path: services/inference/cmd/inference/main_test.go
    note: Verifies provider requests, cache behavior, semantic cache, streaming, validation, metrics, auth, rate limiting, and parsing.
  - id: compose
    type: file
    path: podman-compose.yml
    note: Wires inference to Redis and dashboard in the local stack.
status: active
verified: 2026-06-30
---

The inference service is an adjacent API in AstraCDN rather than part of the CDN delivery path. It listens on port `8082`, exposes `/v1/infer`, uses Redis for exact prompt-response caching, can use an in-memory semantic cache, and supports mock, OpenAI-compatible chat completions, OpenAI Responses API, and Ollama providers [@inference-main].

## Request And Cache Behavior

Requests include `prompt`, optional `model`, optional `params`, and optional `stream`. The exact cache key is stable for semantically equivalent params ordering, so callers do not miss cache because JSON map keys arrive in a different order [@inference-tests].

The handler checks exact cache first, then semantic cache, then provider. Responses include provider, model, cached status, response text, prompt, cache key, and cache-hit layer [@inference-main].

Semantic cache stores embeddings in memory and uses cosine similarity against a threshold. Tests verify semantic cache hits after exact misses and cosine similarity behavior [@inference-tests].

## Providers

The mock provider returns deterministic local responses and is used by smoke tests and non-production secure-config tests. OpenAI-compatible and Ollama providers send chat-style requests to configured base URLs. The OpenAI Responses provider sends Responses API requests and client headers, with parser support for output content and SSE-style data lines [@inference-tests].

Secure config validation requires real provider credentials outside local mode unless using the mock provider. Tests verify that OpenAI configuration without a key is rejected outside local mode and mock provider is accepted [@inference-tests].

## Streaming

When `stream=true`, the service writes server-sent events for provider stream events. Tests verify mock token streaming and SSE formatting [@inference-tests].

## Auth, Rate Limit, And Metrics

If `ASTRACDN_API_KEY` is set, inference requires bearer/API-key auth. Rate limiting separates clients by API key where available. Metrics report exact cache hits, semantic cache hits, misses, rate-limit blocks, and provider latency [@inference-main].

## Related Pages

Read [[dashboard]] for dashboard proxying to inference, and [[observability-and-operations]] for health, readiness, and metrics conventions shared across services.
