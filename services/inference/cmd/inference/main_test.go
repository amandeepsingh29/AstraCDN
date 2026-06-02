package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInferHandlerReturnsDeterministicMockResponse(t *testing.T) {
	app := &inferenceServer{cache: newFakePromptCache(), provider: newMockProvider("mock"), apiKey: "secret", metrics: newInferenceMetrics()}

	req := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{
		"prompt":"explain edge caching",
		"params":{"temperature":0.2}
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.inferHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body inferResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Cached {
		t.Fatal("first response should not be cached")
	}
	if body.Provider != "mock" || body.Model != "mock" {
		t.Fatalf("provider/model = %q/%q, want mock/mock", body.Provider, body.Model)
	}
	if body.Response != "mock inference response for: explain edge caching" {
		t.Fatalf("response = %q", body.Response)
	}
	if body.CacheKey == "" {
		t.Fatal("cache key is required")
	}
	exactHits, semanticHits, misses, rateLimited := app.metricsSnapshot()
	if exactHits != 0 || semanticHits != 0 || misses != 1 || rateLimited != 0 {
		t.Fatalf("cache metrics exact=%d semantic=%d miss=%d, want 0/0/1", exactHits, semanticHits, misses)
	}
	providerLatency := app.providerLatencySnapshot()["mock"]
	if providerLatency.count != 1 {
		t.Fatalf("provider latency count = %d, want 1", providerLatency.count)
	}
}

func TestInferHandlerRejectsOversizedBody(t *testing.T) {
	t.Setenv("HTTP_MAX_REQUEST_BODY_BYTES", "10")
	app := &inferenceServer{cache: newFakePromptCache(), provider: newMockProvider("mock")}

	req := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{"prompt":"this body is too large"}`))
	rec := httptest.NewRecorder()
	app.inferHandler(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestObservabilityMiddlewareAddsRequestID(t *testing.T) {
	handler := observabilityMiddleware("inference", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != "req-inference-1" {
			t.Fatalf("request id in context = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "req-inference-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-inference-1" {
		t.Fatalf("response request id = %q", got)
	}
}

func TestCORSMiddlewareHandlesAllowedPreflight(t *testing.T) {
	t.Setenv("CORS_ENABLED", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://dashboard.example")

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("preflight should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/infer", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("allow origin = %q", got)
	}
}

func TestReadyHandlerReturnsOK(t *testing.T) {
	app := &inferenceServer{cache: newFakePromptCache(), provider: newMockProvider("mock")}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	app.readyHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ready":true`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestReadyHandlerRejectsMissingDependencies(t *testing.T) {
	app := &inferenceServer{}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	app.readyHandler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), `"ready":false`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestMetricsHandlerReportsCacheCounters(t *testing.T) {
	app := &inferenceServer{metrics: newInferenceMetrics()}
	app.recordCacheMetric("exact")
	app.recordCacheMetric("semantic")
	app.recordCacheMetric("provider")
	app.recordRateLimitBlock()
	app.recordProviderLatency("mock", 250*time.Millisecond)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	app.metricsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`astracdn_inference_cache_requests_total{result="hit",layer="exact"} 1`,
		`astracdn_inference_cache_requests_total{result="hit",layer="semantic"} 1`,
		`astracdn_inference_cache_requests_total{result="miss",layer="provider"} 1`,
		`astracdn_inference_rate_limit_blocks_total 1`,
		`astracdn_inference_provider_latency_seconds_total{provider="mock"} 0.250000`,
		`astracdn_inference_provider_requests_total{provider="mock"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestInferHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &inferenceServer{cache: newFakePromptCache(), provider: newMockProvider("mock"), apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{"prompt":"hello"}`))
	rec := httptest.NewRecorder()
	app.inferHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestInferHandlerRateLimitsRequests(t *testing.T) {
	app := &inferenceServer{
		cache:    newFakePromptCache(),
		provider: newMockProvider("mock"),
		apiKey:   "secret",
		limiter:  newRateLimiter(true, 0.001, 1),
		metrics:  newInferenceMetrics(),
	}

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{}`))
	firstReq.Header.Set("Authorization", "Bearer secret")
	first := httptest.NewRecorder()
	app.inferHandler(first, firstReq)
	if first.Code != http.StatusBadRequest {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusBadRequest)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{"prompt":"hello"}`))
	secondReq.Header.Set("Authorization", "Bearer secret")
	second := httptest.NewRecorder()
	app.inferHandler(second, secondReq)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	_, _, _, rateLimited := app.metricsSnapshot()
	if rateLimited != 1 {
		t.Fatalf("rate limited metric = %d, want 1", rateLimited)
	}
}

func TestRateLimiterSeparatesInferenceAPIKeys(t *testing.T) {
	limiter := newRateLimiter(true, 0.001, 1)

	first := httptest.NewRequest(http.MethodPost, "/v1/infer", nil)
	first.Header.Set("X-AstraCDN-API-Key", "key-a")
	if !limiter.allow(first) {
		t.Fatal("first API key should be allowed")
	}
	if limiter.allow(first) {
		t.Fatal("first API key should exceed burst")
	}

	second := httptest.NewRequest(http.MethodPost, "/v1/infer", nil)
	second.Header.Set("X-AstraCDN-API-Key", "key-b")
	if !limiter.allow(second) {
		t.Fatal("second API key should have an independent bucket")
	}
}

func TestValidateSecureConfigRequiresOpenAIKeyOutsideLocal(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "production")
	t.Setenv("ASTRACDN_API_KEY", "production-api-key")
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("INFERENCE_PROVIDER", "openai")
	t.Setenv("OPENAI_API_KEY", "")

	if err := validateSecureConfig(); err == nil {
		t.Fatal("expected missing OpenAI API key to be rejected")
	}
}

func TestValidateSecureConfigAcceptsMockProviderOutsideLocal(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "production")
	t.Setenv("ASTRACDN_API_KEY", "production-api-key")
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("INFERENCE_PROVIDER", "mock")
	t.Setenv("OPENAI_API_KEY", "")

	if err := validateSecureConfig(); err != nil {
		t.Fatalf("secure config rejected mock provider: %v", err)
	}
}

func TestInferHandlerUsesPromptCache(t *testing.T) {
	cache := newFakePromptCache()
	app := &inferenceServer{cache: cache, provider: newMockProvider("mock"), metrics: newInferenceMetrics()}
	body := `{"prompt":"cache me","params":{"max_tokens":16}}`

	first := httptest.NewRecorder()
	app.inferHandler(first, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(body)))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	app.inferHandler(second, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(body)))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d body=%s", second.Code, second.Body.String())
	}
	var cached inferResponse
	if err := json.NewDecoder(second.Body).Decode(&cached); err != nil {
		t.Fatal(err)
	}
	if !cached.Cached {
		t.Fatal("second response should be cached")
	}
	if cache.sets != 1 {
		t.Fatalf("cache sets = %d, want 1", cache.sets)
	}
	exactHits, semanticHits, misses, rateLimited := app.metricsSnapshot()
	if exactHits != 1 || semanticHits != 0 || misses != 1 || rateLimited != 0 {
		t.Fatalf("cache metrics exact=%d semantic=%d miss=%d, want 1/0/1", exactHits, semanticHits, misses)
	}
	providerLatency := app.providerLatencySnapshot()["mock"]
	if providerLatency.count != 1 {
		t.Fatalf("provider latency count = %d, want 1", providerLatency.count)
	}
}

func TestInferHandlerUsesSemanticCacheAfterExactMiss(t *testing.T) {
	cache := newFakePromptCache()
	app := &inferenceServer{
		cache:         cache,
		semanticCache: newMemorySemanticCache(0.9),
		provider:      newMockProvider("mock"),
		metrics:       newInferenceMetrics(),
	}

	firstBody := `{"prompt":"edge cache invalidation","params":{"max_tokens":16}}`
	first := httptest.NewRecorder()
	app.inferHandler(first, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(firstBody)))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}

	secondBody := `{"prompt":"edge cache invalidation","params":{"max_tokens":16,"exact_cache_buster":true}}`
	second := httptest.NewRecorder()
	app.inferHandler(second, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(secondBody)))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d body=%s", second.Code, second.Body.String())
	}
	var cached inferResponse
	if err := json.NewDecoder(second.Body).Decode(&cached); err != nil {
		t.Fatal(err)
	}
	if cached.Cached || cached.CacheHit == "semantic" {
		t.Fatalf("different params should not semantic hit: %+v", cached)
	}

	thirdBody := `{"prompt":"cache edge invalidation","params":{"max_tokens":16}}`
	third := httptest.NewRecorder()
	app.inferHandler(third, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(thirdBody)))
	if third.Code != http.StatusOK {
		t.Fatalf("third status = %d body=%s", third.Code, third.Body.String())
	}
	if err := json.NewDecoder(third.Body).Decode(&cached); err != nil {
		t.Fatal(err)
	}
	if !cached.Cached || cached.CacheHit != "semantic" {
		t.Fatalf("expected semantic cache hit, got %+v", cached)
	}
	exactHits, semanticHits, misses, rateLimited := app.metricsSnapshot()
	if exactHits != 0 || semanticHits != 1 || misses != 2 || rateLimited != 0 {
		t.Fatalf("cache metrics exact=%d semantic=%d miss=%d, want 0/1/2", exactHits, semanticHits, misses)
	}
}

func TestInferHandlerStreamsMockTokens(t *testing.T) {
	cache := newFakePromptCache()
	app := &inferenceServer{cache: cache, provider: newMockProvider("mock"), apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(`{
		"prompt":"stream this",
		"stream":true
	}`))
	req.Header.Set("X-AstraCDN-API-Key", "secret")
	rec := httptest.NewRecorder()
	app.inferHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"event: token\n",
		`"token":"mock"`,
		`"token":"stream"`,
		`"token":"this"`,
		"event: done\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream body missing %q:\n%s", want, body)
		}
	}
	if cache.sets != 0 {
		t.Fatalf("streaming should not populate prompt cache, sets=%d", cache.sets)
	}
}

func TestInferHandlerRejectsInvalidRequests(t *testing.T) {
	app := &inferenceServer{}

	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "missing prompt", body: `{}`, want: http.StatusBadRequest},
		{name: "invalid json", body: `{`, want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(tt.body))
			app.inferHandler(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestPromptCacheKeyIsStableForEquivalentParams(t *testing.T) {
	first, err := promptCacheKey(inferRequest{
		Prompt: "hello",
		Params: map[string]any{
			"temperature": 0.2,
			"max_tokens":  32,
		},
	}, "mock", "mock")
	if err != nil {
		t.Fatal(err)
	}
	second, err := promptCacheKey(inferRequest{
		Prompt: "hello",
		Params: map[string]any{
			"max_tokens":  32,
			"temperature": 0.2,
		},
	}, "mock", "mock")
	if err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Fatalf("cache key should be stable: first=%s second=%s", first, second)
	}
	if !strings.HasPrefix(first, "astracdn:inference-cache:") {
		t.Fatalf("cache key prefix = %q", first)
	}
}

func TestOpenAICompatibleProviderSendsChatCompletionRequest(t *testing.T) {
	var gotAuth string
	var gotPayload map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("path = %q, want /v1/chat/completions", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"content": "provider response",
					},
				},
			},
		})
	}))
	defer upstream.Close()

	provider := newOpenAICompatibleProvider("openai-compatible", upstream.URL+"/v1", "secret", "default-model")
	result, err := provider.Infer(context.Background(), inferRequest{
		Model:  "request-model",
		Prompt: "hello provider",
		Params: map[string]any{
			"temperature": 0.3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPayload["model"] != "request-model" || gotPayload["stream"] != false || gotPayload["temperature"] != 0.3 {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
	messages, ok := gotPayload["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("messages = %#v", gotPayload["messages"])
	}
	if result.Model != "request-model" || result.Response != "provider response" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestOllamaProviderSendsChatRequest(t *testing.T) {
	var gotAuth string
	var gotPayload map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Fatalf("path = %q, want /api/chat", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message": map[string]string{
				"content": "ollama response",
			},
		})
	}))
	defer upstream.Close()

	provider := newOllamaProvider(upstream.URL, "secret", "llama3.2")
	result, err := provider.Infer(context.Background(), inferRequest{
		Prompt: "hello ollama",
		Params: map[string]any{
			"options": map[string]any{
				"temperature": 0.2,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPayload["model"] != "llama3.2" || gotPayload["stream"] != false {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
	messages, ok := gotPayload["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("messages = %#v", gotPayload["messages"])
	}
	if _, ok := gotPayload["options"].(map[string]any); !ok {
		t.Fatalf("options missing from payload: %+v", gotPayload)
	}
	if result.Model != "llama3.2" || result.Response != "ollama response" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestOpenAIResponsesProviderSendsResponsesRequest(t *testing.T) {
	var gotAuth string
	var gotPayload map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path = %q, want /v1/responses", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"output_text": "responses api output",
		})
	}))
	defer upstream.Close()

	provider := newOpenAIResponsesProvider(upstream.URL+"/v1", "secret", "gpt-test", "astra-cdn", "0")
	result, err := provider.Infer(context.Background(), inferRequest{
		Prompt: "hello responses",
		Params: map[string]any{
			"temperature": 0.1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPayload["model"] != "gpt-test" || gotPayload["input"] != "hello responses" || gotPayload["temperature"] != 0.1 {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
	if _, ok := gotPayload["stream"]; ok {
		t.Fatalf("responses payload should omit stream for OCI LiteLLM compatibility: %+v", gotPayload)
	}
	if result.Model != "gpt-test" || result.Response != "responses api output" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestOpenAIResponsesProviderSendsClientHeaders(t *testing.T) {
	var gotClient string
	var gotClientVersion string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClient = r.Header.Get("client")
		gotClientVersion = r.Header.Get("client-version")
		writeJSON(w, http.StatusOK, map[string]any{
			"output_text": "ok",
		})
	}))
	defer upstream.Close()

	provider := newOpenAIResponsesProvider(upstream.URL, "secret", "gpt-test", "astra-cdn", "0")
	if _, err := provider.Infer(context.Background(), inferRequest{Prompt: "hello"}); err != nil {
		t.Fatal(err)
	}
	if gotClient != "astra-cdn" || gotClientVersion != "0" {
		t.Fatalf("client headers = %q/%q, want astra-cdn/0", gotClient, gotClientVersion)
	}
}

func TestParseOpenAIResponseContentFallsBackToOutputItems(t *testing.T) {
	content, err := parseOpenAIResponseContent([]byte(`{
		"output": [
			{
				"content": [
					{"type":"output_text","text":"fallback text"}
				]
			}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if content != "fallback text" {
		t.Fatalf("content = %q, want fallback text", content)
	}
}

func TestParseOpenAIResponseContentFromSSEDataLines(t *testing.T) {
	content, err := parseOpenAIResponseContent([]byte(`data: {"output":[{"type":"message","content":[{"type":"output_text","text":"hey"}]}]}
data: [DONE]
`))
	if err != nil {
		t.Fatal(err)
	}
	if content != "hey" {
		t.Fatalf("content = %q, want hey", content)
	}
}

func TestCosineSimilarity(t *testing.T) {
	if got := cosineSimilarity(mockEmbedding("edge cache"), mockEmbedding("cache edge")); got < 0.99 {
		t.Fatalf("similarity = %f, want near 1", got)
	}
	if got := cosineSimilarity(mockEmbedding("edge cache"), mockEmbedding("unrelated tokens")); got >= 0.8 {
		t.Fatalf("similarity = %f, want lower than 0.8", got)
	}
}

func TestWriteSSE(t *testing.T) {
	var out strings.Builder
	writeSSE(&out, "token", streamEvent{Type: "token", Model: "mock", Token: "hello"})
	got := out.String()
	if !strings.Contains(got, "event: token\n") || !strings.Contains(got, `"token":"hello"`) {
		t.Fatalf("unexpected SSE output: %q", got)
	}
}

type fakePromptCache struct {
	values map[string]inferResponse
	sets   int
}

func newFakePromptCache() *fakePromptCache {
	return &fakePromptCache{values: make(map[string]inferResponse)}
}

func (c *fakePromptCache) get(_ context.Context, key string) (inferResponse, bool) {
	response, ok := c.values[key]
	return response, ok
}

func (c *fakePromptCache) set(_ context.Context, key string, response inferResponse, _ time.Duration) {
	c.sets++
	c.values[key] = response
}

func (c *fakePromptCache) ready(_ context.Context) error {
	return nil
}

func (c *fakePromptCache) close() {}

func BenchmarkInferHandlerExactCacheHit(b *testing.B) {
	cache := newFakePromptCache()
	app := &inferenceServer{
		cache:    cache,
		provider: newMockProvider("mock"),
		metrics:  newInferenceMetrics(),
	}
	body := `{"prompt":"benchmark prompt","params":{"temperature":0.1,"max_tokens":16}}`

	warm := httptest.NewRecorder()
	app.inferHandler(warm, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(body)))
	if warm.Code != http.StatusOK {
		b.Fatalf("warm status = %d body=%s", warm.Code, warm.Body.String())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		app.inferHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/infer", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"cache_hit":"exact"`) {
			b.Fatalf("expected exact cache hit, got %s", rec.Body.String())
		}
	}
}
