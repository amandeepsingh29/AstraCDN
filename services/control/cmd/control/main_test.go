package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRegisterHandlerRejectsMissingRequiredFields(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/register", strings.NewReader(`{"node_id":"edge-1"}`))
	rec := httptest.NewRecorder()
	app.registerHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRegisterHandlerRejectsOversizedBody(t *testing.T) {
	t.Setenv("HTTP_MAX_REQUEST_BODY_BYTES", "10")
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/register", strings.NewReader(`{"node_id":"edge-1","address":"http://edge:8080"}`))
	rec := httptest.NewRecorder()
	app.registerHandler(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestObservabilityMiddlewareAddsRequestID(t *testing.T) {
	handler := observabilityMiddleware("control", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != "req-control-1" {
			t.Fatalf("request id in context = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "req-control-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-control-1" {
		t.Fatalf("response request id = %q", got)
	}
}

func TestCORSMiddlewareHandlesAllowedPreflight(t *testing.T) {
	t.Setenv("CORS_ENABLED", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://dashboard.example")

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("preflight should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/edge/register", nil)
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
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-AstraCDN-API-Key") {
		t.Fatalf("allow headers = %q, want API key header", got)
	}
}

func TestReadyHandlerRejectsMissingDependencies(t *testing.T) {
	app := &server{}

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

func TestMetricsHandlerReportsRateLimitBlocks(t *testing.T) {
	app := &server{metrics: newControlMetrics()}
	app.recordRateLimitBlock()
	app.recordInvalidation("keys")
	app.recordInvalidationFailure()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	app.metricsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "astracdn_control_rate_limit_blocks_total 1") {
		t.Fatalf("rate limit metric missing:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `astracdn_control_cache_invalidations_total{mode="keys"} 1`) {
		t.Fatalf("invalidation metric missing:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "astracdn_control_cache_invalidation_failures_total 1") {
		t.Fatalf("invalidation failure metric missing:\n%s", rec.Body.String())
	}
}

func TestRegisterHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &server{apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/register", strings.NewReader(`{
		"node_id":"edge-1",
		"address":"http://edge:8080"
	}`))
	rec := httptest.NewRecorder()
	app.registerHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRegisterHandlerPersistsNode(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO edge_nodes").
		WithArgs("edge-1", "http://edge:8080", `["cache","proxy"]`).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id",
			"address",
			"capabilities",
			"status",
			"last_seen_at",
			"created_at",
			"updated_at",
		}).AddRow(
			"edge-1",
			"http://edge:8080",
			[]byte(`["cache","proxy"]`),
			"active",
			now,
			now,
			now,
		))

	app := &server{db: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/edge/register", strings.NewReader(`{
		"node_id":"edge-1",
		"address":"http://edge:8080",
		"capabilities":["cache","proxy"]
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.apiKey = "secret"
	app.registerHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status string   `json:"status"`
		Node   edgeNode `json:"node"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Node.NodeID != "edge-1" || len(body.Node.Capabilities) != 2 {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestListEdgeNodesHandlerReturnsNodes(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT node_id, address, capabilities, status, last_seen_at, created_at, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id",
			"address",
			"capabilities",
			"status",
			"last_seen_at",
			"created_at",
			"updated_at",
		}).AddRow(
			"edge-1",
			"http://edge:8080",
			[]byte(`["cache"]`),
			"active",
			now,
			now,
			now,
		))

	app := &server{db: db}
	req := httptest.NewRequest(http.MethodGet, "/v1/edge/nodes", nil)
	rec := httptest.NewRecorder()
	app.listEdgeNodesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Nodes []edgeNode `json:"nodes"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Nodes) != 1 || body.Nodes[0].NodeID != "edge-1" {
		t.Fatalf("unexpected nodes: %+v", body.Nodes)
	}
}

func TestEdgeHealthHandlerReturnsLatestHealth(t *testing.T) {
	t.Setenv("EDGE_HEALTH_STALE_AFTER", "2m")
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	lastSeen := now.Add(-30 * time.Second)
	observed := now.Add(-10 * time.Second)
	fill := `{"count":2,"sum_seconds":0.6,"avg_seconds":0.3,"max_seconds":0.4}`
	mock.ExpectQuery("SELECT n.node_id, n.address, n.capabilities, n.status, n.last_seen_at, n.created_at, n.updated_at,").
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id",
			"address",
			"capabilities",
			"status",
			"last_seen_at",
			"created_at",
			"updated_at",
			"observed_at",
			"cache_fill_latency",
		}).AddRow(
			"edge-1",
			"http://edge:8080",
			[]byte(`["cache","proxy"]`),
			"active",
			lastSeen,
			now,
			now,
			observed,
			[]byte(fill),
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/edge/health", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.edgeHealthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Edges []edgeHealth `json:"edges"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Edges) != 1 || !body.Edges[0].Healthy || body.Edges[0].CacheFillLatency.Count != 2 {
		t.Fatalf("unexpected edge health: %+v", body.Edges)
	}
}

func TestOriginHandlerRejectsInvalidOrigin(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/origins", strings.NewReader(`{
		"name":"primary",
		"base_url":"ftp://origin.example"
	}`))
	rec := httptest.NewRecorder()
	app.originsHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestOriginHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &server{apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/origins", strings.NewReader(`{
		"name":"primary",
		"base_url":"https://origin.example"
	}`))
	rec := httptest.NewRecorder()
	app.originsHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestOriginHandlerPersistsOrigin(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cdn_origins").
		WithArgs("primary", "https://origin.example", `{"X-Origin-Auth":"secret"}`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"base_url",
			"headers",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(7),
			"primary",
			"https://origin.example",
			[]byte(`{"X-Origin-Auth":"secret"}`),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/origins", strings.NewReader(`{
		"name":"primary",
		"base_url":"https://origin.example",
		"headers":{"X-Origin-Auth":"secret"}
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.originsHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status string    `json:"status"`
		Origin cdnOrigin `json:"origin"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Origin.ID != 7 || body.Origin.Name != "primary" {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.Origin.Headers["X-Origin-Auth"] != "secret" {
		t.Fatalf("unexpected headers: %+v", body.Origin.Headers)
	}
}

func TestOriginHandlerListsOrigins(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, name, base_url, headers, status, created_at, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"base_url",
			"headers",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(7),
			"primary",
			"https://origin.example",
			[]byte(`{}`),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/origins", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.originsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Origins []cdnOrigin `json:"origins"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Origins) != 1 || body.Origins[0].Name != "primary" {
		t.Fatalf("unexpected origins: %+v", body.Origins)
	}
}

func TestRouteHandlerRejectsInvalidRoute(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"https://cdn.example",
		"path_prefix":"assets",
		"origin_id":0
	}`))
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRouteHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &server{apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"cdn.example",
		"path_prefix":"/assets/",
		"origin_id":7
	}`))
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRouteHandlerRejectsInvalidCachePolicy(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"cdn.example",
		"path_prefix":"/assets/",
		"origin_id":7,
		"cache_policy":{"mode":"override","ttl_seconds":0}
	}`))
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRouteHandlerPersistsRoute(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("WITH upserted AS").
		WithArgs(
			"cdn.example",
			"/assets/",
			int64(7),
			"override",
			sql.NullInt64{Int64: 300, Valid: true},
			sql.NullInt64{Int64: 60, Valid: true},
			[]byte("{}"),
			[]byte("{}"),
			[]byte("[]"),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"path_prefix",
			"origin_id",
			"origin_name",
			"origin_base_url",
			"cache_mode",
			"cache_ttl_seconds",
			"stale_while_revalidate_seconds",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(11),
			"cdn.example",
			"/assets/",
			int64(7),
			"primary",
			"https://origin.example",
			"override",
			int64(300),
			int64(60),
			[]byte("{}"),
			[]byte("{}"),
			[]byte("[]"),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"CDN.EXAMPLE.",
		"path_prefix":"/assets/",
		"origin_id":7,
		"cache_policy":{
			"mode":"override",
			"ttl_seconds":300,
			"stale_while_revalidate_seconds":60
		}
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status string   `json:"status"`
		Route  cdnRoute `json:"route"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Route.ID != 11 || body.Route.Host != "cdn.example" {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.Route.CacheTTLSeconds == nil || *body.Route.CacheTTLSeconds != 300 {
		t.Fatalf("unexpected ttl: %+v", body.Route.CacheTTLSeconds)
	}
	if body.Route.CachePolicy.Mode != "override" || body.Route.CachePolicy.TTLSeconds == nil || *body.Route.CachePolicy.TTLSeconds != 300 {
		t.Fatalf("unexpected cache policy: %+v", body.Route.CachePolicy)
	}
	if body.Route.CachePolicy.StaleWhileRevalidateSeconds == nil || *body.Route.CachePolicy.StaleWhileRevalidateSeconds != 60 {
		t.Fatalf("unexpected stale policy: %+v", body.Route.CachePolicy)
	}
	if body.Route.OriginName != "primary" || body.Route.OriginBaseURL != "https://origin.example" {
		t.Fatalf("unexpected origin fields: %+v", body.Route)
	}
}

func TestRouteHandlerPersistsDeliveryRules(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	rawRules := []byte(`{"set_headers":[{"path_prefix":"/edge/assets/","name":"X-Astracdn-Control-Rule","value":"yes"}],"remove_headers":[{"path_prefix":"*","name":"Server"}],"redirects":[{"path_prefix":"/edge/old","target":"https://cdn.example/new{path}","status":308}]}`)
	mock.ExpectQuery("WITH upserted AS").
		WithArgs(
			"cdn.example",
			"/assets/",
			int64(7),
			"origin",
			sql.NullInt64{},
			sql.NullInt64{},
			rawRules,
			[]byte("{}"),
			[]byte("[]"),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"path_prefix",
			"origin_id",
			"origin_name",
			"origin_base_url",
			"cache_mode",
			"cache_ttl_seconds",
			"stale_while_revalidate_seconds",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(11),
			"cdn.example",
			"/assets/",
			int64(7),
			"primary",
			"https://origin.example",
			"origin",
			nil,
			nil,
			rawRules,
			[]byte("{}"),
			[]byte("[]"),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"cdn.example",
		"path_prefix":"/assets/",
		"origin_id":7,
		"delivery_rules":{
			"set_headers":[{"path_prefix":"/edge/assets/","name":"x-astracdn-control-rule","value":"yes"}],
			"remove_headers":[{"name":"server"}],
			"redirects":[{"path_prefix":"/edge/old","target":"https://cdn.example/new{path}","status":308}]
		}
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Route cdnRoute `json:"route"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Route.DeliveryRules.SetHeaders) != 1 || body.Route.DeliveryRules.SetHeaders[0].Name != "X-Astracdn-Control-Rule" {
		t.Fatalf("unexpected set headers: %+v", body.Route.DeliveryRules.SetHeaders)
	}
	if len(body.Route.DeliveryRules.RemoveHeaders) != 1 || body.Route.DeliveryRules.RemoveHeaders[0].PathPrefix != "*" {
		t.Fatalf("unexpected remove headers: %+v", body.Route.DeliveryRules.RemoveHeaders)
	}
	if len(body.Route.DeliveryRules.Redirects) != 1 || body.Route.DeliveryRules.Redirects[0].Status != http.StatusPermanentRedirect {
		t.Fatalf("unexpected redirects: %+v", body.Route.DeliveryRules.Redirects)
	}
}

func TestRouteHandlerPersistsWAFRules(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	rawWAFRules := []byte(`{"enabled":true,"methods":["POST"],"path_prefixes":["/edge/admin/"],"headers":[{"name":"User-Agent","value_contains":"badbot"}],"ips":["198.51.100.0/24"]}`)
	mock.ExpectQuery("WITH upserted AS").
		WithArgs(
			"cdn.example",
			"/admin/",
			int64(7),
			"origin",
			sql.NullInt64{},
			sql.NullInt64{},
			[]byte("{}"),
			rawWAFRules,
			[]byte("[]"),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"path_prefix",
			"origin_id",
			"origin_name",
			"origin_base_url",
			"cache_mode",
			"cache_ttl_seconds",
			"stale_while_revalidate_seconds",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(12),
			"cdn.example",
			"/admin/",
			int64(7),
			"primary",
			"https://origin.example",
			"origin",
			nil,
			nil,
			[]byte("{}"),
			rawWAFRules,
			[]byte("[]"),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"cdn.example",
		"path_prefix":"/admin/",
		"origin_id":7,
		"waf_rules":{
			"enabled":true,
			"methods":["post"],
			"path_prefixes":["/edge/admin/"],
			"headers":[{"name":"user-agent","value_contains":"BadBot"}],
			"ips":["198.51.100.0/24"]
		}
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Route cdnRoute `json:"route"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Route.WAFRules.Enabled == nil || !*body.Route.WAFRules.Enabled {
		t.Fatalf("unexpected waf enabled: %+v", body.Route.WAFRules.Enabled)
	}
	if len(body.Route.WAFRules.Methods) != 1 || body.Route.WAFRules.Methods[0] != "POST" {
		t.Fatalf("unexpected waf methods: %+v", body.Route.WAFRules.Methods)
	}
	if len(body.Route.WAFRules.Headers) != 1 || body.Route.WAFRules.Headers[0].ValueContains != "badbot" {
		t.Fatalf("unexpected waf headers: %+v", body.Route.WAFRules.Headers)
	}
}

func TestRouteHandlerPersistsRateLimitRules(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	rawRateLimitRules := []byte(`[{"host":"cdn.example","path_prefix":"/edge/limited/","rps":1.5,"burst":3}]`)
	mock.ExpectQuery("WITH upserted AS").
		WithArgs(
			"cdn.example",
			"/limited/",
			int64(7),
			"origin",
			sql.NullInt64{},
			sql.NullInt64{},
			[]byte("{}"),
			[]byte("{}"),
			rawRateLimitRules,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"path_prefix",
			"origin_id",
			"origin_name",
			"origin_base_url",
			"cache_mode",
			"cache_ttl_seconds",
			"stale_while_revalidate_seconds",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(13),
			"cdn.example",
			"/limited/",
			int64(7),
			"primary",
			"https://origin.example",
			"origin",
			nil,
			nil,
			[]byte("{}"),
			[]byte("{}"),
			rawRateLimitRules,
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{
		"host":"cdn.example",
		"path_prefix":"/limited/",
		"origin_id":7,
		"rate_limit_rules":[{"path_prefix":"/edge/limited/","rps":1.5,"burst":3}]
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Route cdnRoute `json:"route"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Route.RateLimitRules) != 1 {
		t.Fatalf("unexpected rate limit rules: %+v", body.Route.RateLimitRules)
	}
	rule := body.Route.RateLimitRules[0]
	if rule.Host != "cdn.example" || rule.PathPrefix != "/edge/limited/" || rule.RPS != 1.5 || rule.Burst != 3 {
		t.Fatalf("unexpected rate limit rule: %+v", rule)
	}
}

func TestRouteHandlerListsRoutes(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT r.id, r.host, r.path_prefix, r.origin_id, o.name, o.base_url").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"path_prefix",
			"origin_id",
			"origin_name",
			"origin_base_url",
			"cache_mode",
			"cache_ttl_seconds",
			"stale_while_revalidate_seconds",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(11),
			"cdn.example",
			"/assets/",
			int64(7),
			"primary",
			"https://origin.example",
			"origin",
			nil,
			nil,
			[]byte("{}"),
			[]byte("{}"),
			[]byte("[]"),
			"active",
			now,
			now,
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/routes", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.routesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Routes []cdnRoute `json:"routes"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Routes) != 1 || body.Routes[0].Host != "cdn.example" {
		t.Fatalf("unexpected routes: %+v", body.Routes)
	}
	if body.Routes[0].CacheTTLSeconds != nil {
		t.Fatalf("unexpected ttl: %+v", body.Routes[0].CacheTTLSeconds)
	}
	if body.Routes[0].CachePolicy.Mode != "origin" {
		t.Fatalf("unexpected policy: %+v", body.Routes[0].CachePolicy)
	}
}

func TestDomainHandlerRejectsInvalidDomain(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/domains", strings.NewReader(`{
		"host":"https://cdn.example",
		"tls_mode":"managed"
	}`))
	rec := httptest.NewRecorder()
	app.domainsHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDomainHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &server{apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/domains", strings.NewReader(`{
		"host":"cdn.example",
		"tls_mode":"managed"
	}`))
	rec := httptest.NewRecorder()
	app.domainsHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDomainHandlerPersistsDomain(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	routeID := int64(11)
	mock.ExpectQuery("INSERT INTO cdn_domains").
		WithArgs("cdn.example", sql.NullInt64{Int64: routeID, Valid: true}, "managed", domainVerificationTXTName("cdn.example"), domainVerificationTXTValue("cdn.example")).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(17),
			"cdn.example",
			routeID,
			"managed",
			"pending_dns",
			domainVerificationTXTName("cdn.example"),
			domainVerificationTXTValue("cdn.example"),
			nil,
			now,
			now,
		))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/domains", strings.NewReader(`{
		"host":"CDN.EXAMPLE.",
		"route_id":11,
		"tls_mode":"managed"
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.domainsHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status string    `json:"status"`
		Domain cdnDomain `json:"domain"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Domain.ID != 17 || body.Domain.Host != "cdn.example" {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.Domain.RouteID == nil || *body.Domain.RouteID != 11 {
		t.Fatalf("unexpected route id: %+v", body.Domain.RouteID)
	}
	if body.Domain.TLSMode != "managed" {
		t.Fatalf("unexpected tls mode: %q", body.Domain.TLSMode)
	}
	if body.Domain.Status != "pending_dns" {
		t.Fatalf("unexpected status: %q", body.Domain.Status)
	}
	if body.Domain.DNSTXTName == "" || body.Domain.DNSTXTValue == "" {
		t.Fatalf("missing DNS verification fields: %+v", body.Domain)
	}
}

func TestDomainHandlerListsDomains(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(
			int64(17),
			"cdn.example",
			nil,
			"manual",
			"active",
			domainVerificationTXTName("cdn.example"),
			domainVerificationTXTValue("cdn.example"),
			now,
			now,
			now,
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.domainsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Domains []cdnDomain `json:"domains"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Domains) != 1 || body.Domains[0].Host != "cdn.example" {
		t.Fatalf("unexpected domains: %+v", body.Domains)
	}
	if body.Domains[0].RouteID != nil {
		t.Fatalf("unexpected route id: %+v", body.Domains[0].RouteID)
	}
}

func TestDomainVerifyHandlerMarksDomainActiveWhenTXTMatches(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	txtName := domainVerificationTXTName("cdn.example")
	txtValue := domainVerificationTXTValue("cdn.example")
	mock.ExpectQuery("SELECT id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at").
		WithArgs("cdn.example").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(int64(17), "cdn.example", nil, "managed", "pending_dns", txtName, txtValue, nil, now, now))
	mock.ExpectQuery("UPDATE cdn_domains").
		WithArgs("cdn.example").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(int64(17), "cdn.example", nil, "managed", "active", txtName, txtValue, now, now, now))

	app := &server{
		db:     db,
		apiKey: "secret",
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name != txtName {
				t.Fatalf("lookup name = %q, want %q", name, txtName)
			}
			return []string{txtValue}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/domains/verify", strings.NewReader(`{"host":"CDN.EXAMPLE."}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.verifyDomainHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Status string    `json:"status"`
		Domain cdnDomain `json:"domain"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "verified" || body.Domain.Status != "active" || body.Domain.VerifiedAt == nil {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestDomainVerifyHandlerReturnsConflictWhenTXTIsMissing(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	txtName := domainVerificationTXTName("cdn.example")
	txtValue := domainVerificationTXTValue("cdn.example")
	mock.ExpectQuery("SELECT id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at").
		WithArgs("cdn.example").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(int64(17), "cdn.example", nil, "managed", "pending_dns", txtName, txtValue, nil, now, now))
	mock.ExpectQuery("UPDATE cdn_domains").
		WithArgs("cdn.example", "failed").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"route_id",
			"tls_mode",
			"status",
			"dns_txt_name",
			"dns_txt_value",
			"verified_at",
			"created_at",
			"updated_at",
		}).AddRow(int64(17), "cdn.example", nil, "managed", "failed", txtName, txtValue, nil, now, now))

	app := &server{
		db:     db,
		apiKey: "secret",
		lookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"wrong-value"}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/domains/verify", strings.NewReader(`{"host":"cdn.example"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.verifyDomainHandler(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var body struct {
		Status         string            `json:"status"`
		Domain         cdnDomain         `json:"domain"`
		ExpectedRecord map[string]string `json:"expected_record"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "pending_dns" || body.Domain.Status != "failed" || body.ExpectedRecord["value"] != txtValue {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestAPIKeyHandlerCreatesKey(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO api_keys").
		WithArgs(sqlmock.AnyArg(), "deploy", `["control:write","edge:read"]`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"scopes",
			"revoked_at",
			"created_at",
		}).AddRow(int64(7), "deploy", []byte(`["control:write","edge:read"]`), nil, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/api-keys", strings.NewReader(`{
		"name":"deploy",
		"scopes":["edge:read","control:write","edge:read"]
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.apiKeysHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body apiKeyCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "created" || !strings.HasPrefix(body.Key, "ak_") || body.APIKey.ID != 7 {
		t.Fatalf("unexpected response: %+v", body)
	}
	if len(body.APIKey.Scopes) != 2 || body.APIKey.Scopes[0] != "control:write" || body.APIKey.Scopes[1] != "edge:read" {
		t.Fatalf("unexpected scopes: %+v", body.APIKey.Scopes)
	}
}

func TestAPIKeyHandlerListsKeys(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, name, array_to_json\\(scopes\\)::jsonb, revoked_at, created_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"scopes",
			"revoked_at",
			"created_at",
		}).AddRow(int64(7), "deploy", []byte(`["edge:read"]`), nil, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/api-keys", nil)
	req.Header.Set("X-AstraCDN-API-Key", "root")
	rec := httptest.NewRecorder()
	app.apiKeysHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		APIKeys []apiKeyRecord `json:"api_keys"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.APIKeys) != 1 || body.APIKeys[0].Name != "deploy" {
		t.Fatalf("unexpected keys: %+v", body.APIKeys)
	}
}

func TestAPIKeyHandlerRevokesKey(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("UPDATE api_keys").
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"scopes",
			"revoked_at",
			"created_at",
		}).AddRow(int64(7), "deploy", []byte(`["edge:read"]`), now, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/api-keys/revoke", strings.NewReader(`{"id":7}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.revokeAPIKeyHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Status string       `json:"status"`
		APIKey apiKeyRecord `json:"api_key"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "revoked" || body.APIKey.RevokedAt == nil {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestAuthorizeAcceptsPersistedAPIKey(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, name, array_to_json\\(scopes\\)::jsonb, revoked_at, created_at").
		WithArgs(apiKeyHash("persisted-key")).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"scopes",
			"revoked_at",
			"created_at",
		}).AddRow(int64(9), "deploy", []byte(`["control:write"]`), nil, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/origins", nil)
	req.Header.Set("Authorization", "Bearer persisted-key")

	if !app.authorize(req, "control:write") {
		t.Fatal("persisted API key was not authorized")
	}
}

func TestRequireAuthRejectsPersistedAPIKeyWithoutScope(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, name, array_to_json\\(scopes\\)::jsonb, revoked_at, created_at").
		WithArgs(apiKeyHash("read-key")).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"name",
			"scopes",
			"revoked_at",
			"created_at",
		}).AddRow(int64(10), "reader", []byte(`["control:read"]`), nil, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/origins", strings.NewReader(`{"name":"blocked","base_url":"http://example.test"}`))
	req.Header.Set("Authorization", "Bearer read-key")
	rec := httptest.NewRecorder()

	app.upsertOriginHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestAPIKeyHasScopesSupportsWildcardsAndLegacyEmptyScopes(t *testing.T) {
	if !apiKeyHasScopes([]string{"control:*"}, "control:write", "control:read") {
		t.Fatal("control wildcard did not satisfy control scopes")
	}
	if !apiKeyHasScopes([]string{"*"}, "control:admin") {
		t.Fatal("global wildcard did not satisfy admin scope")
	}
	if !apiKeyHasScopes(nil, "control:admin") {
		t.Fatal("legacy empty scopes should preserve access")
	}
	if apiKeyHasScopes([]string{"control:read"}, "control:write") {
		t.Fatal("read scope satisfied write scope")
	}
}

func TestBillingWebhooksHandlerUpdatesAccountByProviderCustomer(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO billing_webhook_events").
		WithArgs("stripe", "evt_123", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectQuery("UPDATE billing_accounts").
		WithArgs("past_due", "team", "stripe", "cus_123").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"tenant_id",
			"provider",
			"provider_customer_id",
			"plan",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(int64(7), int64(42), "stripe", "cus_123", "team", "past_due", now, now))
	mock.ExpectExec("UPDATE billing_webhook_events").
		WithArgs(int64(7), sqlmock.AnyArg(), int64(11)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhooks", strings.NewReader(`{
		"event_id":"evt_123",
		"provider":"stripe",
		"provider_customer_id":"cus_123",
		"plan":"team",
		"status":"past_due"
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.billingWebhooksHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status         string               `json:"status"`
		BillingAccount billingAccountRecord `json:"billing_account"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.BillingAccount.Status != "past_due" || body.BillingAccount.Plan != "team" {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestBillingWebhooksHandlerReturnsDuplicateForReplayedEvent(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO billing_webhook_events").
		WithArgs("stripe", "evt_123", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT ba.id, ba.tenant_id, ba.provider").
		WithArgs("stripe", "evt_123").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"tenant_id",
			"provider",
			"provider_customer_id",
			"plan",
			"status",
			"created_at",
			"updated_at",
		}).AddRow(int64(7), int64(42), "stripe", "cus_123", "team", "past_due", now, now))
	mock.ExpectCommit()

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhooks", strings.NewReader(`{
		"event_id":"evt_123",
		"provider":"stripe",
		"provider_customer_id":"cus_123",
		"status":"past_due"
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.billingWebhooksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Status         string               `json:"status"`
		BillingAccount billingAccountRecord `json:"billing_account"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "duplicate" || body.BillingAccount.Status != "past_due" {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestBillingWebhooksHandlerRequiresValidSignatureWhenConfigured(t *testing.T) {
	t.Setenv("CONTROL_BILLING_WEBHOOK_SECRET", "webhook-secret")
	app := &server{apiKey: "root"}
	body := `{"event_id":"evt_123","provider":"stripe","provider_customer_id":"cus_123","status":"active"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhooks", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.billingWebhooksHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/billing/webhooks", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer root")
	req.Header.Set("X-AstraCDN-Billing-Signature", "sha256=bad")
	rec = httptest.NewRecorder()
	app.billingWebhooksHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestValidBillingWebhookSignature(t *testing.T) {
	body := []byte(`{"event_id":"evt_123"}`)
	secret := "webhook-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !validBillingWebhookSignature(signature, body, secret) {
		t.Fatal("valid signature was rejected")
	}
	if validBillingWebhookSignature(signature, []byte(`{"event_id":"evt_changed"}`), secret) {
		t.Fatal("signature accepted for changed body")
	}
}

func TestBillingWebhooksHandlerRejectsInvalidPayload(t *testing.T) {
	app := &server{apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhooks", strings.NewReader(`{
		"event_id":"evt_bad",
		"provider":"stripe",
		"status":"unknown"
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.billingWebhooksHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestBillingWebhookEventsHandlerListsFilteredEvents(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, provider, event_id, billing_account_id, status, payload, processed_at, created_at").
		WithArgs("stripe", "evt_123", int64(7), 25).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"provider",
			"event_id",
			"billing_account_id",
			"status",
			"payload",
			"processed_at",
			"created_at",
		}).AddRow(
			int64(11),
			"stripe",
			"evt_123",
			int64(7),
			"applied",
			[]byte(`{"event_id":"evt_123","status":"past_due"}`),
			now,
			now,
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/billing/webhook-events?provider=Stripe&event_id=evt_123&billing_account_id=7&limit=25", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.billingWebhookEventsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Events []billingWebhookEventRecord `json:"billing_webhook_events"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 1 || body.Events[0].EventID != "evt_123" || body.Events[0].BillingAccountID == nil || *body.Events[0].BillingAccountID != 7 {
		t.Fatalf("unexpected events: %+v", body.Events)
	}
}

func TestRecordAuditLogPersistsEntry(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	mock.ExpectExec("INSERT INTO control_audit_logs").
		WithArgs(
			"api_key:"+apiKeyHash("secret")[:16],
			"upsert",
			"origin",
			"42",
			"req-audit-1",
			"192.0.2.10",
			`{"name":"assets"}`,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	app := &server{db: db, auditEnabled: true}
	req := httptest.NewRequest(http.MethodPost, "/v1/origins", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDContextKey, "req-audit-1"))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Forwarded-For", "192.0.2.10")

	app.recordAuditLog(req, "upsert", "origin", "42", map[string]any{"name": "assets"})
}

func TestAuditLogsHandlerListsLogs(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, actor, action, resource_type, resource_id, request_id, remote_addr, metadata, created_at").
		WithArgs("upsert", "origin", 25).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"actor",
			"action",
			"resource_type",
			"resource_id",
			"request_id",
			"remote_addr",
			"metadata",
			"created_at",
		}).AddRow(int64(7), "api_key:abc", "upsert", "origin", "42", "req-1", "192.0.2.10", []byte(`{"name":"assets"}`), now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/audit-logs?limit=25&action=upsert&resource_type=origin", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.auditLogsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		AuditLogs []auditLogEntry `json:"audit_logs"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.AuditLogs) != 1 || body.AuditLogs[0].ResourceID != "42" {
		t.Fatalf("unexpected audit logs: %+v", body.AuditLogs)
	}
}

func TestRouteRuleVersionsHandlerListsVersions(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, route_id, version, delivery_rules, waf_rules, rate_limit_rules, changed_by, request_id, created_at").
		WithArgs(int64(11), 25).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"route_id",
			"version",
			"delivery_rules",
			"waf_rules",
			"rate_limit_rules",
			"changed_by",
			"request_id",
			"created_at",
		}).AddRow(
			int64(3),
			int64(11),
			2,
			[]byte(`{"set_headers":[{"path_prefix":"*","name":"X-Version","value":"2"}]}`),
			[]byte(`{}`),
			[]byte(`[{"host":"cdn.example","path_prefix":"/edge/limited/","rps":1,"burst":1}]`),
			"api_key:abc",
			"req-1",
			now,
		))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/route-rule-versions?route_id=11&limit=25", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.routeRuleVersionsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Versions []routeRuleVersion `json:"route_rule_versions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Versions) != 1 || body.Versions[0].Version != 2 || len(body.Versions[0].RateLimitRules) != 1 {
		t.Fatalf("unexpected versions: %+v", body.Versions)
	}
}

func TestCacheAnalyticsSnapshotsHandlerPersistsSnapshot(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	observed := now.Add(-time.Minute)
	byLayer := `{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}`
	byHost := `{"cdn.example":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	byRoute := `{"cdn.example:/assets":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	fill := `{"count":3,"sum_seconds":0.9,"avg_seconds":0.3,"max_seconds":0.5}`
	mock.ExpectQuery("INSERT INTO cache_analytics_snapshots").
		WithArgs("edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, byLayer, byHost, byRoute, fill, observed).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"edge_node_id",
			"host",
			"requests",
			"hits",
			"misses",
			"hit_ratio",
			"by_layer",
			"by_host",
			"by_route",
			"cache_fill_latency",
			"observed_at",
			"created_at",
		}).AddRow(int64(9), "edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, []byte(byLayer), []byte(byHost), []byte(byRoute), []byte(fill), observed, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/cache-snapshots", strings.NewReader(`{
		"edge_node_id":"edge-1",
		"host":"CDN.Example.",
		"observed_at":"`+observed.Format(time.RFC3339Nano)+`",
		"cache":{
			"requests":10,
			"hits":7,
			"misses":3,
			"hit_ratio":0.7,
			"by_layer":{
				"memory":{"result":"hit","requests":7},
				"origin":{"result":"miss","requests":3}
			},
			"by_host":{
				"cdn.example":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"by_route":{
				"cdn.example:/assets":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"cache_fill_latency":{
				"count":3,
				"sum_seconds":0.9,
				"avg_seconds":0.3,
				"max_seconds":0.5
			}
		}
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.cacheAnalyticsSnapshotsHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status   string                 `json:"status"`
		Snapshot cacheAnalyticsSnapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Snapshot.ID != 9 || body.Snapshot.Cache.Requests != 10 {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestCacheAnalyticsSnapshotsHandlerExportsOTLP(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	observed := now.Add(-time.Minute)
	byLayer := `{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}`
	byHost := `{"cdn.example":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	byRoute := `{"cdn.example:/assets":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	fill := `{"count":3,"sum_seconds":0.9,"avg_seconds":0.3,"max_seconds":0.5}`
	mock.ExpectQuery("INSERT INTO cache_analytics_snapshots").
		WithArgs("edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, byLayer, byHost, byRoute, fill, observed).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"edge_node_id",
			"host",
			"requests",
			"hits",
			"misses",
			"hit_ratio",
			"by_layer",
			"by_host",
			"by_route",
			"cache_fill_latency",
			"observed_at",
			"created_at",
		}).AddRow(int64(9), "edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, []byte(byLayer), []byte(byHost), []byte(byRoute), []byte(fill), observed, now))

	var exported map[string]any
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("X-OTLP-Test"); got != "enabled" {
			t.Errorf("X-OTLP-Test = %q, want enabled", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&exported); err != nil {
			t.Errorf("decode otlp payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()

	app := &server{
		db:     db,
		apiKey: "root",
		otlpExporter: &cacheAnalyticsOTLPExporter{
			endpoint: collector.URL,
			headers:  map[string]string{"X-OTLP-Test": "enabled"},
			timeout:  time.Second,
			client:   collector.Client(),
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/cache-snapshots", strings.NewReader(`{
		"edge_node_id":"edge-1",
		"host":"cdn.example",
		"observed_at":"`+observed.Format(time.RFC3339Nano)+`",
		"cache":{
			"requests":10,
			"hits":7,
			"misses":3,
			"hit_ratio":0.7,
			"by_layer":{
				"memory":{"result":"hit","requests":7},
				"origin":{"result":"miss","requests":3}
			},
			"by_host":{
				"cdn.example":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"by_route":{
				"cdn.example:/assets":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"cache_fill_latency":{
				"count":3,
				"sum_seconds":0.9,
				"avg_seconds":0.3,
				"max_seconds":0.5
			}
		}
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.cacheAnalyticsSnapshotsHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if len(exported) == 0 {
		t.Fatal("collector did not receive OTLP payload")
	}
	raw, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`astracdn.control.cache_snapshot.requests`,
		`astracdn.control.cache_snapshot.layer.requests`,
		`astracdn.control.cache_snapshot.dimension.requests`,
		`astracdn.control.cache_snapshot.cache_fill_latency.max`,
		`astra-cdn-control`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("OTLP payload missing %q in %s", want, body)
		}
	}
}

func TestCacheAnalyticsSnapshotsHandlerExportsWarehouseJSONL(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	observed := now.Add(-time.Minute)
	exportedAt := now.Add(time.Minute)
	byLayer := `{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}`
	byHost := `{"cdn.example":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	byRoute := `{"cdn.example:/assets":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	fill := `{"count":3,"sum_seconds":0.9,"avg_seconds":0.3,"max_seconds":0.5}`
	mock.ExpectQuery("INSERT INTO cache_analytics_snapshots").
		WithArgs("edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, byLayer, byHost, byRoute, fill, observed).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"edge_node_id",
			"host",
			"requests",
			"hits",
			"misses",
			"hit_ratio",
			"by_layer",
			"by_host",
			"by_route",
			"cache_fill_latency",
			"observed_at",
			"created_at",
		}).AddRow(int64(9), "edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, []byte(byLayer), []byte(byHost), []byte(byRoute), []byte(fill), observed, now))

	path := filepath.Join(t.TempDir(), "warehouse", "cache-analytics.jsonl")
	app := &server{
		db:     db,
		apiKey: "root",
		warehouseSink: &cacheAnalyticsWarehouseSink{
			path: path,
			now:  func() time.Time { return exportedAt },
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/cache-snapshots", strings.NewReader(`{
		"edge_node_id":"edge-1",
		"host":"cdn.example",
		"observed_at":"`+observed.Format(time.RFC3339Nano)+`",
		"cache":{
			"requests":10,
			"hits":7,
			"misses":3,
			"hit_ratio":0.7,
			"by_layer":{
				"memory":{"result":"hit","requests":7},
				"origin":{"result":"miss","requests":3}
			},
			"by_host":{
				"cdn.example":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"by_route":{
				"cdn.example:/assets":{
					"requests":10,
					"hits":7,
					"misses":3,
					"hit_ratio":0.7,
					"by_layer":{
						"memory":{"result":"hit","requests":7},
						"origin":{"result":"miss","requests":3}
					}
				}
			},
			"cache_fill_latency":{
				"count":3,
				"sum_seconds":0.9,
				"avg_seconds":0.3,
				"max_seconds":0.5
			}
		}
	}`))
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.cacheAnalyticsSnapshotsHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("warehouse lines = %d, want 1 content=%s", len(lines), string(content))
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`cache_analytics_snapshot`,
		`edge-1`,
		`cdn.example`,
		`cache_fill_latency`,
		`"requests":10`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("warehouse record missing %q in %s", want, body)
		}
	}
}

func TestCacheAnalyticsSnapshotsHandlerRejectsInvalidSnapshot(t *testing.T) {
	app := &server{}
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/cache-snapshots", strings.NewReader(`{
		"cache":{"requests":10,"hits":9,"misses":3,"hit_ratio":0.9,"by_layer":{}}
	}`))
	rec := httptest.NewRecorder()
	app.cacheAnalyticsSnapshotsHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCacheAnalyticsSnapshotsHandlerListsSnapshots(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	byLayer := `{"origin":{"result":"miss","requests":1}}`
	mock.ExpectQuery("SELECT id, edge_node_id, host, requests, hits, misses, hit_ratio, by_layer, by_host, by_route, cache_fill_latency, observed_at, created_at").
		WithArgs(25).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"edge_node_id",
			"host",
			"requests",
			"hits",
			"misses",
			"hit_ratio",
			"by_layer",
			"by_host",
			"by_route",
			"cache_fill_latency",
			"observed_at",
			"created_at",
		}).AddRow(int64(9), "edge-1", "cdn.example", int64(1), int64(0), int64(1), 0.0, []byte(byLayer), []byte(`{}`), []byte(`{}`), []byte(`{}`), now, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/analytics/cache-snapshots?limit=25", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.cacheAnalyticsSnapshotsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Snapshots []cacheAnalyticsSnapshot `json:"snapshots"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Snapshots) != 1 || body.Snapshots[0].Host != "cdn.example" {
		t.Fatalf("unexpected snapshots: %+v", body.Snapshots)
	}
}

func TestCacheAnalyticsPrometheusHandlerExportsSnapshots(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Unix(1710000000, 0).UTC()
	byLayer := `{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}`
	byHost := `{"cdn.example":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	byRoute := `{"cdn.example:fallback:/":{"requests":10,"hits":7,"misses":3,"hit_ratio":0.7,"by_layer":{"memory":{"result":"hit","requests":7},"origin":{"result":"miss","requests":3}}}}`
	fill := `{"count":3,"sum_seconds":0.9,"avg_seconds":0.3,"max_seconds":0.5}`
	mock.ExpectQuery("SELECT id, edge_node_id, host, requests, hits, misses, hit_ratio, by_layer, by_host, by_route, cache_fill_latency, observed_at, created_at").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"edge_node_id",
			"host",
			"requests",
			"hits",
			"misses",
			"hit_ratio",
			"by_layer",
			"by_host",
			"by_route",
			"cache_fill_latency",
			"observed_at",
			"created_at",
		}).AddRow(int64(9), "edge-1", "cdn.example", int64(10), int64(7), int64(3), 0.7, []byte(byLayer), []byte(byHost), []byte(byRoute), []byte(fill), now, now))

	app := &server{db: db, apiKey: "root"}
	req := httptest.NewRequest(http.MethodGet, "/v1/analytics/cache-snapshots/prometheus?limit=1", nil)
	req.Header.Set("Authorization", "Bearer root")
	rec := httptest.NewRecorder()
	app.cacheAnalyticsPrometheusHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("content type = %q, want text/plain", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`astracdn_control_cache_snapshot_requests{snapshot_id="9",edge_node_id="edge-1",host="cdn.example"} 10`,
		`astracdn_control_cache_snapshot_layer_requests{snapshot_id="9",edge_node_id="edge-1",host="cdn.example",layer="memory",result="hit"} 7`,
		`astracdn_control_cache_snapshot_dimension_requests{snapshot_id="9",edge_node_id="edge-1",host="cdn.example",dimension_type="host",dimension="cdn.example",result="hit"} 7`,
		`astracdn_control_cache_snapshot_cache_fill_latency_seconds{snapshot_id="9",edge_node_id="edge-1",host="cdn.example",stat="max"} 0.500000`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("prometheus export missing %q in:\n%s", want, body)
		}
	}
}

func TestCacheInvalidationHandlerRejectsAmbiguousRequest(t *testing.T) {
	app := &server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/a.js"],
		"prefixes":["/edge/"]
	}`))
	rec := httptest.NewRecorder()
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCacheInvalidationHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	app := &server{apiKey: "secret"}

	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/a.js"]
	}`))
	rec := httptest.NewRecorder()
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestCachePrewarmHandlerPersistsJob(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cache_prewarm_jobs").
		WithArgs("cdn.example", `["/edge/assets/app.js","/edge/assets/app.css"]`, "test").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"paths",
			"requested_by",
			"status",
			"created_at",
		}).AddRow(int64(55), "cdn.example", []byte(`["/edge/assets/app.js","/edge/assets/app.css"]`), "test", "pending", now))

	app := &server{db: db, apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/prewarm", strings.NewReader(`{
		"host":"CDN.Example.",
		"paths":["/edge/assets/app.js","/edge/assets/app.css","/not-edge","/edge/assets/app.js"],
		"requested_by":"test"
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.cachePrewarmHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status  string          `json:"status"`
		Prewarm cachePrewarmJob `json:"prewarm"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Prewarm.ID != 55 || len(body.Prewarm.Paths) != 2 {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestCachePrewarmHandlerRejectsInvalidPaths(t *testing.T) {
	app := &server{}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/prewarm", strings.NewReader(`{
		"paths":["/assets/app.js"]
	}`))
	rec := httptest.NewRecorder()
	app.cachePrewarmHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCacheInvalidationHandlerRateLimitsRequests(t *testing.T) {
	app := &server{
		apiKey:  "secret",
		limiter: newRateLimiter(true, 0.001, 1),
		metrics: newControlMetrics(),
	}

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/a.js"],
		"prefixes":["/edge/"]
	}`))
	firstReq.Header.Set("Authorization", "Bearer secret")
	first := httptest.NewRecorder()
	app.cacheInvalidationHandler(first, firstReq)
	if first.Code != http.StatusBadRequest {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusBadRequest)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/a.js"]
	}`))
	secondReq.Header.Set("Authorization", "Bearer secret")
	second := httptest.NewRecorder()
	app.cacheInvalidationHandler(second, secondReq)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	if got := app.rateLimitBlocksSnapshot(); got != 1 {
		t.Fatalf("rate limited metric = %d, want 1", got)
	}
}

func TestRateLimiterSeparatesAPIKeys(t *testing.T) {
	limiter := newRateLimiter(true, 0.001, 1)

	first := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", nil)
	first.Header.Set("X-AstraCDN-API-Key", "key-a")
	if !limiter.allow(first) {
		t.Fatal("first API key should be allowed")
	}
	if limiter.allow(first) {
		t.Fatal("first API key should exceed burst")
	}

	second := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", nil)
	second.Header.Set("X-AstraCDN-API-Key", "key-b")
	if !limiter.allow(second) {
		t.Fatal("second API key should have an independent bucket")
	}
}

func TestValidateSecureConfigRejectsProductionDefaults(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "production")
	t.Setenv("ASTRACDN_API_KEY", "astracdn-local-dev-key")
	t.Setenv("POSTGRES_PASSWORD", "not-default")
	t.Setenv("RATE_LIMIT_ENABLED", "true")

	if err := validateSecureConfig(); err == nil {
		t.Fatal("expected default API key to be rejected")
	}
}

func TestValidateSecureConfigAcceptsProductionOverrides(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "production")
	t.Setenv("ASTRACDN_API_KEY", "production-api-key")
	t.Setenv("POSTGRES_PASSWORD", "production-db-password")
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("CONTROL_BILLING_WEBHOOK_SECRET", "production-webhook-secret")

	if err := validateSecureConfig(); err != nil {
		t.Fatalf("secure config rejected production overrides: %v", err)
	}
}

func TestCacheInvalidationHandlerPersistsAndAcknowledges(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cache_invalidations").
		WithArgs("", "keys", `["/edge/assets/app.js?v=1"]`, "test").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"mode",
			"values",
			"requested_by",
			"status",
			"created_at",
		}).AddRow(
			int64(42),
			"",
			"keys",
			[]byte(`["/edge/assets/app.js?v=1"]`),
			"test",
			"pending",
			now,
		))

	app := &server{db: db, metrics: newControlMetrics()}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/assets/app.js?v=1"],
		"requested_by":"test"
	}`))
	req.Header.Set("X-AstraCDN-API-Key", "secret")
	rec := httptest.NewRecorder()
	app.apiKey = "secret"
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Status       string            `json:"status"`
		Invalidation cacheInvalidation `json:"invalidation"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Invalidation.ID != 42 || body.Invalidation.Mode != "keys" {
		t.Fatalf("unexpected response: %+v", body)
	}
	if len(body.Invalidation.Values) != 1 || body.Invalidation.Values[0] != "/edge/assets/app.js?v=1" {
		t.Fatalf("unexpected invalidation values: %+v", body.Invalidation.Values)
	}
	invalidations, failures := app.invalidationMetricsSnapshot()
	if invalidations["keys"] != 1 || failures != 0 {
		t.Fatalf("invalidation metrics = %+v failures=%d, want keys=1 failures=0", invalidations, failures)
	}
}

func TestCacheInvalidationHandlerPersistsHostScopedInvalidation(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cache_invalidations").
		WithArgs("cdn-a.example", "prefixes", `["/edge/assets/"]`, "test").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"mode",
			"values",
			"requested_by",
			"status",
			"created_at",
		}).AddRow(
			int64(43),
			"cdn-a.example",
			"prefixes",
			[]byte(`["/edge/assets/"]`),
			"test",
			"pending",
			now,
		))

	app := &server{db: db, metrics: newControlMetrics(), apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"host":"CDN-A.Example.",
		"prefixes":["/edge/assets/"],
		"requested_by":"test"
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Invalidation cacheInvalidation `json:"invalidation"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Invalidation.Host != "cdn-a.example" {
		t.Fatalf("host = %q, want cdn-a.example", body.Invalidation.Host)
	}
	if body.Invalidation.Mode != "prefixes" {
		t.Fatalf("mode = %q, want prefixes", body.Invalidation.Mode)
	}
}

func TestCacheInvalidationHandlerPersistsSurrogateTags(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cache_invalidations").
		WithArgs("cdn-a.example", "tags", `["release-2026","product:hero"]`, "deploy").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"host",
			"mode",
			"values",
			"requested_by",
			"status",
			"created_at",
		}).AddRow(
			int64(44),
			"cdn-a.example",
			"tags",
			[]byte(`["release-2026","product:hero"]`),
			"deploy",
			"pending",
			now,
		))

	app := &server{db: db, metrics: newControlMetrics(), apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"host":"CDN-A.Example.",
		"tags":["release-2026","product:hero","release-2026","bad tag"],
		"requested_by":"deploy"
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Invalidation cacheInvalidation `json:"invalidation"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Invalidation.Mode != "tags" {
		t.Fatalf("mode = %q, want tags", body.Invalidation.Mode)
	}
	if got, want := strings.Join(body.Invalidation.Values, ","), "release-2026,product:hero"; got != want {
		t.Fatalf("values = %q, want %q", got, want)
	}
}

func TestCacheInvalidationHandlerRejectsAmbiguousTags(t *testing.T) {
	app := &server{metrics: newControlMetrics(), apiKey: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidate", strings.NewReader(`{
		"keys":["/edge/app.js"],
		"tags":["release-2026"]
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.cacheInvalidationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCacheInvalidationDeliveryHandlerPersistsDelivery(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO cache_invalidation_deliveries").
		WithArgs(int64(42), "edge-1", "applied", "").
		WillReturnRows(sqlmock.NewRows([]string{
			"invalidation_id",
			"node_id",
			"status",
			"error",
			"delivered_at",
		}).AddRow(
			int64(42),
			"edge-1",
			"applied",
			"",
			now,
		))

	app := &server{db: db, apiKey: "secret", metrics: newControlMetrics()}
	req := httptest.NewRequest(http.MethodPost, "/v1/cache/invalidation-deliveries", strings.NewReader(`{
		"invalidation_id":42,
		"node_id":"edge-1",
		"status":"applied"
	}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.cacheInvalidationDeliveriesHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var body struct {
		Delivery cacheInvalidationDelivery `json:"delivery"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Delivery.InvalidationID != 42 || body.Delivery.NodeID != "edge-1" || body.Delivery.Status != "applied" {
		t.Fatalf("unexpected delivery: %+v", body.Delivery)
	}
}

func TestCacheInvalidationDeliveryHandlerListsDeliveries(t *testing.T) {
	db, mock, closeDB := newMockDB(t)
	defer closeDB()

	now := time.Now().UTC()
	mock.ExpectQuery("SELECT invalidation_id, node_id, status").
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{
			"invalidation_id",
			"node_id",
			"status",
			"error",
			"delivered_at",
		}).AddRow(
			int64(42),
			"edge-1",
			"applied",
			"",
			now,
		))

	app := &server{db: db}
	req := httptest.NewRequest(http.MethodGet, "/v1/cache/invalidation-deliveries?invalidation_id=42", nil)
	rec := httptest.NewRecorder()
	app.cacheInvalidationDeliveriesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Deliveries []cacheInvalidationDelivery `json:"deliveries"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Deliveries) != 1 || body.Deliveries[0].NodeID != "edge-1" {
		t.Fatalf("unexpected deliveries: %+v", body.Deliveries)
	}
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	mock.MatchExpectationsInOrder(false)
	mock.ExpectClose()
	return db, mock, func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}
