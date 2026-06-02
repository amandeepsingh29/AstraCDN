package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyInjectsAPIKeyAndPreservesPath(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotDashboardToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		gotAuth = r.Header.Get("Authorization")
		gotDashboardToken = r.Header.Get("X-AstraCDN-Dashboard-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer upstream.Close()

	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client:         upstream.Client(),
		apiKey:         "secret",
		controlBaseURL: base,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/control/v1/routes?limit=2", nil)
	req.Header.Set("X-AstraCDN-Dashboard-Token", "dashboard-secret")
	rec := httptest.NewRecorder()
	app.proxyHandler("control", app.controlBaseURL, "/api/control")(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotPath != "/v1/routes?limit=2" {
		t.Fatalf("path = %q, want /v1/routes?limit=2", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization = %q, want Bearer secret", gotAuth)
	}
	if gotDashboardToken != "" {
		t.Fatalf("dashboard token leaked upstream: %q", gotDashboardToken)
	}
}

func TestProxyDoesNotOverrideCallerAuth(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client: &http.Client{
			Timeout: time.Second,
		},
		apiKey:         "secret",
		controlBaseURL: base,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/control/v1/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer caller")
	rec := httptest.NewRecorder()
	app.proxyHandler("control", app.controlBaseURL, "/api/control")(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if gotAuth != "Bearer caller" {
		t.Fatalf("authorization = %q, want Bearer caller", gotAuth)
	}
}

func TestRequireDashboardAuth(t *testing.T) {
	app := &dashboardServer{accessToken: "dashboard-secret"}
	handler := app.requireDashboardAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	unauthorized := httptest.NewRecorder()
	handler(unauthorized, httptest.NewRequest(http.MethodGet, "/api/control/v1/routes", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/control/v1/routes", nil)
	req.Header.Set("X-AstraCDN-Dashboard-Token", "dashboard-secret")
	authorized := httptest.NewRecorder()
	handler(authorized, req)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusNoContent)
	}
}

func TestCDNFetchUsesRequestedHostAndPath(t *testing.T) {
	var gotHost string
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.RequestURI()
		w.Header().Set("X-AstraCDN-Cache", "HIT")
		w.Header().Set("X-AstraCDN-Cache-Layer", "memory")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("edge body"))
	}))
	defer upstream.Close()

	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client:      upstream.Client(),
		edgeBaseURL: base,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/cdn/fetch?host=cdn.localhost&path=/edge/demo.txt", nil)
	rec := httptest.NewRecorder()
	app.cdnFetchHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if gotHost != "cdn.localhost" {
		t.Fatalf("host = %q, want cdn.localhost", gotHost)
	}
	if gotPath != "/edge/demo.txt" {
		t.Fatalf("path = %q, want /edge/demo.txt", gotPath)
	}

	var body struct {
		Status      int    `json:"status"`
		Cache       string `json:"cache"`
		CacheLayer  string `json:"cache_layer"`
		BodyPreview string `json:"body_preview"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != http.StatusOK || body.Cache != "HIT" || body.CacheLayer != "memory" || body.BodyPreview != "edge body" {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestCDNFetchRejectsNonEdgePath(t *testing.T) {
	app := &dashboardServer{edgeBaseURL: &url.URL{Scheme: "http", Host: "edge"}}
	req := httptest.NewRequest(http.MethodGet, "/api/cdn/fetch?host=cdn.localhost&path=/not-edge/demo.txt", nil)
	rec := httptest.NewRecorder()
	app.cdnFetchHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAssetUploadWritesFileAndReturnsEdgePath(t *testing.T) {
	dir := t.TempDir()
	app := &dashboardServer{
		assetDir:         dir,
		maxUploadBytes:   1024,
		publicCDNBaseURL: mustTestURL(t, "http://cdn.localhost:8080"),
	}
	body, contentType := multipartUploadBody(t, "folder", "photos/2026", "file", "smoke photo.txt", "dashboard upload")

	req := httptest.NewRequest(http.MethodPost, "/api/assets/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	app.assetUploadHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var response struct {
		Status    string `json:"status"`
		Filename  string `json:"filename"`
		AssetPath string `json:"asset_path"`
		EdgePath  string `json:"edge_path"`
		PublicURL string `json:"public_url"`
		Bytes     int64  `json:"bytes"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "uploaded" || response.Filename != "smoke-photo.txt" || response.AssetPath != "/assets/photos/2026/smoke-photo.txt" || response.EdgePath != "/edge/assets/photos/2026/smoke-photo.txt" || response.PublicURL != "http://cdn.localhost:8080/edge/assets/photos/2026/smoke-photo.txt" || response.Bytes != 16 {
		t.Fatalf("unexpected response: %+v", response)
	}

	got, err := os.ReadFile(filepath.Join(dir, "photos", "2026", "smoke-photo.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "dashboard upload" {
		t.Fatalf("uploaded body = %q, want dashboard upload", got)
	}
}

func TestAssetUploadPurgesSavedEdgePath(t *testing.T) {
	dir := t.TempDir()
	var gotPath string
	var gotAuth string
	var gotBody string
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer control.Close()
	base, err := url.Parse(control.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client:           control.Client(),
		apiKey:           "secret",
		assetDir:         dir,
		maxUploadBytes:   1024,
		controlBaseURL:   base,
		publicCDNBaseURL: mustTestURL(t, "https://cdn.example"),
	}
	body, contentType := multipartUploadBodyWithFields(t, map[string]string{
		"folder": "uploads",
		"host":   "cdn.localhost",
	}, "file", "photo.jpg", "replacement")

	req := httptest.NewRequest(http.MethodPost, "/api/assets/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	app.assetUploadHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if gotPath != "/v1/cache/invalidate" {
		t.Fatalf("purge path = %q, want /v1/cache/invalidate", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("purge authorization = %q, want Bearer secret", gotAuth)
	}
	if !strings.Contains(gotBody, `"/edge/assets/uploads/photo.jpg"`) || !strings.Contains(gotBody, `"host":"cdn.localhost"`) {
		t.Fatalf("unexpected purge body: %s", gotBody)
	}
	if !strings.Contains(rec.Body.String(), `"purge_status":"accepted"`) {
		t.Fatalf("response missing accepted purge status: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"public_url":"https://cdn.example/edge/assets/uploads/photo.jpg"`) {
		t.Fatalf("response missing public URL: %s", rec.Body.String())
	}
}

func TestAssetUploadRejectsTraversal(t *testing.T) {
	app := &dashboardServer{
		assetDir:       t.TempDir(),
		maxUploadBytes: 1024,
	}

	tests := []struct {
		name     string
		folder   string
		filename string
	}{
		{name: "folder traversal", folder: "../outside", filename: "photo.jpg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := multipartUploadBody(t, "folder", tt.folder, "file", tt.filename, "x")
			req := httptest.NewRequest(http.MethodPost, "/api/assets/upload", body)
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			app.assetUploadHandler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestSafeAssetFilenameRejectsTraversal(t *testing.T) {
	for _, raw := range []string{"../photo.jpg", `..\photo.jpg`, "..", "photos/photo.jpg"} {
		t.Run(raw, func(t *testing.T) {
			if got, err := safeAssetFilename(raw); err == nil {
				t.Fatalf("safeAssetFilename(%q) = %q, want error", raw, got)
			}
		})
	}
}

func TestAssetUploadRejectsOverMaxSize(t *testing.T) {
	app := &dashboardServer{
		assetDir:       t.TempDir(),
		maxUploadBytes: 4,
	}
	body, contentType := multipartUploadBody(t, "folder", "uploads", "file", "large.txt", "12345")

	req := httptest.NewRequest(http.MethodPost, "/api/assets/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	app.assetUploadHandler(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(app.assetDir, "uploads", "large.txt")); !os.IsNotExist(err) {
		t.Fatalf("oversized upload was written, stat err=%v", err)
	}
}

func TestAssetListReturnsUploadedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "photos", "2026"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "photos", "2026", "photo.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "photos", "2026", ".photo.jpg.tmp"), []byte("tmp"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		assetDir:         dir,
		publicCDNBaseURL: mustTestURL(t, "https://assets.example/cdn"),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/assets?folder=photos", nil)
	rec := httptest.NewRecorder()
	app.assetListHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response struct {
		Count  int             `json:"count"`
		Folder string          `json:"folder"`
		Assets []assetListItem `json:"assets"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Count != 1 || response.Folder != "photos" || len(response.Assets) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	got := response.Assets[0]
	if got.Name != "photo.jpg" || got.Folder != "photos/2026" || got.AssetPath != "/assets/photos/2026/photo.jpg" || got.EdgePath != "/edge/assets/photos/2026/photo.jpg" || got.PublicURL != "https://assets.example/cdn/edge/assets/photos/2026/photo.jpg" || got.Bytes != 4 {
		t.Fatalf("unexpected asset: %+v", got)
	}
	if !strings.HasPrefix(got.ContentType, "image/jpeg") {
		t.Fatalf("content type = %q, want image/jpeg", got.ContentType)
	}
}

func TestAssetListRejectsTraversal(t *testing.T) {
	app := &dashboardServer{assetDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodGet, "/api/assets?folder=../outside", nil)
	rec := httptest.NewRecorder()
	app.assetListHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAssetDeleteRemovesFileAndPurgesCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "uploads", "smoke"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "uploads", "smoke", "photo.jpg")
	if err := os.WriteFile(target, []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}

	var gotPath string
	var gotAuth string
	var gotBody string
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer control.Close()
	base, err := url.Parse(control.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client:         control.Client(),
		apiKey:         "secret",
		assetDir:       dir,
		controlBaseURL: base,
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/assets?edge_path=/edge/assets/uploads/smoke/photo.jpg&host=cdn.localhost", nil)
	rec := httptest.NewRecorder()
	app.assetDeleteHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("deleted file still exists, stat err=%v", err)
	}
	if gotPath != "/v1/cache/invalidate" {
		t.Fatalf("purge path = %q, want /v1/cache/invalidate", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("purge authorization = %q, want Bearer secret", gotAuth)
	}
	if !strings.Contains(gotBody, `"/edge/assets/uploads/smoke/photo.jpg"`) || !strings.Contains(gotBody, `"host":"cdn.localhost"`) {
		t.Fatalf("unexpected purge body: %s", gotBody)
	}

	var response struct {
		Status      string `json:"status"`
		AssetPath   string `json:"asset_path"`
		EdgePath    string `json:"edge_path"`
		PurgeStatus string `json:"purge_status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "deleted" || response.AssetPath != "/assets/uploads/smoke/photo.jpg" || response.EdgePath != "/edge/assets/uploads/smoke/photo.jpg" || response.PurgeStatus != "accepted" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestAssetDeleteCanSkipPurge(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "photo.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{assetDir: dir}

	req := httptest.NewRequest(http.MethodDelete, "/api/assets?asset_path=/assets/photo.jpg&purge=false", nil)
	rec := httptest.NewRecorder()
	app.assetDeleteHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "photo.jpg")); !os.IsNotExist(err) {
		t.Fatalf("deleted file still exists, stat err=%v", err)
	}
	if !strings.Contains(rec.Body.String(), `"purge_status":"skipped"`) {
		t.Fatalf("response missing skipped purge status: %s", rec.Body.String())
	}
}

func TestAssetDeleteRejectsTraversal(t *testing.T) {
	app := &dashboardServer{assetDir: t.TempDir()}
	for _, target := range []string{"/assets/../secret.txt", "/edge/assets/../secret.txt", "/assets/photos//secret.txt"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/assets?asset_path="+url.QueryEscape(target), nil)
			rec := httptest.NewRecorder()
			app.assetDeleteHandler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestAssetPurgePublishesCacheInvalidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uploads", "photo.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	var gotPath string
	var gotAuth string
	var gotBody string
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer control.Close()
	base, err := url.Parse(control.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &dashboardServer{
		client:           control.Client(),
		apiKey:           "secret",
		assetDir:         dir,
		controlBaseURL:   base,
		publicCDNBaseURL: mustTestURL(t, "https://cdn.example"),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/assets/purge?edge_path=/edge/assets/uploads/photo.jpg&host=cdn.localhost", nil)
	rec := httptest.NewRecorder()
	app.assetPurgeHandler(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if gotPath != "/v1/cache/invalidate" {
		t.Fatalf("purge path = %q, want /v1/cache/invalidate", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("purge authorization = %q, want Bearer secret", gotAuth)
	}
	if !strings.Contains(gotBody, `"/edge/assets/uploads/photo.jpg"`) || !strings.Contains(gotBody, `"host":"cdn.localhost"`) {
		t.Fatalf("unexpected purge body: %s", gotBody)
	}
	if !strings.Contains(rec.Body.String(), `"status":"purged"`) || !strings.Contains(rec.Body.String(), `"public_url":"https://cdn.example/edge/assets/uploads/photo.jpg"`) {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "uploads", "photo.jpg")); err != nil {
		t.Fatalf("purge should not delete file: %v", err)
	}
}

func TestAssetPurgeRejectsMissingAsset(t *testing.T) {
	app := &dashboardServer{assetDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodPost, "/api/assets/purge?edge_path=/edge/assets/missing.jpg&host=cdn.localhost", nil)
	rec := httptest.NewRecorder()
	app.assetPurgeHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestAssetStorageHandlerReportsLocalMode(t *testing.T) {
	dir := t.TempDir()
	app := &dashboardServer{
		assetDir:         dir,
		maxUploadBytes:   2048,
		publicCDNBaseURL: mustTestURL(t, "https://cdn.example"),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/assets/storage", nil)
	rec := httptest.NewRecorder()
	app.assetStorageHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response["mode"] != "local" || response["backend"] != "local" || response["asset_dir"] != dir || response["public_cdn_base_url"] != "https://cdn.example" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response["configured"] != true {
		t.Fatalf("configured = %+v, want true", response["configured"])
	}
}

func TestAssetStorageHandlerReportsS3ModeWithoutSecrets(t *testing.T) {
	app := &dashboardServer{
		maxUploadBytes: 4096,
		assetStore: s3DashboardAssetStore{
			endpoint:       "https://s3.example.com",
			bucket:         "media-bucket",
			region:         "us-west-2",
			prefix:         "assets",
			forcePathStyle: true,
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/assets/storage", nil)
	rec := httptest.NewRecorder()
	app.assetStorageHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"mode":"s3"`, `"endpoint":"https://s3.example.com"`, `"bucket":"media-bucket"`, `"prefix":"assets"`, `"region":"us-west-2"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "access_key") {
		t.Fatalf("storage status leaked secret fields: %s", body)
	}
}

func TestAssetHandlersUseS3Store(t *testing.T) {
	objects := map[string]string{}
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			if r.URL.Path != "/media-bucket" {
				t.Fatalf("list path = %q", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Contents>
    <Key>assets/uploads/photo.txt</Key>
    <LastModified>2026-05-25T10:00:00Z</LastModified>
    <Size>13</Size>
  </Contents>
</ListBucketResult>`))
			return
		}
		if r.URL.Path != "/media-bucket/assets/uploads/photo.txt" {
			t.Fatalf("object path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Fatalf("missing signed authorization header")
		}
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Fatalf("content type = %q", r.Header.Get("Content-Type"))
			}
			objects["assets/uploads/photo.txt"] = string(body)
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			if _, ok := objects["assets/uploads/photo.txt"]; !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(objects, "assets/uploads/photo.txt")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer objectServer.Close()

	app := &dashboardServer{
		client:           objectServer.Client(),
		maxUploadBytes:   1024,
		publicCDNBaseURL: mustTestURL(t, "https://cdn.example"),
		assetStore: s3DashboardAssetStore{
			endpoint:        objectServer.URL,
			bucket:          "media-bucket",
			region:          "us-east-1",
			accessKeyID:     "test-access",
			secretAccessKey: "test-secret",
			prefix:          "assets",
			forcePathStyle:  true,
			client:          objectServer.Client(),
		},
	}

	uploadBody, contentType := multipartUploadBody(t, "folder", "uploads", "file", "photo.txt", "s3 upload body")
	uploadReq := httptest.NewRequest(http.MethodPost, "/api/assets/upload?purge=false", uploadBody)
	uploadReq.Header.Set("Content-Type", contentType)
	uploadRec := httptest.NewRecorder()
	app.assetUploadHandler(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, want %d body=%s", uploadRec.Code, http.StatusCreated, uploadRec.Body.String())
	}
	if objects["assets/uploads/photo.txt"] != "s3 upload body" {
		t.Fatalf("stored object = %q", objects["assets/uploads/photo.txt"])
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/assets?folder=uploads&limit=20", nil)
	listRec := httptest.NewRecorder()
	app.assetListHandler(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"edge_path":"/edge/assets/uploads/photo.txt"`) ||
		!strings.Contains(listRec.Body.String(), `"public_url":"https://cdn.example/edge/assets/uploads/photo.txt"`) {
		t.Fatalf("unexpected list response: %s", listRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/assets?edge_path=/edge/assets/uploads/photo.txt&purge=false", nil)
	deleteRec := httptest.NewRecorder()
	app.assetDeleteHandler(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d body=%s", deleteRec.Code, http.StatusOK, deleteRec.Body.String())
	}
	if _, ok := objects["assets/uploads/photo.txt"]; ok {
		t.Fatalf("object was not deleted")
	}
}

func multipartUploadBody(t *testing.T, fieldName, fieldValue, fileField, filename, content string) (io.Reader, string) {
	t.Helper()
	return multipartUploadBodyWithFields(t, map[string]string{fieldName: fieldValue}, fileField, filename, content)
}

func multipartUploadBodyWithFields(t *testing.T, fields map[string]string, fileField, filename, content string) (io.Reader, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="`+fileField+`"; filename="`+filename+`"`)
	header.Set("Content-Type", "application/octet-stream")
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(part, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, writer.FormDataContentType()
}

func mustTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
