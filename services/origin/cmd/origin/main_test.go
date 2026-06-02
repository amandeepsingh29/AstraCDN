package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginServesFileBackedAssets(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "photos"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "photos", "hero.txt"), []byte("hello from asset origin"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/photos/hero.txt", nil)
	rec := httptest.NewRecorder()
	newOriginHandler(dir).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "hello from asset origin" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "public") {
		t.Fatalf("cache-control = %q, want public", got)
	}
	if got := rec.Header().Get("Surrogate-Key"); !strings.Contains(got, "asset:photos") || !strings.Contains(got, "asset:hero") {
		t.Fatalf("surrogate-key = %q", got)
	}
}

func TestOriginAssetsSupportRangeRequests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "video.txt"), []byte("0123456789"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/video.txt", nil)
	req.Header.Set("Range", "bytes=2-5")
	rec := httptest.NewRecorder()
	newOriginHandler(dir).ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if rec.Body.String() != "2345" {
		t.Fatalf("body = %q, want 2345", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("content-range = %q", got)
	}
}

func TestOriginRejectsMissingAsset(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/missing.txt", nil)
	rec := httptest.NewRecorder()
	newOriginHandler(t.TempDir()).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestOriginServesS3BackedAssets(t *testing.T) {
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media-bucket/assets/photos/hero.txt" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Range") != "" {
			t.Fatalf("unexpected range header %q", r.Header.Get("Range"))
		}
		w.Header().Set("Cache-Control", "public, max-age=120")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"hero-v1"`)
		w.Header().Set("Last-Modified", "Mon, 25 May 2026 10:00:00 GMT")
		_, _ = io.WriteString(w, "hello from object storage")
	}))
	defer objectServer.Close()

	storage := s3AssetStorage{
		endpoint:       objectServer.URL,
		bucket:         "media-bucket",
		prefix:         "assets",
		region:         "us-east-1",
		forcePathStyle: true,
		client:         objectServer.Client(),
	}
	req := httptest.NewRequest(http.MethodGet, "/assets/photos/hero.txt", nil)
	rec := httptest.NewRecorder()
	newOriginHandlerWithStorage(storage).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "hello from object storage" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("ETag"); got != `"hero-v1"` {
		t.Fatalf("etag = %q", got)
	}
	if got := rec.Header().Get("Surrogate-Key"); !strings.Contains(got, "asset:photos") || !strings.Contains(got, "asset:hero") {
		t.Fatalf("surrogate-key = %q", got)
	}
}

func TestOriginS3AssetsForwardRangeRequests(t *testing.T) {
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=2-5" {
			t.Fatalf("range = %q", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Range", "bytes 2-5/10")
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "2345")
	}))
	defer objectServer.Close()

	storage := s3AssetStorage{
		endpoint:       objectServer.URL,
		bucket:         "media-bucket",
		region:         "us-east-1",
		forcePathStyle: true,
		client:         objectServer.Client(),
	}
	req := httptest.NewRequest(http.MethodGet, "/assets/video.txt", nil)
	req.Header.Set("Range", "bytes=2-5")
	rec := httptest.NewRecorder()
	newOriginHandlerWithStorage(storage).ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if rec.Body.String() != "2345" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("content-range = %q", got)
	}
}

func TestOriginS3AssetsSignRequestsWhenCredentialsConfigured(t *testing.T) {
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=test-access/") {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
			t.Fatalf("payload hash = %q", got)
		}
		fmt.Fprint(w, "signed object")
	}))
	defer objectServer.Close()

	storage := s3AssetStorage{
		endpoint:        objectServer.URL,
		bucket:          "media-bucket",
		region:          "us-east-1",
		accessKeyID:     "test-access",
		secretAccessKey: "test-secret",
		forcePathStyle:  true,
		client:          objectServer.Client(),
	}
	req := httptest.NewRequest(http.MethodGet, "/assets/signed.txt", nil)
	rec := httptest.NewRecorder()
	newOriginHandlerWithStorage(storage).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
