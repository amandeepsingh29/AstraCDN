#!/usr/bin/env bash
set -euo pipefail

COMPOSE="${COMPOSE:-podman-compose}"
COMPOSE_FILE="${COMPOSE_FILE:-podman-compose.yml}"
API_KEY="${ASTRACDN_API_KEY:-astracdn-local-dev-key}"
TMP_DIR="$(mktemp -d)"
SIGNING_SECRET="0123456789abcdef0123456789abcdef"
BILLING_WEBHOOK_SECRET="local-billing-webhook-secret"
export BILLING_WEBHOOK_SECRET

cleanup() {
  "$COMPOSE" -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '[smoke] %s\n' "$*"
}

fail() {
  printf '[smoke] failed: %s\n' "$*" >&2
  exit 1
}

curl_code() {
  local output="$1"
  shift
  curl -sS -o "$output" -w '%{http_code}' "$@"
}

header_value() {
  local file="$1"
  local header="$2"
  awk -v wanted="$header" '
    index(tolower($0), tolower(wanted) ":") == 1 {
      sub(/^[^:]+:[[:space:]]*/, "")
      gsub(/\r/, "")
      print
      exit
    }
  ' "$file"
}

billing_signature() {
  local body="$1"
  ruby -ropenssl -e 'print OpenSSL::HMAC.hexdigest("SHA256", ENV.fetch("BILLING_WEBHOOK_SECRET"), ARGV.fetch(0))' "$body"
}

expect_code() {
  local got="$1"
  local want="$2"
  local context="$3"
  if [[ "$got" != "$want" ]]; then
    fail "$context returned HTTP $got, want $want"
  fi
}

wait_ready() {
  local name="$1"
  local url="$2"
  shift 2
  local output="$TMP_DIR/$name-ready.json"
  local code

  for _ in $(seq 1 45); do
    code="$(curl_code "$output" "$@" "$url" || true)"
    if [[ "$code" == "200" ]]; then
      log "$name ready"
      return 0
    fi
    sleep 2
  done

  printf '%s\n' "last $name readiness response:" >&2
  cat "$output" >&2 || true
  fail "$name did not become ready"
}

log "starting stack with mock inference provider"
log "resetting smoke-test volumes"
"$COMPOSE" -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
mkdir -p data/origin/photos data/origin/videos
printf 'smoke photo asset\n' > data/origin/photos/smoke-photo.txt
printf '0123456789abcdef\n' > data/origin/videos/smoke-video.txt

CORS_ENABLED=true CORS_ALLOWED_ORIGINS=https://dashboard.example INFERENCE_PROVIDER=mock \
  RATE_LIMIT_RPS=50 RATE_LIMIT_BURST=100 \
  CONTROL_DOMAIN_VERIFICATION_BYPASS=true \
  CONTROL_BILLING_WEBHOOK_SECRET="$BILLING_WEBHOOK_SECRET" \
  EDGE_DOMAIN_VALIDATION_ENABLED=true EDGE_CONFIG_REFRESH_INTERVAL=1s \
  EDGE_WAF_ENABLED=true EDGE_WAF_BLOCK_PATH_PREFIXES=/edge/waf-block \
  EDGE_RESPONSE_SET_HEADERS='/edge/smoke-test|X-AstraCDN-Rule=smoke' \
  EDGE_REDIRECT_RULES='/edge/redirect-smoke|https://redirect.example{path}|301' \
  EDGE_RATE_LIMIT_RULES='cdn.localhost|/edge/route-limit|1|1' \
  EDGE_SIGNING_SECRET="$SIGNING_SECRET" \
  EDGE_SIGNED_COOKIE_ENABLED=true \
  EDGE_SIGNED_COOKIE_PATH_PREFIXES=/edge/cookie-protected \
  EDGE_BROTLI_ENABLED=true EDGE_COMPRESSION_MIN_BYTES=1 \
  EDGE_LARGE_OBJECT_STREAMING_ENABLED=true EDGE_LARGE_OBJECT_THRESHOLD_BYTES=4096 \
  EDGE_SEGMENTED_CACHE_ENABLED=true EDGE_SEGMENT_SIZE_BYTES=2048 \
  EDGE_IMAGE_TRANSFORM_ENABLED=true EDGE_IMAGE_TRANSFORM_MAX_DIMENSION=64 \
  "$COMPOSE" -f "$COMPOSE_FILE" up --build -d

wait_ready edge http://localhost:8080/ready
wait_ready control http://localhost:8081/ready
wait_ready inference http://localhost:8082/ready
wait_ready edge-ingress https://localhost:8443/ready -k
wait_ready dashboard http://localhost:3000/health

log "checking dashboard UI"
dashboard_code="$(curl_code "$TMP_DIR/dashboard.html" http://localhost:3000/)"
expect_code "$dashboard_code" "200" "dashboard"
grep -q 'AstraCDN Control Deck' "$TMP_DIR/dashboard.html" || fail "dashboard HTML missing title"
dashboard_unauthorized_code="$(curl_code "$TMP_DIR/dashboard-unauthorized.json" http://localhost:3000/api/control/health)"
expect_code "$dashboard_unauthorized_code" "401" "unauthenticated dashboard API"
dashboard_api_code="$(curl_code "$TMP_DIR/dashboard-api.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  http://localhost:3000/api/control/health)"
expect_code "$dashboard_api_code" "200" "authenticated dashboard API"

log "checking dashboard API key management"
dashboard_api_key_code="$(curl_code "$TMP_DIR/dashboard-api-key.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"dashboard-smoke","scopes":["control:write","edge:read"]}' \
  http://localhost:3000/api/control/v1/api-keys)"
expect_code "$dashboard_api_key_code" "201" "dashboard API key create"
grep -q '"status":"created"' "$TMP_DIR/dashboard-api-key.json" || fail "dashboard API key create missing created status"
grep -q '"key":"ak_' "$TMP_DIR/dashboard-api-key.json" || fail "dashboard API key create missing one-time secret"
dashboard_api_key_id="$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["api_key"]["id"]' "$TMP_DIR/dashboard-api-key.json")"
dashboard_api_key_secret="$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["key"]' "$TMP_DIR/dashboard-api-key.json")"

dashboard_api_keys_code="$(curl_code "$TMP_DIR/dashboard-api-keys.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  http://localhost:3000/api/control/v1/api-keys)"
expect_code "$dashboard_api_keys_code" "200" "dashboard API key list"
grep -q '"name":"dashboard-smoke"' "$TMP_DIR/dashboard-api-keys.json" || fail "dashboard API key list missing created key"

scoped_key_read_code="$(curl_code "$TMP_DIR/scoped-key-read.json" \
  -H "Authorization: Bearer $dashboard_api_key_secret" \
  http://localhost:8081/v1/origins)"
expect_code "$scoped_key_read_code" "403" "control:write scoped key read rejection"

scoped_key_write_code="$(curl_code "$TMP_DIR/scoped-key-write.json" \
  -H "Authorization: Bearer $dashboard_api_key_secret" \
  -H 'Content-Type: application/json' \
  -d '{"name":"scoped-key-origin","base_url":"http://example-origin:9000","headers":{}}' \
  http://localhost:8081/v1/origins)"
expect_code "$scoped_key_write_code" "202" "control:write scoped key origin create"
grep -q '"name":"scoped-key-origin"' "$TMP_DIR/scoped-key-write.json" || fail "scoped key write response missing origin"

dashboard_api_key_revoke_code="$(curl_code "$TMP_DIR/dashboard-api-key-revoke.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"id\":${dashboard_api_key_id}}" \
  http://localhost:3000/api/control/v1/api-keys/revoke)"
expect_code "$dashboard_api_key_revoke_code" "200" "dashboard API key revoke"
grep -q '"status":"revoked"' "$TMP_DIR/dashboard-api-key-revoke.json" || fail "dashboard API key revoke missing revoked status"

log "checking tenant, RBAC, and billing foundations"
tenant_code="$(curl_code "$TMP_DIR/tenant.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Smoke Tenant","slug":"smoke-tenant"}' \
  http://localhost:8081/v1/tenants)"
expect_code "$tenant_code" "202" "tenant create"
grep -q '"slug":"smoke-tenant"' "$TMP_DIR/tenant.json" || fail "tenant create response missing slug"
tenant_id="$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["tenant"]["id"]' "$TMP_DIR/tenant.json")"

tenant_list_code="$(curl_code "$TMP_DIR/tenants.json" \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8081/v1/tenants)"
expect_code "$tenant_list_code" "200" "tenant list"
grep -q '"slug":"smoke-tenant"' "$TMP_DIR/tenants.json" || fail "tenant list missing smoke tenant"

tenant_user_code="$(curl_code "$TMP_DIR/tenant-user.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":${tenant_id},\"email\":\"owner@smoke.example\",\"role\":\"owner\"}" \
  http://localhost:8081/v1/rbac/users)"
expect_code "$tenant_user_code" "202" "tenant RBAC user upsert"
grep -q '"role":"owner"' "$TMP_DIR/tenant-user.json" || fail "tenant RBAC response missing owner role"

billing_code="$(curl_code "$TMP_DIR/billing-account.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":${tenant_id},\"provider\":\"stripe\",\"provider_customer_id\":\"cus_smoke\",\"plan\":\"developer\",\"status\":\"active\"}" \
  http://localhost:8081/v1/billing/accounts)"
expect_code "$billing_code" "202" "billing account upsert"
grep -q '"provider":"stripe"' "$TMP_DIR/billing-account.json" || fail "billing response missing provider"
grep -q '"plan":"developer"' "$TMP_DIR/billing-account.json" || fail "billing response missing plan"

billing_webhook_body='{"event_id":"evt_smoke_past_due","provider":"stripe","provider_customer_id":"cus_smoke","status":"past_due"}'
billing_webhook_signature="$(billing_signature "$billing_webhook_body")"
billing_webhook_code="$(curl_code "$TMP_DIR/billing-webhook.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-AstraCDN-Billing-Signature: sha256=${billing_webhook_signature}" \
  -H 'Content-Type: application/json' \
  -d "$billing_webhook_body" \
  http://localhost:8081/v1/billing/webhooks)"
expect_code "$billing_webhook_code" "202" "billing webhook status update"
grep -q '"status":"past_due"' "$TMP_DIR/billing-webhook.json" || fail "billing webhook response missing past_due status"
billing_webhook_duplicate_code="$(curl_code "$TMP_DIR/billing-webhook-duplicate.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-AstraCDN-Billing-Signature: sha256=${billing_webhook_signature}" \
  -H 'Content-Type: application/json' \
  -d "$billing_webhook_body" \
  http://localhost:8081/v1/billing/webhooks)"
expect_code "$billing_webhook_duplicate_code" "200" "duplicate billing webhook replay"
grep -q '"status":"duplicate"' "$TMP_DIR/billing-webhook-duplicate.json" || fail "duplicate billing webhook response missing duplicate status"

billing_webhook_events_code="$(curl_code "$TMP_DIR/billing-webhook-events.json" \
  -H "Authorization: Bearer $API_KEY" \
  'http://localhost:8081/v1/billing/webhook-events?provider=stripe&event_id=evt_smoke_past_due&limit=5')"
expect_code "$billing_webhook_events_code" "200" "billing webhook event list"
grep -q '"billing_webhook_events":' "$TMP_DIR/billing-webhook-events.json" || fail "billing webhook event list missing events"
grep -q '"event_id":"evt_smoke_past_due"' "$TMP_DIR/billing-webhook-events.json" || fail "billing webhook event list missing smoke event"

dashboard_tenant_code="$(curl_code "$TMP_DIR/dashboard-tenant.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Dashboard Smoke Tenant","slug":"dashboard-smoke-tenant"}' \
  http://localhost:3000/api/control/v1/tenants)"
expect_code "$dashboard_tenant_code" "202" "dashboard tenant create"
grep -q '"slug":"dashboard-smoke-tenant"' "$TMP_DIR/dashboard-tenant.json" || fail "dashboard tenant response missing slug"
dashboard_tenant_id="$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["tenant"]["id"]' "$TMP_DIR/dashboard-tenant.json")"

dashboard_tenant_user_code="$(curl_code "$TMP_DIR/dashboard-tenant-user.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":${dashboard_tenant_id},\"email\":\"dashboard-owner@smoke.example\",\"role\":\"admin\"}" \
  http://localhost:3000/api/control/v1/rbac/users)"
expect_code "$dashboard_tenant_user_code" "202" "dashboard RBAC user upsert"
grep -q '"role":"admin"' "$TMP_DIR/dashboard-tenant-user.json" || fail "dashboard RBAC response missing admin role"

dashboard_billing_code="$(curl_code "$TMP_DIR/dashboard-billing-account.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":${dashboard_tenant_id},\"provider\":\"stripe\",\"provider_customer_id\":\"cus_dashboard_smoke\",\"plan\":\"team\",\"status\":\"active\"}" \
  http://localhost:3000/api/control/v1/billing/accounts)"
expect_code "$dashboard_billing_code" "202" "dashboard billing account upsert"
grep -q '"plan":"team"' "$TMP_DIR/dashboard-billing-account.json" || fail "dashboard billing response missing team plan"

dashboard_billing_webhook_body='{"event_id":"evt_dashboard_smoke_active","provider":"stripe","provider_customer_id":"cus_dashboard_smoke","status":"active"}'
dashboard_billing_webhook_signature="$(billing_signature "$dashboard_billing_webhook_body")"
dashboard_billing_webhook_code="$(curl_code "$TMP_DIR/dashboard-billing-webhook.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H "X-AstraCDN-Billing-Signature: sha256=${dashboard_billing_webhook_signature}" \
  -H 'Content-Type: application/json' \
  -d "$dashboard_billing_webhook_body" \
  http://localhost:3000/api/control/v1/billing/webhooks)"
expect_code "$dashboard_billing_webhook_code" "202" "dashboard billing webhook status update"
grep -q '"status":"active"' "$TMP_DIR/dashboard-billing-webhook.json" || fail "dashboard billing webhook response missing active status"
dashboard_billing_webhook_duplicate_code="$(curl_code "$TMP_DIR/dashboard-billing-webhook-duplicate.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H "X-AstraCDN-Billing-Signature: sha256=${dashboard_billing_webhook_signature}" \
  -H 'Content-Type: application/json' \
  -d "$dashboard_billing_webhook_body" \
  http://localhost:3000/api/control/v1/billing/webhooks)"
expect_code "$dashboard_billing_webhook_duplicate_code" "200" "duplicate dashboard billing webhook replay"
grep -q '"status":"duplicate"' "$TMP_DIR/dashboard-billing-webhook-duplicate.json" || fail "duplicate dashboard billing webhook response missing duplicate status"

dashboard_billing_webhook_events_code="$(curl_code "$TMP_DIR/dashboard-billing-webhook-events.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/control/v1/billing/webhook-events?provider=stripe&event_id=evt_dashboard_smoke_active&limit=5')"
expect_code "$dashboard_billing_webhook_events_code" "200" "dashboard billing webhook event list"
grep -q '"billing_webhook_events":' "$TMP_DIR/dashboard-billing-webhook-events.json" || fail "dashboard billing webhook event list missing events"
grep -q '"event_id":"evt_dashboard_smoke_active"' "$TMP_DIR/dashboard-billing-webhook-events.json" || fail "dashboard billing webhook event list missing smoke event"

log "checking verified domain flow and strict edge host validation"
domain_code="$(curl_code "$TMP_DIR/domain.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"cdn.localhost","tls_mode":"managed"}' \
  http://localhost:8081/v1/domains)"
expect_code "$domain_code" "202" "domain create"
grep -q '"status":"pending_dns"' "$TMP_DIR/domain.json" || fail "created domain is not pending_dns"
grep -q '"dns_txt_name":"_astra-cdn.cdn.localhost"' "$TMP_DIR/domain.json" || fail "domain response missing DNS TXT name"

verify_code="$(curl_code "$TMP_DIR/domain-verify.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"cdn.localhost"}' \
  http://localhost:8081/v1/domains/verify)"
expect_code "$verify_code" "200" "domain verify"
grep -q '"status":"verified"' "$TMP_DIR/domain-verify.json" || fail "domain verify response missing verified status"
grep -q '"status":"active"' "$TMP_DIR/domain-verify.json" || fail "verified domain is not active"

log "checking dashboard domain management proxy"
dashboard_domain_code="$(curl_code "$TMP_DIR/dashboard-domain.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"assets.localhost","tls_mode":"managed"}' \
  http://localhost:3000/api/control/v1/domains)"
expect_code "$dashboard_domain_code" "202" "dashboard domain create"
grep -q '"host":"assets.localhost"' "$TMP_DIR/dashboard-domain.json" || fail "dashboard domain create response missing host"
grep -q '"dns_txt_name":"_astra-cdn.assets.localhost"' "$TMP_DIR/dashboard-domain.json" || fail "dashboard domain create response missing DNS TXT name"

dashboard_domain_verify_code="$(curl_code "$TMP_DIR/dashboard-domain-verify.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"assets.localhost"}' \
  http://localhost:3000/api/control/v1/domains/verify)"
expect_code "$dashboard_domain_verify_code" "200" "dashboard domain verify"
grep -q '"status":"active"' "$TMP_DIR/dashboard-domain-verify.json" || fail "dashboard domain verify did not activate domain"

allowed_code=""
for _ in $(seq 1 15); do
  allowed_code="$(curl_code "$TMP_DIR/domain-edge.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/domain-smoke || true)"
  if [[ "$allowed_code" == "200" ]]; then
    break
  fi
  sleep 1
done
expect_code "$allowed_code" "200" "verified domain edge request"

log "checking dashboard advanced route rules"
dashboard_rule_origin_code="$(curl_code "$TMP_DIR/dashboard-rule-origin.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"dashboard-rule-origin","base_url":"http://example-origin:9000","headers":{}}' \
  http://localhost:3000/api/control/v1/origins)"
expect_code "$dashboard_rule_origin_code" "202" "dashboard rule origin create"
dashboard_rule_origin_id="$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$TMP_DIR/dashboard-rule-origin.json" | head -n1)"
[[ -n "$dashboard_rule_origin_id" ]] || fail "dashboard rule origin id not found"

dashboard_header_route_code="$(curl_code "$TMP_DIR/dashboard-header-route.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/dashboard-rule/\",\"origin_id\":${dashboard_rule_origin_id},\"delivery_rules\":{\"set_headers\":[{\"path_prefix\":\"/edge/dashboard-rule\",\"name\":\"X-AstraCDN-Dashboard-Rule\",\"value\":\"yes\"}]}}" \
  http://localhost:3000/api/control/v1/routes)"
expect_code "$dashboard_header_route_code" "202" "dashboard header rule route create"

dashboard_rule_header=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/dashboard-rule.headers" -o "$TMP_DIR/dashboard-rule.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/dashboard-rule/smoke
  dashboard_rule_header="$(header_value "$TMP_DIR/dashboard-rule.headers" "X-AstraCDN-Dashboard-Rule")"
  if [[ "$dashboard_rule_header" == "yes" ]]; then
    break
  fi
  sleep 1
done
[[ "$dashboard_rule_header" == "yes" ]] || fail "dashboard route response header is $dashboard_rule_header"

dashboard_waf_route_code="$(curl_code "$TMP_DIR/dashboard-waf-route.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/dashboard-waf/\",\"origin_id\":${dashboard_rule_origin_id},\"waf_rules\":{\"enabled\":true,\"path_prefixes\":[\"/edge/dashboard-waf\"]}}" \
  http://localhost:3000/api/control/v1/routes)"
expect_code "$dashboard_waf_route_code" "202" "dashboard WAF route create"

dashboard_waf_code=""
for _ in $(seq 1 15); do
  dashboard_waf_code="$(curl_code "$TMP_DIR/dashboard-waf.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/dashboard-waf/smoke)"
  if [[ "$dashboard_waf_code" == "403" ]]; then
    break
  fi
  sleep 1
done
expect_code "$dashboard_waf_code" "403" "dashboard WAF blocked edge request"

dashboard_limit_route_code="$(curl_code "$TMP_DIR/dashboard-limit-route.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/dashboard-limit/\",\"origin_id\":${dashboard_rule_origin_id},\"rate_limit_rules\":[{\"path_prefix\":\"/edge/dashboard-limit\",\"rps\":1,\"burst\":1}]}" \
  http://localhost:3000/api/control/v1/routes)"
expect_code "$dashboard_limit_route_code" "202" "dashboard rate-limit route create"

dashboard_limit_first=""
for _ in $(seq 1 15); do
  dashboard_limit_first="$(curl_code "$TMP_DIR/dashboard-limit-first.body" \
    -H 'Host: cdn.localhost' \
    -H 'X-Forwarded-For: 198.51.100.21' \
    http://localhost:8080/edge/dashboard-limit/smoke)"
  if [[ "$dashboard_limit_first" == "200" ]]; then
    break
  fi
  sleep 1
done
expect_code "$dashboard_limit_first" "200" "first dashboard rate-limited edge request"
dashboard_limit_second="$(curl_code "$TMP_DIR/dashboard-limit-second.body" \
  -H 'Host: cdn.localhost' \
  -H 'X-Forwarded-For: 198.51.100.21' \
  http://localhost:8080/edge/dashboard-limit/smoke)"
expect_code "$dashboard_limit_second" "429" "second dashboard rate-limited edge request"

log "checking dashboard CDN fetch tester"
dashboard_fetch_code="$(curl_code "$TMP_DIR/dashboard-fetch.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/cdn/fetch?host=cdn.localhost&path=/edge/domain-smoke')"
expect_code "$dashboard_fetch_code" "200" "dashboard CDN fetch"
grep -q '"host":"cdn.localhost"' "$TMP_DIR/dashboard-fetch.json" || fail "dashboard fetch response missing host"
grep -q '"path":"/edge/domain-smoke"' "$TMP_DIR/dashboard-fetch.json" || fail "dashboard fetch response missing path"
grep -q '"status":200' "$TMP_DIR/dashboard-fetch.json" || fail "dashboard fetch response missing status"

log "checking dashboard asset upload"
dashboard_storage_code="$(curl_code "$TMP_DIR/dashboard-storage.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  http://localhost:3000/api/assets/storage)"
expect_code "$dashboard_storage_code" "200" "dashboard asset storage status"
grep -q '"mode":"local"' "$TMP_DIR/dashboard-storage.json" || fail "dashboard asset storage status missing local mode"
grep -q '"configured":true' "$TMP_DIR/dashboard-storage.json" || fail "dashboard asset storage is not configured"

printf 'dashboard uploaded asset\n' > "$TMP_DIR/upload-source.txt"
dashboard_upload_code="$(curl_code "$TMP_DIR/dashboard-upload.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -F 'host=cdn.localhost' \
  -F 'folder=uploads/smoke' \
  -F "file=@$TMP_DIR/upload-source.txt;filename=dashboard upload.txt" \
  http://localhost:3000/api/assets/upload)"
expect_code "$dashboard_upload_code" "201" "dashboard asset upload"
grep -q '"edge_path":"/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-upload.json" || fail "dashboard upload response missing edge path"
grep -q '"public_url":"http://cdn.localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-upload.json" || fail "dashboard upload response missing public URL"
grep -q '"purge_status":"accepted"' "$TMP_DIR/dashboard-upload.json" || fail "dashboard upload did not accept purge"

dashboard_assets_code="$(curl_code "$TMP_DIR/dashboard-assets.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/assets?folder=uploads&limit=20')"
expect_code "$dashboard_assets_code" "200" "dashboard asset list"
grep -q '"edge_path":"/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-assets.json" || fail "dashboard asset list missing uploaded edge path"
grep -q '"public_url":"http://cdn.localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-assets.json" || fail "dashboard asset list missing public URL"

dashboard_assets_filtered_code="$(curl_code "$TMP_DIR/dashboard-assets-filtered.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/assets?folder=uploads/smoke&limit=1')"
expect_code "$dashboard_assets_filtered_code" "200" "dashboard filtered asset list"
grep -q '"count":1' "$TMP_DIR/dashboard-assets-filtered.json" || fail "dashboard filtered asset list did not respect limit"
grep -q '"edge_path":"/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-assets-filtered.json" || fail "dashboard filtered asset list missing uploaded edge path"

curl -sS -D "$TMP_DIR/dashboard-upload-first.headers" -o "$TMP_DIR/dashboard-upload-first.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
dashboard_upload_first_cache="$(header_value "$TMP_DIR/dashboard-upload-first.headers" "X-AstraCDN-Cache")"
[[ "$dashboard_upload_first_cache" == "MISS" ]] || fail "first uploaded asset cache header is $dashboard_upload_first_cache, want MISS"
grep -q 'dashboard uploaded asset' "$TMP_DIR/dashboard-upload-first.body" || fail "uploaded asset body missing expected content"

public_upload_code="$(curl_code "$TMP_DIR/dashboard-upload-public.body" \
  http://cdn.localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt)"
expect_code "$public_upload_code" "200" "dashboard public asset URL"
grep -q 'dashboard uploaded asset' "$TMP_DIR/dashboard-upload-public.body" || fail "public asset URL body missing expected content"

curl -sS -D "$TMP_DIR/dashboard-upload-second.headers" -o "$TMP_DIR/dashboard-upload-second.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
dashboard_upload_second_cache="$(header_value "$TMP_DIR/dashboard-upload-second.headers" "X-AstraCDN-Cache")"
[[ "$dashboard_upload_second_cache" == "HIT" ]] || fail "second uploaded asset cache header is $dashboard_upload_second_cache, want HIT"

dashboard_bulk_purge_code="$(curl_code "$TMP_DIR/dashboard-bulk-purge.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"cdn.localhost","keys":["/edge/assets/uploads/smoke/dashboard-upload.txt"],"requested_by":"dashboard-smoke"}' \
  http://localhost:3000/api/control/v1/cache/invalidate)"
expect_code "$dashboard_bulk_purge_code" "202" "dashboard bulk asset purge"
grep -q '"/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-bulk-purge.json" || fail "dashboard bulk purge response missing asset key"
bulk_purge_cache=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/dashboard-bulk-purge-fetch.headers" -o "$TMP_DIR/dashboard-bulk-purge-fetch.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
  bulk_purge_cache="$(header_value "$TMP_DIR/dashboard-bulk-purge-fetch.headers" "X-AstraCDN-Cache")"
  if [[ "$bulk_purge_cache" == "MISS" ]]; then
    break
  fi
  sleep 1
done
[[ "$bulk_purge_cache" == "MISS" ]] || fail "dashboard bulk purge did not evict asset cache, cache=$bulk_purge_cache"

log "checking dashboard asset prewarm"
dashboard_prewarm_path="/edge/assets/uploads/smoke/prewarm-dashboard.txt"
dashboard_bulk_prewarm_path="/edge/assets/uploads/smoke/prewarm-dashboard-bulk.txt"
dashboard_prewarm_key="astracdn:edge-cache:host:cdn.localhost:${dashboard_prewarm_path}"
dashboard_bulk_prewarm_key="astracdn:edge-cache:host:cdn.localhost:${dashboard_bulk_prewarm_path}"
printf 'dashboard prewarm asset\n' > data/origin/uploads/smoke/prewarm-dashboard.txt
printf 'dashboard bulk prewarm asset\n' > data/origin/uploads/smoke/prewarm-dashboard-bulk.txt
dashboard_prewarm_code="$(curl_code "$TMP_DIR/dashboard-prewarm.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"paths\":[\"${dashboard_prewarm_path}\"],\"requested_by\":\"dashboard-smoke\"}" \
  http://localhost:3000/api/control/v1/cache/prewarm)"
expect_code "$dashboard_prewarm_code" "202" "dashboard asset prewarm"
grep -q "\"paths\":\\[\"${dashboard_prewarm_path}\"\\]" "$TMP_DIR/dashboard-prewarm.json" || fail "dashboard prewarm response missing requested asset path"
dashboard_prewarm_cached=""
for _ in $(seq 1 15); do
  dashboard_prewarm_cached="$(podman exec astra-cdn_redis_1 redis-cli EXISTS "$dashboard_prewarm_key" | tr -d '\r' || true)"
  if [[ "$dashboard_prewarm_cached" == "1" ]]; then
    break
  fi
  sleep 1
done
[[ "$dashboard_prewarm_cached" == "1" ]] || fail "dashboard prewarm did not populate Redis cache key"

dashboard_bulk_prewarm_code="$(curl_code "$TMP_DIR/dashboard-bulk-prewarm.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"paths\":[\"${dashboard_prewarm_path}\",\"${dashboard_bulk_prewarm_path}\"],\"requested_by\":\"dashboard-smoke\"}" \
  http://localhost:3000/api/control/v1/cache/prewarm)"
expect_code "$dashboard_bulk_prewarm_code" "202" "dashboard bulk asset prewarm"
grep -q "\"${dashboard_bulk_prewarm_path}\"" "$TMP_DIR/dashboard-bulk-prewarm.json" || fail "dashboard bulk prewarm response missing bulk asset path"
dashboard_bulk_prewarm_cached=""
for _ in $(seq 1 15); do
  dashboard_bulk_prewarm_cached="$(podman exec astra-cdn_redis_1 redis-cli EXISTS "$dashboard_bulk_prewarm_key" | tr -d '\r' || true)"
  if [[ "$dashboard_bulk_prewarm_cached" == "1" ]]; then
    break
  fi
  sleep 1
done
[[ "$dashboard_bulk_prewarm_cached" == "1" ]] || fail "dashboard bulk prewarm did not populate Redis cache key"

printf 'dashboard replaced asset\n' > "$TMP_DIR/upload-replacement.txt"
dashboard_replace_code="$(curl_code "$TMP_DIR/dashboard-replace.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  -F 'host=cdn.localhost' \
  -F 'folder=uploads/smoke' \
  -F "file=@$TMP_DIR/upload-replacement.txt;filename=dashboard upload.txt" \
  http://localhost:3000/api/assets/upload)"
expect_code "$dashboard_replace_code" "201" "dashboard asset replacement upload"
grep -q '"purge_status":"accepted"' "$TMP_DIR/dashboard-replace.json" || fail "dashboard replacement upload did not accept purge"

replacement_cache=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/dashboard-replace-fetch.headers" -o "$TMP_DIR/dashboard-replace-fetch.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
  replacement_cache="$(header_value "$TMP_DIR/dashboard-replace-fetch.headers" "X-AstraCDN-Cache")"
  if grep -q 'dashboard replaced asset' "$TMP_DIR/dashboard-replace-fetch.body"; then
    break
  fi
  sleep 1
done
grep -q 'dashboard replaced asset' "$TMP_DIR/dashboard-replace-fetch.body" || fail "replacement upload did not refresh edge body"
[[ "$replacement_cache" == "MISS" ]] || fail "replacement edge cache header is $replacement_cache, want MISS after purge"

curl -sS -D "$TMP_DIR/dashboard-replace-hit.headers" -o "$TMP_DIR/dashboard-replace-hit.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
replace_hit_cache="$(header_value "$TMP_DIR/dashboard-replace-hit.headers" "X-AstraCDN-Cache")"
[[ "$replace_hit_cache" == "HIT" ]] || fail "replacement second edge cache header is $replace_hit_cache, want HIT"

dashboard_purge_code="$(curl_code "$TMP_DIR/dashboard-purge.json" \
  -X POST \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/assets/purge?edge_path=/edge/assets/uploads/smoke/dashboard-upload.txt&host=cdn.localhost')"
expect_code "$dashboard_purge_code" "202" "dashboard asset purge"
grep -q '"status":"purged"' "$TMP_DIR/dashboard-purge.json" || fail "dashboard purge response missing purged status"
grep -q '"purge_status":"accepted"' "$TMP_DIR/dashboard-purge.json" || fail "dashboard purge did not accept purge"

purged_asset_cache=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/dashboard-purge-fetch.headers" -o "$TMP_DIR/dashboard-purge-fetch.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt
  purged_asset_cache="$(header_value "$TMP_DIR/dashboard-purge-fetch.headers" "X-AstraCDN-Cache")"
  if [[ "$purged_asset_cache" == "MISS" ]]; then
    break
  fi
  sleep 1
done
[[ "$purged_asset_cache" == "MISS" ]] || fail "purged asset cache header is $purged_asset_cache, want MISS"
grep -q 'dashboard replaced asset' "$TMP_DIR/dashboard-purge-fetch.body" || fail "purged asset body missing expected content"

dashboard_delete_code="$(curl_code "$TMP_DIR/dashboard-delete.json" \
  -X DELETE \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/assets?edge_path=/edge/assets/uploads/smoke/dashboard-upload.txt&host=cdn.localhost')"
expect_code "$dashboard_delete_code" "200" "dashboard asset delete"
grep -q '"purge_status":"accepted"' "$TMP_DIR/dashboard-delete.json" || fail "dashboard delete did not accept purge"

dashboard_assets_after_delete_code="$(curl_code "$TMP_DIR/dashboard-assets-after-delete.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  'http://localhost:3000/api/assets?folder=uploads&limit=20')"
expect_code "$dashboard_assets_after_delete_code" "200" "dashboard asset list after delete"
if grep -q '"edge_path":"/edge/assets/uploads/smoke/dashboard-upload.txt"' "$TMP_DIR/dashboard-assets-after-delete.json"; then
  fail "dashboard asset list still contains deleted asset"
fi

deleted_asset_code=""
for _ in $(seq 1 15); do
  deleted_asset_code="$(curl_code "$TMP_DIR/dashboard-upload-deleted.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/assets/uploads/smoke/dashboard-upload.txt || true)"
  if [[ "$deleted_asset_code" == "404" ]]; then
    break
  fi
  sleep 1
done
expect_code "$deleted_asset_code" "404" "deleted dashboard asset edge request"

log "checking control-plane route delivery rules"
origin_code="$(curl_code "$TMP_DIR/control-rule-origin.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"control-rule-origin","base_url":"http://example-origin:9000","headers":{}}' \
  http://localhost:8081/v1/origins)"
expect_code "$origin_code" "202" "control rule origin create"
control_rule_origin_id="$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$TMP_DIR/control-rule-origin.json" | head -n1)"
[[ -n "$control_rule_origin_id" ]] || fail "control rule origin id not found"

route_header_code="$(curl_code "$TMP_DIR/control-rule-route.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/control-rule/\",\"origin_id\":${control_rule_origin_id},\"delivery_rules\":{\"set_headers\":[{\"path_prefix\":\"/edge/control-rule\",\"name\":\"X-AstraCDN-Control-Rule\",\"value\":\"yes\"}]}}" \
  http://localhost:8081/v1/routes)"
expect_code "$route_header_code" "202" "control rule route create"
control_rule_route_id="$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$TMP_DIR/control-rule-route.json" | head -n1)"
[[ -n "$control_rule_route_id" ]] || fail "control rule route id not found"

control_rule_header=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/control-rule.headers" -o "$TMP_DIR/control-rule.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/control-rule/smoke
  control_rule_header="$(header_value "$TMP_DIR/control-rule.headers" "X-AstraCDN-Control-Rule")"
  if [[ "$control_rule_header" == "yes" ]]; then
    break
  fi
  sleep 1
done
[[ "$control_rule_header" == "yes" ]] || fail "control-plane route response header is $control_rule_header"

route_redirect_code="$(curl_code "$TMP_DIR/control-redirect-route.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/control-redirect/\",\"origin_id\":${control_rule_origin_id},\"delivery_rules\":{\"redirects\":[{\"path_prefix\":\"/edge/control-redirect\",\"target\":\"https://control.example{path}\",\"status\":308}]}}" \
  http://localhost:8081/v1/routes)"
expect_code "$route_redirect_code" "202" "control redirect route create"

control_redirect_status=""
control_redirect_location=""
for _ in $(seq 1 15); do
  curl -sS -D "$TMP_DIR/control-redirect.headers" -o "$TMP_DIR/control-redirect.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/control-redirect/smoke
  control_redirect_status="$(awk 'NR == 1 { print $2 }' "$TMP_DIR/control-redirect.headers")"
  control_redirect_location="$(header_value "$TMP_DIR/control-redirect.headers" "Location")"
  if [[ "$control_redirect_status" == "308" ]]; then
    break
  fi
  sleep 1
done
[[ "$control_redirect_status" == "308" ]] || fail "control-plane route redirect returned HTTP $control_redirect_status, want 308"
[[ "$control_redirect_location" == "https://control.example/edge/control-redirect/smoke" ]] || fail "control-plane redirect location is $control_redirect_location"

route_waf_code="$(curl_code "$TMP_DIR/control-waf-route.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/control-waf/\",\"origin_id\":${control_rule_origin_id},\"waf_rules\":{\"enabled\":true,\"path_prefixes\":[\"/edge/control-waf\"]}}" \
  http://localhost:8081/v1/routes)"
expect_code "$route_waf_code" "202" "control WAF route create"

control_waf_code=""
for _ in $(seq 1 15); do
  control_waf_code="$(curl_code "$TMP_DIR/control-waf.body" \
    -H 'Host: cdn.localhost' \
    http://localhost:8080/edge/control-waf/smoke)"
  if [[ "$control_waf_code" == "403" ]]; then
    break
  fi
  sleep 1
done
expect_code "$control_waf_code" "403" "control-plane WAF blocked edge request"

route_control_limit_code="$(curl_code "$TMP_DIR/control-limit-route.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"path_prefix\":\"/control-limit/\",\"origin_id\":${control_rule_origin_id},\"rate_limit_rules\":[{\"path_prefix\":\"/edge/control-limit\",\"rps\":1,\"burst\":1}]}" \
  http://localhost:8081/v1/routes)"
expect_code "$route_control_limit_code" "202" "control rate-limit route create"

control_limit_first=""
for _ in $(seq 1 15); do
  control_limit_first="$(curl_code "$TMP_DIR/control-limit-first.body" \
    -H 'Host: cdn.localhost' \
    -H 'X-Forwarded-For: 198.51.100.20' \
    http://localhost:8080/edge/control-limit/smoke)"
  if [[ "$control_limit_first" == "200" ]]; then
    break
  fi
  sleep 1
done
expect_code "$control_limit_first" "200" "first control-plane rate-limited edge request"
control_limit_second="$(curl_code "$TMP_DIR/control-limit-second.body" \
  -H 'Host: cdn.localhost' \
  -H 'X-Forwarded-For: 198.51.100.20' \
  http://localhost:8080/edge/control-limit/smoke)"
expect_code "$control_limit_second" "429" "second control-plane rate-limited edge request"

rule_versions_code="$(curl_code "$TMP_DIR/route-rule-versions.json" \
  -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8081/v1/route-rule-versions?route_id=${control_rule_route_id}&limit=5")"
expect_code "$rule_versions_code" "200" "route rule versions list"
grep -q '"route_rule_versions":' "$TMP_DIR/route-rule-versions.json" || fail "route rule versions response missing list"
grep -q '"version":1' "$TMP_DIR/route-rule-versions.json" || fail "route rule versions missing version 1"

dashboard_rule_versions_code="$(curl_code "$TMP_DIR/dashboard-route-rule-versions.json" \
  -H "X-AstraCDN-Dashboard-Token: $API_KEY" \
  "http://localhost:3000/api/control/v1/route-rule-versions?route_id=${control_rule_route_id}&limit=5")"
expect_code "$dashboard_rule_versions_code" "200" "dashboard route rule versions list"
grep -q '"route_rule_versions":' "$TMP_DIR/dashboard-route-rule-versions.json" || fail "dashboard route rule versions response missing list"
grep -q '"version":1' "$TMP_DIR/dashboard-route-rule-versions.json" || fail "dashboard route rule versions missing version 1"

ingress_code="$(curl_code "$TMP_DIR/ingress-edge.body" \
  -k \
  -H 'Host: cdn.localhost' \
  https://localhost:8443/edge/domain-smoke)"
expect_code "$ingress_code" "200" "HTTP/3-capable ingress edge request"
curl -k -sS -D "$TMP_DIR/ingress-edge.headers" -o "$TMP_DIR/ingress-edge.body" \
  -H 'Host: cdn.localhost' \
  https://localhost:8443/edge/domain-smoke
ingress_alt_svc="$(header_value "$TMP_DIR/ingress-edge.headers" "Alt-Svc")"
[[ "$ingress_alt_svc" == *"h3="* ]] || fail "ingress Alt-Svc is $ingress_alt_svc, want h3 advertisement"

unknown_code="$(curl_code "$TMP_DIR/domain-unknown.body" \
  -H 'Host: unknown.localhost' \
  http://localhost:8080/edge/domain-smoke)"
expect_code "$unknown_code" "404" "unknown domain edge request"

log "checking edge WAF path blocking"
waf_code="$(curl_code "$TMP_DIR/waf-block.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/waf-block/smoke)"
expect_code "$waf_code" "403" "WAF blocked edge request"

log "checking edge redirect rule"
curl -sS -D "$TMP_DIR/redirect-rule.headers" -o "$TMP_DIR/redirect-rule.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/redirect-smoke
redirect_status="$(awk 'NR == 1 { print $2 }' "$TMP_DIR/redirect-rule.headers")"
redirect_location="$(header_value "$TMP_DIR/redirect-rule.headers" "Location")"
[[ "$redirect_status" == "301" ]] || fail "redirect rule returned HTTP $redirect_status, want 301"
[[ "$redirect_location" == "https://redirect.example/edge/redirect-smoke" ]] || fail "redirect location is $redirect_location"

log "checking host/path scoped rate limiting"
route_limit_first="$(curl_code "$TMP_DIR/route-limit-first.body" \
  -H 'Host: cdn.localhost' \
  -H 'X-Forwarded-For: 198.51.100.10' \
  http://localhost:8080/edge/route-limit/smoke)"
expect_code "$route_limit_first" "200" "first scoped rate-limited edge request"
route_limit_second="$(curl_code "$TMP_DIR/route-limit-second.body" \
  -H 'Host: cdn.localhost' \
  -H 'X-Forwarded-For: 198.51.100.10' \
  http://localhost:8080/edge/route-limit/smoke)"
expect_code "$route_limit_second" "429" "second scoped rate-limited edge request"

log "checking signed cookie protected path"
cookie_missing_code="$(curl_code "$TMP_DIR/cookie-missing.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/cookie-protected/smoke)"
expect_code "$cookie_missing_code" "403" "missing signed cookie edge request"
cookie_expires="$(($(date +%s) + 300))"
cookie_signature="$(printf 'cookie\n/edge/cookie-protected\n%s' "$cookie_expires" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" -r | awk '{print $1}')"
cookie_valid_code="$(curl_code "$TMP_DIR/cookie-valid.body" \
  -H 'Host: cdn.localhost' \
  -H "Cookie: AstraCDN-Signature=${cookie_expires}:${cookie_signature}" \
  http://localhost:8080/edge/cookie-protected/smoke)"
expect_code "$cookie_valid_code" "200" "valid signed cookie edge request"

log "checking edge cache miss/hit"
curl -sS -D "$TMP_DIR/edge-first.headers" -o "$TMP_DIR/edge-first.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/smoke-test
first_cache="$(header_value "$TMP_DIR/edge-first.headers" "X-AstraCDN-Cache")"
rule_header="$(header_value "$TMP_DIR/edge-first.headers" "X-AstraCDN-Rule")"
[[ "$first_cache" == "MISS" ]] || fail "first edge request cache header is $first_cache, want MISS"
[[ "$rule_header" == "smoke" ]] || fail "edge response rule header is $rule_header, want smoke"

curl -sS -D "$TMP_DIR/edge-second.headers" -o "$TMP_DIR/edge-second.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/smoke-test
second_cache="$(header_value "$TMP_DIR/edge-second.headers" "X-AstraCDN-Cache")"
[[ "$second_cache" == "HIT" ]] || fail "second edge request cache header is $second_cache, want HIT"
cmp -s "$TMP_DIR/edge-first.body" "$TMP_DIR/edge-second.body" || fail "cached edge body changed"

log "checking file-backed origin assets"
curl -sS -D "$TMP_DIR/asset-first.headers" -o "$TMP_DIR/asset-first.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/assets/photos/smoke-photo.txt
asset_first_cache="$(header_value "$TMP_DIR/asset-first.headers" "X-AstraCDN-Cache")"
asset_surrogate="$(header_value "$TMP_DIR/asset-first.headers" "Surrogate-Key")"
[[ "$asset_first_cache" == "MISS" ]] || fail "first asset cache header is $asset_first_cache, want MISS"
[[ "$asset_surrogate" == *"asset:photos"* ]] || fail "asset surrogate key is $asset_surrogate, want asset:photos"
grep -q 'smoke photo asset' "$TMP_DIR/asset-first.body" || fail "asset body missing expected content"

curl -sS -D "$TMP_DIR/asset-second.headers" -o "$TMP_DIR/asset-second.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/assets/photos/smoke-photo.txt
asset_second_cache="$(header_value "$TMP_DIR/asset-second.headers" "X-AstraCDN-Cache")"
[[ "$asset_second_cache" == "HIT" ]] || fail "second asset cache header is $asset_second_cache, want HIT"

curl -sS -D "$TMP_DIR/asset-range.headers" -o "$TMP_DIR/asset-range.body" \
  -H 'Host: cdn.localhost' \
  -H 'Range: bytes=2-5' \
  http://localhost:8080/edge/assets/videos/smoke-video.txt
asset_range_status="$(head -n 1 "$TMP_DIR/asset-range.headers" | tr -d '\r')"
asset_content_range="$(header_value "$TMP_DIR/asset-range.headers" "Content-Range")"
[[ "$asset_range_status" == *"206"* ]] || fail "asset range status is $asset_range_status, want 206"
[[ "$asset_content_range" == "bytes 2-5/17" ]] || fail "asset content-range is $asset_content_range, want bytes 2-5/17"
[[ "$(cat "$TMP_DIR/asset-range.body")" == "2345" ]] || fail "asset range body is $(cat "$TMP_DIR/asset-range.body"), want 2345"

log "checking Brotli delivery compression"
curl -sS -D "$TMP_DIR/brotli.headers" -o "$TMP_DIR/brotli.body" \
  -H 'Host: cdn.localhost' \
  -H 'Accept-Encoding: br' \
  http://localhost:8080/edge/brotli-smoke
brotli_encoding="$(header_value "$TMP_DIR/brotli.headers" "Content-Encoding")"
[[ "$brotli_encoding" == "br" ]] || fail "Brotli content-encoding is $brotli_encoding, want br"

log "checking large object streaming"
curl -sS -D "$TMP_DIR/large-object.headers" -o "$TMP_DIR/large-object.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/large-object-smoke
large_streaming="$(header_value "$TMP_DIR/large-object.headers" "X-AstraCDN-Streaming")"
large_layer="$(header_value "$TMP_DIR/large-object.headers" "X-AstraCDN-Cache-Layer")"
large_size="$(wc -c < "$TMP_DIR/large-object.body" | tr -d '[:space:]')"
[[ "$large_streaming" == "1" ]] || fail "large object streaming header is $large_streaming, want 1"
[[ "$large_layer" == "origin-stream" ]] || fail "large object cache layer is $large_layer, want origin-stream"
[[ "$large_size" == "8192" ]] || fail "large object body size is $large_size, want 8192"

curl -sS -D "$TMP_DIR/large-object-second.headers" -o "$TMP_DIR/large-object-second.body" \
  -H 'Host: cdn.localhost' \
  http://localhost:8080/edge/large-object-smoke
large_second_cache="$(header_value "$TMP_DIR/large-object-second.headers" "X-AstraCDN-Cache")"
large_segmented="$(header_value "$TMP_DIR/large-object-second.headers" "X-AstraCDN-Segmented-Cache")"
[[ "$large_second_cache" == "HIT" ]] || fail "second large object cache header is $large_second_cache, want HIT"
[[ "$large_segmented" == "1" ]] || fail "segmented cache header is $large_segmented, want 1"
cmp -s "$TMP_DIR/large-object.body" "$TMP_DIR/large-object-second.body" || fail "segmented large object body changed"

log "checking image transformation"
curl -sS -D "$TMP_DIR/image-transform-first.headers" -o "$TMP_DIR/image-transform-first.body" \
  -H 'Host: cdn.localhost' \
  'http://localhost:8080/edge/image-smoke.png?width=2&format=png'
image_transform="$(header_value "$TMP_DIR/image-transform-first.headers" "X-AstraCDN-Image-Transform")"
image_type="$(header_value "$TMP_DIR/image-transform-first.headers" "Content-Type")"
[[ "$image_transform" == "width=2;height=1;format=png" ]] || fail "image transform header is $image_transform"
[[ "$image_type" == "image/png" ]] || fail "image content type is $image_type, want image/png"

curl -sS -D "$TMP_DIR/image-transform-second.headers" -o "$TMP_DIR/image-transform-second.body" \
  -H 'Host: cdn.localhost' \
  'http://localhost:8080/edge/image-smoke.png?width=2&format=png'
image_cache="$(header_value "$TMP_DIR/image-transform-second.headers" "X-AstraCDN-Cache")"
[[ "$image_cache" == "HIT" ]] || fail "second transformed image cache header is $image_cache, want HIT"
cmp -s "$TMP_DIR/image-transform-first.body" "$TMP_DIR/image-transform-second.body" || fail "cached transformed image body changed"

log "checking control registration and list"
register_code="$(curl_code "$TMP_DIR/register.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":"smoke-edge","address":"http://edge:8080","capabilities":["cache","proxy"]}' \
  http://localhost:8081/v1/edge/register)"
expect_code "$register_code" "202" "edge registration"
grep -q '"node_id":"smoke-edge"' "$TMP_DIR/register.json" || fail "registration response missing node"

nodes_code="$(curl_code "$TMP_DIR/nodes.json" http://localhost:8081/v1/edge/nodes)"
expect_code "$nodes_code" "200" "edge node list"
grep -q '"node_id":"smoke-edge"' "$TMP_DIR/nodes.json" || fail "node list missing registered node"

log "checking cache invalidation endpoint"
invalidate_code="$(curl_code "$TMP_DIR/invalidate.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"keys":["/edge/smoke-test"],"requested_by":"smoke-test"}' \
  http://localhost:8081/v1/cache/invalidate)"
expect_code "$invalidate_code" "202" "cache invalidation"
grep -q '"mode":"keys"' "$TMP_DIR/invalidate.json" || fail "invalidation response missing keys mode"

log "checking surrogate-key cache invalidation"
surrogate_path="/edge/surrogate-smoke"
curl -sS -D "$TMP_DIR/surrogate-first.headers" -o "$TMP_DIR/surrogate-first.body" \
  -H 'Host: cdn.localhost' \
  "http://localhost:8080${surrogate_path}"
surrogate_first_cache="$(header_value "$TMP_DIR/surrogate-first.headers" "X-AstraCDN-Cache")"
[[ "$surrogate_first_cache" == "MISS" ]] || fail "first surrogate cache header is $surrogate_first_cache, want MISS"

curl -sS -D "$TMP_DIR/surrogate-second.headers" -o "$TMP_DIR/surrogate-second.body" \
  -H 'Host: cdn.localhost' \
  "http://localhost:8080${surrogate_path}"
surrogate_second_cache="$(header_value "$TMP_DIR/surrogate-second.headers" "X-AstraCDN-Cache")"
[[ "$surrogate_second_cache" == "HIT" ]] || fail "second surrogate cache header is $surrogate_second_cache, want HIT"

surrogate_invalidate_code="$(curl_code "$TMP_DIR/surrogate-invalidate.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"host":"cdn.localhost","tags":["smoke-tag"],"requested_by":"smoke-test"}' \
  http://localhost:8081/v1/cache/invalidate)"
expect_code "$surrogate_invalidate_code" "202" "surrogate cache invalidation"
grep -q '"mode":"tags"' "$TMP_DIR/surrogate-invalidate.json" || fail "surrogate invalidation response missing tags mode"

surrogate_after_cache=""
for _ in $(seq 1 10); do
  curl -sS -D "$TMP_DIR/surrogate-after.headers" -o "$TMP_DIR/surrogate-after.body" \
    -H 'Host: cdn.localhost' \
    "http://localhost:8080${surrogate_path}"
  surrogate_after_cache="$(header_value "$TMP_DIR/surrogate-after.headers" "X-AstraCDN-Cache")"
  if [[ "$surrogate_after_cache" == "MISS" ]]; then
    break
  fi
  sleep 1
done
[[ "$surrogate_after_cache" == "MISS" ]] || fail "surrogate tag purge did not evict cached object"

log "checking cache prewarm endpoint"
prewarm_path="/edge/prewarm-smoke"
prewarm_key="astracdn:edge-cache:host:cdn.localhost:${prewarm_path}"
prewarm_code="$(curl_code "$TMP_DIR/prewarm.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"cdn.localhost\",\"paths\":[\"${prewarm_path}\"],\"requested_by\":\"smoke-test\"}" \
  http://localhost:8081/v1/cache/prewarm)"
expect_code "$prewarm_code" "202" "cache prewarm"
grep -q "\"paths\":\\[\"${prewarm_path}\"\\]" "$TMP_DIR/prewarm.json" || fail "prewarm response missing requested path"

prewarm_cached=""
for _ in $(seq 1 15); do
  prewarm_cached="$(podman exec astra-cdn_redis_1 redis-cli EXISTS "$prewarm_key" | tr -d '\r' || true)"
  if [[ "$prewarm_cached" == "1" ]]; then
    break
  fi
  sleep 1
done
[[ "$prewarm_cached" == "1" ]] || fail "prewarm did not populate Redis cache key"

curl -sS -D "$TMP_DIR/prewarm.headers" -o "$TMP_DIR/prewarm.body" \
  -H 'Host: cdn.localhost' \
  "http://localhost:8080${prewarm_path}"
prewarm_cache="$(header_value "$TMP_DIR/prewarm.headers" "X-AstraCDN-Cache")"
[[ "$prewarm_cache" == "HIT" ]] || fail "prewarmed edge request cache header is $prewarm_cache, want HIT"

log "checking per-host and per-route cache analytics"
analytics_code="$(curl_code "$TMP_DIR/cache-analytics.json" \
  http://localhost:8080/v1/cache/analytics)"
expect_code "$analytics_code" "200" "edge cache analytics"
grep -q '"by_host":' "$TMP_DIR/cache-analytics.json" || fail "edge analytics missing by_host"
grep -q '"cdn.localhost"' "$TMP_DIR/cache-analytics.json" || fail "edge analytics missing cdn.localhost host"
grep -q '"by_route":' "$TMP_DIR/cache-analytics.json" || fail "edge analytics missing by_route"
grep -q '"cache_fill_latency":' "$TMP_DIR/cache-analytics.json" || fail "edge analytics missing cache_fill_latency"

metrics_code="$(curl_code "$TMP_DIR/edge-metrics.txt" \
  http://localhost:8080/metrics)"
expect_code "$metrics_code" "200" "edge metrics"
grep -q 'astracdn_edge_cache_fill_latency_seconds_count' "$TMP_DIR/edge-metrics.txt" || fail "edge metrics missing cache-fill latency count"
awk '$1 == "astracdn_edge_waf_blocks_total" && $2 >= 3 { found = 1 } END { exit found ? 0 : 1 }' "$TMP_DIR/edge-metrics.txt" || fail "edge metrics missing WAF block count"
awk '$1 == "astracdn_edge_rate_limit_blocks_total" && $2 >= 3 { found = 1 } END { exit found ? 0 : 1 }' "$TMP_DIR/edge-metrics.txt" || fail "edge metrics missing scoped rate-limit block"

snapshot_code="$(curl_code "$TMP_DIR/cache-snapshot.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "edge_node_id": "smoke-edge",
    "cache": {
      "requests": 2,
      "hits": 1,
      "misses": 1,
      "hit_ratio": 0.5,
      "by_layer": {
        "memory": {"result": "hit", "requests": 1},
        "origin": {"result": "miss", "requests": 1}
      },
      "by_host": {
        "cdn.localhost": {
          "requests": 2,
          "hits": 1,
          "misses": 1,
          "hit_ratio": 0.5,
          "by_layer": {
            "memory": {"result": "hit", "requests": 1},
            "origin": {"result": "miss", "requests": 1}
          }
        }
      },
      "by_route": {
        "cdn.localhost:fallback:/": {
          "requests": 2,
          "hits": 1,
          "misses": 1,
          "hit_ratio": 0.5,
          "by_layer": {
            "memory": {"result": "hit", "requests": 1},
            "origin": {"result": "miss", "requests": 1}
          }
        }
      },
      "cache_fill_latency": {
        "count": 1,
        "sum_seconds": 0.025,
        "avg_seconds": 0.025,
        "max_seconds": 0.025
      }
    }
  }' \
  http://localhost:8081/v1/analytics/cache-snapshots)"
expect_code "$snapshot_code" "202" "cache analytics snapshot"
grep -q '"by_host":' "$TMP_DIR/cache-snapshot.json" || fail "snapshot response missing by_host"
grep -q '"by_route":' "$TMP_DIR/cache-snapshot.json" || fail "snapshot response missing by_route"
grep -q '"cache_fill_latency":' "$TMP_DIR/cache-snapshot.json" || fail "snapshot response missing cache_fill_latency"

prometheus_export_code="$(curl_code "$TMP_DIR/cache-snapshots.prom" \
  -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8081/v1/analytics/cache-snapshots/prometheus?limit=10")"
expect_code "$prometheus_export_code" "200" "cache analytics prometheus export"
grep -q 'astracdn_control_cache_snapshot_requests' "$TMP_DIR/cache-snapshots.prom" || fail "prometheus export missing cache snapshot requests"
grep -q 'astracdn_control_cache_snapshot_cache_fill_latency_seconds' "$TMP_DIR/cache-snapshots.prom" || fail "prometheus export missing cache-fill latency"

log "checking edge health dashboard payload"
health_code="$(curl_code "$TMP_DIR/edge-health.json" \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8081/v1/edge/health)"
expect_code "$health_code" "200" "edge health"
grep -q '"edges":' "$TMP_DIR/edge-health.json" || fail "edge health response missing edges"
grep -q '"node_id":"smoke-edge"' "$TMP_DIR/edge-health.json" || fail "edge health missing smoke-edge"
grep -q '"cache_fill_latency":' "$TMP_DIR/edge-health.json" || fail "edge health missing cache_fill_latency"

log "checking control-plane audit logs"
audit_code="$(curl_code "$TMP_DIR/audit-logs.json" \
  -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8081/v1/audit-logs?limit=50")"
expect_code "$audit_code" "200" "audit logs"
grep -q '"audit_logs":' "$TMP_DIR/audit-logs.json" || fail "audit log response missing audit_logs"
grep -q '"resource_type":"cache_analytics_snapshot"' "$TMP_DIR/audit-logs.json" || fail "audit log missing cache analytics snapshot write"
grep -q '"actor":"api_key:' "$TMP_DIR/audit-logs.json" || fail "audit log missing redacted actor"

log "checking inference exact cache"
infer_payload='{"prompt":"smoke test prompt","params":{"temperature":0.1}}'
infer_first_code="$(curl_code "$TMP_DIR/infer-first.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "$infer_payload" \
  http://localhost:8082/v1/infer)"
expect_code "$infer_first_code" "200" "first inference"
grep -q '"cache_hit":"miss"' "$TMP_DIR/infer-first.json" || fail "first inference did not miss cache"

infer_second_code="$(curl_code "$TMP_DIR/infer-second.json" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "$infer_payload" \
  http://localhost:8082/v1/infer)"
expect_code "$infer_second_code" "200" "second inference"
grep -q '"cache_hit":"exact"' "$TMP_DIR/infer-second.json" || fail "second inference did not hit exact cache"

log "checking CORS preflight"
curl -sS -D "$TMP_DIR/cors.headers" -o "$TMP_DIR/cors.body" -X OPTIONS \
  http://localhost:8082/v1/infer \
  -H 'Origin: https://dashboard.example' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Authorization,Content-Type,X-AstraCDN-API-Key,X-Request-ID'
cors_status="$(awk 'NR == 1 { print $2 }' "$TMP_DIR/cors.headers")"
cors_origin="$(header_value "$TMP_DIR/cors.headers" "Access-Control-Allow-Origin")"
[[ "$cors_status" == "204" ]] || fail "CORS preflight returned HTTP $cors_status, want 204"
[[ "$cors_origin" == "https://dashboard.example" ]] || fail "CORS allow-origin is $cors_origin"

log "smoke test passed"
