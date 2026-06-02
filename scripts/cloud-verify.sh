#!/usr/bin/env bash
set -euo pipefail

CONTROL_URL="${CONTROL_URL:-}"
CDN_URL="${CDN_URL:-}"
DASHBOARD_URL="${DASHBOARD_URL:-}"
CDN_HOST="${CDN_HOST:-}"
PROBE_PATH="${PROBE_PATH:-/edge/probe.txt}"
ASTRACDN_API_KEY="${ASTRACDN_API_KEY:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NAMESPACE="${NAMESPACE:-astra-cdn}"

log() {
  printf '[cloud-verify] %s\n' "$*"
}

fail() {
  printf '[cloud-verify] failed: %s\n' "$*" >&2
  exit 1
}

require_var() {
  local name="$1"
  local value="${!name:-}"
  [[ -n "$value" ]] || fail "$name is required"
}

curl_ok() {
  local label="$1"
  shift
  local code
  code="$(curl -sS -o /tmp/astra-cdn-cloud-verify.out -w '%{http_code}' "$@" || true)"
  if [[ "$code" != "200" && "$code" != "204" ]]; then
    cat /tmp/astra-cdn-cloud-verify.out >&2 || true
    fail "$label returned HTTP $code"
  fi
  log "$label ok"
}

kubectl_cmd() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

require_var CONTROL_URL
require_var CDN_URL
require_var DASHBOARD_URL
require_var CDN_HOST
require_var ASTRACDN_API_KEY

curl_ok "control ready" "${CONTROL_URL%/}/ready"
curl_ok "dashboard health" "${DASHBOARD_URL%/}/health"
curl_ok "cdn ready" "${CDN_URL%/}/ready"
curl_ok "cdn probe" -H "Host: $CDN_HOST" "${CDN_URL%/}${PROBE_PATH}"
curl_ok "edge health API" \
  -H "Authorization: Bearer $ASTRACDN_API_KEY" \
  "${CONTROL_URL%/}/v1/edge/health"

if command -v kubectl >/dev/null 2>&1; then
  log "checking Kubernetes rollout status"
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/control --timeout=60s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/edge --timeout=60s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/inference --timeout=60s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/dashboard --timeout=60s
fi

log "cloud verification passed"
