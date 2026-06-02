#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APPLY="${APPLY:-false}"
PUSH_IMAGES="${PUSH_IMAGES:-false}"
RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS:-false}"
RUN_OPENTOFU="${RUN_OPENTOFU:-false}"
DEPLOY_REGIONAL_EDGES="${DEPLOY_REGIONAL_EDGES:-false}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NAMESPACE="${NAMESPACE:-astra-cdn}"
KUSTOMIZE_PATH="${KUSTOMIZE_PATH:-deploy/k8s/overlays/production}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-}"
OPENTOFU_DIR="${OPENTOFU_DIR:-deploy/opentofu}"
OPENTOFU_VAR_FILE="${OPENTOFU_VAR_FILE:-examples/production.tfvars.example}"
REGIONAL_EDGE_CONTEXTS="${REGIONAL_EDGE_CONTEXTS:-}"

log() {
  printf '[cloud-deploy] %s\n' "$*"
}

fail() {
  printf '[cloud-deploy] failed: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_var() {
  local name="$1"
  local value="${!name:-}"
  [[ -n "$value" ]] || fail "$name is required"
}

kubectl_cmd() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

render_core_manifests() {
  log "rendering Kubernetes manifests from $KUSTOMIZE_PATH"
  if command -v kubectl >/dev/null 2>&1; then
    kubectl kustomize "$KUSTOMIZE_PATH" >/tmp/astra-cdn-cloud-rendered.yaml
  elif command -v go >/dev/null 2>&1; then
    go run sigs.k8s.io/kustomize/kustomize/v5@v5.7.1 build "$KUSTOMIZE_PATH" >/tmp/astra-cdn-cloud-rendered.yaml
  else
    fail "kubectl or go is required to render Kubernetes manifests"
  fi
  log "rendered /tmp/astra-cdn-cloud-rendered.yaml"
}

build_and_push_images() {
  require_var IMAGE_REGISTRY
  require_var IMAGE_TAG
  local services=(edge control inference origin dashboard)
  local compose_names=(edge control inference example-origin dashboard)

  for i in "${!services[@]}"; do
    local service="${services[$i]}"
    local compose_name="${compose_names[$i]}"
    local local_image="localhost/astra-cdn_${compose_name}:latest"
    local remote_image="${IMAGE_REGISTRY}/astra-cdn-${service}:${IMAGE_TAG}"
    log "building $compose_name image with Podman"
    podman build -f "services/${service}/Containerfile" -t "$remote_image" .
    log "pushing $remote_image"
    podman push "$remote_image"
    if podman image exists "$local_image" >/dev/null 2>&1; then
      log "local compose image also exists: $local_image"
    fi
  done
}

run_opentofu() {
  require_cmd tofu
  log "generating global edge artifacts with OpenTofu"
  (
    cd "$OPENTOFU_DIR"
    tofu init
    if [[ "$APPLY" == "true" ]]; then
      tofu apply -auto-approve -var-file="$OPENTOFU_VAR_FILE"
    else
      tofu plan -var-file="$OPENTOFU_VAR_FILE"
    fi
  )
}

apply_core_stack() {
  require_var KUBE_CONTEXT
  log "applying core stack to context=$KUBE_CONTEXT namespace=$NAMESPACE"
  kubectl_cmd apply -k "$KUSTOMIZE_PATH"
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/control --timeout=180s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/edge --timeout=180s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/inference --timeout=180s
  kubectl_cmd -n "$NAMESPACE" rollout status deploy/dashboard --timeout=180s
}

run_migrations() {
  log "running database migrations through scripts/db-migrate.sh"
  ./scripts/db-migrate.sh up
}

apply_regional_edges() {
  [[ -n "$REGIONAL_EDGE_CONTEXTS" ]] || fail "REGIONAL_EDGE_CONTEXTS is required when DEPLOY_REGIONAL_EDGES=true"
  local generated_dir="$OPENTOFU_DIR/generated"
  [[ -d "$generated_dir" ]] || fail "missing generated regional edge directory: $generated_dir"

  IFS=',' read -r -a mappings <<<"$REGIONAL_EDGE_CONTEXTS"
  for mapping in "${mappings[@]}"; do
    local region="${mapping%%=*}"
    local context="${mapping#*=}"
    [[ -n "$region" && -n "$context" && "$region" != "$context" ]] || fail "invalid REGIONAL_EDGE_CONTEXTS entry: $mapping"
    local manifest="$generated_dir/edge-${region}.yaml"
    [[ -f "$manifest" ]] || fail "missing regional edge manifest: $manifest"
    log "applying $manifest to region=$region context=$context"
    kubectl --context "$context" apply -f "$manifest"
    local regional_namespace="astra-cdn-${region}"
    kubectl --context "$context" -n "$regional_namespace" rollout status "deploy/edge-${region}" --timeout=180s
  done
}

if [[ "$APPLY" == "true" ]]; then
  require_cmd kubectl
fi
if [[ "$PUSH_IMAGES" == "true" ]]; then
  require_cmd podman
fi
render_core_manifests

if [[ "$PUSH_IMAGES" == "true" ]]; then
  build_and_push_images
else
  log "skipping image push; set PUSH_IMAGES=true to build and push release images"
fi

if [[ "$RUN_OPENTOFU" == "true" ]]; then
  run_opentofu
else
  log "skipping OpenTofu; set RUN_OPENTOFU=true to plan/apply global edge artifacts"
fi

if [[ "$RUN_DB_MIGRATIONS" == "true" ]]; then
  run_migrations
else
  log "skipping database migrations; set RUN_DB_MIGRATIONS=true after database env is configured"
fi

if [[ "$APPLY" == "true" ]]; then
  apply_core_stack
  if [[ "$DEPLOY_REGIONAL_EDGES" == "true" ]]; then
    apply_regional_edges
  fi
  log "deployment completed"
else
  log "dry run completed; set APPLY=true to deploy to the configured Kubernetes context"
fi
