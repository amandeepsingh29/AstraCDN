# Kubernetes Deployment Skeleton

This directory contains a plain Kubernetes starting point for AstraCDN.

It is intentionally a skeleton:

- Image names use `ghcr.io/your-org/astra-cdn-*`.
- `secret.example.yaml` contains placeholder values only.
- Postgres, Redis, and NATS are included for small deployments and test
  clusters. For production, replace them with managed services where possible.

## Render

```sh
kubectl kustomize deploy/k8s/base
```

If `kubectl` is unavailable, validate YAML parsing with:

```sh
ruby -ryaml -e 'Dir["deploy/k8s/base/*.yaml"].each { |f| YAML.load_stream(File.read(f)) }; puts "ok"'
```

## Before Applying

1. Build and publish service images.
2. Replace image names in:
   - `base/edge.yaml`
   - `base/control.yaml`
   - `base/inference.yaml`
   - `base/example-origin.yaml`
   - `base/dashboard.yaml`
3. Copy `base/secret.example.yaml` to an environment-specific secret manifest
   outside version control, or create the secret directly with `kubectl`.
4. Set production-safe values in `base/configmap.yaml`.
5. Configure production TLS with `../../docs/production-tls.md`. The example
   ingress at `base/edge-ingress.example.yaml` is not included in the base
   kustomization until you copy or reference it from an environment overlay.
6. If using cert-manager, adapt `base/cert-issuer.example.yaml` with your real
   email and DNS/HTTP solver settings.
7. For full cloud infrastructure planning, use the OpenTofu starter in
   `../opentofu`.

## Apply

```sh
kubectl apply -k deploy/k8s/base
```

## Check

```sh
kubectl -n astra-cdn get pods
kubectl -n astra-cdn get svc
kubectl -n astra-cdn rollout status deploy/edge
kubectl -n astra-cdn rollout status deploy/control
kubectl -n astra-cdn rollout status deploy/inference
kubectl -n astra-cdn rollout status deploy/dashboard
```
