# Kubernetes Overlays

Environment overlays live in this directory and compose the shared
[`../base`](../base) manifests.

## Render

```sh
kubectl kustomize deploy/k8s/overlays/staging
kubectl kustomize deploy/k8s/overlays/production
```

## Apply

```sh
kubectl apply -k deploy/k8s/overlays/staging
kubectl apply -k deploy/k8s/overlays/production
```

Before applying, replace the placeholder image tags in each overlay with
published release tags and provide environment-specific secrets. See the
parent [Kubernetes README](../README.md) and
[production TLS notes](../../../docs/production-tls.md) for deployment setup.
