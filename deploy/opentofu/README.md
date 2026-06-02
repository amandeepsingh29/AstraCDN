# AstraCDN OpenTofu Global Edge Template

This provider-neutral root module defines the AstraCDN contract for a real
multi-region edge network. It generates:

- One regional edge Kubernetes manifest per configured region.
- A global DNS or traffic-director routing plan.
- Outputs that cloud-specific AWS, OCI, GCP, Azure, or bare-metal modules can
  consume.

It does not buy IP transit, allocate Anycast IP space, or create cloud load
balancers by itself. Those provider-specific resources must be wired to the
generated manifests and routing plan.

```sh
cd deploy/opentofu
tofu init
tofu plan \
  -var-file=examples/production.tfvars.example
tofu apply \
  -var-file=examples/production.tfvars.example
```

Generated files are written under `deploy/opentofu/generated/`.

## Required Production Resources

- One Kubernetes cluster or node pool per region.
- Managed Postgres or highly available Postgres.
- Redis-compatible cache.
- NATS or cloud pub/sub bridge.
- Object storage bucket with lifecycle and replication.
- DNS records or traffic-director pools for CDN and dashboard domains.
- TLS issuer or DNS credentials for ACME automation.

## Regional Edge Rollout

1. Build and publish the edge image referenced by `service_images.edge`.
2. Run `tofu apply` to generate regional edge manifests and the routing plan.
3. Create `astra-cdn-edge-secrets` in each regional namespace with at least
   `ASTRACDN_API_KEY` or a scoped persisted key that includes `control:read` and
   `control:write`.
4. Apply each generated `edge-<region>.yaml` manifest to its regional cluster.
5. Point `edge-<region>.<cdn_domain>` at that region's Kubernetes load balancer.
6. Configure the DNS provider or traffic director to route `cdn_domain` to the
   regional edge hostnames using `global-dns-routing-plan.json`.
7. Verify `/ready`, `/health`, MISS/HIT behavior, purge fanout, and edge health
   reporting per region before enabling customer traffic.

## Routing Modes

- `latency_dns`: DNS provider returns the closest healthy regional edge.
- `geo_dns`: DNS provider returns a region based on country/continent policy.
- `anycast`: an external network provider announces the same service IP from
  multiple POPs and forwards traffic to the nearest healthy regional edge.
