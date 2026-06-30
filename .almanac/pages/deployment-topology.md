---
title: Deployment Topology
summary: Deployment is modeled through local compose, Kubernetes base/overlays, Caddy ingress, and an OpenTofu generator for regional edge manifests and global DNS routing plans.
topics: [deployment, operations, architecture]
sources:
  - id: compose
    type: file
    path: podman-compose.yml
    note: Defines local development services, profiles, ports, volumes, and environment.
  - id: makefile
    type: file
    path: Makefile
    note: Defines local stack, MinIO, multi-edge, smoke, test, and deployment commands.
  - id: k8s-readme
    type: file
    path: deploy/k8s/README.md
    note: Describes the Kubernetes skeleton.
  - id: k8s-base
    type: file
    path: deploy/k8s/base/
    note: Contains base Kubernetes manifests for namespace, config, secrets example, dependencies, services, and deployments.
  - id: opentofu-readme
    type: file
    path: deploy/opentofu/README.md
    note: Describes the OpenTofu global edge template and required production resources.
  - id: opentofu-main
    type: file
    path: deploy/opentofu/main.tf
    note: Generates regional edge manifests and a DNS routing plan.
status: active
verified: 2026-06-30
---

AstraCDN deployment has three levels: local compose for development and smoke tests, Kubernetes manifests for a cluster skeleton, and OpenTofu templates for regional edge generation and global routing plans. The OpenTofu module is provider-neutral; it does not provision cloud load balancers, databases, object storage, DNS, or Anycast by itself [@opentofu-readme].

## Local Compose

`make up` runs `podman-compose -f podman-compose.yml up --build`. The stack includes Postgres, Redis, NATS, example origin, edge, Caddy edge ingress, control, inference, and dashboard. It maps service ports to localhost and initializes Postgres from `db/schema.sql` [@compose] [@makefile].

Profiles add:

- `object-storage`: MinIO plus bucket initialization for S3-compatible asset mode.
- `multi-edge`: a second edge process on host port `8083` with its own `EDGE_NODE_ID` [@compose].

`make up-minio` sets both origin and dashboard storage mode to S3 and points them at MinIO. `make up-multi-edge` starts the multi-edge profile [@makefile].

## Kubernetes Skeleton

`deploy/k8s/base/` includes namespace, configmap, secret example, Postgres, Redis, NATS, origin assets PVC, example origin, edge, control, inference, and dashboard manifests. Edge is a `LoadBalancer` service with two replicas and `EDGE_NODE_ID` from pod name. Control, dashboard, and inference are single-replica deployments in the base skeleton [@k8s-base].

The base manifests use placeholder images like `ghcr.io/your-org/astra-cdn-edge:latest`; production users must replace image references and secrets before deployment.

## Ingress

The local ingress service uses Caddy from `services/ingress/Containerfile` with `deploy/local/Caddyfile`, exposing HTTPS/HTTP3 on host port `8443`. It fronts edge for local TLS/HTTP3 checks [@compose].

## OpenTofu Global Edge

`deploy/opentofu/main.tf` builds image references from `container_registry` and `environment`, creates a regional edge object for each configured region, renders one `edge-<region>.yaml` manifest from `templates/regional-edge.yaml.tftpl`, and writes `global-dns-routing-plan.json` under the configured output directory [@opentofu-main].

The generated DNS plan supports routing modes named `latency_dns`, `geo_dns`, and `anycast`, but the module only emits the plan. A cloud/provider-specific layer must consume that plan and create DNS or traffic-director resources [@opentofu-readme].

## Operational Commands

Use `make test` for `go test ./...`, `make smoke` for the full local smoke script, `make global-edge-plan` for OpenTofu planning, `make cloud-deploy` for the deployment script, and `make cloud-verify` for production/cloud verification [@makefile].

## Related Pages

Read [[observability-and-operations]] for smoke, migration, and cloud verification details. Read [[system-architecture]] for the runtime service graph.
