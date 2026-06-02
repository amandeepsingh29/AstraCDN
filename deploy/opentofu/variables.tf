variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "staging"
}

variable "regions" {
  description = "Regions where edge compute should run."
  type        = list(string)
  default     = ["us-east-1"]

  validation {
    condition     = length(var.regions) > 0
    error_message = "At least one edge region is required."
  }
}

variable "cdn_domain" {
  description = "Primary CDN hostname."
  type        = string
}

variable "dashboard_domain" {
  description = "Dashboard hostname."
  type        = string
}

variable "object_storage_bucket" {
  description = "Object storage bucket name for origin assets."
  type        = string
  default     = "astra-cdn-assets"
}

variable "container_registry" {
  description = "Container image registry prefix."
  type        = string
  default     = "ghcr.io/your-org"
}

variable "edge_replicas" {
  description = "Number of edge pods per region."
  type        = number
  default     = 3

  validation {
    condition     = var.edge_replicas >= 2
    error_message = "Use at least two edge replicas per region for production readiness."
  }
}

variable "edge_service_type" {
  description = "Kubernetes service type for each regional edge deployment."
  type        = string
  default     = "LoadBalancer"

  validation {
    condition     = contains(["LoadBalancer", "NodePort", "ClusterIP"], var.edge_service_type)
    error_message = "edge_service_type must be LoadBalancer, NodePort, or ClusterIP."
  }
}

variable "edge_hostname_template" {
  description = "Regional edge hostname template. Supports {region} and {cdn_domain}."
  type        = string
  default     = "edge-{region}.{cdn_domain}"
}

variable "global_routing_mode" {
  description = "Production global traffic steering mode expected in front of regional edge endpoints."
  type        = string
  default     = "latency_dns"

  validation {
    condition     = contains(["geo_dns", "latency_dns", "anycast"], var.global_routing_mode)
    error_message = "global_routing_mode must be geo_dns, latency_dns, or anycast."
  }
}

variable "dns_provider" {
  description = "DNS provider or traffic director that will map cdn_domain to regional edge endpoints."
  type        = string
  default     = "external"
}

variable "control_base_url" {
  description = "Control-plane URL reachable from every regional edge deployment."
  type        = string
  default     = "https://control.example.com"
}

variable "redis_addr" {
  description = "Redis-compatible cache endpoint reachable from regional edge deployments."
  type        = string
  default     = "redis.example.com:6379"
}

variable "nats_url" {
  description = "NATS endpoint reachable from regional edge deployments."
  type        = string
  default     = "nats://nats.example.com:4222"
}

variable "edge_config_refresh_interval" {
  description = "How often regional edges poll the control plane when NATS events are delayed."
  type        = string
  default     = "15s"
}

variable "edge_health_push_interval" {
  description = "How often regional edge nodes push heartbeat and cache latency status."
  type        = string
  default     = "30s"
}

variable "output_dir" {
  description = "Directory where generated regional edge manifests and routing plans are written."
  type        = string
  default     = "generated"
}
