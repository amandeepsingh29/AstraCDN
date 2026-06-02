output "service_images" {
  description = "Image names expected by Kubernetes overlays."
  value       = local.service_images
}

output "edge_regions" {
  description = "Regional edge deployment map for cloud-specific modules and generated manifests."
  value       = local.edge_regions
}

output "regional_edge_manifests" {
  description = "Generated Kubernetes manifest path for each regional edge."
  value = {
    for region, file in local_file.regional_edge_manifest : region => file.filename
  }
}

output "dns_routing_plan" {
  description = "Provider-neutral global traffic routing plan."
  value       = local.dns_routing_plan
}

output "dns_routing_plan_file" {
  description = "Generated JSON file containing the global DNS/traffic-routing plan."
  value       = local_file.dns_routing_plan.filename
}

output "cdn_domain" {
  description = "Primary CDN domain."
  value       = var.cdn_domain
}

output "dashboard_domain" {
  description = "Dashboard domain."
  value       = var.dashboard_domain
}
