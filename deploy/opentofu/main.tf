locals {
  service_images = {
    edge      = "${var.container_registry}/astra-cdn-edge:${var.environment}"
    control   = "${var.container_registry}/astra-cdn-control:${var.environment}"
    inference = "${var.container_registry}/astra-cdn-inference:${var.environment}"
    origin    = "${var.container_registry}/astra-cdn-origin:${var.environment}"
    dashboard = "${var.container_registry}/astra-cdn-dashboard:${var.environment}"
  }

  region_slugs = {
    for region in var.regions : region => lower(replace(region, "/[^0-9A-Za-z-]/", "-"))
  }

  edge_regions = {
    for region in var.regions : region => {
      slug              = local.region_slugs[region]
      namespace         = "astra-cdn-${local.region_slugs[region]}"
      deployment_name   = "edge-${local.region_slugs[region]}"
      service_name      = "edge-${local.region_slugs[region]}"
      node_id_prefix    = "edge-${var.environment}-${local.region_slugs[region]}"
      regional_hostname = replace(replace(var.edge_hostname_template, "{region}", local.region_slugs[region]), "{cdn_domain}", var.cdn_domain)
      cdn_domain        = var.cdn_domain
      replicas          = var.edge_replicas
    }
  }

  dns_routing_plan = {
    mode          = var.global_routing_mode
    provider      = var.dns_provider
    cdn_domain    = var.cdn_domain
    dashboard     = var.dashboard_domain
    health_path   = "/ready"
    ttl_seconds   = 60
    regional_edges = [
      for region, edge in local.edge_regions : {
        region            = region
        node_id_prefix    = edge.node_id_prefix
        regional_hostname = edge.regional_hostname
        health_check_url  = "https://${edge.regional_hostname}/ready"
        target            = "regional Kubernetes LoadBalancer for ${edge.service_name}"
      }
    ]
  }
}

resource "local_file" "regional_edge_manifest" {
  for_each = local.edge_regions

  filename = "${path.module}/${var.output_dir}/edge-${each.value.slug}.yaml"
  content = templatefile("${path.module}/templates/regional-edge.yaml.tftpl", {
    cdn_domain                   = each.value.cdn_domain
    control_base_url             = var.control_base_url
    deployment_name              = each.value.deployment_name
    edge_config_refresh_interval = var.edge_config_refresh_interval
    edge_health_push_interval    = var.edge_health_push_interval
    edge_image                   = local.service_images.edge
    edge_node_id_prefix          = each.value.node_id_prefix
    edge_service_type            = var.edge_service_type
    environment                  = var.environment
    namespace                    = each.value.namespace
    nats_url                     = var.nats_url
    redis_addr                   = var.redis_addr
    region                      = each.key
    regional_hostname            = each.value.regional_hostname
    replicas                     = each.value.replicas
    service_name                 = each.value.service_name
  })
}

resource "local_file" "dns_routing_plan" {
  filename = "${path.module}/${var.output_dir}/global-dns-routing-plan.json"
  content  = jsonencode(local.dns_routing_plan)
}
