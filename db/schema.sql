CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS edge_nodes (
    node_id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS edge_nodes_status_idx ON edge_nodes (status);

CREATE TABLE IF NOT EXISTS cdn_origins (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_url TEXT NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cdn_origins_status_idx ON cdn_origins (status);

CREATE TABLE IF NOT EXISTS cdn_routes (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    path_prefix TEXT NOT NULL DEFAULT '/',
    origin_id BIGINT NOT NULL REFERENCES cdn_origins(id),
    cache_mode TEXT NOT NULL DEFAULT 'origin' CHECK (cache_mode IN ('origin', 'override', 'bypass')),
    cache_ttl_seconds INTEGER CHECK (cache_ttl_seconds IS NULL OR cache_ttl_seconds >= 0),
    stale_while_revalidate_seconds INTEGER CHECK (stale_while_revalidate_seconds IS NULL OR stale_while_revalidate_seconds >= 0),
    delivery_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    waf_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    rate_limit_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, path_prefix)
);

CREATE INDEX IF NOT EXISTS cdn_routes_status_idx ON cdn_routes (status);
CREATE INDEX IF NOT EXISTS cdn_routes_host_prefix_idx ON cdn_routes (host, path_prefix);

CREATE TABLE IF NOT EXISTS cdn_domains (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,
    route_id BIGINT REFERENCES cdn_routes(id) ON DELETE SET NULL,
    tls_mode TEXT NOT NULL DEFAULT 'managed' CHECK (tls_mode IN ('off', 'manual', 'managed')),
    status TEXT NOT NULL DEFAULT 'pending_dns' CHECK (status IN ('pending_dns', 'active', 'failed')),
    dns_txt_name TEXT NOT NULL DEFAULT '',
    dns_txt_value TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cdn_domains_status_idx ON cdn_domains (status);
CREATE INDEX IF NOT EXISTS cdn_domains_route_idx ON cdn_domains (route_id);

CREATE TABLE IF NOT EXISTS route_rule_versions (
    id BIGSERIAL PRIMARY KEY,
    route_id BIGINT NOT NULL REFERENCES cdn_routes(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    delivery_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    waf_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    rate_limit_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    changed_by TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (route_id, version)
);

CREATE INDEX IF NOT EXISTS route_rule_versions_route_created_idx
    ON route_rule_versions (route_id, created_at DESC);

CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tenants_status_idx ON tenants (status);

CREATE TABLE IF NOT EXISTS tenant_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer', 'billing')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS tenant_users_tenant_idx ON tenant_users (tenant_id);
CREATE INDEX IF NOT EXISTS tenant_users_email_idx ON tenant_users (email);

CREATE TABLE IF NOT EXISTS billing_accounts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_customer_id TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'trialing' CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS billing_accounts_status_idx ON billing_accounts (status);

CREATE TABLE IF NOT EXISTS billing_webhook_events (
    id BIGSERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    billing_account_id BIGINT REFERENCES billing_accounts(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'applied' CHECK (status IN ('applied')),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, event_id)
);

CREATE INDEX IF NOT EXISTS billing_webhook_events_account_idx
    ON billing_webhook_events (billing_account_id, processed_at DESC);

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cache_invalidations (
    id BIGSERIAL PRIMARY KEY,
    host TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('keys', 'prefixes', 'tags')),
    values JSONB NOT NULL,
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_invalidations_status_idx ON cache_invalidations (status);
CREATE INDEX IF NOT EXISTS cache_invalidations_host_created_idx ON cache_invalidations (host, created_at DESC);

CREATE TABLE IF NOT EXISTS cache_prewarm_jobs (
    id BIGSERIAL PRIMARY KEY,
    host TEXT,
    paths JSONB NOT NULL,
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_prewarm_jobs_status_idx ON cache_prewarm_jobs (status);
CREATE INDEX IF NOT EXISTS cache_prewarm_jobs_host_created_idx ON cache_prewarm_jobs (host, created_at DESC);

CREATE TABLE IF NOT EXISTS cache_invalidation_deliveries (
    invalidation_id BIGINT NOT NULL REFERENCES cache_invalidations(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied', 'failed')),
    error_message TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (invalidation_id, node_id)
);

CREATE INDEX IF NOT EXISTS cache_invalidation_deliveries_status_idx ON cache_invalidation_deliveries (status);
CREATE INDEX IF NOT EXISTS cache_invalidation_deliveries_node_idx ON cache_invalidation_deliveries (node_id, delivered_at DESC);

CREATE TABLE IF NOT EXISTS cache_analytics_snapshots (
    id BIGSERIAL PRIMARY KEY,
    edge_node_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    requests BIGINT NOT NULL CHECK (requests >= 0),
    hits BIGINT NOT NULL CHECK (hits >= 0),
    misses BIGINT NOT NULL CHECK (misses >= 0),
    hit_ratio DOUBLE PRECISION NOT NULL CHECK (hit_ratio >= 0 AND hit_ratio <= 1),
    by_layer JSONB NOT NULL DEFAULT '{}'::jsonb,
    by_host JSONB NOT NULL DEFAULT '{}'::jsonb,
    by_route JSONB NOT NULL DEFAULT '{}'::jsonb,
    cache_fill_latency JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_analytics_snapshots_observed_idx
    ON cache_analytics_snapshots (observed_at DESC);

CREATE INDEX IF NOT EXISTS cache_analytics_snapshots_edge_host_idx
    ON cache_analytics_snapshots (edge_node_id, host, observed_at DESC);

CREATE TABLE IF NOT EXISTS control_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS control_audit_logs_created_idx
    ON control_audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS control_audit_logs_resource_idx
    ON control_audit_logs (resource_type, resource_id, created_at DESC);

CREATE INDEX IF NOT EXISTS control_audit_logs_actor_idx
    ON control_audit_logs (actor, created_at DESC);

CREATE TABLE IF NOT EXISTS service_events (
    id BIGSERIAL PRIMARY KEY,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_events_service_created_idx ON service_events (service, created_at DESC);

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('001', 'initial_schema', '9f2983060fcbdb56f9d7d816c55f8c11bceadc5a560bb53f9148f89a88a507a3')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('002', 'cache_analytics_snapshots', '0f554b426be1057846b9ae24a9e28ba77ae4a0e78489495ec4abd1cfd201f384')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('003', 'cache_prewarm_jobs', '39d54023237031ee6af0188839a0c51cca813fc060a1c9713d743fa99c461008')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('004', 'cache_analytics_dimensions', 'e9a6e78546b9e9ea1a666efa17b917f9f1118cbfd84299f2649ba0b814607861')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('005', 'control_audit_logs', '44d1362dce61f6db046b869532584b2f9c21c81731cf6ae43f6646413e601aa3')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('006', 'edge_health_latency', 'f510ab14c6b2f0e4c2c1a073b0891529d01ce594d133ad627f33a22fcb2c8d0e')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('007', 'route_delivery_rules', '460da4b36e7735cf01de6417abeccefd718730865918cc8ba8600a50d3862982')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('008', 'route_waf_rules', 'e7cf090d637504a221b4173c48f7141d15ec5ed59717e618649710cf22fdd662')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('009', 'route_rate_limit_rules', '339da57ce64609248dec2b732949e7f039cab5c35643df7d1a47917e3ddb1a93')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('010', 'route_rule_versions', 'e02dae75701318769933568490fe107e9a6cdd75141ef245c5e981a555fe804e')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('011', 'surrogate_key_invalidation', '79bcc4269a40efff7b1794f5af84bca010a7ad86de6d770d0d061b7b562b6b74')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('012', 'tenants_rbac_billing', '8338008cc80232937cd08da64c038de69d7704d4a5d0febb63747e5ff67690a2')
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version, description, checksum)
VALUES ('013', 'billing_webhook_events', 'af73009dbc7a72805691a4c104a65a4a92a706886ac6534ecc39bc0e0a63a9b1')
ON CONFLICT (version) DO NOTHING;
