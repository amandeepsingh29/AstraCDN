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
    mode TEXT NOT NULL CHECK (mode IN ('keys', 'prefixes')),
    values JSONB NOT NULL,
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_invalidations_status_idx ON cache_invalidations (status);
CREATE INDEX IF NOT EXISTS cache_invalidations_host_created_idx ON cache_invalidations (host, created_at DESC);

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

CREATE TABLE IF NOT EXISTS service_events (
    id BIGSERIAL PRIMARY KEY,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_events_service_created_idx ON service_events (service, created_at DESC);
