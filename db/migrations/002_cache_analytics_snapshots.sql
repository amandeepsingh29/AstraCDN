CREATE TABLE IF NOT EXISTS cache_analytics_snapshots (
    id BIGSERIAL PRIMARY KEY,
    edge_node_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    requests BIGINT NOT NULL CHECK (requests >= 0),
    hits BIGINT NOT NULL CHECK (hits >= 0),
    misses BIGINT NOT NULL CHECK (misses >= 0),
    hit_ratio DOUBLE PRECISION NOT NULL CHECK (hit_ratio >= 0 AND hit_ratio <= 1),
    by_layer JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_analytics_snapshots_observed_idx
    ON cache_analytics_snapshots (observed_at DESC);

CREATE INDEX IF NOT EXISTS cache_analytics_snapshots_edge_host_idx
    ON cache_analytics_snapshots (edge_node_id, host, observed_at DESC);
