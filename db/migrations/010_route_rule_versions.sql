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
