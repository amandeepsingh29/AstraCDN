ALTER TABLE cache_analytics_snapshots
    ADD COLUMN IF NOT EXISTS by_host JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS by_route JSONB NOT NULL DEFAULT '{}'::jsonb;
