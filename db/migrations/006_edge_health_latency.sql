ALTER TABLE cache_analytics_snapshots
    ADD COLUMN IF NOT EXISTS cache_fill_latency JSONB NOT NULL DEFAULT '{}'::jsonb;
