ALTER TABLE cdn_routes
    ADD COLUMN IF NOT EXISTS waf_rules JSONB NOT NULL DEFAULT '{}'::jsonb;
