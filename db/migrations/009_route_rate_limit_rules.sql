ALTER TABLE cdn_routes
    ADD COLUMN IF NOT EXISTS rate_limit_rules JSONB NOT NULL DEFAULT '[]'::jsonb;
