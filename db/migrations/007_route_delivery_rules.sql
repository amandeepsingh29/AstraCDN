ALTER TABLE cdn_routes
    ADD COLUMN IF NOT EXISTS delivery_rules JSONB NOT NULL DEFAULT '{}'::jsonb;
