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
