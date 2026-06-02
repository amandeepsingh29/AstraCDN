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
