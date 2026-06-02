CREATE TABLE IF NOT EXISTS cache_prewarm_jobs (
    id BIGSERIAL PRIMARY KEY,
    host TEXT,
    paths JSONB NOT NULL,
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cache_prewarm_jobs_status_idx ON cache_prewarm_jobs (status);
CREATE INDEX IF NOT EXISTS cache_prewarm_jobs_host_created_idx ON cache_prewarm_jobs (host, created_at DESC);
