DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT c.conname
    INTO constraint_name
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = current_schema()
      AND t.relname = 'cache_invalidations'
      AND c.contype = 'c'
      AND pg_get_constraintdef(c.oid) LIKE '%mode%'
      AND pg_get_constraintdef(c.oid) LIKE '%keys%'
      AND pg_get_constraintdef(c.oid) LIKE '%prefixes%'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE cache_invalidations DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE cache_invalidations
    ADD CONSTRAINT cache_invalidations_mode_check CHECK (mode IN ('keys', 'prefixes', 'tags'));
