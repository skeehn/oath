ALTER TABLE registry_outbox
    ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE registry_outbox
    ADD COLUMN IF NOT EXISTS leased_until BIGINT;
CREATE INDEX IF NOT EXISTS registry_outbox_claimable
    ON registry_outbox(available_at, leased_until, id)
    WHERE delivered_at IS NULL;

CREATE TABLE IF NOT EXISTS registry_schema_version (
    version INTEGER PRIMARY KEY,
    applied_at BIGINT NOT NULL
);
INSERT INTO registry_schema_version(version, applied_at)
VALUES (4, EXTRACT(EPOCH FROM NOW())::BIGINT)
ON CONFLICT (version) DO NOTHING;
