DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oath_api') THEN
        CREATE ROLE oath_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oath_worker') THEN
        CREATE ROLE oath_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END $$;

-- NOTE: creating the roles is not enough. The database login user that the
-- registry runs as must be a *member* of the role it sets via OATH_DATABASE_ROLE,
-- otherwise `SET ROLE oath_api` fails at startup. As a superuser, run:
--   GRANT oath_api TO <registry_login_user>;
--   GRANT oath_worker TO <worker_login_user>;

CREATE OR REPLACE FUNCTION oath_current_organization() RETURNS TEXT
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('oath.organization', true), '')
$$;

CREATE OR REPLACE FUNCTION oath_authenticate_token(candidate_hash TEXT, current_epoch BIGINT)
RETURNS TABLE(organization TEXT, role TEXT, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT tokens.organization, tokens.role, tokens.kind
      FROM tokens
     WHERE token_hash = candidate_hash
       AND (expires_at IS NULL OR expires_at > current_epoch)
$$;
REVOKE ALL ON FUNCTION oath_authenticate_token(TEXT, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oath_authenticate_token(TEXT, BIGINT) TO oath_api, oath_worker;

CREATE OR REPLACE FUNCTION oath_lookup_invitation(candidate_hash TEXT, current_epoch BIGINT)
RETURNS TABLE(organization TEXT, email TEXT, role TEXT, expires_at BIGINT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT invitations.organization, invitations.email, invitations.role, invitations.expires_at
      FROM invitations
     WHERE token_hash = candidate_hash AND accepted_at IS NULL AND revoked_at IS NULL
       AND expires_at > current_epoch
$$;
CREATE OR REPLACE FUNCTION oath_lookup_membership(candidate_subject TEXT)
RETURNS TABLE(organization TEXT, role TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT organization_members.organization, organization_members.role
      FROM organization_members WHERE subject = candidate_subject ORDER BY created_at LIMIT 1
$$;
REVOKE ALL ON FUNCTION oath_lookup_invitation(TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION oath_lookup_membership(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oath_lookup_invitation(TEXT, BIGINT), oath_lookup_membership(TEXT) TO oath_api, oath_worker;

CREATE OR REPLACE FUNCTION oath_record_download(package_name TEXT, package_version TEXT)
RETURNS BOOLEAN
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH updated AS (
        UPDATE versions
           SET download_count = download_count + 1
         WHERE name = package_name AND version = package_version AND status = 'active'
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated)
$$;
REVOKE ALL ON FUNCTION oath_record_download(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oath_record_download(TEXT, TEXT) TO oath_api, oath_worker;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE package_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dist_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE tombstones ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_tenant ON organizations;
CREATE POLICY organizations_tenant ON organizations
    USING (name = oath_current_organization())
    WITH CHECK (name = oath_current_organization());
DROP POLICY IF EXISTS tokens_tenant ON tokens;
CREATE POLICY tokens_tenant ON tokens
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS packages_tenant_or_public ON packages;
DROP POLICY IF EXISTS packages_select ON packages;
DROP POLICY IF EXISTS packages_insert ON packages;
DROP POLICY IF EXISTS packages_update ON packages;
DROP POLICY IF EXISTS packages_delete ON packages;
CREATE POLICY packages_select ON packages FOR SELECT
    USING (organization = oath_current_organization() OR private = false OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=packages.name
          AND package_roles.principal_org=oath_current_organization()));
CREATE POLICY packages_insert ON packages FOR INSERT
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY packages_update ON packages FOR UPDATE
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY packages_delete ON packages FOR DELETE
    USING (organization = oath_current_organization());
DROP POLICY IF EXISTS package_roles_tenant ON package_roles;
DROP POLICY IF EXISTS package_roles_select ON package_roles;
DROP POLICY IF EXISTS package_roles_insert ON package_roles;
DROP POLICY IF EXISTS package_roles_update ON package_roles;
DROP POLICY IF EXISTS package_roles_delete ON package_roles;
CREATE POLICY package_roles_select ON package_roles FOR SELECT
    USING (organization = oath_current_organization() OR principal_org = oath_current_organization());
CREATE POLICY package_roles_insert ON package_roles FOR INSERT
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY package_roles_update ON package_roles FOR UPDATE
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY package_roles_delete ON package_roles FOR DELETE
    USING (organization = oath_current_organization());
DROP POLICY IF EXISTS invitations_tenant ON invitations;
CREATE POLICY invitations_tenant ON invitations
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS organization_members_tenant ON organization_members;
CREATE POLICY organization_members_tenant ON organization_members
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS stages_tenant ON stages;
DROP POLICY IF EXISTS stages_select ON stages;
DROP POLICY IF EXISTS stages_insert ON stages;
DROP POLICY IF EXISTS stages_update ON stages;
DROP POLICY IF EXISTS stages_delete ON stages;
CREATE POLICY stages_select ON stages FOR SELECT
    USING (organization = oath_current_organization() OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=stages.name
          AND package_roles.principal_org=oath_current_organization()));
CREATE POLICY stages_insert ON stages FOR INSERT
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY stages_update ON stages FOR UPDATE
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY stages_delete ON stages FOR DELETE
    USING (organization = oath_current_organization());
DROP POLICY IF EXISTS versions_tenant_or_public ON versions;
DROP POLICY IF EXISTS versions_select ON versions;
DROP POLICY IF EXISTS versions_insert ON versions;
DROP POLICY IF EXISTS versions_update ON versions;
DROP POLICY IF EXISTS versions_delete ON versions;
CREATE POLICY versions_select ON versions FOR SELECT
    USING (organization = oath_current_organization() OR private = false OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=versions.name
          AND package_roles.principal_org=oath_current_organization()));
CREATE POLICY versions_insert ON versions FOR INSERT
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY versions_update ON versions FOR UPDATE
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
CREATE POLICY versions_delete ON versions FOR DELETE
    USING (organization = oath_current_organization());

DROP POLICY IF EXISTS dist_tags_select ON dist_tags;
DROP POLICY IF EXISTS dist_tags_insert ON dist_tags;
DROP POLICY IF EXISTS dist_tags_update ON dist_tags;
DROP POLICY IF EXISTS dist_tags_delete ON dist_tags;
CREATE POLICY dist_tags_select ON dist_tags FOR SELECT USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=dist_tags.name
));
CREATE POLICY dist_tags_insert ON dist_tags FOR INSERT WITH CHECK (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=dist_tags.name
      AND packages.organization=oath_current_organization()
));
CREATE POLICY dist_tags_update ON dist_tags FOR UPDATE USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=dist_tags.name
      AND packages.organization=oath_current_organization()
)) WITH CHECK (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=dist_tags.name
      AND packages.organization=oath_current_organization()
));
CREATE POLICY dist_tags_delete ON dist_tags FOR DELETE USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=dist_tags.name
      AND packages.organization=oath_current_organization()
));

DROP POLICY IF EXISTS tombstones_select ON tombstones;
DROP POLICY IF EXISTS tombstones_insert ON tombstones;
DROP POLICY IF EXISTS tombstones_update ON tombstones;
DROP POLICY IF EXISTS tombstones_delete ON tombstones;
CREATE POLICY tombstones_select ON tombstones FOR SELECT USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=tombstones.name
));
CREATE POLICY tombstones_insert ON tombstones FOR INSERT WITH CHECK (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=tombstones.name
      AND packages.organization=oath_current_organization()
));
CREATE POLICY tombstones_update ON tombstones FOR UPDATE USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=tombstones.name
      AND packages.organization=oath_current_organization()
)) WITH CHECK (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=tombstones.name
      AND packages.organization=oath_current_organization()
));
CREATE POLICY tombstones_delete ON tombstones FOR DELETE USING (EXISTS (
    SELECT 1 FROM packages WHERE packages.name=tombstones.name
      AND packages.organization=oath_current_organization()
));

GRANT USAGE ON SCHEMA public TO oath_api, oath_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO oath_worker;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO oath_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, tokens, packages, package_roles,
    invitations, organization_members, stages, versions, dist_tags, tombstones,
    registry_outbox, registry_rate_limits, billing_events TO oath_api;
GRANT SELECT, INSERT ON registry_events TO oath_api;
GRANT SELECT ON registry_schema_version TO oath_api;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO oath_api;

CREATE TABLE IF NOT EXISTS registry_replication_receipts (
    region TEXT NOT NULL,
    event_key TEXT NOT NULL,
    object_digest TEXT,
    checkpoint_root TEXT,
    observed_at BIGINT NOT NULL,
    source_created_at BIGINT NOT NULL,
    PRIMARY KEY(region, event_key)
);
GRANT SELECT, INSERT, UPDATE ON registry_replication_receipts TO oath_worker;

INSERT INTO registry_schema_version(version, applied_at)
VALUES (5, EXTRACT(EPOCH FROM NOW())::BIGINT)
ON CONFLICT (version) DO NOTHING;
