use anyhow::{Context, Result};
use serde_json::Value;
use sqlx_core::{query::query, query_scalar::query_scalar, raw_sql::raw_sql, row::Row};
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions, PgRow};

use crate::{Principal, StageRecord};

#[derive(Clone)]
pub struct PostgresControlPlane {
    pool: PgPool,
}

#[derive(Debug)]
pub struct VersionRecord {
    pub organization: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
}

#[derive(Debug)]
pub struct PackageVersionRecord {
    pub organization: String,
    pub version: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub manifest: Value,
    pub assessment: Value,
    pub server_evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
    pub published_at: i64,
    pub download_count: i64,
}

#[derive(Debug)]
pub struct PackageRecord {
    pub organization: String,
    pub private: bool,
}

#[derive(Debug)]
pub struct VersionBundleRecord {
    pub organization: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub assessment: Value,
    pub server_evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
    pub published_at: i64,
    pub download_count: i64,
    pub tombstone: Option<Value>,
}

#[derive(Debug)]
pub struct InvitationRecord {
    pub organization: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
}

impl PostgresControlPlane {
    pub async fn connect(url: &str) -> Result<Self> {
        let role = std::env::var("OATH_DATABASE_ROLE").ok();
        Self::connect_with_role(url, role.as_deref()).await
    }

    pub async fn connect_with_role(url: &str, role: Option<&str>) -> Result<Self> {
        if let Some(role) = role {
            anyhow::ensure!(
                matches!(role, "oath_api" | "oath_worker"),
                "OATH_DATABASE_ROLE must be oath_api or oath_worker"
            );
        }
        let role = role.map(str::to_owned);
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(20)
            .after_connect(move |connection, _metadata| {
                let role = role.clone();
                Box::pin(async move {
                    if let Some(role) = role {
                        query(&format!("SET ROLE {role}"))
                            .execute(connection)
                            .await
                            .map_err(|error| {
                                sqlx_core::Error::Protocol(
                                    format!(
                                        "SET ROLE {role} failed ({error:#}): the database login user must be a \
                                         member of the role (as superuser: GRANT {role} TO <login_user>;)"
                                    )
                                    .into(),
                                )
                            })?;
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await
            .context("connect PostgreSQL control plane")?;
        let control = Self { pool };
        control.verify_schema().await?;
        Ok(control)
    }

    pub async fn migrate_url(url: &str) -> Result<()> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect(url)
            .await
            .context("connect PostgreSQL migration control plane")?;
        let control = Self { pool };
        control.migrate().await
    }

    async fn migrate(&self) -> Result<()> {
        raw_sql(include_str!("../migrations/0001_registry.sql"))
            .execute(&self.pool)
            .await
            .context("migrate PostgreSQL control plane")?;
        raw_sql(include_str!("../migrations/0002_ga_foundation.sql"))
            .execute(&self.pool)
            .await
            .context("migrate GA foundation schema")?;
        raw_sql(include_str!("../migrations/0003_limits.sql"))
            .execute(&self.pool)
            .await
            .context("migrate registry limits schema")?;
        raw_sql(include_str!("../migrations/0004_outbox_leases.sql"))
            .execute(&self.pool)
            .await
            .context("migrate registry outbox leases")?;
        raw_sql(include_str!("../migrations/0005_tenant_rls.sql"))
            .execute(&self.pool)
            .await
            .context("migrate registry tenant RLS")?;
        Ok(())
    }

    async fn verify_schema(&self) -> Result<()> {
        let version: Option<i32> =
            query_scalar("SELECT version FROM registry_schema_version WHERE version=5")
                .fetch_optional(&self.pool)
                .await
                .context("registry schema is not initialized; run `oath-registry migrate`")?;
        anyhow::ensure!(
            version == Some(5),
            "registry schema version 5 is required; run `oath-registry migrate`"
        );
        Ok(())
    }

    pub async fn bootstrap_token(&self, organization: &str, hash: &str, role: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        query("INSERT INTO organizations(name,created_at) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING")
            .bind(organization).bind(crate::now() as i64).execute(&mut *tx).await?;
        query("INSERT INTO tokens(token_hash,organization,role,expires_at,kind) VALUES ($1,$2,$3,NULL,'bootstrap') ON CONFLICT (token_hash) DO UPDATE SET organization=EXCLUDED.organization, role=EXCLUDED.role, expires_at=NULL, kind='bootstrap'")
            .bind(hash).bind(organization).bind(role).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn insert_token(
        &self,
        hash: &str,
        organization: &str,
        role: &str,
        expires_at: i64,
        kind: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        query("INSERT INTO tokens(token_hash,organization,role,expires_at,kind) VALUES ($1,$2,$3,$4,$5)")
            .bind(hash).bind(organization).bind(role).bind(expires_at).bind(kind).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn authenticate(&self, hash: &str) -> Result<Option<Principal>> {
        let row = query("SELECT organization,role,kind FROM oath_authenticate_token($1,$2)")
            .bind(hash)
            .bind(crate::now() as i64)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| Principal {
            organization: row.get("organization"),
            role: row.get("role"),
            kind: row.get("kind"),
        }))
    }

    pub async fn package_role(&self, name: &str, organization: &str) -> Result<Option<String>> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        let role =
            query_scalar("SELECT role FROM package_roles WHERE name=$1 AND principal_org=$2")
                .bind(name)
                .bind(organization)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(role)
    }

    pub async fn package(&self, name: &str) -> Result<Option<PackageRecord>> {
        self.package_for(name, None).await
    }

    pub async fn package_for(
        &self,
        name: &str,
        organization: Option<&str>,
    ) -> Result<Option<PackageRecord>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let row = query("SELECT organization,private FROM packages WHERE name=$1")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(row.map(|row| PackageRecord {
            organization: row.get("organization"),
            private: row.get("private"),
        }))
    }

    pub async fn create_stage(
        &self,
        stage: &StageRecord,
        event_key: &str,
        event: &Value,
        maximum_pending_stages: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, &stage.organization).await?;
        query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&stage.organization)
            .execute(&mut *tx)
            .await?;
        let pending: i64 =
            query_scalar("SELECT COUNT(*) FROM stages WHERE organization=$1 AND status='staged'")
                .bind(&stage.organization)
                .fetch_one(&mut *tx)
                .await?;
        if pending >= maximum_pending_stages {
            tx.rollback().await?;
            return Ok(false);
        }
        query("INSERT INTO packages(name,organization,private,created_at) VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING")
            .bind(&stage.name).bind(&stage.organization).bind(stage.private).bind(stage.created_at as i64).execute(&mut *tx).await?;
        let package = query("SELECT organization,private FROM packages WHERE name=$1 FOR UPDATE")
            .bind(&stage.name)
            .fetch_one(&mut *tx)
            .await?;
        let owner: String = package.get("organization");
        let private: bool = package.get("private");
        anyhow::ensure!(
            owner == stage.organization,
            "package belongs to another organization"
        );
        anyhow::ensure!(
            private == stage.private,
            "package visibility cannot change between versions"
        );
        query("INSERT INTO stages(id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(&stage.id).bind(&stage.organization).bind(&stage.name).bind(&stage.version)
            .bind(&stage.tag).bind(&stage.digest).bind(&stage.status).bind(stage.private)
            .bind(&stage.manifest).bind(&stage.publisher_assessment).bind(&stage.assessment)
            .bind(&stage.server_evidence).bind(&stage.sbom).bind(&stage.provenance)
            .bind(stage.created_at as i64).execute(&mut *tx).await?;
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn consume_rate_limit(
        &self,
        subject_hash: &str,
        bucket: &str,
        maximum: i64,
        window_seconds: i64,
    ) -> Result<bool> {
        let now = crate::now() as i64;
        let window_start = now - now.rem_euclid(window_seconds);
        let count: i64 = query_scalar(
            "INSERT INTO registry_rate_limits(subject_hash,bucket,window_start,request_count) VALUES ($1,$2,$3,1) ON CONFLICT (subject_hash,bucket,window_start) DO UPDATE SET request_count=registry_rate_limits.request_count+1 RETURNING request_count",
        )
        .bind(subject_hash)
        .bind(bucket)
        .bind(window_start)
        .fetch_one(&self.pool)
        .await?;
        Ok(count <= maximum)
    }

    pub async fn prune_rate_limits_before(&self, cutoff: i64) -> Result<u64> {
        Ok(
            query("DELETE FROM registry_rate_limits WHERE window_start<$1")
                .bind(cutoff)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    pub async fn read_stage(&self, id: &str) -> Result<Option<StageRecord>> {
        self.read_stage_for(id, None).await
    }

    pub async fn read_stage_for(
        &self,
        id: &str,
        organization: Option<&str>,
    ) -> Result<Option<StageRecord>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let row = query("SELECT id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at FROM stages WHERE id=$1")
            .bind(id).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(stage_from_row))
    }

    pub async fn list_stages(&self, organization: &str) -> Result<Vec<StageRecord>> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        let rows = query("SELECT id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at FROM stages WHERE stages.organization=$1 OR EXISTS (SELECT 1 FROM package_roles WHERE package_roles.name=stages.name AND package_roles.principal_org=$1) ORDER BY created_at DESC")
            .bind(organization).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(stage_from_row).collect())
    }

    pub async fn decide_stage(
        &self,
        stage: &StageRecord,
        approve: bool,
        reason: Option<&str>,
        event_key: &str,
        event: &Value,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, &stage.organization).await?;
        let status: Option<String> =
            query_scalar("SELECT status FROM stages WHERE id=$1 FOR UPDATE")
                .bind(&stage.id)
                .fetch_optional(&mut *tx)
                .await?;
        if status.as_deref() != Some("staged") {
            tx.rollback().await?;
            return Ok(false);
        }
        if approve {
            query("UPDATE stages SET status='approved',decision_reason=$2 WHERE id=$1")
                .bind(&stage.id)
                .bind(reason)
                .execute(&mut *tx)
                .await?;
            query("INSERT INTO versions(name,version,organization,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,published_at) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(&stage.name).bind(&stage.version).bind(&stage.organization).bind(&stage.digest)
                .bind(stage.private).bind(&stage.manifest).bind(&stage.publisher_assessment)
                .bind(&stage.assessment).bind(&stage.server_evidence).bind(&stage.sbom)
                .bind(&stage.provenance).bind(crate::now() as i64).execute(&mut *tx).await?;
            query("INSERT INTO dist_tags(name,tag,version) VALUES ($1,$2,$3) ON CONFLICT (name,tag) DO UPDATE SET version=EXCLUDED.version")
                .bind(&stage.name).bind(&stage.tag).bind(&stage.version).execute(&mut *tx).await?;
        } else {
            query("UPDATE stages SET status='rejected',decision_reason=$2 WHERE id=$1")
                .bind(&stage.id)
                .bind(reason)
                .execute(&mut *tx)
                .await?;
        }
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn event_hashes(&self) -> Result<Vec<String>> {
        Ok(
            query_scalar("SELECT event_hash FROM registry_events ORDER BY sequence")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn version(&self, name: &str, version: &str) -> Result<Option<VersionRecord>> {
        self.version_for(name, version, None).await
    }

    pub async fn version_for(
        &self,
        name: &str,
        version: &str,
        organization: Option<&str>,
    ) -> Result<Option<VersionRecord>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let row = query(
            "SELECT organization,digest,status,private FROM versions WHERE name=$1 AND version=$2",
        )
        .bind(name)
        .bind(version)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| VersionRecord {
            organization: row.get("organization"),
            digest: row.get("digest"),
            status: row.get("status"),
            private: row.get("private"),
        }))
    }

    pub async fn version_bundle(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionBundleRecord>> {
        self.version_bundle_for(name, version, None).await
    }

    pub async fn version_bundle_for(
        &self,
        name: &str,
        version: &str,
        organization: Option<&str>,
    ) -> Result<Option<VersionBundleRecord>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let row = query("SELECT versions.organization,versions.digest,versions.status,versions.private,versions.assessment,versions.server_evidence,versions.sbom,versions.provenance,versions.published_at,versions.download_count,to_jsonb(tombstones) AS tombstone FROM versions LEFT JOIN tombstones USING (name,version) WHERE versions.name=$1 AND versions.version=$2")
            .bind(name).bind(version).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(|row| VersionBundleRecord {
            organization: row.get("organization"),
            digest: row.get("digest"),
            status: row.get("status"),
            private: row.get("private"),
            assessment: row.get("assessment"),
            server_evidence: row.get("server_evidence"),
            sbom: row.get("sbom"),
            provenance: row.get("provenance"),
            published_at: row.get("published_at"),
            download_count: row.get("download_count"),
            tombstone: row.get("tombstone"),
        }))
    }

    pub async fn public_quarantines(&self) -> Result<Vec<(String, String, String, i64)>> {
        let rows = query("SELECT tombstones.name,tombstones.version,tombstones.reason,tombstones.created_at FROM tombstones JOIN packages USING (name) WHERE tombstones.status='quarantined' AND packages.private=false ORDER BY tombstones.created_at")
            .fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get("name"),
                    row.get("version"),
                    row.get("reason"),
                    row.get("created_at"),
                )
            })
            .collect())
    }

    pub async fn package_versions(&self, name: &str) -> Result<Vec<PackageVersionRecord>> {
        self.package_versions_for(name, None).await
    }

    pub async fn package_versions_for(
        &self,
        name: &str,
        organization: Option<&str>,
    ) -> Result<Vec<PackageVersionRecord>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let rows = query("SELECT organization,version,digest,status,private,manifest,assessment,server_evidence,sbom,provenance,published_at,download_count FROM versions WHERE name=$1 AND status='active' ORDER BY published_at")
            .bind(name).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|row| PackageVersionRecord {
                organization: row.get("organization"),
                version: row.get("version"),
                digest: row.get("digest"),
                status: row.get("status"),
                private: row.get("private"),
                manifest: row.get("manifest"),
                assessment: row.get("assessment"),
                server_evidence: row.get("server_evidence"),
                sbom: row.get("sbom"),
                provenance: row.get("provenance"),
                published_at: row.get("published_at"),
                download_count: row.get("download_count"),
            })
            .collect())
    }

    pub async fn record_download(&self, name: &str, version: &str) -> Result<()> {
        let recorded: bool = query_scalar("SELECT oath_record_download($1,$2)")
            .bind(name)
            .bind(version)
            .fetch_one(&self.pool)
            .await?;
        anyhow::ensure!(
            recorded,
            "active package version disappeared before download accounting"
        );
        Ok(())
    }

    pub async fn dist_tags(&self, name: &str) -> Result<Vec<(String, String)>> {
        self.dist_tags_for(name, None).await
    }

    pub async fn dist_tags_for(
        &self,
        name: &str,
        organization: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        let mut tx = self.pool.begin().await?;
        if let Some(organization) = organization {
            set_tenant(&mut tx, organization).await?;
        }
        let rows = query("SELECT tag,version FROM dist_tags WHERE name=$1")
            .bind(name)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("tag"), row.get("version")))
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_version(
        &self,
        name: &str,
        version: &str,
        status: &str,
        reason: &str,
        actor_org: &str,
        created_at: i64,
        signature: &str,
        public_key: &str,
        event_key: &str,
        event: &Value,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, actor_org).await?;
        let updated = query("UPDATE versions SET status=$3 WHERE name=$1 AND version=$2")
            .bind(name)
            .bind(version)
            .bind(status)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if updated == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        query("INSERT INTO tombstones(name,version,status,reason,actor_org,created_at,signature,public_key) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name,version) DO UPDATE SET status=EXCLUDED.status,reason=EXCLUDED.reason,actor_org=EXCLUDED.actor_org,created_at=EXCLUDED.created_at,signature=EXCLUDED.signature,public_key=EXCLUDED.public_key")
            .bind(name).bind(version).bind(status).bind(reason).bind(actor_org).bind(created_at).bind(signature).bind(public_key).execute(&mut *tx).await?;
        let active: Vec<String> =
            query_scalar("SELECT version FROM versions WHERE name=$1 AND status='active'")
                .bind(name)
                .fetch_all(&mut *tx)
                .await?;
        let rollback = active
            .into_iter()
            .filter_map(|value| {
                value
                    .parse::<node_semver::Version>()
                    .ok()
                    .map(|parsed| (parsed, value))
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, value)| value);
        if let Some(rollback) = rollback {
            query("UPDATE dist_tags SET version=$2 WHERE name=$1 AND version=$3")
                .bind(name)
                .bind(rollback)
                .bind(version)
                .execute(&mut *tx)
                .await?;
        } else {
            query("DELETE FROM dist_tags WHERE name=$1 AND version=$2")
                .bind(name)
                .bind(version)
                .execute(&mut *tx)
                .await?;
        }
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn grant_package_role(
        &self,
        name: &str,
        owner_org: &str,
        principal_org: &str,
        role: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, owner_org).await?;
        let package = query("SELECT organization,private FROM packages WHERE name=$1")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
            .context("package not found")?;
        anyhow::ensure!(
            package.get::<String, _>("organization") == owner_org,
            "only the package-owning organization may grant roles"
        );
        query("INSERT INTO package_roles(name,organization,principal_org,role) VALUES ($1,$2,$3,$4) ON CONFLICT (name,principal_org) DO UPDATE SET organization=EXCLUDED.organization,role=EXCLUDED.role")
            .bind(name).bind(owner_org).bind(principal_org).bind(role).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_invitation(
        &self,
        token_hash: &str,
        organization: &str,
        email: &str,
        role: &str,
        expires_at: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        query("INSERT INTO invitations(token_hash,organization,email,role,expires_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(token_hash).bind(organization).bind(email).bind(role).bind(expires_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_invitation(&self, token_hash: &str, organization: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization).await?;
        let revoked = query("UPDATE invitations SET revoked_at=$3 WHERE token_hash=$1 AND organization=$2 AND accepted_at IS NULL AND revoked_at IS NULL")
            .bind(token_hash).bind(organization).bind(crate::now() as i64).execute(&mut *tx).await?.rows_affected() == 1;
        tx.commit().await?;
        Ok(revoked)
    }

    pub async fn accept_invitation(
        &self,
        token_hash: &str,
        subject: &str,
        email: &str,
    ) -> Result<Option<InvitationRecord>> {
        let mut tx = self.pool.begin().await?;
        let row =
            query("SELECT organization,email,role,expires_at FROM oath_lookup_invitation($1,$2)")
                .bind(token_hash)
                .bind(crate::now() as i64)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let invitation = InvitationRecord {
            organization: row.get("organization"),
            email: row.get("email"),
            role: row.get("role"),
            expires_at: row.get("expires_at"),
        };
        // Lock the invitation row so concurrent accepts serialize; the guarded
        // UPDATE below then guarantees exactly one winner.
        query("SELECT 1 FROM invitations WHERE token_hash=$1 FOR UPDATE")
            .bind(token_hash)
            .fetch_optional(&mut *tx)
            .await?;
        set_tenant(&mut tx, &invitation.organization).await?;
        if !invitation.email.eq_ignore_ascii_case(email) {
            tx.rollback().await?;
            anyhow::bail!("invitation email does not match verified identity");
        }
        query("INSERT INTO organization_members(organization,subject,email,role,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (organization,subject) DO UPDATE SET email=EXCLUDED.email,role=EXCLUDED.role")
            .bind(&invitation.organization).bind(subject).bind(email).bind(&invitation.role).bind(crate::now() as i64).execute(&mut *tx).await?;
        let accepted = query(
            "UPDATE invitations SET accepted_at=$2 WHERE token_hash=$1 AND accepted_at IS NULL",
        )
        .bind(token_hash)
        .bind(crate::now() as i64)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !accepted {
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(invitation))
    }

    pub async fn membership(&self, subject: &str) -> Result<Option<(String, String)>> {
        let row = query("SELECT organization,role FROM oath_lookup_membership($1)")
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| (row.get("organization"), row.get("role"))))
    }

    pub async fn record_billing_event(
        &self,
        event_id: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<bool> {
        Ok(query("INSERT INTO billing_events(provider_event_id,event_type,payload,received_at) VALUES ($1,$2,$3,$4) ON CONFLICT (provider_event_id) DO NOTHING")
            .bind(event_id).bind(event_type).bind(payload).bind(crate::now() as i64).execute(&self.pool).await?.rows_affected()==1)
    }

    pub async fn claim_outbox(
        &self,
        worker_id: &str,
        limit: i64,
    ) -> Result<Vec<(i64, String, Value)>> {
        let now = crate::now() as i64;
        let rows = query(
            "WITH candidates AS (SELECT id FROM registry_outbox WHERE delivered_at IS NULL AND available_at<=$1 AND (leased_until IS NULL OR leased_until<$1) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE registry_outbox AS outbox SET lease_owner=$3,leased_until=$4,attempts=outbox.attempts+1 FROM candidates WHERE outbox.id=candidates.id RETURNING outbox.id,outbox.event_key,outbox.event_json",
        )
        .bind(now)
        .bind(limit)
        .bind(worker_id)
        .bind(now.saturating_add(30))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("id"), row.get("event_key"), row.get("event_json")))
            .collect())
    }

    pub async fn mark_outbox_delivered(&self, id: i64, worker_id: &str) -> Result<()> {
        let result = query("UPDATE registry_outbox SET delivered_at=$3,lease_owner=NULL,leased_until=NULL WHERE id=$1 AND lease_owner=$2")
            .bind(id)
            .bind(worker_id)
            .bind(crate::now() as i64)
            .execute(&self.pool)
            .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "outbox lease was lost before delivery"
        );
        Ok(())
    }

    pub async fn retry_outbox(&self, id: i64, worker_id: &str) -> Result<()> {
        query("UPDATE registry_outbox SET available_at=$3,lease_owner=NULL,leased_until=NULL WHERE id=$1 AND lease_owner=$2")
            .bind(id)
            .bind(worker_id)
            .bind(crate::now().saturating_add(5) as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn ready(&self) -> Result<()> {
        let value: i32 = query_scalar("SELECT 1").fetch_one(&self.pool).await?;
        anyhow::ensure!(
            value == 1,
            "PostgreSQL readiness query returned an invalid value"
        );
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

async fn set_tenant(connection: &mut PgConnection, organization: &str) -> Result<()> {
    anyhow::ensure!(
        !organization.is_empty(),
        "tenant organization must not be empty"
    );
    query("SELECT set_config('oath.organization',$1,true)")
        .bind(organization)
        .execute(connection)
        .await?;
    Ok(())
}

fn stage_from_row(row: PgRow) -> StageRecord {
    StageRecord {
        id: row.get("id"),
        organization: row.get("organization"),
        name: row.get("name"),
        version: row.get("version"),
        tag: row.get("tag"),
        digest: row.get("digest"),
        status: row.get("status"),
        private: row.get("private"),
        manifest: row.get::<Value, _>("manifest"),
        publisher_assessment: row.get::<Value, _>("publisher_assessment"),
        assessment: row.get::<Value, _>("assessment"),
        server_evidence: row.get::<Value, _>("server_evidence"),
        sbom: row.get::<Value, _>("sbom"),
        provenance: row.get::<Value, _>("provenance"),
        created_at: row.get::<i64, _>("created_at") as u64,
    }
}
