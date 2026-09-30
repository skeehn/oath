use std::{io::Read, path::Path, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::{Value, json};
#[cfg(test)]
use sqlx_core::raw_sql::raw_sql;
use sqlx_core::{query::query, query_scalar::query_scalar};
#[cfg(test)]
use sqlx_postgres::PgPool;

use crate::{
    ApiError, DecisionRequest, PackageRoleRequest, Principal, RevokeRequest, StageRecord,
    StageRequest, TokenRequest, TransparencyCheckpoint,
    analysis_backend::{SharedAnalysisBackend, analysis_backend_from_env},
    assessment::RegistryAssessmentBundle,
    billing::StripeBilling,
    control_plane::PostgresControlPlane,
    hex_sha256,
    identity::{InvitationMailer, OidcVerifier},
    merkle_consistency_proof, merkle_inclusion_proof, merkle_root,
    metrics::{RegistryMetrics, RegistryOperation},
    now,
    object_backend::ArtifactStore,
    rate_limit::{SharedRateLimiter, rate_limiter_from_env},
    signer::{SharedSigner, signer_from_env},
};

#[derive(Clone)]
pub struct PostgresRegistry {
    control: PostgresControlPlane,
    objects: ArtifactStore,
    signer: SharedSigner,
    rate_limiter: SharedRateLimiter,
    analysis: SharedAnalysisBackend,
    oidc: Option<OidcVerifier>,
    mailer: Option<InvitationMailer>,
    public_url: String,
    invitation_accept_url: Option<String>,
    max_stage_request_bytes: usize,
    metrics: RegistryMetrics,
    billing: Option<StripeBilling>,
    require_step_up_approval: bool,
    requests_per_minute: i64,
    maximum_pending_stages: i64,
    outbox_worker_id: String,
}

impl PostgresRegistry {
    pub async fn connect(
        database_url: &str,
        objects: ArtifactStore,
        key_path: &Path,
    ) -> Result<Self> {
        let oidc = match (
            std::env::var("OATH_OIDC_ISSUER").ok(),
            std::env::var("OATH_OIDC_AUDIENCE").ok(),
        ) {
            (Some(issuer), Some(audience)) => {
                Some(OidcVerifier::discover(&issuer, &audience).await?)
            }
            (None, None) => None,
            _ => {
                anyhow::bail!("OATH_OIDC_ISSUER and OATH_OIDC_AUDIENCE must be configured together")
            }
        };
        let mailer = match (
            std::env::var("OATH_RESEND_API_KEY").ok(),
            std::env::var("OATH_EMAIL_FROM").ok(),
        ) {
            (Some(key), Some(from)) => Some(InvitationMailer::resend(key, from)),
            (None, None) => None,
            _ => {
                anyhow::bail!("OATH_RESEND_API_KEY and OATH_EMAIL_FROM must be configured together")
            }
        };
        let billing = match (
            std::env::var("STRIPE_SECRET_KEY").ok(),
            std::env::var("STRIPE_WEBHOOK_SECRET").ok(),
        ) {
            (Some(key), Some(webhook)) => Some(StripeBilling::new(key, webhook)),
            (None, None) => None,
            _ => anyhow::bail!(
                "STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET must be configured together"
            ),
        };
        let invitation_accept_url = std::env::var("OATH_INVITATION_ACCEPT_URL").ok();
        if mailer.is_some() && invitation_accept_url.is_none() {
            anyhow::bail!(
                "OATH_INVITATION_ACCEPT_URL is required when invitation email is configured"
            );
        }
        let max_stage_request_bytes = std::env::var("OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES")
            .ok()
            .map(|value| value.parse::<usize>())
            .transpose()
            .context("OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES must be an integer")?
            .unwrap_or(64 * 1024 * 1024);
        anyhow::ensure!(
            (1024 * 1024..=1024 * 1024 * 1024).contains(&max_stage_request_bytes),
            "OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES must be between 1 MiB and 1 GiB"
        );
        let requests_per_minute = positive_limit("OATH_REGISTRY_REQUESTS_PER_MINUTE", 6_000)?;
        let maximum_pending_stages = positive_limit("OATH_REGISTRY_MAX_PENDING_STAGES", 100)?;
        let control = PostgresControlPlane::connect(database_url).await?;
        let signer = signer_from_env(key_path).await?;
        let rate_limiter = rate_limiter_from_env(control.clone())?;
        let analysis = analysis_backend_from_env()?;
        Ok(Self {
            control,
            objects,
            signer,
            rate_limiter,
            analysis,
            oidc,
            mailer,
            public_url: std::env::var("OATH_PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:4873".into())
                .trim_end_matches('/')
                .to_owned(),
            invitation_accept_url,
            max_stage_request_bytes,
            metrics: RegistryMetrics::default(),
            billing,
            require_step_up_approval: std::env::var("OATH_REQUIRE_STEP_UP_APPROVAL")
                .ok()
                .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                .unwrap_or(false),
            requests_per_minute,
            maximum_pending_stages,
            outbox_worker_id: format!("registry-{}-{}", std::process::id(), crate::now()),
        })
    }

    async fn detached_signature(
        &self,
        domain: &str,
        payload: &[u8],
    ) -> Result<oath_contracts::DetachedSignature> {
        Ok(oath_contracts::DetachedSignature {
            algorithm: "ed25519".into(),
            canonicalization: "oath-json-v1+oath-domain-sha256-v1".into(),
            domain: Some(domain.to_owned()),
            public_key: base64::engine::general_purpose::STANDARD.encode(self.signer.public_key()),
            signature: base64::engine::general_purpose::STANDARD
                .encode(self.signer.sign(domain, payload).await?),
        })
    }

    async fn issue_identity_token(
        &self,
        organization: &str,
        role: &str,
        step_up: bool,
    ) -> Result<String> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!(error))?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        self.control
            .insert_token(
                &hex_sha256(token.as_bytes()),
                organization,
                role,
                now().saturating_add(3600) as i64,
                if step_up { "oidc-mfa" } else { "oidc" },
            )
            .await?;
        Ok(token)
    }

    pub async fn bootstrap_token(&self, organization: &str, token: &str, role: &str) -> Result<()> {
        self.control
            .bootstrap_token(organization, &hex_sha256(token.as_bytes()), role)
            .await
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, ApiError> {
        let token = bearer(headers)?;
        self.control
            .authenticate(&hex_sha256(token.as_bytes()))
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::unauthorized)
    }

    async fn authenticate_optional(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<Principal>, ApiError> {
        let Some(token) = bearer_optional(headers)? else {
            return Ok(None);
        };
        self.control
            .authenticate(&hex_sha256(token.as_bytes()))
            .await
            .map_err(ApiError::internal)?
            .map(Some)
            .ok_or_else(ApiError::unauthorized)
    }

    async fn authorize_name(
        &self,
        principal: &Principal,
        name: &str,
        write: bool,
    ) -> Result<String, ApiError> {
        if let Some(package) = self
            .control
            .package_for(name, Some(&principal.organization))
            .await
            .map_err(ApiError::internal)?
        {
            if package.organization == principal.organization {
                if write && !matches!(principal.role.as_str(), "publisher" | "admin") {
                    return Err(ApiError::forbidden("publisher role required"));
                }
                return Ok(package.organization);
            }
            let role = self
                .control
                .package_role(name, &principal.organization)
                .await
                .map_err(ApiError::internal)?;
            let allowed = matches!(
                (write, role.as_deref()),
                (false, Some(_)) | (true, Some("publisher" | "admin"))
            );
            if !allowed {
                return Err(ApiError::forbidden(
                    "package belongs to another organization",
                ));
            }
            return Ok(package.organization);
        }

        if !write {
            return Err(ApiError::not_found("package not found"));
        }
        if !matches!(principal.role.as_str(), "publisher" | "admin") {
            return Err(ApiError::forbidden("publisher role required"));
        }
        if let Some(scope) = name
            .strip_prefix('@')
            .and_then(|value| value.split('/').next())
            && scope != principal.organization
        {
            return Err(ApiError::forbidden(
                "package scope belongs to another organization",
            ));
        }
        Ok(principal.organization.clone())
    }

    async fn append_event_keyed(&self, event_key: &str, event: &Value) -> Result<()> {
        let mut tx = self.control.pool().begin().await?;
        query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x4f41_5448_i64)
            .execute(&mut *tx)
            .await?;
        if query_scalar::<_, i32>("SELECT 1 FROM registry_events WHERE event_key=$1")
            .bind(event_key)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        {
            tx.commit().await?;
            return Ok(());
        }
        let previous: String =
            query_scalar("SELECT event_hash FROM registry_events ORDER BY sequence DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or_else(|| "GENESIS".into());
        let event_json = serde_json::to_string(event)?;
        let event_hash = hex_sha256(format!("{previous}{event_json}").as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(
            self.signer
                .sign("transparency-event", event_hash.as_bytes())
                .await?,
        );
        query("INSERT INTO registry_events(event_key,event_json,previous_hash,event_hash,signature,created_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(event_key)
            .bind(event_json)
            .bind(previous)
            .bind(event_hash)
            .bind(signature)
            .bind(now() as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn append_event(&self, event: &Value) -> Result<()> {
        let event_key = format!(
            "direct:{}",
            hex_sha256(serde_json::to_string(event)?.as_bytes())
        );
        self.append_event_keyed(&event_key, event).await
    }

    pub async fn drain_outbox(&self) -> Result<usize> {
        let pending = self
            .control
            .claim_outbox(&self.outbox_worker_id, 100)
            .await?;
        let mut delivered = 0;
        for (id, event_key, event) in pending {
            match self.append_event_keyed(&event_key, &event).await {
                Ok(()) => {
                    self.control
                        .mark_outbox_delivered(id, &self.outbox_worker_id)
                        .await?;
                    delivered += 1;
                }
                Err(error) => {
                    self.control
                        .retry_outbox(id, &self.outbox_worker_id)
                        .await?;
                    tracing::warn!(outbox_id = id, %error, "registry audit event delivery failed");
                }
            }
        }
        Ok(delivered)
    }

    pub async fn prune_expired_rate_limits(&self) -> Result<u64> {
        self.rate_limiter
            .prune(now().saturating_sub(24 * 3600) as i64)
            .await
    }
}

fn positive_limit(name: &str, default: i64) -> Result<i64> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<i64>())
        .transpose()
        .with_context(|| format!("{name} must be a positive integer"))?
        .unwrap_or(default);
    anyhow::ensure!(value > 0, "{name} must be a positive integer");
    Ok(value)
}

async fn track_registry_metrics(
    State(metrics): State<RegistryMetrics>,
    request: Request,
    next: Next,
) -> Response {
    metrics.request();
    let operation = registry_operation(request.method().as_str(), request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        metrics.denied();
    }
    if response.status().is_server_error() {
        metrics.error();
    }
    if let Some(operation) = operation {
        metrics.observe(
            operation,
            started.elapsed(),
            !response.status().is_server_error(),
        );
    }
    response
}

fn registry_operation(method: &str, path: &str) -> Option<RegistryOperation> {
    if method == "POST" && path.ends_with("/revoke") && path.contains("/-/oath/versions/") {
        return Some(RegistryOperation::Revocation);
    }
    if method == "POST" && path.ends_with("/approve") && path.contains("/-/oath/stages/") {
        return Some(RegistryOperation::Publish);
    }
    if method == "POST" && path == "/-/oath/stages" {
        return Some(RegistryOperation::Assessment);
    }
    if method == "GET" && (path.contains("/-/oath/tarballs/") || path.ends_with("/download")) {
        return Some(RegistryOperation::Tarball);
    }
    if method == "GET" && path.starts_with("/v1/verdicts/") {
        return Some(RegistryOperation::Assessment);
    }
    if method == "GET"
        && !matches!(path, "/health" | "/livez" | "/readyz" | "/metrics")
        && !path.starts_with("/-/")
        && !path.starts_with("/v1/")
    {
        return Some(RegistryOperation::Metadata);
    }
    None
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    bearer_optional(headers)?.ok_or_else(ApiError::unauthorized)
}

fn bearer_optional(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ApiError::unauthorized())?;
    let (scheme, token) = value.split_once(' ').ok_or_else(ApiError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.chars().any(char::is_whitespace)
    {
        return Err(ApiError::unauthorized());
    }
    Ok(Some(token))
}

fn manifest_from_tarball(
    tarball: &[u8],
    expected_name: &str,
    expected_version: &str,
) -> Result<Value, ApiError> {
    const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
    const MAX_ARCHIVE_ENTRIES: usize = 200_000;

    let decoder = GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| ApiError::bad(format!("invalid npm tarball: {error}")))?;
    let mut manifest = None;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_ARCHIVE_ENTRIES {
            return Err(ApiError::bad("npm tarball has too many entries"));
        }
        let entry =
            entry.map_err(|error| ApiError::bad(format!("invalid npm tarball entry: {error}")))?;
        let path = entry
            .path()
            .map_err(|error| ApiError::bad(format!("invalid npm tarball path: {error}")))?;
        if path.as_ref() != Path::new("package/package.json") {
            continue;
        }
        if manifest.is_some() {
            return Err(ApiError::bad(
                "npm tarball contains multiple package manifests",
            ));
        }
        let mut bytes = Vec::new();
        entry
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ApiError::bad(format!("cannot read package manifest: {error}")))?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(ApiError::bad("package manifest exceeds 1 MiB"));
        }
        manifest = Some(
            serde_json::from_slice::<Value>(&bytes)
                .map_err(|error| ApiError::bad(format!("invalid package manifest: {error}")))?,
        );
    }

    let manifest = manifest.ok_or_else(|| ApiError::bad("npm tarball has no package.json"))?;
    let object = manifest
        .as_object()
        .ok_or_else(|| ApiError::bad("package manifest must be a JSON object"))?;
    if object.get("name").and_then(Value::as_str) != Some(expected_name) {
        return Err(ApiError::bad(
            "package manifest name does not match stage request",
        ));
    }
    if object.get("version").and_then(Value::as_str) != Some(expected_version) {
        return Err(ApiError::bad(
            "package manifest version does not match stage request",
        ));
    }
    Ok(manifest)
}

fn validate_assessment_bundle(
    bundle: &RegistryAssessmentBundle,
    tarball: &[u8],
    manifest: &Value,
    name: &str,
    version: &str,
    publisher: &str,
    registry: &str,
) -> Result<(), ApiError> {
    let expected_package_digest = format!("sha256:{}", hex_sha256(tarball));
    let expected_manifest_digest =
        oath_contracts::digest_json(manifest).map_err(ApiError::internal)?;
    let verdict = &bundle.verdict;
    let evidence_package_digest = bundle
        .evidence
        .get("package_digest")
        .and_then(Value::as_str);
    let evidence_manifest_digest = bundle
        .evidence
        .get("manifest_digest")
        .and_then(Value::as_str);
    let assessment_digest =
        oath_contracts::digest_json(&bundle.evidence).map_err(ApiError::internal)?;
    let valid = verdict.package.name == name
        && verdict.package.version == version
        && verdict.package.registry == registry
        && verdict.package.publisher.as_deref() == Some(publisher)
        && verdict.package.integrity.as_deref() == Some(expected_package_digest.as_str())
        && verdict.package_digest == expected_package_digest
        && evidence_package_digest == Some(expected_package_digest.as_str())
        && evidence_manifest_digest == Some(expected_manifest_digest.as_str())
        && verdict.assessment_digest == assessment_digest;
    if !valid {
        return Err(ApiError::bad(
            "analysis response is not bound to the submitted package, manifest, publisher, and registry",
        ));
    }
    Ok(())
}

async fn livez() -> Json<Value> {
    Json(json!({"status":"ok","service":"oath-registry","schema_version":1}))
}

async fn readyz(State(registry): State<Arc<PostgresRegistry>>) -> Result<Json<Value>, ApiError> {
    registry.control.ready().await.map_err(ApiError::internal)?;
    registry.objects.ready().await.map_err(ApiError::internal)?;
    registry
        .rate_limiter
        .ready()
        .await
        .map_err(ApiError::internal)?;
    registry.signer.ready().await.map_err(ApiError::internal)?;
    registry
        .analysis
        .ready()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status":"ready",
        "service":"oath-registry",
        "dependencies":{
            "postgresql":"ready",
            "object_store":"ready",
            "rate_limiter":{"status":"ready","backend":registry.rate_limiter.backend()},
            "signer":{"status":"ready","backend":registry.signer.backend()},
            "analyzer":{"status":"ready","backend":registry.analysis.backend()}
        },
        "schema_version":2
    })))
}

async fn create_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<StageRequest>,
) -> Result<(StatusCode, Json<StageRecord>), ApiError> {
    let principal = registry.authenticate(&headers).await?;
    let owner = registry
        .authorize_name(&principal, &request.name, true)
        .await?;
    if let Some(package) = registry
        .control
        .package_for(&request.name, Some(&principal.organization))
        .await
        .map_err(ApiError::internal)?
        && package.private != request.private
    {
        return Err(ApiError::conflict(
            "package visibility cannot change between versions",
        ));
    }
    request
        .version
        .parse::<node_semver::Version>()
        .map_err(|_| ApiError::bad("invalid semantic version"))?;
    let tarball = base64::engine::general_purpose::STANDARD
        .decode(&request.tarball_base64)
        .map_err(|_| ApiError::bad("invalid tarball base64"))?;
    let manifest = manifest_from_tarball(&tarball, &request.name, &request.version)?;
    let digest = hex_sha256(&tarball);
    let mut server_bundle = registry
        .analysis
        .assess(
            &tarball,
            &manifest,
            &request.name,
            &request.version,
            &principal.organization,
            &registry.public_url,
        )
        .await
        .map_err(|error| ApiError::bad(format!("server assessment failed: {error}")))?;
    validate_assessment_bundle(
        &server_bundle,
        &tarball,
        &manifest,
        &request.name,
        &request.version,
        &principal.organization,
        &registry.public_url,
    )?;
    let verdict_bytes =
        oath_contracts::canonical_json_bytes(&server_bundle.verdict).map_err(ApiError::internal)?;
    server_bundle.verdict.signature = Some(
        registry
            .detached_signature("assessment-verdict", &verdict_bytes)
            .await
            .map_err(ApiError::internal)?,
    );
    registry
        .objects
        .put_immutable(&digest, &tarball)
        .await
        .map_err(ApiError::internal)?;
    let created_at = now();
    let stage = StageRecord {
        id: hex_sha256(
            format!(
                "{}:{}:{}:{}:{created_at}",
                owner, request.name, request.version, digest
            )
            .as_bytes(),
        ),
        organization: owner,
        name: request.name,
        version: request.version,
        tag: request.tag,
        digest,
        status: "staged".into(),
        private: request.private,
        manifest,
        publisher_assessment: request.assessment,
        assessment: serde_json::to_value(server_bundle.verdict).map_err(ApiError::internal)?,
        server_evidence: server_bundle.evidence,
        sbom: server_bundle.sbom,
        provenance: server_bundle.provenance,
        created_at,
    };
    let event = json!({"type":"stage.created","id":stage.id,"organization":stage.organization,"actor_org":principal.organization,"name":stage.name,"version":stage.version,"digest":stage.digest});
    let event_key = format!("stage.created:{}", stage.id);
    if !registry
        .control
        .create_stage(&stage, &event_key, &event, registry.maximum_pending_stages)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::too_many_requests(
            "organization pending-stage quota reached",
        ));
    }
    if let Err(error) = registry.drain_outbox().await {
        tracing::warn!(%error, "registry audit outbox will retry stage event");
    }
    registry.metrics.stage();
    Ok((StatusCode::CREATED, Json(stage)))
}

async fn list_stages(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
) -> Result<Json<Vec<StageRecord>>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    Ok(Json(
        registry
            .control
            .list_stages(&principal.organization)
            .await
            .map_err(ApiError::internal)?,
    ))
}

async fn view_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<StageRecord>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    let stage = registry
        .control
        .read_stage_for(&id, Some(&principal.organization))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("stage not found"))?;
    registry
        .authorize_name(&principal, &stage.name, false)
        .await?;
    Ok(Json(stage))
}

async fn download_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let Json(stage) = view_stage(State(registry.clone()), headers, AxumPath(id)).await?;
    let bytes = registry
        .objects
        .get(&stage.digest)
        .await
        .map_err(ApiError::internal)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn decide(
    registry: Arc<PostgresRegistry>,
    headers: HeaderMap,
    id: String,
    approve: bool,
    reason: Option<String>,
) -> Result<Json<StageRecord>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin approval required"));
    }
    if approve && registry.require_step_up_approval && principal.kind != "oidc-mfa" {
        return Err(ApiError::forbidden(
            "approval requires a fresh OIDC identity with MFA or phishing-resistant authentication",
        ));
    }
    let stage = registry
        .control
        .read_stage_for(&id, Some(&principal.organization))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("stage not found"))?;
    if stage.organization != principal.organization {
        return Err(ApiError::forbidden(
            "only the owning organization may approve or reject a stage",
        ));
    }
    if approve && stage.assessment.get("decision").and_then(Value::as_str) == Some("deny") {
        return Err(ApiError::conflict(
            "server assessment denied this exact artifact; approval is not permitted",
        ));
    }
    let event = json!({"type":if approve {"stage.approved"} else {"stage.rejected"},"id":id,"organization":principal.organization,"name":stage.name,"version":stage.version,"reason":reason});
    let event_key = format!(
        "stage.{}:{id}",
        if approve { "approved" } else { "rejected" }
    );
    if !registry
        .control
        .decide_stage(&stage, approve, reason.as_deref(), &event_key, &event)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("stage has already been decided"));
    }
    if let Err(error) = registry.drain_outbox().await {
        tracing::warn!(%error, "registry audit outbox will retry stage decision event");
    }
    Ok(Json(
        registry
            .control
            .read_stage_for(&id, Some(&principal.organization))
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::internal("stage disappeared"))?,
    ))
}

async fn approve_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<StageRecord>, ApiError> {
    decide(registry, headers, id, true, request.reason).await
}
async fn reject_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<StageRecord>, ApiError> {
    decide(registry, headers, id, false, request.reason).await
}

async fn package_metadata(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate_optional(&headers).await?;
    let package = registry
        .control
        .package_for(
            &name,
            principal.as_ref().map(|value| value.organization.as_str()),
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("package not found"))?;
    if package.private {
        let principal = principal.as_ref().ok_or_else(ApiError::unauthorized)?;
        registry.authorize_name(principal, &name, false).await?;
    }
    let mut versions = serde_json::Map::new();
    for row in registry
        .control
        .package_versions_for(
            &name,
            principal.as_ref().map(|value| value.organization.as_str()),
        )
        .await
        .map_err(ApiError::internal)?
    {
        let integrity_bytes = hex::decode(&row.digest).map_err(ApiError::internal)?;
        if integrity_bytes.len() != 32 {
            return Err(ApiError::internal(
                "stored SHA-256 digest has invalid length",
            ));
        }
        let encoded_name =
            url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>();
        let version = row.version;
        let encoded_version =
            url::form_urlencoded::byte_serialize(version.as_bytes()).collect::<String>();
        let tarball = format!(
            "{}/-/oath/tarballs/{encoded_name}/{encoded_version}",
            registry.public_url
        );
        let mut version_metadata = row.manifest;
        let object = version_metadata
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("stored package manifest is not an object"))?;
        object.insert("name".into(), Value::String(name.clone()));
        object.insert("version".into(), Value::String(version.clone()));
        object.insert(
            "dist".into(),
            json!({"integrity":format!("sha256-{}",base64::engine::general_purpose::STANDARD.encode(integrity_bytes)),"tarball":tarball}),
        );
        object.insert(
            "oath".into(),
            json!({
                "status":row.status,
                "private":row.private,
                "publisher_organization":row.organization,
                "published_at":row.published_at,
                "release_age_seconds":(now() as i64).saturating_sub(row.published_at),
                "downloads":row.download_count,
                "source_available":row.assessment["package"]["repository"].is_string(),
                "risk_score":row.assessment["risk_score"],
                "assessment":row.assessment,
                "server_evidence":row.server_evidence,
                "sbom":row.sbom,
                "provenance":row.provenance
            }),
        );
        versions.insert(version, version_metadata);
    }
    if versions.is_empty() {
        return Err(ApiError::not_found("package has no published versions"));
    }
    let tags = registry
        .control
        .dist_tags_for(
            &name,
            principal.as_ref().map(|value| value.organization.as_str()),
        )
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect::<serde_json::Map<_, _>>();
    Ok(Json(
        json!({"name":name,"dist-tags":tags,"versions":versions}),
    ))
}

async fn revoke_version(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath((name, version)): AxumPath<(String, String)>,
    Json(request): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    registry.authorize_name(&principal, &name, true).await?;
    let status = if request.quarantine {
        "quarantined"
    } else {
        "revoked"
    };
    let created_at = now();
    let payload = json!({"name":name,"version":version,"status":status,"reason":request.reason,"actor_org":principal.organization,"created_at":created_at});
    let bytes = oath_contracts::canonical_json_bytes(&payload).map_err(ApiError::internal)?;
    let signature = base64::engine::general_purpose::STANDARD.encode(
        registry
            .signer
            .sign("revocation-tombstone", &bytes)
            .await
            .map_err(ApiError::internal)?,
    );
    let public_key = base64::engine::general_purpose::STANDARD.encode(registry.signer.public_key());
    let event = json!({"type":"version.revoked","tombstone":payload.clone(),"signature":signature,"public_key":public_key});
    let event_key = format!("version.{status}:{name}@{version}");
    if !registry
        .control
        .revoke_version(
            &name,
            &version,
            status,
            &request.reason,
            &principal.organization,
            created_at as i64,
            &signature,
            &public_key,
            &event_key,
            &event,
        )
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found("package version not found"));
    }
    if let Err(error) = registry.drain_outbox().await {
        tracing::warn!(%error, "registry audit outbox will retry revocation event");
    }
    Ok(Json(json!({
        "tombstone": {
            "payload": payload,
            "algorithm": "ed25519",
            "canonicalization": "oath-json-v1+oath-domain-sha256-v1",
            "domain": "revocation-tombstone",
            "signature": signature,
            "public_key": public_key
        }
    })))
}

async fn download_version(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath((name, version)): AxumPath<(String, String)>,
) -> Result<Response, ApiError> {
    let principal = registry.authenticate_optional(&headers).await?;
    let row = registry
        .control
        .version_for(
            &name,
            &version,
            principal.as_ref().map(|value| value.organization.as_str()),
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("package version not found"))?;
    if row.private {
        let principal = principal.as_ref().ok_or_else(ApiError::unauthorized)?;
        registry.authorize_name(principal, &name, false).await?;
    }
    if row.status != "active" {
        return Err(ApiError::forbidden(format!(
            "package version is {}",
            row.status
        )));
    }
    let bytes = registry
        .objects
        .get(&row.digest)
        .await
        .map_err(ApiError::internal)?;
    registry
        .control
        .record_download(&name, &version)
        .await
        .map_err(ApiError::internal)?;
    registry.metrics.download();
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn metrics(State(registry): State<Arc<PostgresRegistry>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        registry.metrics.prometheus(),
    )
        .into_response()
}

async fn admin_summary(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(Json(
        json!({"service":"oath-registry","control_plane":"postgresql","organization":principal.organization,"metrics":registry.metrics.snapshot()}),
    ))
}

async fn admin_ui() -> Html<&'static str> {
    Html(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Oath Registry Administration</title><style>body{font:16px system-ui;max-width:900px;margin:4rem auto;padding:0 1rem;background:#0b0d10;color:#e8edf2}button,input{font:inherit;padding:.7rem}pre{background:#151a20;padding:1rem;overflow:auto}.card{border:1px solid #303842;border-radius:12px;padding:1.25rem}</style><h1>Oath Registry</h1><div class="card"><p>Paste a short-lived administrator token. It stays in this tab.</p><input id="token" type="password" size="50" autocomplete="off"><button id="load">Load control-plane status</button><pre id="output">No data loaded.</pre></div><script>load.onclick=async()=>{const r=await fetch('/-/oath/admin/summary',{headers:{Authorization:'Bearer '+token.value}});output.textContent=JSON.stringify(await r.json(),null,2)}</script>"#,
    )
}

async fn checkpoint(
    State(registry): State<Arc<PostgresRegistry>>,
) -> Result<Json<TransparencyCheckpoint>, ApiError> {
    let hashes = registry
        .control
        .event_hashes()
        .await
        .map_err(ApiError::internal)?;
    let root = merkle_root(hashes.clone());
    let payload = json!({
        "schema_version": 2,
        "event_count": hashes.len(),
        "merkle_root": root,
        "latest_hash": hashes.last(),
    });
    let signature = base64::engine::general_purpose::STANDARD.encode(
        registry
            .signer
            .sign(
                "transparency-checkpoint",
                &oath_contracts::canonical_json_bytes(&payload).map_err(ApiError::internal)?,
            )
            .await
            .map_err(ApiError::internal)?,
    );
    Ok(Json(TransparencyCheckpoint {
        schema_version: 2,
        event_count: hashes.len(),
        merkle_root: root,
        latest_hash: hashes.last().cloned(),
        canonicalization: "oath-json-v1+oath-domain-sha256-v1".into(),
        domain: "transparency-checkpoint".into(),
        public_key: base64::engine::general_purpose::STANDARD.encode(registry.signer.public_key()),
        signature,
    }))
}

async fn inclusion_proof(
    State(registry): State<Arc<PostgresRegistry>>,
    AxumPath(sequence): AxumPath<usize>,
) -> Result<Json<Value>, ApiError> {
    if sequence == 0 {
        return Err(ApiError::bad("event sequence starts at 1"));
    }
    let hashes = registry
        .control
        .event_hashes()
        .await
        .map_err(ApiError::internal)?;
    let index = sequence - 1;
    let leaf = hashes
        .get(index)
        .cloned()
        .ok_or_else(|| ApiError::not_found("transparency event not found"))?;
    let root = merkle_root(hashes.clone());
    let proof = merkle_inclusion_proof(hashes.clone(), index)
        .ok_or_else(|| ApiError::internal("cannot build inclusion proof"))?;
    Ok(Json(json!({
        "schema_version":1,
        "sequence":sequence,
        "tree_size":hashes.len(),
        "leaf_hash":leaf,
        "merkle_root":root,
        "proof":proof
    })))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    from: usize,
}

async fn consistency_proof(
    State(registry): State<Arc<PostgresRegistry>>,
    Query(query): Query<ConsistencyQuery>,
) -> Result<Json<Value>, ApiError> {
    let hashes = registry
        .control
        .event_hashes()
        .await
        .map_err(ApiError::internal)?;
    if query.from > hashes.len() {
        return Err(ApiError::bad("from tree size exceeds current tree size"));
    }
    let proof = merkle_consistency_proof(&hashes, query.from)
        .ok_or_else(|| ApiError::internal("cannot build consistency proof"))?;
    Ok(Json(json!({
        "schema_version":2,
        "proof_type":"compact-frontier-v1",
        "from_size":query.from,
        "to_size":hashes.len(),
        "from_root":merkle_root(hashes[..query.from].to_vec()),
        "to_root":merkle_root(hashes.clone()),
        "prefix":proof.prefix,
        "suffix":proof.suffix,
        "hash_algorithm":"sha256",
        "domain_separation":{"leaf":0,"node":1}
    })))
}

async fn verdict_bundle(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath((name, version)): AxumPath<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate_optional(&headers).await?;
    let record = registry
        .control
        .version_bundle_for(
            &name,
            &version,
            principal.as_ref().map(|value| value.organization.as_str()),
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("package version not found"))?;
    if record.private {
        let principal = principal.as_ref().ok_or_else(ApiError::unauthorized)?;
        registry.authorize_name(principal, &name, false).await?;
    }
    let hashes = registry
        .control
        .event_hashes()
        .await
        .map_err(ApiError::internal)?;
    let root = merkle_root(hashes.clone());
    let checkpoint_payload = json!({
        "schema_version":2,
        "event_count":hashes.len(),
        "merkle_root":root,
        "latest_hash":hashes.last(),
    });
    let checkpoint_signature = base64::engine::general_purpose::STANDARD.encode(
        registry
            .signer
            .sign(
                "transparency-checkpoint",
                &oath_contracts::canonical_json_bytes(&checkpoint_payload)
                    .map_err(ApiError::internal)?,
            )
            .await
            .map_err(ApiError::internal)?,
    );
    let tombstone = record.tombstone.map(tombstone_bundle).transpose()?;
    Ok(Json(json!({
        "schema_version":1,
        "package":{"name":name,"version":version,"organization":record.organization},
        "digest":format!("sha256:{}",record.digest),
        "status":record.status,
        "published_at":record.published_at,
        "downloads":record.download_count,
        "verdict":record.assessment,
        "server_evidence":record.server_evidence,
        "sbom":record.sbom,
        "provenance":record.provenance,
        "tombstone":tombstone,
        "checkpoint":{
            "payload":checkpoint_payload,
            "algorithm":"ed25519",
            "canonicalization":"oath-json-v1+oath-domain-sha256-v1",
            "domain":"transparency-checkpoint",
            "public_key":base64::engine::general_purpose::STANDARD.encode(registry.signer.public_key()),
            "signature":checkpoint_signature,
        }
    })))
}

fn tombstone_bundle(value: Value) -> Result<Value, ApiError> {
    let field = |name: &str| {
        value
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::internal(format!("stored tombstone has no {name}")))
    };
    Ok(json!({
        "payload": {
            "name": field("name")?,
            "version": field("version")?,
            "status": field("status")?,
            "reason": field("reason")?,
            "actor_org": field("actor_org")?,
            "created_at": field("created_at")?
        },
        "algorithm": "ed25519",
        "canonicalization": "oath-json-v1+oath-domain-sha256-v1",
        "domain": "revocation-tombstone",
        "signature": field("signature")?,
        "public_key": field("public_key")?
    }))
}

async fn osv_feed(State(registry): State<Arc<PostgresRegistry>>) -> Result<Json<Value>, ApiError> {
    let rows = registry
        .control
        .public_quarantines()
        .await
        .map_err(ApiError::internal)?;
    let entries = rows.into_iter().map(|(name, version, reason, created_at)| {
        let modified = chrono::DateTime::from_timestamp(created_at, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH)
            .to_rfc3339();
        json!({
            "schema_version":"1.6.0",
            "id":format!("OATH-MAL-{}",hex_sha256(format!("{name}@{version}").as_bytes())[..16].to_uppercase()),
            "modified":modified,
            "published":modified,
            "summary":format!("Oath quarantined {name}@{version}"),
            "details":reason,
            "affected":[{
                "package":{"ecosystem":"npm","name":name},
                "versions":[version],
                "database_specific":{"source":"oath-registry","status":"quarantined"}
            }]
        })
    }).collect::<Vec<_>>();
    Ok(Json(json!({"schema_version":1,"vulns":entries})))
}

async fn issue_token(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid token role"));
    }
    if !(60..=86_400).contains(&request.ttl_secs) {
        return Err(ApiError::bad(
            "token ttl must be between 60 and 86400 seconds",
        ));
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(ApiError::internal)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    registry
        .control
        .insert_token(
            &hex_sha256(token.as_bytes()),
            &principal.organization,
            &request.role,
            now().saturating_add(request.ttl_secs) as i64,
            "service",
        )
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"token.issued","organization":principal.organization,"role":request.role,"expires_at":now()+request.ttl_secs})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","role":request.role,"expires_in":request.ttl_secs}),
    ))
}

async fn grant_role(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(request): Json<PackageRoleRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    let owner = registry.authorize_name(&principal, &name, true).await?;
    if owner != principal.organization {
        return Err(ApiError::forbidden(
            "only the package-owning organization may grant roles",
        ));
    }
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid package role"));
    }
    registry
        .control
        .grant_package_role(
            &name,
            &principal.organization,
            &request.principal_org,
            &request.role,
        )
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"package.role_granted","name":name,"owner_org":principal.organization,"principal_org":request.principal_org,"role":request.role})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"name":name,"principal_org":request.principal_org,"role":request.role}),
    ))
}

#[derive(Deserialize)]
struct InvitationRequest {
    email: String,
    role: String,
    #[serde(default = "invitation_ttl")]
    ttl_secs: u64,
}
fn invitation_ttl() -> u64 {
    86_400
}
#[derive(Deserialize)]
struct InvitationAcceptRequest {
    invitation_token: String,
    id_token: String,
}
#[derive(Deserialize)]
struct SsoExchangeRequest {
    id_token: String,
}

async fn create_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<InvitationRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid invitation role"));
    }
    if !(300..=604_800).contains(&request.ttl_secs) {
        return Err(ApiError::bad(
            "invitation ttl must be between 300 and 604800 seconds",
        ));
    }
    let mailer = registry
        .mailer
        .as_ref()
        .ok_or_else(|| ApiError::internal("invitation email provider is not configured"))?;
    let invitation_accept_url = registry
        .invitation_accept_url
        .as_deref()
        .ok_or_else(|| ApiError::internal("invitation accept URL is not configured"))?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(ApiError::internal)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let token_hash = hex_sha256(token.as_bytes());
    let expires_at = now().saturating_add(request.ttl_secs);
    registry
        .control
        .create_invitation(
            &token_hash,
            &principal.organization,
            &request.email,
            &request.role,
            expires_at as i64,
        )
        .await
        .map_err(ApiError::internal)?;
    let separator = if invitation_accept_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let accept_url = format!("{invitation_accept_url}{separator}invitation_token={token}");
    if let Err(error) = mailer
        .send_invitation(&request.email, &principal.organization, &accept_url)
        .await
    {
        registry
            .control
            .revoke_invitation(&token_hash, &principal.organization)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::internal(error));
    }
    registry.append_event(&json!({"type":"invitation.created","organization":principal.organization,"email_hash":hex_sha256(request.email.as_bytes()),"role":request.role,"expires_at":expires_at})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"status":"sent","token_id":token_hash,"expires_at":expires_at}),
    ))
}

async fn revoke_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(token_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !registry
        .control
        .revoke_invitation(&token_id, &principal.organization)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found("active invitation not found"));
    }
    registry.append_event(&json!({"type":"invitation.revoked","organization":principal.organization,"token_id":token_id})).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"status":"revoked","token_id":token_id})))
}

async fn accept_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    Json(request): Json<InvitationAcceptRequest>,
) -> Result<Json<Value>, ApiError> {
    let verifier = registry
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC provider is not configured"))?;
    let claims = verifier
        .verify(&request.id_token)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    if !claims.email_verified {
        return Err(ApiError::forbidden("OIDC email is not verified"));
    }
    let step_up = claims.has_step_up_authentication();
    let email = claims
        .email
        .ok_or_else(|| ApiError::forbidden("OIDC identity has no email"))?;
    let token_hash = hex_sha256(request.invitation_token.as_bytes());
    let invitation = registry
        .control
        .accept_invitation(&token_hash, &claims.sub, &email)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("active invitation not found"))?;
    let token = registry
        .issue_identity_token(&invitation.organization, &invitation.role, step_up)
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"invitation.accepted","organization":invitation.organization,"subject_hash":hex_sha256(claims.sub.as_bytes()),"email_hash":hex_sha256(email.as_bytes()),"role":invitation.role})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","expires_in":3600,"organization":invitation.organization,"role":invitation.role}),
    ))
}

async fn sso_exchange(
    State(registry): State<Arc<PostgresRegistry>>,
    Json(request): Json<SsoExchangeRequest>,
) -> Result<Json<Value>, ApiError> {
    let verifier = registry
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC provider is not configured"))?;
    let claims = verifier
        .verify(&request.id_token)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    let (organization, role) = registry
        .control
        .membership(&claims.sub)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::forbidden("identity is not an organization member"))?;
    let token = registry
        .issue_identity_token(&organization, &role, claims.has_step_up_authentication())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","expires_in":3600,"organization":organization,"role":role}),
    ))
}

#[derive(Deserialize)]
struct CheckoutRequest {
    price_id: String,
    success_url: String,
    cancel_url: String,
}

async fn billing_checkout(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<CheckoutRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    let billing = registry
        .billing
        .as_ref()
        .ok_or_else(|| ApiError::internal("billing provider is not configured"))?;
    let url = billing
        .create_checkout(
            &principal.organization,
            &request.price_id,
            &request.success_url,
            &request.cancel_url,
        )
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"checkout_url":url})))
}

async fn billing_webhook(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let billing = registry
        .billing
        .as_ref()
        .ok_or_else(|| ApiError::internal("billing provider is not configured"))?;
    let event = billing
        .verify_webhook(signature, &body, now())
        .map_err(|_| ApiError::unauthorized())?;
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("billing event has no id"))?;
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("billing event has no type"))?;
    registry
        .control
        .record_billing_event(id, event_type, &event)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router(registry: PostgresRegistry) -> Router {
    let metrics_state = registry.metrics.clone();
    let max_stage_request_bytes = registry.max_stage_request_bytes;
    let registry = Arc::new(registry);
    Router::new()
        .route("/health", get(readyz))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route(
            "/-/oath/stages",
            post(create_stage)
                .get(list_stages)
                .layer(DefaultBodyLimit::max(max_stage_request_bytes)),
        )
        .route("/-/oath/stages/{id}", get(view_stage))
        .route("/-/oath/stages/{id}/download", get(download_stage))
        .route("/-/oath/stages/{id}/approve", post(approve_stage))
        .route("/-/oath/stages/{id}/reject", post(reject_stage))
        .route(
            "/-/oath/versions/{name}/{version}/revoke",
            post(revoke_version),
        )
        .route("/-/oath/tarballs/{name}/{version}", get(download_version))
        .route("/-/oath/transparency/checkpoint", get(checkpoint))
        .route(
            "/-/oath/transparency/inclusion/{sequence}",
            get(inclusion_proof),
        )
        .route("/-/oath/transparency/consistency", get(consistency_proof))
        .route("/v1/verdicts/{name}/{version}", get(verdict_bundle))
        .route("/v1/security/osv", get(osv_feed))
        .route("/-/oath/tokens", post(issue_token))
        .route("/metrics", get(metrics))
        .route("/-/oath/admin/summary", get(admin_summary))
        .route("/-/oath/admin", get(admin_ui))
        .route("/-/oath/invitations", post(create_invitation))
        .route(
            "/-/oath/invitations/{token_id}/revoke",
            post(revoke_invitation),
        )
        .route("/-/oath/invitations/accept", post(accept_invitation))
        .route("/-/oath/sso/exchange", post(sso_exchange))
        .route("/-/oath/billing/checkout", post(billing_checkout))
        .route("/-/oath/billing/webhook", post(billing_webhook))
        .route("/-/oath/packages/{name}/roles", post(grant_role))
        .route("/{*name}", get(package_metadata))
        .with_state(registry.clone())
        .layer(middleware::from_fn_with_state(
            registry,
            enforce_registry_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            metrics_state,
            track_registry_metrics,
        ))
}

async fn enforce_registry_rate_limit(
    State(registry): State<Arc<PostgresRegistry>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let path = request.uri().path();
    if matches!(path, "/livez" | "/readyz" | "/health" | "/metrics") {
        return Ok(next.run(request).await);
    }
    let subject = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| hex_sha256(value.as_bytes()))
        .unwrap_or_else(|| "anonymous".into());
    let allowed = registry
        .rate_limiter
        .consume(&subject, "api-minute", registry.requests_per_minute, 60)
        .await
        .map_err(ApiError::internal)?;
    if !allowed {
        return Err(ApiError::too_many_requests(
            "registry request rate exceeded",
        ));
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    #[test]
    fn classifies_slo_operations_without_dynamic_metric_labels() {
        assert_eq!(
            registry_operation("GET", "/left-pad"),
            Some(RegistryOperation::Metadata)
        );
        assert_eq!(
            registry_operation("GET", "/-/oath/tarballs/left-pad/1.0.0"),
            Some(RegistryOperation::Tarball)
        );
        assert_eq!(
            registry_operation("POST", "/-/oath/stages"),
            Some(RegistryOperation::Assessment)
        );
        assert_eq!(
            registry_operation("POST", "/-/oath/stages/123/approve"),
            Some(RegistryOperation::Publish)
        );
        assert_eq!(
            registry_operation("POST", "/-/oath/versions/pkg/1.0.0/revoke"),
            Some(RegistryOperation::Revocation)
        );
        assert_eq!(registry_operation("GET", "/metrics"), None);
    }
    use http_body_util::{BodyExt, Collected};
    use object_store::memory::InMemory;
    use sha2::{Digest, Sha256};
    use sqlx_core::row::Row;
    use tower::ServiceExt;

    fn get_request(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut request = Request::get(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::empty()).unwrap()
    }

    fn post_request(uri: &str, token: &str, body: Value) -> Request<Body> {
        Request::post(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn call(app: &Router, request: Request<Body>) -> Response {
        app.clone().oneshot(request).await.unwrap()
    }

    async fn body(response: Response) -> Collected<Bytes> {
        response.into_body().collect().await.unwrap()
    }

    fn package_tarball(name: &str, version: &str) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};

        let manifest = serde_json::to_vec(&json!({
            "name": name,
            "version": version,
            "dependencies": {},
            "bin": {"tool": "bin.js"}
        }))
        .unwrap();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "package/package.json", manifest.as_slice())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    async fn stage(
        app: &Router,
        token: &str,
        name: &str,
        version: &str,
        private: bool,
    ) -> StageRecord {
        let response = call(
            app,
            post_request(
                "/-/oath/stages",
                token,
                json!({
                    "name": name,
                    "version": version,
                    "tag": "latest",
                    "tarball_base64": base64::engine::general_purpose::STANDARD
                        .encode(package_tarball(name, version)),
                    "assessment": {"decision": "allow"},
                    "private": private
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        serde_json::from_slice(&body(response).await.to_bytes()).unwrap()
    }

    async fn approve(app: &Router, token: &str, id: &str) -> Response {
        call(
            app,
            post_request(
                &format!("/-/oath/stages/{id}/approve"),
                token,
                json!({"reason": "verified"}),
            ),
        )
        .await
    }

    #[test]
    fn bearer_parser_is_case_insensitive_and_rejects_malformed_values() {
        let mut headers = HeaderMap::new();
        assert!(bearer_optional(&headers).unwrap().is_none());
        headers.insert(header::AUTHORIZATION, "bearer token".parse().unwrap());
        assert_eq!(bearer(&headers).unwrap(), "token");

        for malformed in ["token", "Basic token", "Bearer ", "Bearer one two"] {
            headers.insert(header::AUTHORIZATION, malformed.parse().unwrap());
            assert_eq!(
                bearer_optional(&headers).unwrap_err().status,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[test]
    fn staged_tarball_manifest_is_required_and_bound_to_identity() {
        let tarball = package_tarball("demo", "1.2.3");
        let manifest = manifest_from_tarball(&tarball, "demo", "1.2.3").unwrap();
        assert_eq!(manifest["name"], "demo");
        assert!(manifest_from_tarball(&tarball, "other", "1.2.3").is_err());
        assert!(manifest_from_tarball(&tarball, "demo", "2.0.0").is_err());
        assert!(manifest_from_tarball(b"not-a-tarball", "demo", "1.2.3").is_err());
    }

    #[test]
    fn assessment_bundle_is_cryptographically_bound_to_stage_inputs() {
        let tarball = package_tarball("demo", "1.2.3");
        let manifest = manifest_from_tarball(&tarball, "demo", "1.2.3").unwrap();
        let mut bundle = crate::assessment::assess_tarball(
            &tarball,
            &manifest,
            "demo",
            "1.2.3",
            "acme",
            "https://registry.example",
        )
        .unwrap();
        assert!(
            validate_assessment_bundle(
                &bundle,
                &tarball,
                &manifest,
                "demo",
                "1.2.3",
                "acme",
                "https://registry.example",
            )
            .is_ok()
        );
        bundle.evidence["manifest_digest"] = json!("sha256:deadbeef");
        assert!(
            validate_assessment_bundle(
                &bundle,
                &tarball,
                &manifest,
                "demo",
                "1.2.3",
                "acme",
                "https://registry.example",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn live_postgres_enforces_tenants_publish_download_and_revoke() {
        let Ok(database_url) = std::env::var("OATH_TEST_DATABASE_URL") else {
            return;
        };
        let pool = PgPool::connect(&database_url).await.unwrap();
        raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        PostgresControlPlane::migrate_url(&database_url)
            .await
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(Arc::new(InMemory::new()));
        let registry = PostgresRegistry::connect(&database_url, store, &temp.path().join("key"))
            .await
            .unwrap();
        registry
            .bootstrap_token("acme", "secret", "admin")
            .await
            .unwrap();
        registry
            .bootstrap_token("rival", "rival-secret", "admin")
            .await
            .unwrap();
        let registry_assertions = registry.clone();
        assert!(
            registry_assertions
                .control
                .consume_rate_limit("rate-test", "test-window", 2, 60)
                .await
                .unwrap()
        );
        assert!(
            registry_assertions
                .control
                .consume_rate_limit("rate-test", "test-window", 2, 60)
                .await
                .unwrap()
        );
        assert!(
            !registry_assertions
                .control
                .consume_rate_limit("rate-test", "test-window", 2, 60)
                .await
                .unwrap()
        );
        let mut quota_registry = registry.clone();
        quota_registry.maximum_pending_stages = 1;
        let quota_app = router(quota_registry);
        let quota_stage = stage(&quota_app, "secret", "quota-tool", "1.0.0", true).await;
        let quota_response = call(
            &quota_app,
            post_request(
                "/-/oath/stages",
                "secret",
                json!({
                    "name": "quota-tool-two",
                    "version": "1.0.0",
                    "tag": "latest",
                    "tarball_base64": base64::engine::general_purpose::STANDARD
                        .encode(package_tarball("quota-tool-two", "1.0.0")),
                    "assessment": {"decision": "allow"},
                    "private": true
                }),
            ),
        )
        .await;
        assert_eq!(quota_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            call(
                &quota_app,
                post_request(
                    &format!("/-/oath/stages/{}/reject", quota_stage.id),
                    "secret",
                    json!({"reason": "quota test complete"}),
                ),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let mut guarded_registry = registry.clone();
        guarded_registry.require_step_up_approval = true;
        let guarded_app = router(guarded_registry);
        let guarded = stage(&guarded_app, "secret", "step-up-tool", "1.0.0", true).await;
        assert_eq!(
            approve(&guarded_app, "secret", &guarded.id).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &guarded_app,
                post_request(
                    &format!("/-/oath/stages/{}/reject", guarded.id),
                    "secret",
                    json!({"reason": "step-up test complete"}),
                ),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let app = router(registry);

        for path in ["/livez", "/readyz", "/health"] {
            assert_eq!(
                call(&app, get_request(path, None)).await.status(),
                StatusCode::OK
            );
        }

        let first = stage(&app, "secret", "private-tool", "1.0.0", true).await;
        assert_eq!(first.publisher_assessment["decision"], "allow");
        assert_eq!(first.assessment["schema_version"], 1);
        assert_eq!(first.assessment["package"]["publisher"], "acme");
        assert_eq!(first.server_evidence["schema_version"], 1);
        assert_eq!(first.sbom["spdxVersion"], "SPDX-2.3");
        assert_eq!(
            first.provenance["predicateType"],
            "https://oath.dev/attestation/registry-assessment/v1"
        );
        assert_ne!(first.assessment, first.publisher_assessment);
        let first_verdict: oath_contracts::RegistryVerdictV1 =
            serde_json::from_value(first.assessment.clone()).unwrap();
        oath_contracts::verify_registry_verdict(&first_verdict).unwrap();

        let response = call(&app, get_request("/-/oath/stages", Some("rival-secret"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let rival_stages: Vec<StageRecord> =
            serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert!(rival_stages.is_empty());

        for response in [
            call(
                &app,
                get_request(
                    &format!("/-/oath/stages/{}", first.id),
                    Some("rival-secret"),
                ),
            )
            .await,
            approve(&app, "rival-secret", &first.id).await,
            call(
                &app,
                post_request(
                    "/-/oath/stages",
                    "rival-secret",
                    json!({
                        "name": "private-tool",
                        "version": "9.0.0",
                        "tarball_base64": base64::engine::general_purpose::STANDARD.encode(b"bad"),
                        "assessment": {"decision": "allow"},
                        "private": true
                    }),
                ),
            )
            .await,
        ] {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        assert_eq!(
            approve(&app, "secret", &first.id).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            approve(&app, "secret", &first.id).await.status(),
            StatusCode::CONFLICT
        );

        let private_verdict = "/v1/verdicts/private-tool/1.0.0";
        assert_eq!(
            call(&app, get_request(private_verdict, None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, get_request(private_verdict, Some("rival-secret")))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = call(&app, get_request(private_verdict, Some("secret"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let private_bundle: Value =
            serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(private_bundle["status"], "active");
        assert_eq!(private_bundle["server_evidence"]["schema_version"], 1);
        assert_eq!(private_bundle["sbom"]["spdxVersion"], "SPDX-2.3");
        let checkpoint_signature = oath_contracts::DetachedSignature {
            algorithm: private_bundle["checkpoint"]["algorithm"]
                .as_str()
                .unwrap()
                .into(),
            canonicalization: private_bundle["checkpoint"]["canonicalization"]
                .as_str()
                .unwrap()
                .into(),
            domain: private_bundle["checkpoint"]["domain"]
                .as_str()
                .map(str::to_owned),
            public_key: private_bundle["checkpoint"]["public_key"]
                .as_str()
                .unwrap()
                .into(),
            signature: private_bundle["checkpoint"]["signature"]
                .as_str()
                .unwrap()
                .into(),
        };
        oath_contracts::verify_json(
            &private_bundle["checkpoint"]["payload"],
            &checkpoint_signature,
        )
        .unwrap();

        assert_eq!(
            call(&app, get_request("/private-tool", None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, get_request("/private-tool", Some("rival-secret")))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, get_request("/private-tool", Some("secret")))
                .await
                .status(),
            StatusCode::OK
        );

        let private_tarball = "/-/oath/tarballs/private-tool/1.0.0";
        assert_eq!(
            call(&app, get_request(private_tarball, Some("rival-secret")))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = call(&app, get_request(private_tarball, Some("secret"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response).await.to_bytes(),
            package_tarball("private-tool", "1.0.0")
        );

        assert_eq!(
            call(
                &app,
                post_request(
                    "/-/oath/packages/private-tool/roles",
                    "rival-secret",
                    json!({"principal_org": "rival", "role": "admin"}),
                ),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                post_request(
                    "/-/oath/versions/private-tool/1.0.0/revoke",
                    "rival-secret",
                    json!({"reason": "not mine"}),
                ),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        let second = stage(&app, "secret", "private-tool", "2.0.0", true).await;
        assert_eq!(
            approve(&app, "secret", &second.id).await.status(),
            StatusCode::OK
        );
        let response = call(&app, get_request("/private-tool", Some("secret"))).await;
        let metadata: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(metadata["dist-tags"]["latest"], "2.0.0");

        assert_eq!(
            call(
                &app,
                post_request(
                    "/-/oath/versions/private-tool/2.0.0/revoke",
                    "secret",
                    json!({"reason": "bad release"}),
                ),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let response = call(&app, get_request("/private-tool", Some("secret"))).await;
        let metadata: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(metadata["dist-tags"]["latest"], "1.0.0");
        assert!(metadata["versions"].get("2.0.0").is_none());
        assert!(metadata["versions"].get("1.0.0").is_some());

        let response = call(
            &app,
            post_request(
                "/-/oath/versions/private-tool/1.0.0/revoke",
                "secret",
                json!({"reason": "retired"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let revocation: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        let detached = oath_contracts::DetachedSignature {
            algorithm: revocation["tombstone"]["algorithm"]
                .as_str()
                .unwrap()
                .to_owned(),
            canonicalization: revocation["tombstone"]["canonicalization"]
                .as_str()
                .unwrap()
                .to_owned(),
            domain: revocation["tombstone"]["domain"]
                .as_str()
                .map(str::to_owned),
            public_key: revocation["tombstone"]["public_key"]
                .as_str()
                .unwrap()
                .to_owned(),
            signature: revocation["tombstone"]["signature"]
                .as_str()
                .unwrap()
                .to_owned(),
        };
        oath_contracts::verify_json(&revocation["tombstone"]["payload"], &detached).unwrap();
        let response = call(
            &app,
            get_request("/v1/verdicts/private-tool/1.0.0", Some("secret")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let revoked_bundle: Value =
            serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(
            revoked_bundle["tombstone"]["payload"],
            revocation["tombstone"]["payload"]
        );
        oath_contracts::verify_json(&revoked_bundle["tombstone"]["payload"], &detached).unwrap();
        let response = call(&app, get_request("/private-tool", Some("secret"))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            call(&app, get_request(private_tarball, None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let public = stage(&app, "secret", "public-tool", "1.0.0", false).await;
        assert_eq!(
            approve(&app, "secret", &public.id).await.status(),
            StatusCode::OK
        );
        let response = call(&app, get_request("/public-tool", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metadata: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        let expected_integrity = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(package_tarball("public-tool", "1.0.0")))
        );
        assert_eq!(
            metadata["versions"]["1.0.0"]["dist"]["integrity"],
            expected_integrity
        );
        assert_eq!(
            metadata["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:4873/-/oath/tarballs/public-tool/1.0.0"
        );
        let packument: oath_fetch::packument::Packument = serde_json::from_value(metadata).unwrap();
        assert_eq!(packument.latest_version(), Some("1.0.0"));

        let response = call(&app, get_request("/v1/verdicts/public-tool/1.0.0", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let public_bundle: Value =
            serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(public_bundle["verdict"]["decision"], "allow");
        let public_verdict: oath_contracts::RegistryVerdictV1 =
            serde_json::from_value(public_bundle["verdict"].clone()).unwrap();
        oath_contracts::verify_registry_verdict(&public_verdict).unwrap();
        assert_eq!(
            packument
                .version_info("1.0.0")
                .unwrap()
                .bin
                .as_ref()
                .map(|_| true),
            Some(true)
        );
        assert_eq!(
            call(
                &app,
                get_request("/-/oath/tarballs/public-tool/1.0.0", None)
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            query_scalar::<_, i64>(
                "SELECT download_count FROM versions WHERE name='public-tool' AND version='1.0.0'"
            )
            .fetch_one(registry_assertions.control.pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            call(&app, get_request("/public-tool", Some("invalid")))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                post_request(
                    "/-/oath/stages",
                    "secret",
                    json!({
                        "name": "public-tool",
                        "version": "2.0.0",
                        "tarball_base64": base64::engine::general_purpose::STANDARD.encode(b"private"),
                        "assessment": {"decision": "allow"},
                        "private": true
                    }),
                ),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );

        let scoped = stage(&app, "secret", "@acme/scoped", "1.0.0", false).await;
        assert_eq!(
            approve(&app, "secret", &scoped.id).await.status(),
            StatusCode::OK
        );
        let response = call(&app, get_request("/@acme/scoped", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metadata: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(
            metadata["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:4873/-/oath/tarballs/%40acme%2Fscoped/1.0.0"
        );
        assert_eq!(
            call(
                &app,
                get_request("/-/oath/tarballs/%40acme%2Fscoped/1.0.0", None)
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                get_request("/v1/verdicts/%40acme%2Fscoped/1.0.0", None)
            )
            .await
            .status(),
            StatusCode::OK
        );

        assert!(
            registry_assertions
                .control
                .record_billing_event("evt_once", "test", &json!({"id": "evt_once"}))
                .await
                .unwrap()
        );
        assert!(
            !registry_assertions
                .control
                .record_billing_event("evt_once", "test", &json!({"id": "evt_once"}))
                .await
                .unwrap()
        );

        let handles = (0..16)
            .map(|index| {
                let registry = registry_assertions.clone();
                tokio::spawn(async move {
                    registry
                        .append_event(&json!({"type": "concurrency.test", "index": index}))
                        .await
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.await.unwrap();
        }

        let rows = query("SELECT previous_hash,event_hash FROM registry_events ORDER BY sequence")
            .fetch_all(registry_assertions.control.pool())
            .await
            .unwrap();
        let mut previous = "GENESIS".to_owned();
        for row in &rows {
            assert_eq!(row.get::<String, _>("previous_hash"), previous);
            previous = row.get("event_hash");
        }
        assert_eq!(
            query_scalar::<_, i64>("SELECT COUNT(*) FROM tombstones")
                .fetch_one(registry_assertions.control.pool())
                .await
                .unwrap(),
            2
        );

        let response = call(&app, get_request("/-/oath/transparency/checkpoint", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let checkpoint: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(checkpoint["event_count"], rows.len());

        let response = call(&app, get_request("/-/oath/transparency/inclusion/1", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let inclusion: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert!(crate::verify_merkle_inclusion(
            inclusion["leaf_hash"].as_str().unwrap(),
            0,
            inclusion["tree_size"].as_u64().unwrap() as usize,
            &inclusion["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
            inclusion["merkle_root"].as_str().unwrap(),
        ));

        let response = call(
            &app,
            get_request("/-/oath/transparency/consistency?from=1", None),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let consistency: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(consistency["from_size"], 1);
        assert_eq!(consistency["proof_type"], "compact-frontier-v1");
        let proof = crate::MerkleConsistencyProof {
            from_size: consistency["from_size"].as_u64().unwrap() as usize,
            to_size: consistency["to_size"].as_u64().unwrap() as usize,
            prefix: serde_json::from_value(consistency["prefix"].clone()).unwrap(),
            suffix: serde_json::from_value(consistency["suffix"].clone()).unwrap(),
        };
        assert!(crate::verify_merkle_consistency(
            &proof,
            consistency["from_root"].as_str().unwrap(),
            consistency["to_root"].as_str().unwrap()
        ));

        assert_eq!(
            call(
                &app,
                post_request(
                    "/-/oath/versions/public-tool/1.0.0/revoke",
                    "secret",
                    json!({"reason": "confirmed malicious release", "quarantine": true}),
                ),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let response = call(&app, get_request("/v1/security/osv", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let osv: Value = serde_json::from_slice(&body(response).await.to_bytes()).unwrap();
        assert_eq!(osv["vulns"].as_array().unwrap().len(), 1);
        assert_eq!(
            osv["vulns"][0]["affected"][0]["package"]["name"],
            "public-tool"
        );

        assert_eq!(
            query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM registry_outbox WHERE delivered_at IS NULL"
            )
            .fetch_one(registry_assertions.control.pool())
            .await
            .unwrap(),
            0
        );
        let keyed_events = query(
            "SELECT COUNT(*) AS total, COUNT(DISTINCT event_key) AS unique_total FROM registry_events WHERE event_key IS NOT NULL",
        )
        .fetch_one(registry_assertions.control.pool())
        .await
        .unwrap();
        assert_eq!(
            keyed_events.get::<i64, _>("total"),
            keyed_events.get::<i64, _>("unique_total")
        );

        // Exercise the same non-owner role a hosted API process receives.
        // Missing tenant context cannot see private rows; tenant context is
        // transaction-local and never exposes a rival organization's rows.
        let mut rls = registry_assertions.control.pool().begin().await.unwrap();
        query("SET LOCAL ROLE oath_api")
            .execute(&mut *rls)
            .await
            .unwrap();
        let private_without_context: i64 =
            query_scalar("SELECT COUNT(*) FROM packages WHERE private=true")
                .fetch_one(&mut *rls)
                .await
                .unwrap();
        assert_eq!(private_without_context, 0);
        query("SELECT set_config('oath.organization','acme',true)")
            .execute(&mut *rls)
            .await
            .unwrap();
        let acme_private: i64 = query_scalar(
            "SELECT COUNT(*) FROM packages WHERE organization='acme' AND private=true",
        )
        .fetch_one(&mut *rls)
        .await
        .unwrap();
        let rival_private: i64 = query_scalar(
            "SELECT COUNT(*) FROM packages WHERE organization='rival' AND private=true",
        )
        .fetch_one(&mut *rls)
        .await
        .unwrap();
        assert!(acme_private > 0);
        assert_eq!(rival_private, 0);
        rls.rollback().await.unwrap();

        let mut rls_write = registry_assertions.control.pool().begin().await.unwrap();
        query("SET LOCAL ROLE oath_api")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        query("SELECT set_config('oath.organization','rival',true)")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        assert!(query("INSERT INTO packages(name,organization,private,created_at) VALUES ('cross-tenant-write','acme',true,0)")
            .execute(&mut *rls_write).await.is_err());
        // The expected RLS violation above aborted this transaction; start a
        // fresh one for the remaining cross-tenant checks.
        rls_write.rollback().await.unwrap();
        let mut rls_write = registry_assertions.control.pool().begin().await.unwrap();
        query("SET LOCAL ROLE oath_api")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        query("SELECT set_config('oath.organization','rival',true)")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        let public_delete = query("DELETE FROM packages WHERE name='public-tool'")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        assert_eq!(public_delete.rows_affected(), 0);
        let public_update = query("UPDATE packages SET private=true WHERE name='public-tool'")
            .execute(&mut *rls_write)
            .await
            .unwrap();
        assert_eq!(public_update.rows_affected(), 0);
        rls_write.rollback().await.unwrap();

        let api_control = PostgresControlPlane::connect_with_role(&database_url, Some("oath_api"))
            .await
            .unwrap();
        let api_principal = api_control
            .authenticate(&hex_sha256(b"secret"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(api_principal.organization, "acme");
        assert!(
            api_control
                .package_for("private-tool", Some("acme"))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            api_control
                .package_for("private-tool", Some("rival"))
                .await
                .unwrap()
                .is_none()
        );

        let response = call(&app, get_request("/metrics", None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = String::from_utf8(body(response).await.to_bytes().to_vec()).unwrap();
        let metric = |name: &str| {
            metrics
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name} ")))
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        assert!(metric("oath_registry_requests_total") >= 20);
        assert!(metric("oath_registry_denied_total") >= 7);
        assert_eq!(metric("oath_registry_errors_total"), 0);
    }
}
