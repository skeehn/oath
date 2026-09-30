use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assessment::RegistryAssessmentBundle;

#[derive(Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub schema_version: u8,
    pub tarball_base64: String,
    pub manifest: Value,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub registry: String,
}

#[async_trait]
pub trait AnalysisBackend: Send + Sync {
    async fn assess(
        &self,
        tarball: &[u8],
        manifest: &Value,
        name: &str,
        version: &str,
        publisher: &str,
        registry: &str,
    ) -> Result<RegistryAssessmentBundle>;
    async fn ready(&self) -> Result<()>;
    fn backend(&self) -> &'static str;
}

pub type SharedAnalysisBackend = Arc<dyn AnalysisBackend>;

pub struct InlineAnalysis;

#[async_trait]
impl AnalysisBackend for InlineAnalysis {
    async fn assess(
        &self,
        tarball: &[u8],
        manifest: &Value,
        name: &str,
        version: &str,
        publisher: &str,
        registry: &str,
    ) -> Result<RegistryAssessmentBundle> {
        crate::assessment::assess_tarball(tarball, manifest, name, version, publisher, registry)
    }

    async fn ready(&self) -> Result<()> {
        Ok(())
    }
    fn backend(&self) -> &'static str {
        "inline"
    }
}

pub struct RemoteAnalysis {
    client: reqwest::Client,
    endpoint: String,
    bearer: String,
}

impl RemoteAnalysis {
    pub fn connect(
        endpoint: String,
        bearer: String,
        allow_insecure_internal: bool,
    ) -> Result<Self> {
        let parsed = url::Url::parse(&endpoint).context("parse OATH_ANALYZER_URL")?;
        let loopback = parsed.host_str().is_some_and(|host| {
            let host = host.trim_matches(['[', ']']);
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        anyhow::ensure!(
            parsed.scheme() == "https"
                || (parsed.scheme() == "http" && (loopback || allow_insecure_internal)),
            "remote analyzer must use HTTPS except on loopback; the explicit insecure-internal override is for isolated development networks only"
        );
        Ok(Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.trim_end_matches('/').into(),
            bearer,
        })
    }
}

#[async_trait]
impl AnalysisBackend for RemoteAnalysis {
    async fn assess(
        &self,
        tarball: &[u8],
        manifest: &Value,
        name: &str,
        version: &str,
        publisher: &str,
        registry: &str,
    ) -> Result<RegistryAssessmentBundle> {
        let request = AnalysisRequest {
            schema_version: 1,
            tarball_base64: base64::engine::general_purpose::STANDARD.encode(tarball),
            manifest: manifest.clone(),
            name: name.into(),
            version: version.into(),
            publisher: publisher.into(),
            registry: registry.into(),
        };
        Ok(self
            .client
            .post(format!("{}/v1/analyze", self.endpoint))
            .bearer_auth(&self.bearer)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn ready(&self) -> Result<()> {
        self.client
            .get(format!("{}/readyz", self.endpoint))
            .bearer_auth(&self.bearer)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    fn backend(&self) -> &'static str {
        "remote"
    }
}

pub fn analysis_backend_from_env() -> Result<SharedAnalysisBackend> {
    match std::env::var("OATH_ANALYZER_BACKEND")
        .unwrap_or_else(|_| "inline".into())
        .as_str()
    {
        "inline" => Ok(Arc::new(InlineAnalysis)),
        "remote" => Ok(Arc::new(RemoteAnalysis::connect(
            std::env::var("OATH_ANALYZER_URL").context("OATH_ANALYZER_URL is required")?,
            std::env::var("OATH_ANALYZER_TOKEN").context("OATH_ANALYZER_TOKEN is required")?,
            std::env::var("OATH_ANALYZER_ALLOW_INSECURE_INTERNAL").as_deref() == Ok("1"),
        )?)),
        value => anyhow::bail!("unsupported OATH_ANALYZER_BACKEND `{value}`"),
    }
}

#[derive(Clone)]
struct WorkerState {
    token_hash: String,
}

pub fn worker_router(token: &str) -> Result<Router> {
    anyhow::ensure!(
        !token.trim().is_empty(),
        "analysis worker token must not be empty"
    );
    let stage_limit = std::env::var("OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES must be an integer")?
        .unwrap_or(64 * 1024 * 1024);
    anyhow::ensure!(
        (1024 * 1024..=1024 * 1024 * 1024).contains(&stage_limit),
        "OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES must be between 1 MiB and 1 GiB"
    );
    let body_limit = stage_limit
        .checked_mul(4)
        .and_then(|value| value.checked_add(2))
        .map(|value| value / 3)
        .and_then(|value| value.checked_add(1024 * 1024))
        .context("analysis worker body limit overflow")?;
    Ok(Router::new()
        .route(
            "/livez",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .route("/readyz", get(worker_ready))
        .route("/v1/analyze", post(worker_analyze))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(WorkerState {
            token_hash: crate::hex_sha256(token.as_bytes()),
        }))
}

async fn worker_ready(
    State(state): State<WorkerState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    authenticate_worker(&state, &headers)?;
    Ok(Json(
        serde_json::json!({"status":"ready","backend":"native"}),
    ))
}

async fn worker_analyze(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Json(request): Json<AnalysisRequest>,
) -> Result<Json<RegistryAssessmentBundle>, (StatusCode, String)> {
    authenticate_worker(&state, &headers)
        .map_err(|status| (status, "unauthorized analyzer request".into()))?;
    if request.schema_version != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported analysis request schema".into(),
        ));
    }
    let tarball = base64::engine::general_purpose::STANDARD
        .decode(&request.tarball_base64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid tarball base64".into()))?;
    let bundle = crate::assessment::assess_tarball(
        &tarball,
        &request.manifest,
        &request.name,
        &request.version,
        &request.publisher,
        &request.registry,
    )
    .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))?;
    Ok(Json(bundle))
}

fn authenticate_worker(state: &WorkerState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if crate::hex_sha256(token.as_bytes()) != state.token_hash {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn remote_transport_is_https_or_explicitly_development_only() {
        assert!(
            RemoteAnalysis::connect("https://analyzer.example".into(), "token".into(), false)
                .is_ok()
        );
        assert!(
            RemoteAnalysis::connect("http://127.0.0.1:4874".into(), "token".into(), false).is_ok()
        );
        assert!(
            RemoteAnalysis::connect("http://analysis-worker:4874".into(), "token".into(), false)
                .is_err()
        );
        assert!(
            RemoteAnalysis::connect("http://analysis-worker:4874".into(), "token".into(), true)
                .is_ok()
        );
    }

    fn analysis_request(schema_version: u8, tarball_base64: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/analyze")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "schema_version": schema_version,
                    "tarball_base64": tarball_base64,
                    "manifest": {"name":"pkg","version":"1.0.0"},
                    "name": "pkg",
                    "version": "1.0.0",
                    "publisher": "test",
                    "registry": "https://registry.example.test"
                })
                .to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn analysis_worker_fails_closed_without_authentication() {
        let response = worker_router("secret")
            .unwrap()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn analysis_worker_reports_readiness_with_valid_token() {
        let response = worker_router("secret")
            .unwrap()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn analysis_endpoint_fails_closed_before_processing_invalid_requests() {
        let app = worker_router("secret").unwrap();
        let missing_auth = app
            .clone()
            .oneshot(analysis_request(1, "not-base64"))
            .await
            .unwrap();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        let mut wrong_schema = analysis_request(2, "not-base64");
        wrong_schema
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        let wrong_schema = app.clone().oneshot(wrong_schema).await.unwrap();
        assert_eq!(wrong_schema.status(), StatusCode::BAD_REQUEST);

        let mut invalid_base64 = analysis_request(1, "not-base64");
        invalid_base64
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        let invalid_base64 = app.oneshot(invalid_base64).await.unwrap();
        assert_eq!(invalid_base64.status(), StatusCode::BAD_REQUEST);
    }
}
