//! Registry HTTP client
//!
//! Speaks the npm registry protocol. Supports abbreviated metadata,
//! etag caching, and multiple registry sources.

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, RETRY_AFTER};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use crate::packument::Packument;
use crate::tarball::{IntegrityVerifier, TarballLimits};

/// Abbreviated packument Accept header (much smaller than full application/json)
const ABBREVIATED_ACCEPT: &str =
    "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8";

/// TTL for disk cache in seconds: if the cached file is younger than this,
/// return it directly without any HTTP request.
const CACHE_TTL_SECS: u64 = 300; // 5 minutes
const TARBALL_TIMEOUT_SECS: u64 = 120;
const REQUEST_ATTEMPTS: usize = 3;
const RETRY_BASE_DELAY_MS: u64 = 200;
const RETRY_MAX_DELAY_SECS: u64 = 2;

struct BufferedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

/// Registry client configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Default registry URL (default: https://registry.npmjs.org)
    pub registry_url: String,
    /// Per-scope registry overrides: "@scope" -> registry URL.
    pub scoped_registries: HashMap<String, String>,
    /// Per-host auth tokens: host -> token.
    pub tokens: HashMap<String, String>,
    /// Directory for cached packuments
    pub cache_dir: PathBuf,
    /// Legacy single auth token (applied to the default registry host).
    pub token: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        let cache_dir = dirs_home().join(".oath").join("cache").join("registry");
        Self {
            registry_url: "https://registry.npmjs.org".to_string(),
            scoped_registries: HashMap::new(),
            tokens: HashMap::new(),
            cache_dir,
            token: None,
            timeout_secs: 10,
        }
    }
}

impl RegistryConfig {
    /// Build config from the project's and user's `.npmrc` (+ OATH_REGISTRY env).
    /// This is what enables private/scoped/mirror registries.
    pub fn from_npmrc(project_dir: &Path) -> Self {
        let npmrc = crate::npmrc::NpmrcConfig::load(project_dir);
        let mut cfg = RegistryConfig::default();
        if let Some(reg) = npmrc.default_registry {
            cfg.registry_url = reg;
        }
        cfg.scoped_registries = npmrc.scoped_registries;
        cfg.tokens = npmrc.tokens;
        cfg
    }
}

fn dirs_home() -> PathBuf {
    oath_core::home_dir().unwrap_or_else(std::env::temp_dir)
}

/// Extract the host from a URL (for per-host auth lookup).
fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

/// The main registry client. Thread-safe, cloneable.
#[derive(Clone)]
pub struct RegistryClient {
    config: RegistryConfig,
    http: reqwest::Client,
    /// In-memory etag cache: package_name -> etag
    etag_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(mut config: RegistryConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();

        // Use abbreviated packument format -- much smaller than full application/json
        // vnd.npm.install-v1+json is ~100x smaller for large packages like babel
        headers.insert(ACCEPT, HeaderValue::from_static(ABBREVIATED_ACCEPT));

        // Fold a legacy single token into the per-host map (keyed by the default
        // registry's host). Auth is attached per-request by host, because a
        // scoped package may route to a different registry than the default.
        if let Some(token) = config.token.clone()
            && let Some(host) = host_of(&config.registry_url)
        {
            config.tokens.entry(host).or_insert(token);
        }

        let http = crate::http::client_builder()?
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .gzip(true)
            .tcp_nodelay(true)
            .pool_max_idle_per_host(32)
            .build()
            .context("failed to build HTTP client")?;

        // Ensure cache dir exists
        std::fs::create_dir_all(&config.cache_dir).ok();

        Ok(Self {
            config,
            http,
            etag_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a client, loading registry + auth config from `.npmrc` (project and
    /// home) plus the OATH_REGISTRY env var. Falls back to registry.npmjs.org.
    pub fn default_client() -> Result<Self> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::new(RegistryConfig::from_npmrc(&cwd))
    }

    /// Fetch a packument (package metadata) from the registry.
    /// Uses etag caching -- returns cached version if unchanged.
    pub async fn fetch_packument(&self, name: &str) -> Result<Packument> {
        let url = self.package_url(name);
        tracing::debug!("fetching packument: {url}");

        // Fast path: check disk cache first with TTL
        // If the cached file is fresh (< CACHE_TTL_SECS), use it directly without HTTP
        let cache_path = self.cache_path(name);
        if let Ok(meta) = std::fs::metadata(&cache_path)
            && let Ok(modified) = meta.modified()
        {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age.as_secs() < CACHE_TTL_SECS
                && let Ok(data) = std::fs::read(&cache_path)
                && let Ok(packument) = serde_json::from_slice::<Packument>(&data)
            {
                tracing::debug!("{name}: disk cache hit ({}s old)", age.as_secs());
                return Ok(packument);
            }
        }

        let mut req = self.http.get(&url);
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }

        // Attach etag for conditional request
        let etag_cache = self.etag_cache.read().await;
        if let Some(etag) = etag_cache.get(name) {
            req = req.header(IF_NONE_MATCH, etag.as_str());
        } else {
            // Try to load persisted etag from disk sidecar file
            let etag_path = self.etag_path(name);
            if let Ok(etag_str) = std::fs::read_to_string(&etag_path) {
                let etag_str = etag_str.trim().to_string();
                req = req.header(IF_NONE_MATCH, etag_str.as_str());
            }
        }
        drop(etag_cache);

        let resp = self
            .send_bytes_with_retries(req, "registry request failed")
            .await?;

        // Check for 304 Not Modified
        if resp.status == StatusCode::NOT_MODIFIED {
            tracing::debug!("{name}: not modified (etag cache hit)");
            return self.load_cached_packument(name).await;
        }

        if resp.status == StatusCode::NOT_FOUND {
            anyhow::bail!("package not found: {name}");
        }

        if !resp.status.is_success() {
            anyhow::bail!(
                "registry returned {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            );
        }

        // Store new etag
        if let Some(etag) = resp.headers.get(ETAG)
            && let Ok(etag_str) = etag.to_str()
        {
            let mut cache = self.etag_cache.write().await;
            cache.insert(name.to_string(), etag_str.to_string());
            // Persist etag to disk for use across process restarts
            let etag_path = self.etag_path(name);
            tokio::fs::write(&etag_path, etag_str).await.ok();
        }

        // Cache to disk
        self.write_cache(name, &resp.body).await;

        // Parse
        let packument: Packument =
            serde_json::from_slice(&resp.body).context("failed to parse packument")?;

        Ok(packument)
    }

    /// Fetch full (non-abbreviated) packument for detailed info
    pub async fn fetch_packument_full(&self, name: &str) -> Result<serde_json::Value> {
        let url = self.package_url(name);

        let mut req = self.http.get(&url).header(ACCEPT, "application/json");
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }
        let resp = self
            .send_bytes_with_retries(req, "registry request failed")
            .await?;

        if resp.status == StatusCode::NOT_FOUND {
            anyhow::bail!("package not found: {name}");
        }

        if !resp.status.is_success() {
            anyhow::bail!("registry returned {}", resp.status);
        }

        serde_json::from_slice(&resp.body).context("failed to parse full packument")
    }

    /// Download a tarball, verify integrity, return bytes
    pub async fn fetch_tarball(
        &self,
        url: &str,
        expected_integrity: Option<&str>,
    ) -> Result<Vec<u8>> {
        let limits = TarballLimits::from_env()?;
        let tmp = tempfile::NamedTempFile::new().context("failed to create temp tarball")?;
        self.fetch_tarball_to_file(url, expected_integrity, tmp.path(), &limits)
            .await?;
        std::fs::read(tmp.path())
            .with_context(|| format!("failed to read temp tarball {}", tmp.path().display()))
    }

    /// Stream a tarball to disk while enforcing compressed-size and SRI limits.
    pub async fn fetch_tarball_to_file(
        &self,
        url: &str,
        expected_integrity: Option<&str>,
        dest: &Path,
        limits: &TarballLimits,
    ) -> Result<u64> {
        tracing::debug!("downloading tarball: {url}");

        for attempt in 0..REQUEST_ATTEMPTS {
            let mut req = self
                .http
                .get(url)
                .header(ACCEPT, "application/octet-stream")
                .timeout(Duration::from_secs(
                    self.config.timeout_secs.max(TARBALL_TIMEOUT_SECS),
                ));
            if let Some(tok) = self.token_for_url(url) {
                req = req.bearer_auth(tok);
            }

            let resp = match req.send().await {
                Ok(resp)
                    if should_retry_status(resp.status()) && attempt + 1 < REQUEST_ATTEMPTS =>
                {
                    let delay = retry_delay(attempt, Some(resp.headers()));
                    tracing::debug!(
                        status = %resp.status(),
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis(),
                        "retrying transient tarball response"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Ok(resp) => resp,
                Err(err) if is_retryable_request_error(&err) && attempt + 1 < REQUEST_ATTEMPTS => {
                    let delay = retry_delay(attempt, None);
                    tracing::debug!(
                        error = %err,
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis(),
                        "retrying transient tarball request failure"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(err) => return Err(err).context("tarball download failed"),
            };

            if !resp.status().is_success() {
                anyhow::bail!("tarball download returned {}", resp.status());
            }

            if let Some(content_length) = resp.content_length() {
                limits.check_archive_size(content_length)?;
            }

            let mut verifier = expected_integrity
                .map(IntegrityVerifier::new)
                .transpose()
                .context("invalid tarball integrity metadata")?;
            let mut file = tokio::fs::File::create(dest)
                .await
                .with_context(|| format!("failed to create {}", dest.display()))?;
            let mut downloaded = 0u64;
            let mut stream = resp.bytes_stream();
            let mut stream_error = None;

            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => {
                        downloaded = downloaded
                            .checked_add(chunk.len() as u64)
                            .context("tarball compressed size overflow")?;
                        limits.check_archive_size(downloaded)?;
                        if let Some(verifier) = verifier.as_mut() {
                            verifier.update(&chunk);
                        }
                        file.write_all(&chunk)
                            .await
                            .with_context(|| format!("failed to write {}", dest.display()))?;
                    }
                    Err(err) => {
                        stream_error = Some(err);
                        break;
                    }
                }
            }

            if let Some(err) = stream_error {
                drop(file);
                tokio::fs::remove_file(dest).await.ok();
                if is_retryable_request_error(&err) && attempt + 1 < REQUEST_ATTEMPTS {
                    let delay = retry_delay(attempt, None);
                    tracing::debug!(
                        error = %err,
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis(),
                        "restarting interrupted tarball download"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(err).context("failed to read tarball chunk");
            }

            file.flush()
                .await
                .with_context(|| format!("failed to flush {}", dest.display()))?;

            if let Some(verifier) = verifier
                && let Err(err) = verifier.finish()
            {
                drop(file);
                tokio::fs::remove_file(dest).await.ok();
                return Err(err);
            }

            return Ok(downloaded);
        }

        unreachable!("tarball retry loop always returns on the final attempt")
    }

    /// Search packages
    pub async fn search(&self, query: &str, limit: usize) -> Result<serde_json::Value> {
        let url = format!(
            "{}/-/v1/search?text={}&size={}",
            self.config.registry_url,
            urlencoding::encode(query),
            limit
        );

        let mut req = self.http.get(&url).header(ACCEPT, "application/json");
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }
        let resp = self
            .send_bytes_with_retries(req, "registry search request failed")
            .await?;

        if !resp.status.is_success() {
            anyhow::bail!("registry search returned {}", resp.status);
        }

        serde_json::from_slice(&resp.body).context("failed to parse search results")
    }

    // -- Private helpers --

    /// Pick the registry for a package (per-scope override or default) and build
    /// the packument URL. Scoped packages keep the `@scope/name` path -- npm
    /// registries accept it directly.
    fn package_url(&self, name: &str) -> String {
        format!("{}/{}", self.registry_for(name), name)
    }

    /// The registry a package should be fetched from: a `@scope:registry`
    /// override if one matches, otherwise the default registry.
    fn registry_for(&self, name: &str) -> &str {
        if name.starts_with('@')
            && let Some(scope) = name.split('/').next()
            && let Some(reg) = self.config.scoped_registries.get(scope)
        {
            return reg;
        }
        &self.config.registry_url
    }

    /// The auth token for a request URL, matched by host.
    fn token_for_url(&self, url: &str) -> Option<String> {
        let host = host_of(url)?;
        self.config.tokens.get(&host).cloned()
    }

    async fn send_bytes_with_retries(
        &self,
        req: reqwest::RequestBuilder,
        context: &'static str,
    ) -> Result<BufferedResponse> {
        if req.try_clone().is_none() {
            let resp = req.send().await.context(context)?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.bytes().await.context(context)?;
            return Ok(BufferedResponse {
                status,
                headers,
                body,
            });
        }

        for attempt in 0..REQUEST_ATTEMPTS {
            let attempt_req = req
                .try_clone()
                .expect("request cloneability checked before retry loop");
            match attempt_req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if should_retry_status(status) && attempt + 1 < REQUEST_ATTEMPTS {
                        let delay = retry_delay(attempt, Some(resp.headers()));
                        tracing::debug!(
                            status = %status,
                            attempt = attempt + 1,
                            delay_ms = delay.as_millis(),
                            "retrying transient registry response"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    let headers = resp.headers().clone();
                    match resp.bytes().await {
                        Ok(body) => {
                            return Ok(BufferedResponse {
                                status,
                                headers,
                                body,
                            });
                        }
                        Err(err)
                            if is_retryable_request_error(&err)
                                && attempt + 1 < REQUEST_ATTEMPTS =>
                        {
                            let delay = retry_delay(attempt, None);
                            tracing::debug!(
                                error = %err,
                                attempt = attempt + 1,
                                delay_ms = delay.as_millis(),
                                "retrying interrupted registry response body"
                            );
                            tokio::time::sleep(delay).await;
                        }
                        Err(err) => return Err(err).context(context),
                    }
                }
                Err(err) if is_retryable_request_error(&err) && attempt + 1 < REQUEST_ATTEMPTS => {
                    let delay = retry_delay(attempt, None);
                    tracing::debug!(
                        error = %err,
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis(),
                        "retrying transient registry request failure"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(err) => return Err(err).context(context),
            }
        }

        unreachable!("registry retry loop always returns on the final attempt")
    }

    async fn write_cache(&self, name: &str, data: &[u8]) {
        let path = self.cache_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        tokio::fs::write(&path, data).await.ok();
    }

    async fn load_cached_packument(&self, name: &str) -> Result<Packument> {
        let path = self.cache_path(name);
        let data = tokio::fs::read(&path)
            .await
            .context("cache miss after 304")?;
        serde_json::from_slice(&data).context("corrupt cache entry")
    }

    fn cache_path(&self, name: &str) -> PathBuf {
        // @scope/name -> @scope__name
        let safe_name = name.replace('/', "__");
        self.config.cache_dir.join(format!("{safe_name}.json"))
    }

    fn etag_path(&self, name: &str) -> PathBuf {
        let safe_name = name.replace('/', "__");
        self.config.cache_dir.join(format!("{safe_name}.etag"))
    }
}

fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_retryable_request_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_body() || err.is_decode()
}

fn retry_delay(attempt: usize, headers: Option<&HeaderMap>) -> Duration {
    let max_delay = Duration::from_secs(RETRY_MAX_DELAY_SECS);
    if let Some(retry_after) = headers
        .and_then(|headers| headers.get(RETRY_AFTER))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_secs(retry_after).min(max_delay);
    }

    Duration::from_millis(RETRY_BASE_DELAY_MS.saturating_mul(1u64 << attempt.min(10)))
        .min(max_delay)
}

/// URL encoding helper (minimal, just for search)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(b as char);
                }
                _ => {
                    result.push_str(&format!("%{b:02X}"));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn flaky_server(
        statuses: Vec<StatusCode>,
        success_body: &'static [u8],
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&attempts);

        let handle = tokio::spawn(async move {
            for status in statuses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request).await.unwrap();
                server_attempts.fetch_add(1, Ordering::SeqCst);

                let body = if status.is_success() {
                    success_body
                } else {
                    b"retry"
                };
                let reason = status.canonical_reason().unwrap_or("Unknown");
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status.as_u16(),
                    reason,
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
            }
        });

        (format!("http://{address}"), attempts, handle)
    }

    async fn interrupted_tarball_server(
        success_body: &'static [u8],
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&attempts);

        let handle = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request).await.unwrap();
                server_attempts.fetch_add(1, Ordering::SeqCst);

                if attempt == 0 {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
                        )
                        .await
                        .unwrap();
                    continue;
                }

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    success_body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(success_body).await.unwrap();
            }
        });

        (format!("http://{address}"), attempts, handle)
    }

    fn client_with(scoped: &[(&str, &str)], tokens: &[(&str, &str)]) -> RegistryClient {
        let mut cfg = RegistryConfig::default();
        for (k, v) in scoped {
            cfg.scoped_registries.insert(k.to_string(), v.to_string());
        }
        for (k, v) in tokens {
            cfg.tokens.insert(k.to_string(), v.to_string());
        }
        RegistryClient::new(cfg).unwrap()
    }

    #[test]
    fn routes_scoped_packages_to_their_registry() {
        let c = client_with(&[("@myorg", "https://private.example")], &[]);
        assert_eq!(c.registry_for("@myorg/pkg"), "https://private.example");
        assert_eq!(c.registry_for("lodash"), "https://registry.npmjs.org");
        assert_eq!(
            c.package_url("@myorg/pkg"),
            "https://private.example/@myorg/pkg"
        );
        assert_eq!(c.package_url("lodash"), "https://registry.npmjs.org/lodash");
    }

    #[test]
    fn attaches_token_by_host() {
        let c = client_with(&[], &[("private.example", "tok-1")]);
        assert_eq!(
            c.token_for_url("https://private.example/@myorg/pkg"),
            Some("tok-1".to_string())
        );
        assert_eq!(c.token_for_url("https://registry.npmjs.org/lodash"), None);
    }

    #[test]
    fn legacy_token_maps_to_default_registry_host() {
        let cfg = RegistryConfig {
            token: Some("legacy".to_string()),
            ..Default::default()
        };
        let c = RegistryClient::new(cfg).unwrap();
        assert_eq!(
            c.token_for_url("https://registry.npmjs.org/lodash"),
            Some("legacy".to_string())
        );
    }

    #[test]
    fn retry_policy_is_bounded_and_transient_only() {
        assert_eq!(REQUEST_ATTEMPTS, 3);
        assert!(should_retry_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(should_retry_status(StatusCode::BAD_GATEWAY));
        assert!(should_retry_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!should_retry_status(StatusCode::NOT_FOUND));
        assert!(!should_retry_status(StatusCode::UNAUTHORIZED));
        assert_eq!(retry_delay(0, None), Duration::from_millis(200));
        assert_eq!(retry_delay(1, None), Duration::from_millis(400));

        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("60"));
        assert_eq!(retry_delay(0, Some(&headers)), Duration::from_secs(2));
    }

    #[tokio::test]
    async fn metadata_fetch_retries_transient_responses() {
        let (url, attempts, server) = flaky_server(
            vec![
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::BAD_GATEWAY,
                StatusCode::OK,
            ],
            br#"{"name":"demo"}"#,
        )
        .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new(RegistryConfig {
            registry_url: url,
            cache_dir: cache.path().to_path_buf(),
            timeout_secs: 2,
            ..Default::default()
        })
        .unwrap();

        let packument = client.fetch_packument("demo").await.unwrap();
        server.await.unwrap();

        assert_eq!(packument.name, "demo");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn metadata_fetch_stops_after_bounded_attempts() {
        let (url, attempts, server) = flaky_server(
            vec![
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ],
            br#"{"name":"unused"}"#,
        )
        .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new(RegistryConfig {
            registry_url: url,
            cache_dir: cache.path().to_path_buf(),
            timeout_secs: 2,
            ..Default::default()
        })
        .unwrap();

        let error = client.fetch_packument("demo").await.unwrap_err();
        server.await.unwrap();

        assert!(error.to_string().contains("503 Service Unavailable"));
        assert_eq!(attempts.load(Ordering::SeqCst), REQUEST_ATTEMPTS);
    }

    #[tokio::test]
    async fn tarball_fetch_retries_transient_responses() {
        let (url, attempts, server) = flaky_server(
            vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK],
            b"tarball bytes",
        )
        .await;
        let client = RegistryClient::new(RegistryConfig::default()).unwrap();
        let output = tempfile::NamedTempFile::new().unwrap();

        let downloaded = client
            .fetch_tarball_to_file(&url, None, output.path(), &TarballLimits::default())
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(downloaded, 13);
        assert_eq!(std::fs::read(output.path()).unwrap(), b"tarball bytes");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn tarball_fetch_restarts_after_interrupted_body() {
        let (url, attempts, server) = interrupted_tarball_server(b"complete tarball").await;
        let client = RegistryClient::new(RegistryConfig::default()).unwrap();
        let output = tempfile::NamedTempFile::new().unwrap();

        let downloaded = client
            .fetch_tarball_to_file(&url, None, output.path(), &TarballLimits::default())
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(downloaded, 16);
        assert_eq!(std::fs::read(output.path()).unwrap(), b"complete tarball");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
