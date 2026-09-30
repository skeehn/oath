use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::registry_signing_key;

#[async_trait]
pub trait RegistrySigner: Send + Sync {
    async fn sign(&self, domain: &str, payload: &[u8]) -> Result<Vec<u8>>;
    async fn ready(&self) -> Result<()>;
    fn public_key(&self) -> &[u8; 32];
    fn backend(&self) -> &'static str;
}

pub type SharedSigner = Arc<dyn RegistrySigner>;

pub struct FileSigner {
    key: SigningKey,
    public_key: [u8; 32],
}

impl FileSigner {
    pub fn open(path: &Path) -> Result<Self> {
        let key = registry_signing_key(path)?;
        let public_key = key.verifying_key().to_bytes();
        Ok(Self { key, public_key })
    }
}

#[async_trait]
impl RegistrySigner for FileSigner {
    async fn sign(&self, domain: &str, payload: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!domain.is_empty(), "signing domain must not be empty");
        let digest = oath_contracts::domain_separated_digest(domain, payload);
        Ok(self.key.sign(&digest).to_bytes().to_vec())
    }

    async fn ready(&self) -> Result<()> {
        Ok(())
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn backend(&self) -> &'static str {
        "file"
    }
}

#[derive(Clone)]
pub struct RemoteSigner {
    client: reqwest::Client,
    endpoint: String,
    bearer: Option<String>,
    public_key: [u8; 32],
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    algorithm: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct SignRequest {
    schema_version: u8,
    domain: String,
    digest_sha256_base64: String,
}

#[derive(Deserialize)]
struct SignResponse {
    algorithm: String,
    signature: String,
}

impl RemoteSigner {
    pub async fn connect(endpoint: &str, bearer: Option<String>) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&endpoint).context("parse OATH_REGISTRY_SIGNER_URL")?;
        let loopback = parsed.host_str().is_some_and(|host| {
            let host = host.trim_matches(['[', ']']);
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        anyhow::ensure!(
            parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback),
            "remote signer must use HTTPS except on loopback"
        );
        let client = reqwest::Client::builder().build()?;
        let request = client.get(format!("{endpoint}/v1/public-key"));
        let response = add_auth(request, bearer.as_deref())
            .send()
            .await?
            .error_for_status()?
            .json::<PublicKeyResponse>()
            .await?;
        anyhow::ensure!(
            response.algorithm == "ed25519",
            "remote signer must use ed25519"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(response.public_key)
            .context("decode remote signer public key")?;
        let public_key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("remote signer public key must be 32 bytes"))?;
        Ok(Self {
            client,
            endpoint,
            bearer,
            public_key,
        })
    }
}

#[async_trait]
impl RegistrySigner for RemoteSigner {
    async fn sign(&self, domain: &str, payload: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!domain.is_empty(), "signing domain must not be empty");
        let request = SignRequest {
            schema_version: 1,
            domain: domain.to_owned(),
            digest_sha256_base64: base64::engine::general_purpose::STANDARD
                .encode(oath_contracts::domain_separated_digest(domain, payload)),
        };
        let response = add_auth(
            self.client.post(format!("{}/v1/sign", self.endpoint)),
            self.bearer.as_deref(),
        )
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json::<SignResponse>()
        .await?;
        anyhow::ensure!(
            response.algorithm == "ed25519",
            "remote signer changed algorithm"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(response.signature)
            .context("decode remote signer signature")?;
        let signature = Signature::from_slice(&bytes).context("invalid remote signer signature")?;
        let digest = oath_contracts::domain_separated_digest(domain, payload);
        VerifyingKey::from_bytes(&self.public_key)?
            .verify(&digest, &signature)
            .context("remote signer returned a signature that does not verify")?;
        Ok(bytes)
    }

    async fn ready(&self) -> Result<()> {
        let challenge = b"oath-registry-signer-readiness-v1";
        self.sign("readiness", challenge).await.map(|_| ())
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn backend(&self) -> &'static str {
        "remote"
    }
}

fn add_auth(builder: reqwest::RequestBuilder, bearer: Option<&str>) -> reqwest::RequestBuilder {
    match bearer {
        Some(token) => builder.bearer_auth(token),
        None => builder,
    }
}

pub async fn signer_from_env(key_path: &Path) -> Result<SharedSigner> {
    match std::env::var("OATH_REGISTRY_SIGNER")
        .unwrap_or_else(|_| "file".into())
        .as_str()
    {
        "file" => Ok(Arc::new(FileSigner::open(key_path)?)),
        "remote" => {
            let endpoint = std::env::var("OATH_REGISTRY_SIGNER_URL")
                .context("OATH_REGISTRY_SIGNER_URL is required for remote signing")?;
            let bearer = std::env::var("OATH_REGISTRY_SIGNER_TOKEN").context(
                "OATH_REGISTRY_SIGNER_TOKEN is required for authenticated remote signing",
            )?;
            anyhow::ensure!(
                !bearer.trim().is_empty(),
                "OATH_REGISTRY_SIGNER_TOKEN must not be empty"
            );
            Ok(Arc::new(
                RemoteSigner::connect(&endpoint, Some(bearer)).await?,
            ))
        }
        value => anyhow::bail!("unsupported OATH_REGISTRY_SIGNER backend `{value}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        routing::{get, post},
    };
    use serde_json::{Value, json};

    #[tokio::test]
    async fn file_signer_produces_verifiable_signatures() {
        let directory = tempfile::tempdir().unwrap();
        let signer = FileSigner::open(&directory.path().join("key")).unwrap();
        let payload = b"payload";
        let signature =
            Signature::from_slice(&signer.sign("test", payload).await.unwrap()).unwrap();
        let digest = oath_contracts::domain_separated_digest("test", payload);
        VerifyingKey::from_bytes(signer.public_key())
            .unwrap()
            .verify(&digest, &signature)
            .unwrap();
        let other = oath_contracts::domain_separated_digest("other", payload);
        assert!(
            VerifyingKey::from_bytes(signer.public_key())
                .unwrap()
                .verify(&other, &signature)
                .is_err()
        );
        assert!(signer.sign("", payload).await.is_err());
    }

    #[tokio::test]
    async fn remote_signer_rejects_unverifiable_responses() {
        let key = Arc::new(SigningKey::from_bytes(&[7; 32]));
        let app = Router::new()
            .route("/v1/public-key", get({
                let key = key.clone();
                move || async move { Json(json!({"algorithm":"ed25519","public_key":base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())})) }
            }))
            .route("/v1/sign", post(|State(_key): State<Arc<SigningKey>>, Json(_request): Json<Value>| async move {
                Json(json!({"algorithm":"ed25519","signature":base64::engine::general_purpose::STANDARD.encode([0;64])}))
            }))
            .with_state(key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let signer = RemoteSigner::connect(&format!("http://{address}"), None)
            .await
            .unwrap();
        assert!(signer.sign("test", b"payload").await.is_err());
    }

    #[tokio::test]
    async fn remote_signer_uses_the_domain_separated_digest_contract() {
        let key = Arc::new(SigningKey::from_bytes(&[9; 32]));
        let app = Router::new()
            .route("/v1/public-key", get({
                let key = key.clone();
                move || async move { Json(json!({"algorithm":"ed25519","public_key":base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())})) }
            }))
            .route("/v1/sign", post(|State(key): State<Arc<SigningKey>>, Json(request): Json<SignRequest>| async move {
                assert_eq!(request.schema_version, 1);
                assert!(!request.domain.is_empty());
                let digest = base64::engine::general_purpose::STANDARD.decode(request.digest_sha256_base64).unwrap();
                assert_eq!(digest.len(), 32);
                Json(json!({"algorithm":"ed25519","signature":base64::engine::general_purpose::STANDARD.encode(key.sign(&digest).to_bytes())}))
            }))
            .with_state(key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let signer = RemoteSigner::connect(&format!("http://{address}"), None)
            .await
            .unwrap();
        let first = signer.sign("assessment-verdict", b"payload").await.unwrap();
        let second = signer
            .sign("transparency-checkpoint", b"payload")
            .await
            .unwrap();
        assert_ne!(first, second);
    }
}
