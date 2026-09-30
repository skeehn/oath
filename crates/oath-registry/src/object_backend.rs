use anyhow::{Context, Result};
use futures_util::StreamExt;
use object_store::{
    ObjectStore, ObjectStoreExt, PutMode, PutOptions, aws::AmazonS3Builder,
    azure::MicrosoftAzureBuilder, gcp::GoogleCloudStorageBuilder, local::LocalFileSystem,
    path::Path as ObjectPath,
};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug)]
pub enum ArtifactReadError {
    InvalidDigest(String),
    NotFound(String),
    Corrupt {
        location: String,
        expected: String,
        actual: String,
    },
    Store {
        location: String,
        source: object_store::Error,
    },
    Repair(String),
}

impl std::fmt::Display for ArtifactReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDigest(digest) => {
                write!(formatter, "invalid SHA-256 artifact digest {digest}")
            }
            Self::NotFound(digest) => write!(
                formatter,
                "artifact {digest} was not found in primary or replica stores"
            ),
            Self::Corrupt {
                location,
                expected,
                actual,
            } => write!(
                formatter,
                "artifact corruption in {location}: expected SHA-256 {expected}, got {actual}"
            ),
            Self::Store { location, source } => {
                write!(formatter, "artifact read from {location} failed: {source}")
            }
            Self::Repair(source) => {
                write!(formatter, "primary artifact read-repair failed: {source}")
            }
        }
    }
}

impl std::error::Error for ArtifactReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_digest(digest: &str) -> std::result::Result<(), ArtifactReadError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ArtifactReadError::InvalidDigest(digest.to_owned()))
    }
}

fn verify_bytes(
    location: &str,
    expected: &str,
    bytes: &[u8],
) -> std::result::Result<(), ArtifactReadError> {
    let actual = sha256(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(ArtifactReadError::Corrupt {
            location: location.to_owned(),
            expected: expected.to_owned(),
            actual,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ObjectBackendConfig {
    Local {
        root: PathBuf,
    },
    S3 {
        bucket: String,
        endpoint: Option<String>,
    },
    Gcs {
        bucket: String,
    },
    Azure {
        container: String,
    },
}

#[derive(Clone)]
pub struct ArtifactStore {
    primary: Arc<dyn ObjectStore>,
    replicas: Vec<Arc<dyn ObjectStore>>,
}

impl ArtifactStore {
    pub fn new(primary: Arc<dyn ObjectStore>) -> Self {
        Self {
            primary,
            replicas: Vec::new(),
        }
    }

    pub fn with_replicas(
        primary: Arc<dyn ObjectStore>,
        replicas: Vec<Arc<dyn ObjectStore>>,
    ) -> Self {
        Self { primary, replicas }
    }

    async fn put_one(
        store: &Arc<dyn ObjectStore>,
        path: &ObjectPath,
        digest: &str,
        bytes: &[u8],
    ) -> Result<()> {
        validate_digest(digest)?;
        verify_bytes("write candidate", digest, bytes)?;
        let options = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match store.put_opts(path, bytes.to_vec().into(), options).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = store.get(path).await?.bytes().await?;
                verify_bytes("existing immutable object", digest, &existing)?;
                anyhow::ensure!(
                    existing.as_ref() == bytes,
                    "immutable object digest collision"
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn put_immutable(&self, digest: &str, bytes: &[u8]) -> Result<()> {
        let path = ObjectPath::from(digest);
        Self::put_one(&self.primary, &path, digest, bytes).await?;
        for replica in &self.replicas {
            Self::put_one(replica, &path, digest, bytes).await?;
        }
        Ok(())
    }

    async fn read_one(
        store: &Arc<dyn ObjectStore>,
        path: &ObjectPath,
        digest: &str,
        location: &str,
    ) -> std::result::Result<Option<Vec<u8>>, ArtifactReadError> {
        let result = match store.get(path).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(source) => {
                return Err(ArtifactReadError::Store {
                    location: location.to_owned(),
                    source,
                });
            }
        };
        let bytes = result
            .bytes()
            .await
            .map_err(|source| ArtifactReadError::Store {
                location: location.to_owned(),
                source,
            })?
            .to_vec();
        verify_bytes(location, digest, &bytes)?;
        Ok(Some(bytes))
    }

    pub async fn get(&self, digest: &str) -> std::result::Result<Vec<u8>, ArtifactReadError> {
        validate_digest(digest)?;
        let path = ObjectPath::from(digest);
        if let Some(bytes) = Self::read_one(&self.primary, &path, digest, "primary").await? {
            return Ok(bytes);
        }
        for (index, replica) in self.replicas.iter().enumerate() {
            let location = format!("replica[{index}]");
            if let Some(bytes) = Self::read_one(replica, &path, digest, &location).await? {
                Self::put_one(&self.primary, &path, digest, &bytes)
                    .await
                    .map_err(|source| ArtifactReadError::Repair(source.to_string()))?;
                return Ok(bytes);
            }
        }
        Err(ArtifactReadError::NotFound(digest.to_owned()))
    }

    pub async fn ready(&self) -> Result<()> {
        for store in std::iter::once(&self.primary).chain(self.replicas.iter()) {
            let mut objects = store.list(None);
            if let Some(result) = objects.next().await {
                result.context("object store readiness listing failed")?;
            }
        }
        Ok(())
    }
}

impl ObjectBackendConfig {
    pub fn from_env(default_root: PathBuf) -> Result<Self> {
        match std::env::var("OATH_OBJECT_BACKEND")
            .unwrap_or_else(|_| "local".into())
            .as_str()
        {
            "local" => Ok(Self::Local { root: default_root }),
            "s3" | "r2" => Ok(Self::S3 {
                bucket: std::env::var("OATH_OBJECT_BUCKET")
                    .context("OATH_OBJECT_BUCKET is required")?,
                endpoint: std::env::var("OATH_OBJECT_ENDPOINT").ok(),
            }),
            "gcs" => Ok(Self::Gcs {
                bucket: std::env::var("OATH_OBJECT_BUCKET")
                    .context("OATH_OBJECT_BUCKET is required")?,
            }),
            "azure" => Ok(Self::Azure {
                container: std::env::var("OATH_OBJECT_BUCKET")
                    .context("OATH_OBJECT_BUCKET is required")?,
            }),
            backend => anyhow::bail!("unsupported object backend {backend}"),
        }
    }
}

pub fn build(config: ObjectBackendConfig) -> Result<Arc<dyn ObjectStore>> {
    match config {
        ObjectBackendConfig::Local { root } => {
            std::fs::create_dir_all(&root)?;
            Ok(Arc::new(LocalFileSystem::new_with_prefix(root)?))
        }
        ObjectBackendConfig::S3 { bucket, endpoint } => {
            let mut builder = AmazonS3Builder::from_env().with_bucket_name(bucket);
            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            Ok(Arc::new(builder.build()?))
        }
        ObjectBackendConfig::Gcs { bucket } => Ok(Arc::new(
            GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()?,
        )),
        ObjectBackendConfig::Azure { container } => Ok(Arc::new(
            MicrosoftAzureBuilder::from_env()
                .with_container_name(container)
                .build()?,
        )),
    }
}

pub fn artifact_store_from_env(default_root: PathBuf) -> Result<ArtifactStore> {
    let primary = build(ObjectBackendConfig::from_env(default_root.clone())?)?;
    let Some(backend) = std::env::var("OATH_OBJECT_REPLICA_BACKEND").ok() else {
        return Ok(ArtifactStore::new(primary));
    };
    let replica = match backend.as_str() {
        "local" => ObjectBackendConfig::Local {
            root: std::env::var_os("OATH_OBJECT_REPLICA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.with_extension("replica")),
        },
        "s3" | "r2" => ObjectBackendConfig::S3 {
            bucket: std::env::var("OATH_OBJECT_REPLICA_BUCKET")
                .context("OATH_OBJECT_REPLICA_BUCKET is required")?,
            endpoint: std::env::var("OATH_OBJECT_REPLICA_ENDPOINT").ok(),
        },
        "gcs" => ObjectBackendConfig::Gcs {
            bucket: std::env::var("OATH_OBJECT_REPLICA_BUCKET")
                .context("OATH_OBJECT_REPLICA_BUCKET is required")?,
        },
        "azure" => ObjectBackendConfig::Azure {
            container: std::env::var("OATH_OBJECT_REPLICA_BUCKET")
                .context("OATH_OBJECT_REPLICA_BUCKET is required")?,
        },
        value => anyhow::bail!("unsupported replica object backend {value}"),
    };
    Ok(ArtifactStore::with_replicas(primary, vec![build(replica)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn digest(bytes: &[u8]) -> String {
        sha256(bytes)
    }
    #[test]
    fn local_backend_builds_for_offline_tests() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            build(ObjectBackendConfig::Local {
                root: dir.path().into()
            })
            .is_ok()
        );
    }

    #[tokio::test]
    async fn replicates_writes_to_all_stores() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = ArtifactStore::with_replicas(primary.clone(), vec![replica.clone()]);
        let digest = digest(b"artifact");
        store.put_immutable(&digest, b"artifact").await.unwrap();
        let path = ObjectPath::from(digest);
        assert_eq!(
            primary
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
        assert_eq!(
            replica
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
    }

    #[tokio::test]
    async fn reads_from_replica_and_repairs_primary() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let digest = digest(b"artifact");
        let path = ObjectPath::from(digest.clone());
        replica
            .put(&path, b"artifact".to_vec().into())
            .await
            .unwrap();
        let store = ArtifactStore::with_replicas(primary.clone(), vec![replica]);
        assert_eq!(store.get(&digest).await.unwrap(), b"artifact");
        assert_eq!(
            primary
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
    }

    #[tokio::test]
    async fn rejects_corrupt_primary_without_hiding_it_with_a_replica() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let digest = digest(b"artifact");
        let path = ObjectPath::from(digest.clone());
        primary
            .put(&path, b"corrupt".to_vec().into())
            .await
            .unwrap();
        replica
            .put(&path, b"artifact".to_vec().into())
            .await
            .unwrap();

        let error = ArtifactStore::with_replicas(primary, vec![replica])
            .get(&digest)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ArtifactReadError::Corrupt { ref location, .. } if location == "primary"
        ));
    }

    #[tokio::test]
    async fn rejects_corrupt_replica_without_repairing_primary() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let digest = digest(b"artifact");
        let path = ObjectPath::from(digest.clone());
        replica
            .put(&path, b"corrupt".to_vec().into())
            .await
            .unwrap();

        let error = ArtifactStore::with_replicas(primary.clone(), vec![replica])
            .get(&digest)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ArtifactReadError::Corrupt { ref location, .. } if location == "replica[0]"
        ));
        assert!(matches!(
            primary.get(&path).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_put_when_bytes_do_not_match_digest() {
        let store = ArtifactStore::new(Arc::new(InMemory::new()));
        let error = store
            .put_immutable(&digest(b"expected"), b"different")
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ArtifactReadError>().is_some());
    }
}
