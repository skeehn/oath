use anyhow::Result;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{ErrorKind, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub mod analysis_backend;
pub mod assessment;
pub mod billing;
pub mod control_plane;
pub mod identity;
pub mod metrics;
pub mod object_backend;
pub mod postgres_api;
pub mod rate_limit;
pub mod signer;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(crate) fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid or missing bearer token".into(),
        }
    }
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
    pub(crate) fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    pub(crate) fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub organization: String,
    pub role: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct TransparencyCheckpoint {
    pub schema_version: u32,
    pub event_count: usize,
    pub merkle_root: String,
    pub latest_hash: Option<String>,
    pub canonicalization: String,
    pub domain: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct StageRequest {
    pub name: String,
    pub version: String,
    #[serde(default = "latest_tag")]
    pub tag: String,
    pub tarball_base64: String,
    pub assessment: Value,
    #[serde(default)]
    pub private: bool,
}

fn latest_tag() -> String {
    "latest".into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageRecord {
    pub id: String,
    pub organization: String,
    pub name: String,
    pub version: String,
    pub tag: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub manifest: Value,
    pub publisher_assessment: Value,
    pub assessment: Value,
    pub server_evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
    pub created_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub reason: String,
    #[serde(default)]
    pub quarantine: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub role: String,
    #[serde(default = "default_token_ttl")]
    pub ttl_secs: u64,
}

fn default_token_ttl() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
pub struct PackageRoleRequest {
    pub principal_org: String,
    pub role: String,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn registry_signing_key(path: &Path) -> Result<SigningKey> {
    fn read_key(path: &Path) -> Result<SigningKey> {
        let bytes: [u8; 32] = std::fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid registry signing key"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    if path.exists() {
        return read_key(path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("registry key generation failed: {error}"))?;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let suffix = hex_sha256(&bytes);
    let temp_path = path.with_extension(format!("{}.tmp", &suffix[..16]));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let result = match std::fs::hard_link(&temp_path, path) {
        Ok(()) => Ok(SigningKey::from_bytes(&bytes)),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => read_key(path),
        Err(error) => Err(error.into()),
    };
    let _ = std::fs::remove_file(temp_path);
    result
}

fn hash_leaf(leaf: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(leaf.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_children(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn split_point(length: usize) -> usize {
    debug_assert!(length > 1);
    let mut power = 1usize;
    while power << 1 < length {
        power <<= 1;
    }
    power
}

fn subtree_root(hashes: &[String]) -> String {
    match hashes.len() {
        0 => hex_sha256(&[]),
        1 => hash_leaf(&hashes[0]),
        length => {
            let split = split_point(length);
            hash_children(
                &subtree_root(&hashes[..split]),
                &subtree_root(&hashes[split..]),
            )
        }
    }
}

pub(crate) fn merkle_root(hashes: Vec<String>) -> String {
    subtree_root(&hashes)
}

fn inclusion_path(hashes: &[String], index: usize, proof: &mut Vec<String>) {
    if hashes.len() <= 1 {
        return;
    }
    let split = split_point(hashes.len());
    if index < split {
        inclusion_path(&hashes[..split], index, proof);
        proof.push(subtree_root(&hashes[split..]));
    } else {
        inclusion_path(&hashes[split..], index - split, proof);
        proof.push(subtree_root(&hashes[..split]));
    }
}

pub(crate) fn merkle_inclusion_proof(hashes: Vec<String>, index: usize) -> Option<Vec<String>> {
    if hashes.is_empty() || index >= hashes.len() {
        return None;
    }
    let mut proof = Vec::new();
    inclusion_path(&hashes, index, &mut proof);
    Some(proof)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleRangeNode {
    pub start: usize,
    pub size: usize,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleConsistencyProof {
    pub from_size: usize,
    pub to_size: usize,
    pub prefix: Vec<MerkleRangeNode>,
    pub suffix: Vec<MerkleRangeNode>,
}

fn compact_range(hashes: &[String], start: usize, end: usize) -> Vec<MerkleRangeNode> {
    let mut nodes = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let remaining = end - cursor;
        let alignment = if cursor == 0 {
            1usize << (usize::BITS - 1 - remaining.leading_zeros())
        } else {
            1usize << cursor.trailing_zeros()
        };
        let mut size = alignment.min(1usize << (usize::BITS - 1 - remaining.leading_zeros()));
        while cursor + size > end {
            size >>= 1;
        }
        nodes.push(MerkleRangeNode {
            start: cursor,
            size,
            hash: subtree_root(&hashes[cursor..cursor + size]),
        });
        cursor += size;
    }
    nodes
}

pub fn merkle_consistency_proof(
    hashes: &[String],
    from_size: usize,
) -> Option<MerkleConsistencyProof> {
    if from_size > hashes.len() {
        return None;
    }
    Some(MerkleConsistencyProof {
        from_size,
        to_size: hashes.len(),
        prefix: compact_range(hashes, 0, from_size),
        suffix: compact_range(hashes, from_size, hashes.len()),
    })
}

fn root_from_frontier(nodes: &[MerkleRangeNode], expected_size: usize) -> Option<String> {
    if expected_size == 0 {
        return nodes.is_empty().then(|| hex_sha256(&[]));
    }
    let mut cursor = 0usize;
    let mut stack = Vec::<MerkleRangeNode>::new();
    for node in nodes {
        if node.start != cursor || node.size == 0 || !node.size.is_power_of_two() {
            return None;
        }
        cursor = cursor.checked_add(node.size)?;
        stack.push(node.clone());
        loop {
            let length = stack.len();
            if length < 2 {
                break;
            }
            let left = &stack[length - 2];
            let right = &stack[length - 1];
            if left.size != right.size
                || left.start + left.size != right.start
                || !left.start.is_multiple_of(left.size * 2)
            {
                break;
            }
            let right = stack.pop()?;
            let left = stack.pop()?;
            stack.push(MerkleRangeNode {
                start: left.start,
                size: left.size * 2,
                hash: hash_children(&left.hash, &right.hash),
            });
        }
    }
    if cursor != expected_size {
        return None;
    }
    let mut nodes = stack.into_iter().rev();
    let mut root = nodes.next()?.hash;
    for node in nodes {
        root = hash_children(&node.hash, &root);
    }
    Some(root)
}

pub fn verify_merkle_consistency(
    proof: &MerkleConsistencyProof,
    from_root: &str,
    to_root: &str,
) -> bool {
    if proof.from_size > proof.to_size {
        return false;
    }
    let prefix_root = root_from_frontier(&proof.prefix, proof.from_size);
    let mut full = proof.prefix.clone();
    full.extend(proof.suffix.clone());
    prefix_root.as_deref() == Some(from_root)
        && root_from_frontier(&full, proof.to_size).as_deref() == Some(to_root)
}

#[cfg(test)]
pub(crate) fn verify_merkle_inclusion(
    leaf: &str,
    index: usize,
    tree_size: usize,
    proof: &[String],
    root: &str,
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    fn reconstruct(
        current: String,
        index: usize,
        tree_size: usize,
        proof: &[String],
        cursor: &mut usize,
    ) -> Option<String> {
        if tree_size == 1 {
            return Some(current);
        }
        let split = split_point(tree_size);
        let child = if index < split {
            reconstruct(current, index, split, proof, cursor)?
        } else {
            reconstruct(current, index - split, tree_size - split, proof, cursor)?
        };
        let sibling = proof.get(*cursor)?;
        *cursor += 1;
        Some(if index < split {
            hash_children(&child, sibling)
        } else {
            hash_children(sibling, &child)
        })
    }
    let mut cursor = 0;
    reconstruct(hash_leaf(leaf), index, tree_size, proof, &mut cursor)
        .is_some_and(|candidate| candidate == root && cursor == proof.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    #[test]
    fn merkle_checkpoints_are_deterministic() {
        assert_eq!(
            merkle_root(vec!["a".into(), "b".into()]),
            merkle_root(vec!["a".into(), "b".into()])
        );
        assert_ne!(merkle_root(vec!["a".into()]), merkle_root(vec!["b".into()]));
    }

    #[test]
    fn inclusion_proofs_verify_every_leaf() {
        let leaves = vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()];
        let root = merkle_root(leaves.clone());
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = merkle_inclusion_proof(leaves.clone(), index).unwrap();
            assert!(verify_merkle_inclusion(
                leaf,
                index,
                leaves.len(),
                &proof,
                &root
            ));
        }
    }

    #[test]
    fn compact_consistency_proofs_link_every_prefix() {
        let leaves = (0..33)
            .map(|value| format!("leaf-{value}"))
            .collect::<Vec<_>>();
        let to_root = merkle_root(leaves.clone());
        for from_size in 0..=leaves.len() {
            let proof = merkle_consistency_proof(&leaves, from_size).unwrap();
            let from_root = merkle_root(leaves[..from_size].to_vec());
            assert!(verify_merkle_consistency(&proof, &from_root, &to_root));
            assert!(proof.prefix.len() + proof.suffix.len() <= 12);
        }
    }

    #[test]
    fn concurrent_signing_key_creation_converges_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("registry-signing.key"));
        let barrier = Arc::new(Barrier::new(16));
        let handles = (0..16)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry_signing_key(&path)
                        .unwrap()
                        .verifying_key()
                        .to_bytes()
                })
            })
            .collect::<Vec<_>>();
        let keys = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(std::fs::read(&*path).unwrap().len(), 32);
    }
}
