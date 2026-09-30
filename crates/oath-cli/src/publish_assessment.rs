use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use oath_contracts::{Decision, ReasonCode};
pub use oath_contracts::{
    DetachedSignature, PublishAssessmentV2 as PublishAssessment, PublishDiff, PublishFile,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

pub const PUBLISH_ASSESSMENT_VERSION: u32 = oath_contracts::PUBLISH_ASSESSMENT_VERSION;

#[derive(Debug, Serialize)]
pub struct PersistedEvidence {
    pub directory: String,
    pub assessment_signature: String,
    pub signing_public_key: String,
    pub sbom_path: String,
    pub provenance_path: String,
}

pub fn legacy_v1(assessment: &PublishAssessment) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "name": assessment.name,
        "version": assessment.version,
        "tag": assessment.tag,
        "access": assessment.access,
        "package_digest": assessment.package_digest,
        "unpacked_bytes": assessment.unpacked_bytes,
        "files": assessment.files,
        "dependency_count": assessment.dependency_count,
        "lifecycle_hooks": assessment.lifecycle_hooks,
        "capabilities": assessment.capabilities,
        "source_available": assessment.source_available,
        "secret_findings": assessment.secret_findings,
        "decision": if assessment.decision == Decision::Deny { serde_json::json!("block") } else { serde_json::json!(assessment.decision) },
        "reason_code": assessment.reason_code,
        "previous_release": assessment.previous_release,
    })
}

pub fn sign_json(value: &impl Serialize) -> Result<DetachedSignature> {
    let key = signing_key()?;
    sign_json_with_key(value, &key)
}

fn sign_json_with_key(value: &impl Serialize, key: &SigningKey) -> Result<DetachedSignature> {
    Ok(oath_contracts::sign_json(value, key)?)
}

pub fn verify_json_signature(value: &impl Serialize, signature: &DetachedSignature) -> Result<()> {
    oath_contracts::verify_json(value, signature).context("Ed25519 signature verification failed")
}

pub fn spdx_sbom(package: &serde_json::Value, assessment: &PublishAssessment) -> serde_json::Value {
    let mut packages = vec![serde_json::json!({
        "SPDXID": "SPDXRef-RootPackage", "name": assessment.name, "versionInfo": assessment.version,
        "downloadLocation": "NOASSERTION", "filesAnalyzed": true,
        "checksums": [{ "algorithm": "SHA256", "checksumValue": assessment.package_digest.trim_start_matches("sha256:") }]
    })];
    for key in ["dependencies", "optionalDependencies", "peerDependencies"] {
        if let Some(deps) = package.get(key).and_then(|v| v.as_object()) {
            for (name, version) in deps {
                packages.push(serde_json::json!({ "SPDXID": format!("SPDXRef-Dependency-{}", name.replace(['@', '/'], "-")), "name": name, "versionInfo": version.as_str().unwrap_or("NOASSERTION"), "downloadLocation": "NOASSERTION", "filesAnalyzed": false }));
            }
        }
    }
    serde_json::json!({
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}-{}", assessment.name, assessment.version),
        "documentNamespace": format!("https://oath.dev/spdx/{}/{}", assessment.name, assessment.package_digest.trim_start_matches("sha256:")),
        "creationInfo": { "created": "1970-01-01T00:00:00Z", "creators": [format!("Tool: oath-{}", env!("CARGO_PKG_VERSION"))] },
        "packages": packages
    })
}

pub fn assessment_attestation(assessment: &PublishAssessment) -> serde_json::Value {
    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{ "name": format!("{}@{}", assessment.name, assessment.version), "digest": { "sha256": assessment.package_digest.trim_start_matches("sha256:") } }],
        "predicateType": "https://oath.dev/attestation/publish-assessment/v1",
        "predicate": {
            "assessor": format!("oath/{}", env!("CARGO_PKG_VERSION")),
            "assessment_time": assessment.generated_at,
            "tag": assessment.tag,
            "access": assessment.access,
            "decision": assessment.decision,
            "reason_code": assessment.reason_code,
            "evidence_digest": assessment.evidence_digest,
            "note": "This attests the local package snapshot and assessment, not source-build provenance."
        }
    })
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn signing_key() -> Result<SigningKey> {
    let home =
        oath_core::home_dir().context("HOME or USERPROFILE is required for publish signing")?;
    load_or_create_signing_key(&home.join(".oath").join("publish-signing.key"))
}

fn load_or_create_signing_key(path: &Path) -> Result<SigningKey> {
    fn read_key(path: &Path) -> Result<SigningKey> {
        let bytes: [u8; 32] = std::fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid publish signing key length"))?;
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
        .map_err(|error| anyhow::anyhow!("failed to generate publish signing key: {error}"))?;
    let suffix = u64::from_le_bytes(bytes[..8].try_into().expect("eight-byte key prefix"));
    let temp_path = path.with_extension(format!("{suffix:016x}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let result = match std::fs::hard_link(&temp_path, path) {
        Ok(()) => Ok(SigningKey::from_bytes(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_key(path),
        Err(error) => Err(error.into()),
    };
    let _ = std::fs::remove_file(temp_path);
    result
}

fn publish_assessment_root(root: &Path) -> Result<PathBuf> {
    let home =
        oath_core::home_dir().context("HOME or USERPROFILE is required for publish evidence")?;
    let canonical = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize package root {}", root.display()))?;
    let project_id = format!(
        "{:x}",
        Sha256::digest(canonical.to_string_lossy().as_bytes())
    );
    Ok(home
        .join(".oath")
        .join("publish-assessments")
        .join("projects")
        .join(project_id))
}

pub fn persist_signed(
    root: &Path,
    assessment: &PublishAssessment,
    package: &serde_json::Value,
) -> Result<PersistedEvidence> {
    let safe_name = assessment.name.replace(['@', '/'], "-");
    let digest = assessment.package_digest.trim_start_matches("sha256:");
    let directory = publish_assessment_root(root)?.join(format!(
        "{}-{}-{}",
        safe_name,
        assessment.version,
        &digest[..digest.len().min(12)]
    ));
    std::fs::create_dir_all(&directory)?;
    let assessment_path = directory.join("assessment.json");
    let sbom_path = directory.join("sbom.spdx.json");
    let provenance_path = directory.join("provenance.intoto.json");
    atomic_json(&assessment_path, assessment)?;
    atomic_json(&sbom_path, &spdx_sbom(package, assessment))?;
    atomic_json(&provenance_path, &assessment_attestation(assessment))?;
    let key = signing_key()?;
    let canonical = oath_contracts::canonical_json_bytes(assessment)?;
    let signature = key.sign(&canonical);
    let encoded_signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    atomic_json(
        &directory.join("signature.json"),
        &serde_json::json!({ "algorithm": "ed25519", "canonicalization": "oath-json-v1", "signature": encoded_signature, "public_key": public_key, "subject": "assessment.json" }),
    )?;
    Ok(PersistedEvidence {
        directory: directory.display().to_string(),
        assessment_signature: encoded_signature,
        signing_public_key: public_key,
        sbom_path: sbom_path.display().to_string(),
        provenance_path: provenance_path.display().to_string(),
    })
}

fn looks_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == ".env"
        || lower.ends_with("/.env")
        || lower.ends_with(".pem")
        || lower.ends_with("id_rsa")
        || lower.ends_with(".npmrc")
        || lower.contains("credentials")
}

fn content_secret_marker(bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    let fixed = [
        ("-----BEGIN PRIVATE KEY-----", "private-key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "rsa-private-key"),
        ("AKIA", "aws-access-key-id"),
        ("ghp_", "github-token"),
    ]
    .into_iter()
    .find_map(|(marker, reason)| text.contains(marker).then_some(reason));
    fixed.or_else(|| contains_npm_token(&text).then_some("npm-token"))
}

fn contains_npm_token(text: &str) -> bool {
    text.match_indices("npm_").any(|(offset, _)| {
        let candidate = &text[offset + 4..];
        let token_len = candidate
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric())
            .count();
        token_len >= 36
    })
}

fn inferred_capabilities(contents: &[Vec<u8>]) -> Vec<String> {
    let joined = contents
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .collect::<Vec<_>>()
        .join("\n");
    let mut capabilities = Vec::new();
    for (name, markers) in [
        (
            "network",
            &["fetch(", "http.request", "https.request", "node:net"][..],
        ),
        (
            "filesystem",
            &["node:fs", "require('fs')", "require(\"fs\")"][..],
        ),
        ("environment", &["process.env"][..]),
        ("subprocess", &["child_process", "node:child_process"][..]),
        ("dynamic-exec", &["eval(", "new Function("][..]),
    ] {
        if markers.iter().any(|marker| joined.contains(marker)) {
            capabilities.push(name.into());
        }
    }
    capabilities
}

pub fn assess(
    root: &Path,
    files: &[PathBuf],
    package: &serde_json::Value,
    tag: &str,
    access: Option<&str>,
) -> Result<PublishAssessment> {
    let key = signing_key()?;
    assess_with_signing_key(root, files, package, tag, access, &key)
}

fn assess_with_signing_key(
    root: &Path,
    files: &[PathBuf],
    package: &serde_json::Value,
    tag: &str,
    access: Option<&str>,
    signing_key: &SigningKey,
) -> Result<PublishAssessment> {
    let name = package
        .get("name")
        .and_then(|v| v.as_str())
        .context("package name missing")?;
    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .context("package version missing")?;
    let mut manifest = Vec::new();
    let mut secret_findings = Vec::new();
    let mut total = 0;
    let mut contents = Vec::new();
    for file in files {
        let bytes = std::fs::read(file)?;
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        contents.push(bytes.clone());
        total += bytes.len() as u64;
        if looks_sensitive_path(&rel) {
            secret_findings.push(format!("sensitive-path:{rel}"));
        }
        if let Some(marker) = content_secret_marker(&bytes) {
            secret_findings.push(format!("{marker}:{rel}"));
        }
        manifest.push(PublishFile {
            path: rel,
            bytes: bytes.len() as u64,
            sha256: digest,
        });
    }
    manifest.sort_by(|a, b| a.path.cmp(&b.path));
    secret_findings.sort();
    secret_findings.dedup();
    let mut package_hasher = Sha256::new();
    for file in &manifest {
        package_hasher.update(file.path.as_bytes());
        package_hasher.update([0]);
        package_hasher.update(file.sha256.as_bytes());
        package_hasher.update(b"\n");
    }
    let lifecycle_hooks = package
        .get("scripts")
        .and_then(|v| v.as_object())
        .map(|scripts| {
            scripts
                .keys()
                .filter(|name| {
                    matches!(
                        name.as_str(),
                        "preinstall" | "install" | "postinstall" | "prepare" | "prepublishOnly"
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let dependency_count = ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|key| package.get(key).and_then(|v| v.as_object()))
        .map(|deps| deps.len())
        .sum();
    let blocked = !secret_findings.is_empty();
    let capabilities = inferred_capabilities(&contents);
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let policy_digest = oath_contracts::digest_json(&serde_json::json!({
        "secrets": "deny",
        "lifecycle_hooks": "review",
        "tag": tag,
        "access": access,
    }))?;
    let evidence_digest = oath_contracts::digest_json(&serde_json::json!({
        "files": manifest,
        "capabilities": capabilities,
        "secret_findings": secret_findings,
        "lifecycle_hooks": lifecycle_hooks,
    }))?;
    let mut assessment = PublishAssessment {
        schema_version: PUBLISH_ASSESSMENT_VERSION,
        generated_at,
        expires_at: generated_at.saturating_add(3600),
        name: name.into(),
        version: version.into(),
        tag: tag.into(),
        access: access.map(String::from),
        package_digest: format!("sha256:{:x}", package_hasher.finalize()),
        unpacked_bytes: total,
        files: manifest,
        dependency_count,
        lifecycle_hooks,
        capabilities,
        source_available: package.get("repository").is_some(),
        secret_findings,
        decision: if blocked {
            Decision::Deny
        } else {
            Decision::Allow
        },
        reason_code: if blocked {
            ReasonCode::PublishSecretDetected
        } else {
            ReasonCode::PublishAllowed
        },
        previous_release: None,
        policy_digest,
        evidence_digest,
        rule_bundle_version: format!("oath-rules/{}", env!("CARGO_PKG_VERSION")),
        limitations: vec![
            "Static analysis cannot prove package safety".into(),
            "Opaque binaries and remote second-stage payloads require containment".into(),
        ],
        signature: None,
    };
    assessment.signature = Some(sign_json_with_key(&assessment, signing_key)?);
    Ok(assessment)
}

pub fn attach_previous_release(root: &Path, assessment: &mut PublishAssessment) -> Result<()> {
    let key = signing_key()?;
    attach_previous_release_from_bases(
        &[
            publish_assessment_root(root)?,
            root.join(".oath").join("publish-assessments"),
        ],
        assessment,
        &key,
    )
}

fn attach_previous_release_from_bases(
    bases: &[PathBuf],
    assessment: &mut PublishAssessment,
    signing_key: &SigningKey,
) -> Result<()> {
    let current = assessment.version.parse::<node_semver::Version>().ok();
    let mut candidates = Vec::new();
    for base in bases.iter().filter(|base| base.exists()) {
        for entry in std::fs::read_dir(base)?.flatten() {
            let path = entry.path().join("assessment.json");
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let Ok(previous) = serde_json::from_slice::<PublishAssessment>(&bytes) else {
                continue;
            };
            if previous.name != assessment.name {
                continue;
            }
            let Some(version) = previous.version.parse::<node_semver::Version>().ok() else {
                continue;
            };
            if current
                .as_ref()
                .map(|value| version < *value)
                .unwrap_or(false)
            {
                candidates.push((version, previous));
            }
        }
    }
    let Some((_, previous)) = candidates.into_iter().max_by(|(a, _), (b, _)| a.cmp(b)) else {
        return Ok(());
    };
    let old: std::collections::BTreeMap<_, _> = previous
        .files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect();
    let new: std::collections::BTreeMap<_, _> = assessment
        .files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect();
    let added_files = new
        .keys()
        .filter(|path| !old.contains_key(*path))
        .cloned()
        .collect();
    let removed_files = old
        .keys()
        .filter(|path| !new.contains_key(*path))
        .cloned()
        .collect();
    let changed_files = new
        .iter()
        .filter(|(path, digest)| old.get(*path).map(|old| old != *digest).unwrap_or(false))
        .map(|(path, _)| path.clone())
        .collect();
    let capabilities_added = assessment
        .capabilities
        .iter()
        .filter(|cap| !previous.capabilities.contains(*cap))
        .cloned()
        .collect();
    let capabilities_removed = previous
        .capabilities
        .iter()
        .filter(|cap| !assessment.capabilities.contains(*cap))
        .cloned()
        .collect();
    assessment.previous_release = Some(PublishDiff {
        previous_version: previous.version,
        added_files,
        removed_files,
        changed_files,
        capabilities_added,
        capabilities_removed,
    });
    assessment.signature = None;
    assessment.signature = Some(sign_json_with_key(assessment, signing_key)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_lifecycle_environment_names_are_not_tokens() {
        assert_eq!(content_secret_marker(b"process.env.npm_package_name"), None);
        assert_eq!(content_secret_marker(b"npm_config_registry"), None);
        let token = format!("npm_{}", "a".repeat(36));
        assert_eq!(content_secret_marker(token.as_bytes()), Some("npm-token"));
    }

    #[test]
    fn concurrent_key_creation_converges() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("publish.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_signing_key(&path).unwrap().to_bytes()
                })
            })
            .collect::<Vec<_>>();
        let keys = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(std::fs::read(path).unwrap().len(), 32);
    }

    #[test]
    fn assessment_is_deterministic_and_blocks_private_keys() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let dir = tempfile::tempdir().unwrap();
        let package_path = dir.path().join("package.json");
        let key_path = dir.path().join("secret.pem");
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.0.0"}"#).unwrap();
        std::fs::write(&key_path, "-----BEGIN PRIVATE KEY-----").unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let assessment = assess_with_signing_key(
            dir.path(),
            &[package_path, key_path],
            &package,
            "latest",
            None,
            &signing_key,
        )
        .unwrap();
        assert_eq!(assessment.decision, Decision::Deny);
        assert_eq!(assessment.reason_code, ReasonCode::PublishSecretDetected);
        assert!(assessment.package_digest.starts_with("sha256:"));
        let signature = assessment.signature.clone().unwrap();
        let mut unsigned = assessment.clone();
        unsigned.signature = None;
        verify_json_signature(&unsigned, &signature).unwrap();
        unsigned.reason_code = ReasonCode::PublishAllowed;
        assert!(verify_json_signature(&unsigned, &signature).is_err());
        let sbom = spdx_sbom(&package, &assessment);
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        let provenance = assessment_attestation(&assessment);
        assert_eq!(
            provenance["predicateType"],
            "https://oath.dev/attestation/publish-assessment/v1"
        );
        assert!(
            provenance["predicate"]["note"]
                .as_str()
                .unwrap()
                .contains("not source-build provenance")
        );
    }

    #[test]
    fn previous_release_reports_file_and_capability_changes() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let dir = tempfile::tempdir().unwrap();
        let package_path = dir.path().join("package.json");
        let source_path = dir.path().join("index.js");
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.0.0"}"#).unwrap();
        std::fs::write(&source_path, "module.exports = 1").unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let previous = assess_with_signing_key(
            dir.path(),
            &[package_path.clone(), source_path.clone()],
            &package,
            "latest",
            None,
            &signing_key,
        )
        .unwrap();
        let previous_dir = dir.path().join(".oath/publish-assessments/demo-1");
        std::fs::create_dir_all(&previous_dir).unwrap();
        std::fs::write(
            previous_dir.join("assessment.json"),
            serde_json::to_vec(&previous).unwrap(),
        )
        .unwrap();
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.1.0"}"#).unwrap();
        std::fs::write(
            &source_path,
            "const fs = require('fs'); module.exports = fs",
        )
        .unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let mut current = assess_with_signing_key(
            dir.path(),
            &[package_path, source_path],
            &package,
            "latest",
            None,
            &signing_key,
        )
        .unwrap();
        attach_previous_release_from_bases(
            &[dir.path().join(".oath/publish-assessments")],
            &mut current,
            &signing_key,
        )
        .unwrap();
        let diff = current.previous_release.unwrap();
        assert_eq!(diff.previous_version, "1.0.0");
        assert!(diff.changed_files.contains(&"index.js".into()));
        assert!(diff.capabilities_added.contains(&"filesystem".into()));
    }
}
