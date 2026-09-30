use crate::publish_assessment::{self, DetachedSignature, PersistedEvidence, PublishAssessment};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

const TRANSFER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferAsset {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTarball {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferManifest {
    pub schema_version: u32,
    pub format: String,
    pub name: String,
    pub version: String,
    pub package_digest: String,
    pub assessment_decision: String,
    pub assessment_reason_code: String,
    pub capabilities: Vec<String>,
    pub signing_public_key: String,
    pub tarball: TransferTarball,
    pub evidence: Vec<TransferAsset>,
    pub consumer_decision: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TransferVerification {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub verified: bool,
    pub integrity_verified: bool,
    pub package_sha512: String,
    pub signature_valid: bool,
    pub signature_trusted: bool,
    pub signature_trust: String,
    pub signing_public_key: String,
    pub consumer_decision: String,
    pub limitations: Vec<String>,
}

fn npm_command() -> std::process::Command {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("npm.cmd")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("npm")
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn sha512_file(path: &Path) -> Result<String> {
    let mut hasher = Sha512::new();
    let mut file = std::fs::File::open(path)?;
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha512:{:x}", hasher.finalize()))
}

fn pack_without_scripts(root: &Path, destination: &Path) -> Result<PathBuf> {
    let cache = tempfile::tempdir().context("failed to create isolated npm pack cache")?;
    let output = npm_command()
        .args(["pack", "--json", "--ignore-scripts", "--pack-destination"])
        .arg(destination)
        .current_dir(root)
        .env("npm_config_cache", cache.path())
        .output()
        .context("npm 11 is required to build the transfer tarball")?;
    anyhow::ensure!(
        output.status.success(),
        "npm pack failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("invalid npm pack --json output")?;
    let filename = report
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("filename"))
        .and_then(|value| value.as_str())
        .context("npm pack output did not contain filename")?;
    let tarball = destination.join(filename);
    anyhow::ensure!(
        tarball.is_file(),
        "npm pack did not create {}",
        tarball.display()
    );
    Ok(tarball)
}

fn verify_tarball_matches_assessment(tarball: &Path, assessment: &PublishAssessment) -> Result<()> {
    let expected: BTreeMap<_, _> = assessment
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let decoder = flate2::read::GzDecoder::new(std::fs::File::open(tarball)?);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        anyhow::ensure!(
            entry.header().entry_type().is_file(),
            "transfer tarball contains a non-regular entry"
        );
        let path = entry.path()?.into_owned();
        let relative = path
            .strip_prefix("package")
            .context("transfer tarball entry is outside package/")?;
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
            "transfer tarball contains an unsafe path {}",
            path.display()
        );
        let relative = relative.to_string_lossy().replace('\\', "/");
        let expected_file = expected
            .get(relative.as_str())
            .with_context(|| format!("tarball contains unassessed file {relative}"))?;
        anyhow::ensure!(
            seen.insert(relative.clone()),
            "duplicate tarball entry {relative}"
        );
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 == expected_file.bytes,
            "tarball byte length changed after assessment for {relative}"
        );
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == expected_file.sha256,
            "tarball bytes changed after assessment for {relative}"
        );
    }
    anyhow::ensure!(
        seen.len() == expected.len(),
        "tarball contains {} assessed files; expected {}",
        seen.len(),
        expected.len()
    );
    for path in expected.keys() {
        anyhow::ensure!(seen.contains(*path), "tarball omitted assessed file {path}");
    }
    Ok(())
}

fn stage_assessed_files(root: &Path, assessment: &PublishAssessment) -> Result<tempfile::TempDir> {
    let staged = tempfile::tempdir().context("failed to create assessed package staging root")?;
    for file in &assessment.files {
        let relative = Path::new(&file.path);
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
            "assessed package contains an unsafe path {}",
            file.path
        );
        let source = root.join(relative);
        let target = staged.path().join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&source, &target).with_context(|| {
            format!(
                "failed to stage assessed file {} for transfer",
                source.display()
            )
        })?;
    }
    Ok(staged)
}

fn copy_asset(source: &Path, capsule: &Path, relative: &str) -> Result<TransferAsset> {
    let target = capsule.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, &target).with_context(|| {
        format!(
            "failed to copy transfer evidence {} to {}",
            source.display(),
            target.display()
        )
    })?;
    Ok(TransferAsset {
        path: relative.to_string(),
        bytes: std::fs::metadata(&target)?.len(),
        sha256: sha256_file(&target)?,
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn create_capsule(
    root: &Path,
    output: &Path,
    assessment: &PublishAssessment,
    persisted: &PersistedEvidence,
) -> Result<TransferManifest> {
    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        root.join(output)
    };
    anyhow::ensure!(output != root, "transfer output cannot be the package root");
    anyhow::ensure!(
        !output.exists(),
        "transfer output {} already exists; refusing to overwrite",
        output.display()
    );

    // Pack only an isolated copy of the assessed files. This prevents evidence
    // created under .oath/ (or concurrent unrelated files) from entering the
    // tarball after the assessment snapshot.
    let staging = tempfile::tempdir().context("failed to create transfer staging directory")?;
    let assessed_source = stage_assessed_files(root, assessment)?;
    let packed = pack_without_scripts(assessed_source.path(), staging.path())?;
    verify_tarball_matches_assessment(&packed, assessment)?;
    std::fs::create_dir_all(&output)?;
    let tarball_name = packed
        .file_name()
        .and_then(|value| value.to_str())
        .context("npm produced a non-UTF-8 tarball name")?;
    let tarball_relative = format!("package/{tarball_name}");
    let tarball_target = output.join(&tarball_relative);
    std::fs::create_dir_all(tarball_target.parent().unwrap_or(&output))?;
    std::fs::copy(&packed, &tarball_target)?;

    let evidence_root = PathBuf::from(&persisted.directory);
    let mut evidence = Vec::new();
    for filename in [
        "assessment.json",
        "signature.json",
        "sbom.spdx.json",
        "provenance.intoto.json",
    ] {
        evidence.push(copy_asset(
            &evidence_root.join(filename),
            &output,
            &format!("evidence/{filename}"),
        )?);
    }

    let manifest = TransferManifest {
        schema_version: TRANSFER_SCHEMA_VERSION,
        format: "oath-package-transfer".to_string(),
        name: assessment.name.clone(),
        version: assessment.version.clone(),
        package_digest: assessment.package_digest.clone(),
        assessment_decision: assessment.decision.to_string(),
        assessment_reason_code: assessment.reason_code.to_string(),
        capabilities: assessment.capabilities.clone(),
        signing_public_key: persisted.signing_public_key.clone(),
        tarball: TransferTarball {
            path: tarball_relative,
            bytes: std::fs::metadata(&tarball_target)?.len(),
            sha256: sha256_file(&tarball_target)?,
            sha512: sha512_file(&tarball_target)?,
        },
        evidence,
        consumer_decision: "review-required".to_string(),
        limitations: vec![
            "Hash and signature verification proves integrity; signer identity is established only when the public key is anchored through a separate trusted channel.".to_string(),
            "Lifecycle scripts are disabled while packing; build artifacts must already exist.".to_string(),
            "Run an Oath execution assessment and enforce an OS sandbox before executing transferred code.".to_string(),
        ],
    };
    let signature = publish_assessment::sign_json(&manifest)?;
    write_json(&output.join("transfer.json"), &manifest)?;
    write_json(&output.join("transfer.signature.json"), &signature)?;
    Ok(manifest)
}

pub fn verify_capsule(
    capsule: &Path,
    trusted_public_key: Option<&str>,
) -> Result<TransferVerification> {
    let manifest: TransferManifest = serde_json::from_slice(
        &std::fs::read(capsule.join("transfer.json"))
            .context("transfer.json is missing from the capsule")?,
    )?;
    anyhow::ensure!(
        manifest.schema_version == TRANSFER_SCHEMA_VERSION
            && manifest.format == "oath-package-transfer",
        "unsupported Oath transfer format"
    );
    let transfer_signature: DetachedSignature = serde_json::from_slice(
        &std::fs::read(capsule.join("transfer.signature.json"))
            .context("transfer.signature.json is missing from the capsule")?,
    )?;
    publish_assessment::verify_json_signature(&manifest, &transfer_signature)
        .context("transfer manifest signature is invalid")?;
    anyhow::ensure!(
        transfer_signature.public_key == manifest.signing_public_key,
        "transfer signature key does not match the signed manifest"
    );

    let tarball = capsule.join(&manifest.tarball.path);
    anyhow::ensure!(
        std::fs::metadata(&tarball)?.len() == manifest.tarball.bytes,
        "tarball length does not match transfer manifest"
    );
    anyhow::ensure!(
        sha256_file(&tarball)? == manifest.tarball.sha256,
        "tarball SHA-256 does not match transfer manifest"
    );
    anyhow::ensure!(
        sha512_file(&tarball)? == manifest.tarball.sha512,
        "tarball SHA-512 does not match transfer manifest"
    );
    for asset in &manifest.evidence {
        let path = capsule.join(&asset.path);
        anyhow::ensure!(
            std::fs::metadata(&path)?.len() == asset.bytes,
            "{} length does not match transfer manifest",
            asset.path
        );
        anyhow::ensure!(
            sha256_file(&path)? == asset.sha256,
            "{} SHA-256 does not match transfer manifest",
            asset.path
        );
    }

    let assessment: PublishAssessment =
        serde_json::from_slice(&std::fs::read(capsule.join("evidence/assessment.json"))?)?;
    verify_tarball_matches_assessment(&tarball, &assessment)
        .context("tarball bytes do not match the signed publish assessment")?;
    let assessment_signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capsule.join("evidence/signature.json"))?)?;
    let detached = DetachedSignature {
        algorithm: assessment_signature["algorithm"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        canonicalization: assessment_signature["canonicalization"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        domain: assessment_signature["domain"].as_str().map(str::to_owned),
        signature: assessment_signature["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        public_key: assessment_signature["public_key"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    publish_assessment::verify_json_signature(&assessment, &detached)
        .context("publish assessment signature is invalid")?;
    anyhow::ensure!(
        detached.public_key == manifest.signing_public_key,
        "assessment and transfer manifest were signed by different keys"
    );
    anyhow::ensure!(
        assessment.name == manifest.name
            && assessment.version == manifest.version
            && assessment.package_digest == manifest.package_digest,
        "signed assessment identity does not match transfer manifest"
    );

    let signature_trusted = trusted_public_key
        .map(|expected| expected == manifest.signing_public_key)
        .unwrap_or(false);
    if trusted_public_key.is_some() {
        anyhow::ensure!(
            signature_trusted,
            "transfer signing key does not match --trusted-public-key"
        );
    }

    Ok(TransferVerification {
        schema_version: TRANSFER_SCHEMA_VERSION,
        name: manifest.name,
        version: manifest.version,
        verified: signature_trusted,
        integrity_verified: true,
        package_sha512: manifest.tarball.sha512,
        signature_valid: true,
        signature_trusted,
        signature_trust: if signature_trusted {
            "anchored".to_string()
        } else {
            "unanchored".to_string()
        },
        signing_public_key: manifest.signing_public_key,
        consumer_decision: if signature_trusted {
            "review-required".to_string()
        } else {
            "abstain".to_string()
        },
        limitations: manifest.limitations,
    })
}
