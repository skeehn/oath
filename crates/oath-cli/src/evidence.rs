use anyhow::{Context, Result, bail};
use oath_contracts::{DetachedSignature, verify_json};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub operation: &'static str,
    pub bundle: PathBuf,
    pub source_commit: String,
    pub files_verified: usize,
    pub signatures_verified: usize,
    pub schema_identities_verified: usize,
    pub environment_differences: Vec<String>,
    pub valid: bool,
}

pub fn verify(path: &Path, replay: bool) -> Result<VerificationReport> {
    let manifest_path = locate_manifest(path)?;
    let root = manifest_path
        .parent()
        .context("evidence manifest has no parent")?;
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .with_context(|| format!("read evidence manifest {}", manifest_path.display()))?,
    )
    .context("decode evidence manifest")?;
    let source_commit = manifest
        .get("commit")
        .or_else(|| manifest.get("source_commit"))
        .and_then(serde_json::Value::as_str)
        .context("manifest is missing its source commit")?;
    anyhow::ensure!(
        source_commit.len() == 40
            && source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "manifest source commit must be a lowercase 40-character Git commit"
    );
    if let Ok(expected) = std::env::var("OATH_EXPECTED_COMMIT") {
        anyhow::ensure!(
            expected == source_commit,
            "evidence commit {source_commit} does not match OATH_EXPECTED_COMMIT {expected}"
        );
    }
    if manifest.get("source_tree_clean").is_some() {
        anyhow::ensure!(
            manifest["source_tree_clean"] == serde_json::Value::Bool(true),
            "evidence bundle was produced from a dirty source tree"
        );
    }
    verify_freshness(&manifest)?;

    let entries = manifest
        .get("artifacts")
        .or_else(|| manifest.get("files"))
        .and_then(serde_json::Value::as_array)
        .context("manifest has no artifact/file inventory")?;
    let mut signatures_verified = 0;
    let mut schema_identities_verified = 0;
    let mut environment_differences = Vec::new();
    for entry in entries {
        let relative = entry["path"]
            .as_str()
            .context("inventory entry has no path")?;
        let expected = entry["sha256"]
            .as_str()
            .context("inventory entry has no sha256")?;
        let artifact_path = safe_join(root, relative)?;
        let bytes = std::fs::read(&artifact_path)
            .with_context(|| format!("read inventoried artifact {}", artifact_path.display()))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        anyhow::ensure!(
            actual == expected,
            "artifact digest mismatch for {relative}"
        );

        if artifact_path.extension().and_then(|value| value.to_str()) == Some("json") {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("decode JSON artifact {relative}"))?;
            if supported_schema_identity(&value) {
                schema_identities_verified += 1;
            }
            if let Some(commit) = report_commit(&value) {
                anyhow::ensure!(
                    commit == source_commit,
                    "artifact {relative} was generated for {commit}, not {source_commit}"
                );
            }
            if value
                .get("signature")
                .is_some_and(|signature| !signature.is_null())
            {
                verify_detached_document(&value)
                    .with_context(|| format!("verify detached signature for {relative}"))?;
                signatures_verified += 1;
            }
            if replay {
                collect_environment_differences(&value, &mut environment_differences);
            }
        }
    }

    Ok(VerificationReport {
        schema_version: 1,
        operation: if replay { "replay" } else { "verify" },
        bundle: manifest_path,
        source_commit: source_commit.to_owned(),
        files_verified: entries.len(),
        signatures_verified,
        schema_identities_verified,
        environment_differences,
        valid: true,
    })
}

fn locate_manifest(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    for name in ["ga-evidence-manifest.json", "contract-manifest.json"] {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("no supported evidence manifest found at {}", path.display())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    anyhow::ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "unsafe artifact path {}",
        relative.display()
    );
    Ok(root.join(relative))
}

fn verify_freshness(manifest: &serde_json::Value) -> Result<()> {
    let Some(generated) = manifest
        .get("generated_at")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };
    let generated = OffsetDateTime::parse(generated, &Rfc3339).context("invalid generated_at")?;
    let maximum_days = std::env::var("OATH_EVIDENCE_MAX_AGE_DAYS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(30);
    anyhow::ensure!(
        generated <= OffsetDateTime::now_utc() + Duration::minutes(5),
        "evidence was generated in the future"
    );
    anyhow::ensure!(
        generated >= OffsetDateTime::now_utc() - Duration::days(maximum_days),
        "evidence is older than {maximum_days} days"
    );
    Ok(())
}

fn report_commit(value: &serde_json::Value) -> Option<&str> {
    value
        .get("release_commit")
        .or_else(|| value.get("environment")?.get("git_commit"))
        .and_then(serde_json::Value::as_str)
}

fn verify_detached_document(value: &serde_json::Value) -> Result<()> {
    let detached: DetachedSignature = serde_json::from_value(value["signature"].clone())?;
    let mut unsigned = value.clone();
    unsigned["signature"] = serde_json::Value::Null;
    verify_json(&unsigned, &detached).map_err(anyhow::Error::from)
}

fn supported_schema_identity(value: &serde_json::Value) -> bool {
    matches!(
        (
            value
                .get("evidence_type")
                .and_then(serde_json::Value::as_str),
            value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
        ),
        (Some("CompatibilityEvidence"), Some(1)) | (Some("PerformanceEvidence"), Some(1 | 2))
    ) || matches!(
        (
            value
                .get("evidence_class")
                .and_then(serde_json::Value::as_str),
            value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
        ),
        (Some("detection-quality"), Some(2))
            | (Some("operational-drill"), Some(2))
            | (Some("production-deployment"), Some(1))
            | (Some("transparency-checkpoint"), Some(3))
            | (Some("independent-security-audit"), Some(1))
    )
}

fn collect_environment_differences(value: &serde_json::Value, differences: &mut Vec<String>) {
    let Some(environment) = value.get("environment") else {
        return;
    };
    for (field, current) in [
        ("platform", std::env::consts::OS),
        ("architecture", std::env::consts::ARCH),
    ] {
        if let Some(recorded) = environment.get(field).and_then(serde_json::Value::as_str)
            && recorded != current
        {
            differences.push(format!("{field}: evidence={recorded}, current={current}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_directory_artifact() {
        assert!(safe_join(Path::new("/tmp/evidence"), "../secret").is_err());
    }

    #[test]
    fn recognizes_new_evidence_versions() {
        assert!(supported_schema_identity(&serde_json::json!({
            "evidence_type": "PerformanceEvidence",
            "schema_version": 2
        })));
    }
}
