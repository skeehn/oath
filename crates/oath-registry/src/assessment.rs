use crate::{hex_sha256, now};
use anyhow::{Context, Result};
use oath_analyze::{PackageScanner, RiskLevel};
use oath_contracts::{Decision, PackageIdentity, ReasonCode, RegistryVerdictV1};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, path::Path};

const MAX_ARCHIVE_ENTRIES: usize = 200_000;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryAssessmentBundle {
    pub verdict: RegistryVerdictV1,
    pub evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
}

pub fn assess_tarball(
    tarball: &[u8],
    manifest: &Value,
    name: &str,
    version: &str,
    publisher: &str,
    registry: &str,
) -> Result<RegistryAssessmentBundle> {
    let temp = tempfile::tempdir()?;
    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    let mut expanded = 0u64;
    let mut secret_findings = Vec::new();
    for (index, entry) in archive.entries()?.enumerate() {
        anyhow::ensure!(index < MAX_ARCHIVE_ENTRIES, "archive has too many entries");
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        anyhow::ensure!(
            entry_type.is_file() || entry_type.is_dir(),
            "archive contains unsupported link or special entry"
        );
        let path = entry.path()?.into_owned();
        anyhow::ensure!(
            path.starts_with("package") && !path.is_absolute(),
            "archive path is outside package root"
        );
        let size = entry.size();
        anyhow::ensure!(size <= MAX_FILE_BYTES, "archive entry exceeds size limit");
        expanded = expanded.saturating_add(size);
        anyhow::ensure!(
            expanded <= MAX_EXPANDED_BYTES,
            "archive exceeds expanded size limit"
        );

        if entry_type.is_file() {
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if sensitive_path(&lower) {
                secret_findings.push(format!("sensitive-path:{lower}"));
            }
            if size <= 2 * 1024 * 1024 {
                let mut bytes = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut bytes)?;
                if let Some(marker) = secret_marker(&bytes) {
                    secret_findings.push(format!("{marker}:{lower}"));
                }
                write_extracted(temp.path(), &path, &bytes)?;
                continue;
            }
        }
        anyhow::ensure!(
            entry.unpack_in(temp.path())?,
            "archive path escaped extraction root"
        );
    }

    secret_findings.sort();
    secret_findings.dedup();
    let package_root = temp.path().join("package");
    let report = PackageScanner::scan(name, version, &package_root)
        .context("server-side package analysis failed")?;
    let decision = if !secret_findings.is_empty() || report.overall_risk == RiskLevel::Critical {
        Decision::Deny
    } else if matches!(report.overall_risk, RiskLevel::Medium | RiskLevel::High)
        || report.capabilities.has_install_scripts
        || report.capabilities.native_addon
    {
        Decision::Review
    } else {
        Decision::Allow
    };
    let reason_code = match decision {
        Decision::Deny if !secret_findings.is_empty() => ReasonCode::RegistrySecretDetected,
        Decision::Deny => ReasonCode::RegistryCriticalBehavior,
        Decision::Review => ReasonCode::RegistryReviewRequired,
        Decision::Allow => ReasonCode::RegistryAllowed,
        Decision::Unknown => ReasonCode::RegistryUnknown,
    };
    let risk_score = if !secret_findings.is_empty() {
        100
    } else {
        match report.overall_risk {
            RiskLevel::Clean | RiskLevel::Info => 0,
            RiskLevel::Low => 20,
            RiskLevel::Medium => 50,
            RiskLevel::High => 75,
            RiskLevel::Critical => 100,
        }
    };
    let package_digest = format!("sha256:{}", hex_sha256(tarball));
    let evidence = json!({
        "schema_version": 1,
        "package_digest": package_digest,
        "manifest_digest": oath_contracts::digest_json(manifest)?,
        "risk": report.overall_risk,
        "risk_score": risk_score,
        "findings": report.findings,
        "capabilities": report.capabilities,
        "files_scanned": report.files_scanned,
        "lines_scanned": report.lines_scanned,
        "secret_findings": secret_findings,
        "expanded_bytes": expanded,
        "source_available": manifest.get("repository").is_some(),
        "scanner": format!("oath-analyze/{}", env!("CARGO_PKG_VERSION")),
    });
    let policy = json!({
        "deny_secrets": true,
        "deny_critical_behavior": true,
        "review_medium_high_hooks_native": true,
    });
    let generated_at = now();
    let sbom = server_sbom(manifest, name, version, &package_digest, generated_at);
    let provenance = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": format!("{name}@{version}"), "digest": {"sha256": package_digest.trim_start_matches("sha256:")}}],
        "predicateType": "https://oath.dev/attestation/registry-assessment/v1",
        "predicate": {
            "assessor": format!("oath-registry/{}", env!("CARGO_PKG_VERSION")),
            "publisher_organization": publisher,
            "registry": registry,
            "assessment_time": generated_at,
            "manifest_digest": evidence["manifest_digest"],
            "note": "This attests registry observation and assessment, not source-build provenance."
        }
    });
    let verdict = RegistryVerdictV1 {
        schema_version: oath_contracts::REGISTRY_VERDICT_VERSION,
        generated_at,
        expires_at: generated_at.saturating_add(24 * 3600),
        package: PackageIdentity {
            name: name.into(),
            version: version.into(),
            registry: registry.into(),
            integrity: Some(package_digest.clone()),
            publisher: Some(publisher.into()),
            publish_age_days: Some(0),
            repository: manifest
                .get("repository")
                .and_then(repository_url)
                .map(String::from),
        },
        decision,
        reason_code,
        risk_score,
        package_digest,
        assessment_digest: oath_contracts::digest_json(&evidence)?,
        policy_digest: oath_contracts::digest_json(&policy)?,
        rule_bundle_version: format!("oath-rules/{}", env!("CARGO_PKG_VERSION")),
        limitations: vec![
            "Static analysis cannot prove package safety".into(),
            "Approval and runtime containment remain required for review verdicts".into(),
        ],
        signature: None,
    };
    Ok(RegistryAssessmentBundle {
        verdict,
        evidence,
        sbom,
        provenance,
    })
}

fn server_sbom(
    manifest: &Value,
    name: &str,
    version: &str,
    package_digest: &str,
    generated_at: u64,
) -> Value {
    let created = i64::try_from(generated_at)
        .ok()
        .and_then(|timestamp| chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0))
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    let mut packages = vec![json!({
        "SPDXID": "SPDXRef-RootPackage",
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": true,
        "checksums": [{"algorithm": "SHA256", "checksumValue": package_digest.trim_start_matches("sha256:")}]
    })];
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(dependencies) = manifest.get(group).and_then(Value::as_object) {
            for (dependency, requested) in dependencies {
                packages.push(json!({
                    "SPDXID": format!("SPDXRef-Dependency-{}", dependency.replace(['@', '/'], "-")),
                    "name": dependency,
                    "versionInfo": requested.as_str().unwrap_or("NOASSERTION"),
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "primaryPackagePurpose": "LIBRARY"
                }));
            }
        }
    }
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{name}-{version}"),
        "documentNamespace": format!("https://oath.dev/spdx/{}/{}", name.replace(['@', '/'], "-"), package_digest.trim_start_matches("sha256:")),
        "creationInfo": {"created": created, "creators": [format!("Tool: oath-registry-{}", env!("CARGO_PKG_VERSION"))]},
        "packages": packages
    })
}

fn write_extracted(root: &Path, relative: &Path, bytes: &[u8]) -> Result<()> {
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(destination, bytes)?;
    Ok(())
}

fn sensitive_path(path: &str) -> bool {
    path.ends_with("/.env")
        || path.ends_with(".pem")
        || path.ends_with("id_rsa")
        || path.ends_with(".npmrc")
        || path.contains("credentials")
}

fn secret_marker(bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    [
        ("-----BEGIN PRIVATE KEY-----", "private-key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "rsa-private-key"),
        ("AKIA", "aws-access-key-id"),
        ("ghp_", "github-token"),
        ("npm_", "npm-token"),
    ]
    .into_iter()
    .find_map(|(marker, name)| text.contains(marker).then_some(name))
}

fn repository_url(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("url").and_then(Value::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, *bytes).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn server_assessment_denies_secrets() {
        let bytes = tarball(&[
            (
                "package/package.json",
                br#"{"name":"demo","version":"1.0.0"}"#,
            ),
            ("package/.env", b"TOKEN=ghp_example"),
        ]);
        let bundle = assess_tarball(
            &bytes,
            &json!({"name":"demo","version":"1.0.0"}),
            "demo",
            "1.0.0",
            "acme",
            "https://registry.example",
        )
        .unwrap();
        assert_eq!(bundle.verdict.decision, Decision::Deny);
        assert_eq!(bundle.verdict.risk_score, 100);
        assert_eq!(
            bundle.verdict.reason_code,
            ReasonCode::RegistrySecretDetected
        );
        assert_eq!(bundle.sbom["spdxVersion"], "SPDX-2.3");
        assert!(
            chrono::DateTime::parse_from_rfc3339(
                bundle.sbom["creationInfo"]["created"].as_str().unwrap()
            )
            .is_ok()
        );
        assert!(
            bundle.sbom["creationInfo"]
                .get("createdEpochSeconds")
                .is_none()
        );
        assert_eq!(
            bundle.provenance["predicateType"],
            "https://oath.dev/attestation/registry-assessment/v1"
        );
    }
}
