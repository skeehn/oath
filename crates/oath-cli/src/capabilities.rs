use anyhow::Result;
use serde::{Deserialize, Serialize};

const COMPATIBILITY_MANIFEST: &str =
    include_str!("../../../contracts/npm-compatibility-manifest-v2.json");

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub schema_version: u32,
    pub product: &'static str,
    pub version: &'static str,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub compatibility: CompatibilityCapabilities,
    pub containment: oath_sandbox::BackendCapabilities,
    pub evidence: EvidenceCapabilities,
    pub signing: SigningCapabilities,
}

#[derive(Debug, Serialize)]
pub struct CompatibilityCapabilities {
    pub target: String,
    pub manifest_version: u64,
    pub reference: serde_json::Value,
    pub qualification: serde_json::Value,
    pub command_counts: CoverageCounts,
    pub surface_counts: CoverageCounts,
    pub commands: Vec<CommandCapability>,
    pub missing_required_commands: Vec<String>,
    pub partial_required_commands: Vec<String>,
    pub unqualified_required_surfaces: Vec<String>,
    pub intentional_exceptions: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandCapability {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub replacement_required: bool,
    pub implementation: String,
    pub evidence: String,
    #[serde(default)]
    pub surfaces: Vec<SurfaceCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceCapability {
    pub id: String,
    pub implementation: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoverageCounts {
    pub total: usize,
    pub complete: usize,
    pub partial: usize,
    pub missing: usize,
    pub intentional_divergence: usize,
    pub locally_evidenced: usize,
    pub cross_platform_evidenced: usize,
    pub qualified: usize,
}

fn coverage_counts<'a>(entries: impl Iterator<Item = (&'a str, &'a str)>) -> CoverageCounts {
    let entries: Vec<_> = entries.collect();
    let implementation = |status: &str| {
        entries
            .iter()
            .filter(|(observed, _)| *observed == status)
            .count()
    };
    let evidence = |status: &str| {
        entries
            .iter()
            .filter(|(_, observed)| *observed == status)
            .count()
    };
    CoverageCounts {
        total: entries.len(),
        complete: implementation("complete"),
        partial: implementation("partial"),
        missing: implementation("missing"),
        intentional_divergence: implementation("intentional-divergence"),
        locally_evidenced: entries
            .iter()
            .filter(|(_, observed)| matches!(*observed, "local-contract" | "local-differential"))
            .count(),
        cross_platform_evidenced: evidence("cross-platform"),
        qualified: evidence("qualified"),
    }
}

#[derive(Debug, Serialize)]
pub struct EvidenceCapabilities {
    pub verify: bool,
    pub replay: bool,
    pub supported_contracts: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SigningCapabilities {
    pub detached_document_algorithm: &'static str,
    pub canonicalization: &'static str,
    pub platform_release_signing_required: bool,
    pub sigstore_provenance_required: bool,
}

pub fn report() -> Result<CapabilityReport> {
    let manifest: serde_json::Value = serde_json::from_str(COMPATIBILITY_MANIFEST)?;
    let commands: Vec<CommandCapability> = serde_json::from_value(manifest["commands"].clone())?;
    let required = commands
        .iter()
        .filter(|command| command.replacement_required);
    let missing_required_commands = required
        .clone()
        .filter(|command| command.implementation == "missing")
        .map(|command| command.name.clone())
        .collect();
    let partial_required_commands = required
        .clone()
        .filter(|command| command.implementation == "partial")
        .map(|command| command.name.clone())
        .collect();
    let unqualified_required_surfaces = required
        .flat_map(|command| command.surfaces.iter())
        .filter(|surface| surface.evidence != "qualified")
        .map(|surface| surface.id.clone())
        .collect();
    let command_counts = coverage_counts(
        commands
            .iter()
            .map(|command| (command.implementation.as_str(), command.evidence.as_str())),
    );
    let surface_counts = coverage_counts(commands.iter().flat_map(|command| {
        command
            .surfaces
            .iter()
            .map(|surface| (surface.implementation.as_str(), surface.evidence.as_str()))
    }));
    Ok(CapabilityReport {
        schema_version: 2,
        product: "oath-cli",
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        compatibility: CompatibilityCapabilities {
            target: manifest["compatibility_target"]
                .as_str()
                .unwrap_or("npm/npx")
                .to_owned(),
            manifest_version: manifest["schema_version"].as_u64().unwrap_or(1),
            reference: manifest["reference"].clone(),
            qualification: manifest["qualification"].clone(),
            command_counts,
            surface_counts,
            commands,
            missing_required_commands,
            partial_required_commands,
            unqualified_required_surfaces,
            intentional_exceptions: manifest["intentional_exceptions"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        },
        containment: oath_sandbox::verified_native_capabilities(),
        evidence: EvidenceCapabilities {
            verify: true,
            replay: true,
            supported_contracts: vec![
                "CompatibilityEvidence/v1",
                "DetectionEvidenceReport/v2",
                "PerformanceEvidence/v1",
                "PerformanceEvidence/v2",
                "OperationalDrillReport/v2",
                "ProductionDeploymentEvidence/v1",
                "TransparencyCheckpoint/v3",
                "IndependentAuditReport/v1",
            ],
        },
        signing: SigningCapabilities {
            detached_document_algorithm: "ed25519",
            canonicalization: "oath-json-v1",
            platform_release_signing_required: true,
            sigstore_provenance_required: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_exposes_complete_local_surface_and_open_qualification() {
        let report = report().unwrap();
        assert_eq!(report.schema_version, 2);
        assert_eq!(report.compatibility.manifest_version, 2);
        assert!(report.compatibility.command_counts.total >= 68);
        assert!(
            report.compatibility.surface_counts.total > report.compatibility.command_counts.total
        );
        assert!(report.compatibility.missing_required_commands.is_empty());
        assert!(report.compatibility.partial_required_commands.is_empty());
        assert!(report.compatibility.command_counts.complete >= 68);
        assert_eq!(
            report.compatibility.command_counts.intentional_divergence,
            1
        );
        assert!(
            report
                .compatibility
                .unqualified_required_surfaces
                .contains(&"install.production-omit".into())
        );
        assert_eq!(report.compatibility.command_counts.qualified, 0);
    }
}
