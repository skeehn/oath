//! Four-population detection-quality gate. Samples are scanned statically and
//! are never imported or executed.

use oath_analyze::{PackageScanner, RiskLevel};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const KNOWN_MALWARE_TARGET: f64 = 0.99;
const PRIVATE_HOLDOUT_TARGET: f64 = 0.95;
const BENIGN_FP_TARGET: f64 = 0.005;

#[derive(Debug)]
struct Arguments {
    benign: PathBuf,
    known_malware: PathBuf,
    private_holdout: PathBuf,
    secret_exfiltration: PathBuf,
    metadata: PathBuf,
    qualification: String,
}

#[derive(Debug, Serialize)]
struct SampleResult {
    sample_id: String,
    risk: RiskLevel,
    blocked: bool,
}

#[derive(Debug, Serialize)]
struct ScanError {
    sample_id: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct CorpusResult {
    corpus_digest: String,
    discovered: usize,
    scanned: usize,
    blocked: usize,
    rate: f64,
    wilson_95: ConfidenceInterval,
    results: Vec<SampleResult>,
    errors: Vec<ScanError>,
}

#[derive(Debug, Serialize)]
struct ConfidenceInterval {
    lower: f64,
    upper: f64,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut values = std::env::args().skip(1);
    let mut named = BTreeMap::new();
    while let Some(argument) = values.next() {
        if !argument.starts_with("--") {
            return Err(format!("unexpected positional argument: {argument}"));
        }
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        named.insert(argument, value);
    }
    let mut take_path = |name: &str| {
        named
            .remove(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing required argument {name}"))
    };
    let arguments = Arguments {
        benign: take_path("--benign")?,
        known_malware: take_path("--known-malware")?,
        private_holdout: take_path("--private-holdout")?,
        secret_exfiltration: take_path("--secret-exfiltration")?,
        metadata: take_path("--metadata")?,
        qualification: named
            .remove("--qualification")
            .unwrap_or_else(|| "self-test".into()),
    };
    if !named.is_empty() {
        return Err(format!(
            "unsupported arguments: {}",
            named.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if !matches!(arguments.qualification.as_str(), "self-test" | "qualifying") {
        return Err("--qualification must be self-test or qualifying".into());
    }
    Ok(arguments)
}

fn find_package_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut has_package = false;
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() && entry.file_name() == "package.json" {
            has_package = true;
        } else if file_type.is_dir() && entry.file_name() != "node_modules" {
            directories.push(entry.path());
        }
    }
    if has_package {
        out.push(root.to_path_buf());
    }
    directories.sort();
    for directory in directories {
        find_package_dirs(&directory, out);
    }
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn digest_corpus(root: &Path) -> Result<String, String> {
    let mut files = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "node_modules")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&path).map_err(|error| format!("{relative}: {error}"))?;
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn wilson(successes: usize, total: usize) -> ConfidenceInterval {
    if total == 0 {
        return ConfidenceInterval {
            lower: 0.0,
            upper: 1.0,
        };
    }
    let z = 1.959_963_984_540_054_f64;
    let n = total as f64;
    let p = successes as f64 / n;
    let denominator = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denominator;
    let margin = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ConfidenceInterval {
        lower: (center - margin).max(0.0),
        upper: (center + margin).min(1.0),
    }
}

fn scan_corpus(root: &Path) -> Result<CorpusResult, String> {
    let mut directories = Vec::new();
    find_package_dirs(root, &mut directories);
    directories.sort();
    let mut results = Vec::new();
    let mut errors = Vec::new();
    for directory in &directories {
        let relative = directory
            .strip_prefix(root)
            .unwrap_or(directory)
            .to_string_lossy()
            .replace('\\', "/");
        let sample_id = digest_hex(relative.as_bytes());
        match PackageScanner::scan(&sample_id, "0.0.0", directory) {
            Ok(report) => {
                let blocked = report.overall_risk >= RiskLevel::High;
                results.push(SampleResult {
                    sample_id,
                    risk: report.overall_risk,
                    blocked,
                });
            }
            Err(error) => errors.push(ScanError {
                sample_id,
                error: error.to_string(),
            }),
        }
    }
    let blocked = results.iter().filter(|result| result.blocked).count();
    let scanned = results.len();
    Ok(CorpusResult {
        corpus_digest: digest_corpus(root)?,
        discovered: directories.len(),
        scanned,
        blocked,
        rate: blocked as f64 / scanned.max(1) as f64,
        wilson_95: wilson(blocked, scanned),
        results,
        errors,
    })
}

fn nonempty_string(value: &serde_json::Value, pointer: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn validate_metadata(metadata: &serde_json::Value) -> Vec<String> {
    let mut errors = Vec::new();
    if metadata
        .get("schema_version")
        .and_then(|value| value.as_u64())
        != Some(1)
    {
        errors.push("schema_version must equal 1".into());
    }
    for pointer in ["/evidence_id", "/source_commit", "/captured_at"] {
        if !nonempty_string(metadata, pointer) {
            errors.push(format!("{pointer} must be a non-empty string"));
        }
    }
    if metadata
        .get("evidence_scope")
        .and_then(serde_json::Value::as_str)
        != Some("qualifying")
    {
        errors.push("evidence_scope must equal qualifying".into());
    }
    if metadata
        .get("source_commit")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.chars().all(|character| character == '0'))
    {
        errors.push("source_commit cannot be the all-zero self-test value".into());
    }
    for corpus in [
        "benign",
        "known_malware",
        "private_holdout",
        "secret_exfiltration",
    ] {
        for field in ["dataset_id", "dataset_version", "selection_policy"] {
            let pointer = format!("/corpora/{corpus}/{field}");
            if !nonempty_string(metadata, &pointer) {
                errors.push(format!("{pointer} must be a non-empty string"));
            }
        }
        let exclusions = format!("/corpora/{corpus}/exclusions");
        if !metadata
            .pointer(&exclusions)
            .is_some_and(serde_json::Value::is_array)
        {
            errors.push(format!("{exclusions} must be an array"));
        }
    }
    for pointer in [
        "/corpora/private_holdout/family_separated",
        "/corpora/private_holdout/time_separated",
        "/corpora/private_holdout/labels_independently_held",
    ] {
        if metadata.pointer(pointer).and_then(|value| value.as_bool()) != Some(true) {
            errors.push(format!("{pointer} must be true for qualifying evidence"));
        }
    }
    errors
}

fn corpus_complete(corpus: &CorpusResult) -> bool {
    corpus.discovered > 0 && corpus.discovered == corpus.scanned && corpus.errors.is_empty()
}

fn corpus_evidence(
    corpus: &CorpusResult,
    metadata: &serde_json::Value,
    name: &str,
) -> serde_json::Value {
    let metadata = metadata
        .pointer(&format!("/corpora/{name}"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut value = serde_json::json!({
        "dataset_digest": format!("sha256:{}", corpus.corpus_digest),
        "discovered": corpus.discovered,
        "scanned": corpus.scanned,
        "blocked": corpus.blocked,
        "rate": corpus.rate,
        "wilson_95": corpus.wilson_95,
        "results": corpus.results,
        "scan_errors": corpus.errors,
        "exclusions": metadata.get("exclusions").cloned().unwrap_or_else(|| serde_json::json!([])),
    });
    if name == "private_holdout" {
        let object = value.as_object_mut().expect("corpus evidence is an object");
        for field in [
            "family_separated",
            "time_separated",
            "labels_independently_held",
        ] {
            object.insert(
                field.into(),
                metadata
                    .get(field)
                    .cloned()
                    .unwrap_or(serde_json::Value::Bool(false)),
            );
        }
    }
    value
}

fn main() {
    let arguments = parse_arguments().unwrap_or_else(|error| {
        eprintln!("{error}");
        eprintln!(
            "usage: detection_gate --benign DIR --known-malware DIR --private-holdout DIR --secret-exfiltration DIR --metadata FILE [--qualification self-test|qualifying]"
        );
        std::process::exit(2);
    });
    let metadata_bytes = std::fs::read(&arguments.metadata).unwrap_or_else(|error| {
        eprintln!("failed to read {}: {error}", arguments.metadata.display());
        std::process::exit(2);
    });
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata_bytes).unwrap_or_else(|error| {
            eprintln!("invalid metadata JSON: {error}");
            std::process::exit(2);
        });
    let metadata_errors = validate_metadata(&metadata);
    let benign = scan_or_exit(&arguments.benign);
    let known = scan_or_exit(&arguments.known_malware);
    let holdout = scan_or_exit(&arguments.private_holdout);
    let exfiltration = scan_or_exit(&arguments.secret_exfiltration);

    let measurements_pass = corpus_complete(&benign)
        && corpus_complete(&known)
        && corpus_complete(&holdout)
        && corpus_complete(&exfiltration)
        && benign.rate <= BENIGN_FP_TARGET
        && known.rate >= KNOWN_MALWARE_TARGET
        && holdout.rate >= PRIVATE_HOLDOUT_TARGET
        && exfiltration.blocked == exfiltration.scanned;
    let qualifying = arguments.qualification == "qualifying";
    let qualifies_for_ga = measurements_pass && qualifying && metadata_errors.is_empty();
    let release_commit = metadata
        .get("source_commit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0000000000000000000000000000000000000000");
    let generated_at = metadata
        .get("captured_at")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z");
    let output = serde_json::json!({
        "schema_version": 2,
        "evidence_class": "detection-quality",
        "qualification": arguments.qualification,
        "release_commit": release_commit,
        "generated_at": generated_at,
        "engine": {
            "version": env!("CARGO_PKG_VERSION"),
            "rule_bundle_digest": format!("sha256:{}", digest_hex(include_bytes!("../src/patterns.rs"))),
            "known_malware_feed_digest": format!("sha256:{}", known.corpus_digest),
        },
        "corpora": {
            "benign": corpus_evidence(&benign, &metadata, "benign"),
            "known_malware": corpus_evidence(&known, &metadata, "known_malware"),
            "private_holdout": corpus_evidence(&holdout, &metadata, "private_holdout"),
            "secret_exfiltration": corpus_evidence(&exfiltration, &metadata, "secret_exfiltration"),
        },
        "thresholds": {
            "known_malware_recall": KNOWN_MALWARE_TARGET,
            "private_holdout_recall": PRIVATE_HOLDOUT_TARGET,
            "benign_false_positive_rate": BENIGN_FP_TARGET,
            "secret_exfiltration_block_rate": 1.0,
        },
        "measurements_pass": measurements_pass,
        "qualifies_for_ga": qualifies_for_ga,
        "errors": metadata_errors,
        "limitations": [
            "Static and structural analysis does not prove a package safe; containment and registry evidence are evaluated separately."
        ]
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    let passes_selected_mode = if qualifying {
        qualifies_for_ga
    } else {
        measurements_pass
    };
    if !passes_selected_mode {
        std::process::exit(1);
    }
}

fn fatal(error: String) -> ! {
    eprintln!("detection gate failed: {error}");
    std::process::exit(2);
}

fn scan_or_exit(root: &Path) -> CorpusResult {
    match scan_corpus(root) {
        Ok(result) => result,
        Err(error) => fatal(error),
    }
}
