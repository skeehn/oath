use anyhow::{Context, Result};
use oath_resolve::placement::PlacementPlan;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "install-state-v1.json";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct InstallState {
    schema_version: u32,
    oath_version: String,
    platform: String,
    architecture: String,
    package_json_sha256: String,
    lockfile_sha256: String,
    placement_plan_sha256: String,
    node_modules_tree_sha256: String,
    policy_sha256: String,
    audit_enabled: bool,
    lifecycle_mode: String,
}

pub fn is_current(
    root: &Path,
    audit_enabled: bool,
    ignore_scripts: bool,
    run_scripts: bool,
    yes: bool,
) -> Result<bool> {
    let state_path = root.join(".oath").join(STATE_FILE);
    let state: InstallState = match std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(state) => state,
        None => return Ok(false),
    };
    let expected = capture(root, audit_enabled, ignore_scripts, run_scripts, yes)?;
    if state != expected {
        return Ok(false);
    }
    validate_placements(root)
}

pub fn write(
    root: &Path,
    audit_enabled: bool,
    ignore_scripts: bool,
    run_scripts: bool,
    yes: bool,
) -> Result<()> {
    let state = capture(root, audit_enabled, ignore_scripts, run_scripts, yes)?;
    let oath_dir = root.join(".oath");
    std::fs::create_dir_all(&oath_dir).context("create project Oath state directory")?;
    let target = oath_dir.join(STATE_FILE);
    let temporary = oath_dir.join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, serde_json::to_vec_pretty(&state)?)
        .context("write temporary install state")?;
    std::fs::rename(&temporary, &target).context("commit install state")?;
    Ok(())
}

fn capture(
    root: &Path,
    audit_enabled: bool,
    ignore_scripts: bool,
    run_scripts: bool,
    yes: bool,
) -> Result<InstallState> {
    Ok(InstallState {
        schema_version: 1,
        oath_version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        package_json_sha256: hash_required(&root.join("package.json"))?,
        lockfile_sha256: hash_required(&root.join("oath-lock.json"))?,
        placement_plan_sha256: hash_required(&root.join(".oath/placement-plan.json"))?,
        node_modules_tree_sha256: tree_structure_digest(&root.join("node_modules"))?,
        policy_sha256: policy_digest(root)?,
        audit_enabled,
        lifecycle_mode: if ignore_scripts {
            "ignored"
        } else if yes {
            "approved"
        } else if run_scripts {
            "prompted"
        } else {
            "blocked"
        }
        .to_owned(),
    })
}

fn validate_placements(root: &Path) -> Result<bool> {
    let plan = PlacementPlan::read(&root.join(".oath/placement-plan.json"))?;
    for node in plan.nodes {
        let installed = root.join(&node.location);
        if node.link {
            if std::fs::symlink_metadata(installed).is_err() {
                return Ok(false);
            }
            continue;
        }
        let manifest: serde_json::Value = match std::fs::read(installed.join("package.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(manifest) => manifest,
            None => return Ok(false),
        };
        if manifest["name"].as_str() != Some(&node.name)
            || manifest["version"].as_str() != Some(&node.version)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn policy_digest(root: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    for path in [
        Some(root.join("oath-policy.toml")),
        oath_core::home_dir().map(|home| home.join(".oath/policy.toml")),
    ]
    .into_iter()
    .flatten()
    {
        digest.update(path.to_string_lossy().as_bytes());
        digest.update([0]);
        if path.is_file() {
            digest.update(std::fs::read(path)?);
        }
        digest.update([0xff]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn hash_required(path: &PathBuf) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn tree_structure_digest(root: &Path) -> Result<String> {
    fn collect(
        root: &Path,
        directory: &Path,
        entries: &mut Vec<(String, u8, String)>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            if metadata.file_type().is_symlink() {
                entries.push((
                    relative,
                    b'l',
                    std::fs::read_link(&path)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                ));
            } else if metadata.is_dir() {
                entries.push((relative, b'd', String::new()));
                collect(root, &path, entries)?;
            } else if metadata.is_file() {
                let content_digest = hex::encode(Sha256::digest(std::fs::read(&path)?));
                entries.push((relative, b'f', content_digest));
            }
        }
        Ok(())
    }

    anyhow::ensure!(root.is_dir(), "node_modules is missing");
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort();
    let mut digest = Sha256::new();
    for (path, kind, target) in entries {
        digest.update(path.as_bytes());
        digest.update([0, kind, 0]);
        digest.update(target.as_bytes());
        digest.update([0xff]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_not_current() {
        let root = tempfile::tempdir().unwrap();
        assert!(!is_current(root.path(), true, true, false, false).unwrap());
    }

    #[test]
    fn tree_digest_detects_content_tampering() {
        let root = tempfile::tempdir().unwrap();
        let modules = root.path().join("node_modules/example");
        std::fs::create_dir_all(&modules).unwrap();
        let file = modules.join("index.js");
        std::fs::write(&file, "safe").unwrap();
        let before = tree_structure_digest(&root.path().join("node_modules")).unwrap();
        std::fs::write(&file, "evil").unwrap();
        let after = tree_structure_digest(&root.path().join("node_modules")).unwrap();
        assert_ne!(before, after);
    }
}
