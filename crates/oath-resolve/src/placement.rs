use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::Path;

use crate::graph::{DepGraph, DepNode};

pub const PLACEMENT_PLAN_VERSION: u32 = 2;
const PLANNER: &str = include_str!("arborist-plan.cjs");
const QUERY: &str = include_str!("arborist-query.cjs");
const NPM_REFERENCE_VERSION: &str = "11.12.1";
const ARBORIST_VERSION: &str = "9.4.2";
const INSTALL_CHECKS_VERSION: &str = "8.0.0";
const PACKLIST_VERSION: &str = "10.0.4";
const NPM_RUNTIME: &[u8] = include_bytes!("../vendor/npm-11.12.1.tgz");
const NPM_RUNTIME_SHA256: &str = "e679850e663b16f5f146ee425d0eb0e3442c1d2bda3d513bbfd7c81f5ee5db38";
const NPM_RUNTIME_TREE_SHA256: &str =
    "c2edcae26e1e00752863da3f86a991acf9129771ecb13b2d4fadadfc65eb6254";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPlan {
    pub schema_version: u32,
    pub planner: PlannerIdentity,
    pub project: String,
    pub nodes: Vec<PlacementNode>,
    #[serde(default)]
    pub removed_locations: Vec<String>,
    pub invalid_edges: Vec<PlacementEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerIdentity {
    pub name: String,
    pub npm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementNode {
    pub location: String,
    pub install_name: String,
    pub name: String,
    pub version: String,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
    pub dev: bool,
    pub optional: bool,
    #[serde(default)]
    pub peer: bool,
    pub has_install_script: bool,
    #[serde(default)]
    pub reuse_existing: bool,
    pub link: bool,
    pub target: Option<String>,
    pub edges: Vec<PlacementEdge>,
}

impl PlacementPlan {
    /// Convert Arborist's location-aware ideal tree into the package graph used
    /// by Oath's fetch, integrity, scanning, lockfile, and lifecycle pipeline.
    /// Node keys intentionally remain exact locations: version-only keys cannot
    /// represent two copies of the same package at different peer contexts.
    pub fn to_dep_graph(&self) -> Result<DepGraph> {
        let mut graph = DepGraph::new();

        for node in &self.nodes {
            if node.link {
                continue;
            }
            let resolved = node
                .resolved
                .clone()
                .with_context(|| format!("Arborist omitted resolved URL for {}", node.location))?;
            let dependencies = node
                .edges
                .iter()
                .filter(|edge| !edge.dependency_type.starts_with("peer"))
                .filter_map(|edge| {
                    edge.target_location
                        .as_ref()
                        .map(|target| (edge.name.clone(), target.clone()))
                })
                .collect();
            let peer_dependencies = node
                .edges
                .iter()
                .filter(|edge| edge.dependency_type.starts_with("peer"))
                .map(|edge| (edge.name.clone(), edge.spec.clone()))
                .collect();
            let optional_peers = node
                .edges
                .iter()
                .filter(|edge| edge.dependency_type == "peerOptional")
                .map(|edge| edge.name.clone())
                .collect();
            let resolved_peers = node
                .edges
                .iter()
                .filter(|edge| edge.dependency_type.starts_with("peer"))
                .filter_map(|edge| {
                    edge.target_location
                        .as_ref()
                        .map(|target| (edge.name.clone(), target.clone()))
                })
                .collect();

            graph.nodes.insert(
                node.location.clone(),
                DepNode {
                    name: node.name.clone(),
                    alias: (node.install_name != node.name).then(|| node.install_name.clone()),
                    version: node.version.clone(),
                    resolved,
                    integrity: node.integrity.clone(),
                    dependencies,
                    has_install_script: node.has_install_script,
                    dev: node.dev,
                    optional: node.optional,
                    peer_dependencies,
                    optional_peers,
                    resolved_peers,
                },
            );
        }

        graph.roots = self
            .nodes
            .iter()
            .filter(|node| !node.link && is_root_location(&node.location))
            .map(|node| node.location.clone())
            .collect();
        Ok(graph)
    }
}

fn is_root_location(location: &str) -> bool {
    location
        .strip_prefix("node_modules/")
        .is_some_and(|rest| !rest.contains("/node_modules/"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementEdge {
    pub name: String,
    pub spec: String,
    #[serde(rename = "type")]
    pub dependency_type: String,
    pub target_location: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlacementRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rm: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspaces: Vec<String>,
    #[serde(default)]
    pub prefer_dedupe: bool,
}

impl PlacementRequest {
    pub fn add(specs: Vec<String>, dev: bool) -> Self {
        Self {
            add: specs,
            save_type: dev.then(|| "dev".to_string()),
            ..Self::default()
        }
    }

    pub fn remove(names: Vec<String>) -> Self {
        Self {
            rm: names,
            ..Self::default()
        }
    }

    pub fn update(names: Vec<String>) -> Self {
        Self {
            update: Some(if names.is_empty() {
                serde_json::Value::Bool(true)
            } else {
                serde_json::to_value(names).expect("string list serializes")
            }),
            ..Self::default()
        }
    }
}

pub struct ArboristPlanner;

#[cfg(target_os = "windows")]
fn node_process_path(path: &Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{unc}"));
    }
    text.strip_prefix(r"\\?\")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(not(target_os = "windows"))]
fn node_process_path(path: &Path) -> std::path::PathBuf {
    path.to_path_buf()
}

impl ArboristPlanner {
    pub fn plan(project: &Path) -> Result<PlacementPlan> {
        Self::plan_with(project, &PlacementRequest::default())
    }

    pub fn plan_with(project: &Path, request: &PlacementRequest) -> Result<PlacementPlan> {
        let runtime = BundledRuntime::cached()?;
        let script = tempfile::NamedTempFile::new().context("create Arborist planner script")?;
        std::fs::write(script.path(), PLANNER)?;
        let project_argument = node_process_path(project);
        let output = std::process::Command::new("node")
            .arg(script.path())
            .arg(project_argument)
            .arg(serde_json::to_string(request)?)
            .env("OATH_ARBORIST_PATH", runtime.arborist_path())
            .env("OATH_INSTALL_CHECKS_PATH", runtime.install_checks_path())
            .env("OATH_NPM_REFERENCE_VERSION", NPM_REFERENCE_VERSION)
            .output()
            .context("launch Arborist planner")?;
        anyhow::ensure!(
            output.status.success(),
            "Arborist planning failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut plan: PlacementPlan =
            serde_json::from_slice(&output.stdout).context("decode Arborist placement plan")?;
        anyhow::ensure!(
            plan.schema_version == PLACEMENT_PLAN_VERSION,
            "unsupported placement plan version {}",
            plan.schema_version
        );
        hydrate_from_persisted_plan(project, &mut plan);
        validate_locations(&plan)?;
        Ok(plan)
    }

    /// Evaluate npm's complete dependency-selector language against Oath's
    /// materialized tree using the integrity-pinned Arborist runtime.
    pub fn query(project: &Path, selector: &str) -> Result<serde_json::Value> {
        let runtime = BundledRuntime::cached()?;
        let script = tempfile::NamedTempFile::new().context("create Arborist query script")?;
        std::fs::write(script.path(), QUERY)?;
        let output = std::process::Command::new("node")
            .arg(script.path())
            .arg(node_process_path(project))
            .arg(selector)
            .env("OATH_ARBORIST_PATH", runtime.arborist_path())
            .output()
            .context("launch Arborist dependency query")?;
        anyhow::ensure!(
            output.status.success(),
            "dependency query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).context("decode Arborist query result")
    }
}

/// Return the exact relative file list npm would place in a package tarball.
/// Git dependencies must be packed from this list rather than from the entire
/// repository checkout, otherwise editor config, tests, and ignored source can
/// leak into node_modules and into Oath's assessment surface.
pub(crate) fn npm_packlist(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    const SCRIPT: &str = r#"'use strict'
const Arborist = require(process.argv[3])
const packlist = require(process.argv[4])
async function main () {
  const root = process.argv[2]
  const tree = await new Arborist({ path: root }).loadActual()
  const files = await packlist(tree)
  process.stdout.write(JSON.stringify(files.sort()))
}
main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1 })
"#;

    let runtime = BundledRuntime::cached()?;
    let script = tempfile::NamedTempFile::new().context("create npm packlist script")?;
    std::fs::write(script.path(), SCRIPT)?;
    let root_argument = node_process_path(root);
    let output = std::process::Command::new("node")
        .arg(script.path())
        .arg(root_argument)
        .arg(runtime.arborist_path())
        .arg(runtime.packlist_path())
        .output()
        .context("launch pinned npm packlist")?;
    anyhow::ensure!(
        output.status.success(),
        "npm packlist failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files: Vec<std::path::PathBuf> =
        serde_json::from_slice(&output.stdout).context("decode npm packlist")?;
    for file in &files {
        anyhow::ensure!(!file.is_absolute(), "absolute npm packlist path rejected");
        anyhow::ensure!(
            file.components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
            "unsafe npm packlist path rejected: {}",
            file.display()
        );
    }
    Ok(files)
}

fn hydrate_from_persisted_plan(project: &Path, plan: &mut PlacementPlan) {
    let path = project.join(".oath").join("placement-plan.json");
    let Ok(previous) = PlacementPlan::read(&path) else {
        return;
    };
    let previous_by_location: std::collections::HashMap<_, _> = previous
        .nodes
        .into_iter()
        .map(|node| (node.location.clone(), node))
        .collect();
    for node in &mut plan.nodes {
        let Some(old) = previous_by_location.get(&node.location) else {
            continue;
        };
        if old.name != node.name || old.version != node.version {
            continue;
        }
        if node.resolved.is_none() {
            node.resolved.clone_from(&old.resolved);
        }
        if node.integrity.is_none() {
            node.integrity.clone_from(&old.integrity);
        }
    }
}

struct BundledRuntime {
    package_root: std::path::PathBuf,
}

/// Return the pinned npm CLI entrypoint used by Oath's compatibility adapters.
/// The runtime is content-addressed and integrity-verified before this path is returned.
pub fn pinned_npm_cli_path() -> Result<std::path::PathBuf> {
    let runtime = BundledRuntime::cached()?;
    let path = runtime.package_root.join("bin").join("npm-cli.js");
    anyhow::ensure!(path.is_file(), "pinned npm CLI entrypoint is missing");
    Ok(path)
}

/// Return integrity-verified npm library entrypoints used for Sigstore
/// provenance generation and npm package-URL normalization.
pub fn pinned_npm_provenance_paths() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let runtime = BundledRuntime::cached()?;
    let provenance = runtime
        .package_root
        .join("node_modules/libnpmpublish/lib/provenance.js");
    let package_arg = runtime.package_root.join("node_modules/npm-package-arg");
    anyhow::ensure!(
        provenance.is_file(),
        "pinned npm provenance module is missing"
    );
    anyhow::ensure!(
        package_arg.is_dir(),
        "pinned npm package-arg module is missing"
    );
    Ok((provenance, package_arg))
}

/// Probe once per process whether a usable `node` is on PATH. Windows binary
/// linking shells out to node per binary, so fail fast with a clear message
/// instead of a cryptic per-binary spawn error.
#[cfg(windows)]
fn node_available() -> bool {
    static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

/// Create npm-compatible package executable links. Windows requires cmd-shim
/// wrappers rather than privileged file symlinks.
pub fn link_package_binary(from: &Path, to: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(from, to)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        anyhow::ensure!(
            node_available(),
            "node is required on PATH to create Windows command shims"
        );
        let runtime = BundledRuntime::cached()?;
        let cmd_shim = runtime.package_root.join("node_modules/cmd-shim");
        anyhow::ensure!(cmd_shim.is_dir(), "pinned npm cmd-shim module is missing");
        let source = if from.is_absolute() {
            from.to_path_buf()
        } else {
            to.parent().context("binary link has no parent")?.join(from)
        };
        let output = std::process::Command::new("node")
            .args([
                "-e",
                "require(process.argv[1])(process.argv[2], process.argv[3]).catch(e=>{console.error(e.stack||e);process.exit(1)})",
            ])
            .arg(cmd_shim)
            .arg(source)
            .arg(to)
            .output()
            .context("launch npm cmd-shim")?;
        anyhow::ensure!(
            output.status.success(),
            "npm cmd-shim failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}

impl BundledRuntime {
    /// Process-cached extraction. The bundled runtime is content-addressed and
    /// immutable, so hashing and verifying it once per process is sufficient;
    /// callers must not re-extract per package or per binary.
    fn cached() -> Result<&'static Self> {
        static CACHED: std::sync::OnceLock<Result<BundledRuntime, String>> =
            std::sync::OnceLock::new();
        let cached = CACHED.get_or_init(|| Self::extract().map_err(|error| format!("{error:#}")));
        cached
            .as_ref()
            .map_err(|error| anyhow::anyhow!("bundled npm runtime: {error}"))
    }

    fn extract() -> Result<Self> {
        let digest = Sha256::digest(NPM_RUNTIME);
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        anyhow::ensure!(
            actual == NPM_RUNTIME_SHA256,
            "bundled npm runtime checksum mismatch"
        );
        let cache_root = std::env::var_os("OATH_RUNTIME_CACHE_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("OATH_HOME").map(std::path::PathBuf::from))
            .or_else(|| oath_core::home_dir().map(|home| home.join(".oath")))
            .context("HOME, USERPROFILE, OATH_HOME, or OATH_RUNTIME_CACHE_DIR must be set")?
            .join("runtime");
        Self::extract_at(&cache_root)
    }

    fn extract_at(cache_root: &Path) -> Result<Self> {
        let runtime_root = cache_root.join(format!("npm-{NPM_RUNTIME_SHA256}"));
        let package_root = runtime_root.join("package");
        if verify_runtime_tree(&package_root).is_ok() {
            return Ok(Self { package_root });
        }

        std::fs::create_dir_all(cache_root).context("create pinned npm runtime cache")?;
        let lock_path = cache_root.join(format!("npm-{NPM_RUNTIME_SHA256}.lock"));
        let _lock = RuntimeCacheLock::acquire(&lock_path, &package_root)?;
        if verify_runtime_tree(&package_root).is_ok() {
            return Ok(Self { package_root });
        }
        if runtime_root.exists() {
            std::fs::remove_dir_all(&runtime_root)
                .context("remove corrupt pinned npm runtime cache")?;
        }
        let temp = tempfile::Builder::new()
            .prefix("npm-runtime-")
            .tempdir_in(cache_root)
            .context("create pinned npm runtime staging directory")?;
        tar::Archive::new(GzDecoder::new(Cursor::new(NPM_RUNTIME)))
            .unpack(temp.path())
            .context("extract bundled npm runtime")?;
        let staged_package = temp.path().join("package");
        verify_runtime_tree(&staged_package)?;
        verify_runtime_package(
            &staged_package.join("node_modules/@npmcli/arborist/package.json"),
            "@npmcli/arborist",
            ARBORIST_VERSION,
        )?;
        verify_runtime_package(
            &staged_package.join("node_modules/npm-install-checks/package.json"),
            "npm-install-checks",
            INSTALL_CHECKS_VERSION,
        )?;
        verify_runtime_package(
            &staged_package.join("node_modules/npm-packlist/package.json"),
            "npm-packlist",
            PACKLIST_VERSION,
        )?;
        let staged_root = temp.keep();
        std::fs::rename(&staged_root, &runtime_root).with_context(|| {
            format!(
                "commit pinned npm runtime cache {} -> {}",
                staged_root.display(),
                runtime_root.display()
            )
        })?;
        Ok(Self { package_root })
    }

    fn arborist_path(&self) -> std::path::PathBuf {
        self.package_root.join("node_modules/@npmcli/arborist")
    }

    fn install_checks_path(&self) -> std::path::PathBuf {
        self.package_root.join("node_modules/npm-install-checks")
    }

    fn packlist_path(&self) -> std::path::PathBuf {
        self.package_root.join("node_modules/npm-packlist")
    }
}

struct RuntimeCacheLock {
    path: std::path::PathBuf,
}

impl RuntimeCacheLock {
    fn acquire(path: &Path, package_root: &Path) -> Result<Self> {
        use std::io::ErrorKind;
        for _ in 0..400 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if verify_runtime_tree(package_root).is_ok() {
                        return Ok(Self {
                            path: std::path::PathBuf::new(),
                        });
                    }
                    let stale = std::fs::metadata(path)
                        .and_then(|metadata| metadata.modified())
                        .ok()
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > 60);
                    if stale {
                        let _ = std::fs::remove_file(path);
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                }
                Err(error) => return Err(error).context("acquire pinned npm runtime cache lock"),
            }
        }
        anyhow::bail!("timed out waiting for pinned npm runtime cache lock")
    }
}

impl Drop for RuntimeCacheLock {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn verify_runtime_tree(root: &Path) -> Result<()> {
    fn collect(root: &Path, directory: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata.is_file() {
                files.push(path.strip_prefix(root)?.to_path_buf());
            } else if metadata.is_dir() {
                collect(root, &path, files)?;
            }
        }
        Ok(())
    }

    anyhow::ensure!(root.is_dir(), "pinned npm runtime cache is missing");
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort_by(|left, right| {
        left.to_string_lossy()
            .replace('\\', "/")
            .cmp(&right.to_string_lossy().replace('\\', "/"))
    });
    let mut digest = Sha256::new();
    for relative in files {
        let portable = relative.to_string_lossy().replace('\\', "/");
        digest.update(portable.as_bytes());
        digest.update([0]);
        let path = root.join(&relative);
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            digest.update(b"l\0");
            digest.update(std::fs::read_link(&path)?.to_string_lossy().as_bytes());
        } else {
            digest.update(b"f\0");
            digest.update(std::fs::read(&path)?);
        }
        digest.update([0xff]);
    }
    let actual = hex::encode(digest.finalize());
    anyhow::ensure!(
        actual == NPM_RUNTIME_TREE_SHA256,
        "pinned npm runtime cache checksum mismatch"
    );
    Ok(())
}

fn verify_runtime_package(path: &Path, name: &str, expected_version: &str) -> Result<()> {
    let package: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read bundled runtime {}", path.display()))?,
    )?;
    anyhow::ensure!(package["name"] == name, "bundled runtime package mismatch");
    anyhow::ensure!(
        package["version"] == expected_version,
        "bundled {name} version mismatch"
    );
    Ok(())
}

impl PlacementPlan {
    pub fn read(path: &Path) -> Result<Self> {
        let plan: Self = serde_json::from_slice(&std::fs::read(path)?)
            .with_context(|| format!("decode placement plan {}", path.display()))?;
        anyhow::ensure!(
            plan.schema_version == PLACEMENT_PLAN_VERSION,
            "unsupported placement plan version {}",
            plan.schema_version
        );
        validate_locations(&plan)?;
        Ok(plan)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("write placement plan {}", path.display()))
    }
}

fn validate_locations(plan: &PlacementPlan) -> Result<()> {
    for node in &plan.nodes {
        let location = Path::new(&node.location);
        anyhow::ensure!(
            !location.is_absolute(),
            "absolute placement path rejected: {}",
            node.location
        );
        anyhow::ensure!(
            location
                .components()
                .all(|part| !matches!(part, std::path::Component::ParentDir)),
            "placement traversal rejected: {}",
            node.location
        );
        anyhow::ensure!(
            node.location.starts_with("node_modules/"),
            "placement outside node_modules rejected: {}",
            node.location
        );
    }
    for removed in &plan.removed_locations {
        let location = Path::new(removed);
        anyhow::ensure!(
            !location.is_absolute(),
            "absolute removal path rejected: {removed}"
        );
        anyhow::ensure!(
            location
                .components()
                .all(|part| !matches!(part, std::path::Component::ParentDir)),
            "removal traversal rejected: {removed}"
        );
        anyhow::ensure!(
            removed.starts_with("node_modules/"),
            "removal outside node_modules rejected: {removed}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal_locations() {
        let plan = PlacementPlan {
            schema_version: PLACEMENT_PLAN_VERSION,
            planner: PlannerIdentity {
                name: "test".into(),
                npm: "11".into(),
            },
            project: ".".into(),
            nodes: vec![PlacementNode {
                location: "node_modules/../escape".into(),
                install_name: "bad".into(),
                name: "bad".into(),
                version: "1.0.0".into(),
                resolved: None,
                integrity: None,
                dev: false,
                optional: false,
                peer: false,
                has_install_script: false,
                reuse_existing: false,
                link: false,
                target: None,
                edges: vec![],
            }],
            removed_locations: vec![],
            invalid_edges: vec![],
        };
        assert!(validate_locations(&plan).is_err());
    }

    #[test]
    fn preserves_location_identity_in_dependency_graph() {
        let plan: PlacementPlan = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "planner": {"name": "test", "npm": "11"},
            "project": ".",
            "invalid_edges": [],
            "nodes": [
                {"location":"node_modules/a","install_name":"a","name":"a","version":"1.0.0","resolved":"https://example/a.tgz","integrity":null,"dev":false,"optional":false,"has_install_script":false,"link":false,"target":null,"edges":[{"name":"b","spec":"^1","type":"prod","target_location":"node_modules/a/node_modules/b","valid":true}]},
                {"location":"node_modules/a/node_modules/b","install_name":"b","name":"b","version":"1.0.0","resolved":"https://example/b.tgz","integrity":null,"dev":false,"optional":false,"has_install_script":false,"link":false,"target":null,"edges":[]}
            ]
        })).unwrap();
        let graph = plan.to_dep_graph().unwrap();
        assert_eq!(graph.roots, vec!["node_modules/a"]);
        assert_eq!(
            graph.nodes["node_modules/a"].dependencies["b"],
            "node_modules/a/node_modules/b"
        );
    }

    #[test]
    fn bundled_planner_runs_without_host_npm_modules() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"empty","version":"1.0.0","private":true}"#,
        )
        .unwrap();
        let plan = ArboristPlanner::plan(project.path()).unwrap();
        assert_eq!(plan.planner.name, "@npmcli/arborist");
        assert_eq!(plan.planner.npm, NPM_REFERENCE_VERSION);
        assert!(plan.nodes.is_empty());
    }

    #[test]
    fn bundled_packlist_obeys_npm_files_field() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("lib")).unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"packed","version":"1.0.0","files":["lib"]}"#,
        )
        .unwrap();
        std::fs::write(project.path().join("lib/index.js"), "module.exports = 1").unwrap();
        std::fs::write(project.path().join("secret.txt"), "do not publish").unwrap();

        let files = npm_packlist(project.path()).unwrap();
        assert!(files.contains(&std::path::PathBuf::from("package.json")));
        assert!(files.contains(&std::path::PathBuf::from("lib/index.js")));
        assert!(!files.contains(&std::path::PathBuf::from("secret.txt")));
    }

    #[test]
    fn bundled_planner_uses_npm_default_for_local_directory_links() {
        let project = tempfile::tempdir().unwrap();
        let local = project.path().join("local");
        std::fs::create_dir(&local).unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"root","version":"1.0.0","dependencies":{"local":"file:./local"}}"#,
        )
        .unwrap();
        std::fs::write(
            local.join("package.json"),
            r#"{"name":"local","version":"1.0.0"}"#,
        )
        .unwrap();
        let plan = ArboristPlanner::plan(project.path()).unwrap();
        let local_node = plan
            .nodes
            .iter()
            .find(|node| node.location == "node_modules/local")
            .unwrap();
        assert!(local_node.link);
        let planned_target = std::path::PathBuf::from(local_node.target.as_ref().unwrap());
        assert_eq!(
            planned_target.canonicalize().unwrap(),
            local.canonicalize().unwrap()
        );
    }

    #[test]
    fn bundled_planner_accepts_quoted_legacy_peer_deps_config() {
        let project = tempfile::tempdir().unwrap();
        for (directory, package) in [
            ("peer-v1", r#"{"name":"peer","version":"1.0.0"}"#),
            (
                "consumer",
                r#"{"name":"consumer","version":"1.0.0","peerDependencies":{"peer":"2.x"}}"#,
            ),
        ] {
            let path = project.path().join(directory);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("package.json"), package).unwrap();
        }
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"root","version":"1.0.0","dependencies":{"peer":"file:./peer-v1","consumer":"file:./consumer"}}"#,
        )
        .unwrap();
        std::fs::write(project.path().join(".npmrc"), "legacy-peer-deps=\"true\"\n").unwrap();

        let plan = ArboristPlanner::plan(project.path()).unwrap();
        assert!(plan.nodes.iter().any(|node| node.name == "consumer"));
    }

    #[test]
    fn planner_uses_arborists_dependency_bundle_boundary() {
        assert!(PLANNER.contains(".filter(node => !node.inDepBundle"));
        assert!(!PLANNER.contains(".filter(node => !node.inBundle &&"));
    }
}
