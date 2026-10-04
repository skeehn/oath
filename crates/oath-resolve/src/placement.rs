use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::Path;

use crate::graph::{DepGraph, DepNode};

pub const PLACEMENT_PLAN_VERSION: u32 = 2;
const PLANNER: &str = include_str!("arborist-plan.cjs");
const NPM_REFERENCE_VERSION: &str = "11.12.1";
const ARBORIST_VERSION: &str = "9.4.2";
const INSTALL_CHECKS_VERSION: &str = "8.0.0";
const PACKLIST_VERSION: &str = "10.0.4";
const NPM_RUNTIME: &[u8] = include_bytes!("../vendor/npm-11.12.1.tgz");
const NPM_RUNTIME_SHA256: &str = "e679850e663b16f5f146ee425d0eb0e3442c1d2bda3d513bbfd7c81f5ee5db38";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPlan {
    pub schema_version: u32,
    pub planner: PlannerIdentity,
    pub project: String,
    pub nodes: Vec<PlacementNode>,
    #[serde(default)]
    pub removed_locations: Vec<String>,
    pub invalid_edges: Vec<PlacementEdge>,
    /// The dependency fields npm would write to the root package.json after an
    /// add or remove request. Absent for plain install, ci, and update plans,
    /// which never rewrite package.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_manifest: Option<RootManifest>,
}

/// Root package.json dependency sections as npm's `saveIdealTree` would save
/// them: alphabetically ordered, with empty sections removed (`None`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RootManifest {
    #[serde(default)]
    pub dependencies: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: Option<serde_json::Map<String, serde_json::Value>>,
}

impl RootManifest {
    /// Apply the saved dependency sections to a parsed package.json, replacing
    /// each section npm would have written and deleting sections npm would
    /// have pruned. Every other key keeps its position and value.
    pub fn apply_to(&self, manifest: &mut serde_json::Value) {
        let Some(object) = manifest.as_object_mut() else {
            return;
        };
        for (key, section) in [
            ("dependencies", &self.dependencies),
            ("devDependencies", &self.dev_dependencies),
            ("optionalDependencies", &self.optional_dependencies),
            ("peerDependencies", &self.peer_dependencies),
        ] {
            match section {
                Some(map) => {
                    object.insert(key.to_string(), serde_json::Value::Object(map.clone()));
                }
                None => {
                    object.remove(key);
                }
            }
        }
    }

    /// The root `dependencies` and `devDependencies` as plain name/spec maps,
    /// used for the lockfile's manifest snapshot.
    pub fn snapshot(
        &self,
    ) -> (
        std::collections::HashMap<String, String>,
        std::collections::HashMap<String, String>,
    ) {
        let to_map = |section: &Option<serde_json::Map<String, serde_json::Value>>| {
            section
                .as_ref()
                .map(|map| {
                    map.iter()
                        .map(|(name, spec)| {
                            (name.clone(), spec.as_str().unwrap_or("*").to_string())
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        (to_map(&self.dependencies), to_map(&self.dev_dependencies))
    }
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
        let runtime = BundledRuntime::extract()?;
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

    let runtime = BundledRuntime::extract()?;
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
    _temp: tempfile::TempDir,
    package_root: std::path::PathBuf,
}

impl BundledRuntime {
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
        let temp = tempfile::tempdir().context("create pinned Arborist runtime directory")?;
        tar::Archive::new(GzDecoder::new(Cursor::new(NPM_RUNTIME)))
            .unpack(temp.path())
            .context("extract bundled npm runtime")?;
        let package_root = temp.path().join("package");
        verify_runtime_package(
            &package_root.join("node_modules/@npmcli/arborist/package.json"),
            "@npmcli/arborist",
            ARBORIST_VERSION,
        )?;
        verify_runtime_package(
            &package_root.join("node_modules/npm-install-checks/package.json"),
            "npm-install-checks",
            INSTALL_CHECKS_VERSION,
        )?;
        verify_runtime_package(
            &package_root.join("node_modules/npm-packlist/package.json"),
            "npm-packlist",
            PACKLIST_VERSION,
        )?;
        Ok(Self {
            _temp: temp,
            package_root,
        })
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
                has_install_script: false,
                reuse_existing: false,
                link: false,
                target: None,
                edges: vec![],
            }],
            removed_locations: vec![],
            invalid_edges: vec![],
            root_manifest: None,
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
