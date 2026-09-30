//! oath-workspace: monorepo/workspace detection and management
//!
//! Supports:
//!   - pnpm-workspace.yaml (preferred, used by pnpm/turborepo)
//!   - package.json "workspaces" field (npm/yarn classic)
//!
//! Glob expansion, workspace:* specifier parsing, and local package resolution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::debug;

// ---- Public Types -----------------------------------------------------------

/// A resolved workspace root with all discovered packages
#[derive(Debug, Clone)]
pub struct WorkspaceRoot {
    /// Absolute path to the workspace root directory
    pub root: PathBuf,
    /// All workspace packages discovered via glob patterns
    pub packages: Vec<WorkspacePackage>,
}

/// A single workspace package
#[derive(Debug, Clone)]
pub struct WorkspacePackage {
    /// Package name from package.json
    pub name: String,
    /// Package version from package.json
    pub version: String,
    /// Absolute path to the package directory
    pub path: PathBuf,
    /// Full parsed package.json manifest
    pub package_json: Manifest,
}

/// Minimal package.json manifest (all fields optional except name/version)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
    #[serde(default)]
    pub dev_dependencies: HashMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: HashMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: HashMap<String, String>,
    /// npm/yarn workspaces field (array or object form)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspaces: Option<WorkspacesField>,
}

/// The "workspaces" field in package.json (array or object form)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkspacesField {
    /// Simple array: ["packages/*", "apps/*"]
    Array(Vec<String>),
    /// Object form: { "packages": ["packages/*"] }  (legacy Yarn Berry)
    Object { packages: Vec<String> },
}

impl WorkspacesField {
    pub fn patterns(&self) -> &[String] {
        match self {
            WorkspacesField::Array(v) => v,
            WorkspacesField::Object { packages } => packages,
        }
    }
}

/// Workspace specifier variants for the workspace: protocol
#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceSpecifier {
    /// workspace:* -- use local, any version
    Any,
    /// workspace:^ -- use local, will use ^version on publish
    Caret,
    /// workspace:~ -- use local, will use ~version on publish
    Tilde,
    /// workspace:1.2.3 -- use local, must match exact version
    Exact(String),
    /// Not a workspace specifier
    NotWorkspace,
}

// ---- pnpm-workspace.yaml types ----------------------------------------------

#[derive(Debug, Deserialize)]
struct PnpmWorkspaceYaml {
    #[serde(default)]
    packages: Vec<String>,
}

// ---- Detection --------------------------------------------------------------

/// Walk up from `start` looking for a workspace root.
///
/// Detects:
///   1. pnpm-workspace.yaml in directory
///   2. package.json with "workspaces" field
///
/// Returns `None` if no workspace root is found (i.e., this is a single-package project).
pub fn detect_workspace_root(start: &Path) -> Option<WorkspaceRoot> {
    let start = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };

    let mut current = start.as_path();
    loop {
        // Check for pnpm-workspace.yaml first (authoritative pnpm format)
        let pnpm_yaml = current.join("pnpm-workspace.yaml");
        if pnpm_yaml.exists() {
            debug!("found pnpm-workspace.yaml at {}", current.display());
            if let Some(root) = try_load_pnpm_workspace(current) {
                return Some(root);
            }
        }

        // Check for package.json with "workspaces" field
        let pkg_json = current.join("package.json");
        if pkg_json.exists()
            && let Ok(content) = std::fs::read_to_string(&pkg_json)
            && let Ok(manifest) = serde_json::from_str::<Manifest>(&content)
            && let Some(ws) = &manifest.workspaces
        {
            let patterns: Vec<String> = ws.patterns().to_vec();
            debug!(
                "found package.json workspaces at {}: {:?}",
                current.display(),
                patterns
            );
            let packages = expand_and_load_packages(current, &patterns);
            return Some(WorkspaceRoot {
                root: current.to_path_buf(),
                packages,
            });
        }

        // Move up one directory
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    None
}

fn try_load_pnpm_workspace(root: &Path) -> Option<WorkspaceRoot> {
    let yaml_path = root.join("pnpm-workspace.yaml");
    let content = std::fs::read_to_string(&yaml_path).ok()?;
    let config: PnpmWorkspaceYaml = serde_yaml::from_str(&content).ok()?;
    let packages = expand_and_load_packages(root, &config.packages);
    Some(WorkspaceRoot {
        root: root.to_path_buf(),
        packages,
    })
}

// ---- Glob expansion ---------------------------------------------------------

/// Expand workspace glob patterns relative to `root` and return package directories.
///
/// Supports:
///   - "packages/*"     -- all direct subdirs of packages/
///   - "apps/**"        -- recursive
///   - "!**/node_modules" -- negation (excluded)
pub fn expand_workspace_globs(root: &Path, patterns: &[String]) -> Vec<PathBuf> {
    let mut results: Vec<PathBuf> = Vec::new();
    let mut negations: Vec<glob::Pattern> = Vec::new();

    // Split into positive and negative patterns
    let (positives, negatives): (Vec<_>, Vec<_>) =
        patterns.iter().partition(|p| !p.starts_with('!'));

    // Compile negation patterns
    for neg in &negatives {
        let trimmed = neg.trim_start_matches('!');
        // Make absolute if needed
        let abs_pattern = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            root.join(trimmed).to_string_lossy().into_owned()
        };
        if let Ok(pat) = glob::Pattern::new(&abs_pattern) {
            negations.push(pat);
        }
    }

    for pattern in &positives {
        // Ensure pattern targets directories by appending /package.json probe later
        let abs_pattern = if pattern.starts_with('/') {
            pattern.to_string()
        } else {
            root.join(pattern.as_str()).to_string_lossy().into_owned()
        };
        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: false,
            require_literal_leading_dot: false,
        };

        if let Ok(paths) = glob::glob_with(&abs_pattern, options) {
            for entry in paths.flatten() {
                if !entry.is_dir() {
                    continue;
                }
                // Skip if matches a negation pattern
                let entry_str = entry.to_string_lossy();
                if negations
                    .iter()
                    .any(|neg| neg.matches(&entry_str) || entry_str.contains("node_modules"))
                {
                    continue;
                }
                // Must contain a package.json to be a valid workspace package
                if entry.join("package.json").exists() {
                    results.push(entry);
                }
            }
        }
    }

    // Deduplicate
    results.sort();
    results.dedup();
    results
}

/// Load WorkspacePackage from a directory path
fn load_workspace_package(path: &Path) -> Option<WorkspacePackage> {
    let pkg_json_path = path.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let manifest: Manifest = serde_json::from_str(&content).ok()?;

    if manifest.name.is_empty() {
        return None;
    }

    Some(WorkspacePackage {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        path: path.to_path_buf(),
        package_json: manifest,
    })
}

fn expand_and_load_packages(root: &Path, patterns: &[String]) -> Vec<WorkspacePackage> {
    let dirs = expand_workspace_globs(root, patterns);
    dirs.iter()
        .filter_map(|p| load_workspace_package(p))
        .collect()
}

// ---- Workspace specifier parsing --------------------------------------------

/// Parse a dependency specifier for workspace: protocol.
///
/// Examples:
///   "workspace:*"   -> WorkspaceSpecifier::Any
///   "workspace:^"   -> WorkspaceSpecifier::Caret
///   "workspace:~"   -> WorkspaceSpecifier::Tilde
///   "workspace:1.2.3" -> WorkspaceSpecifier::Exact("1.2.3")
///   "^1.0.0"        -> WorkspaceSpecifier::NotWorkspace
pub fn parse_workspace_spec(spec: &str) -> WorkspaceSpecifier {
    if !spec.starts_with("workspace:") {
        return WorkspaceSpecifier::NotWorkspace;
    }

    let rest = &spec["workspace:".len()..];
    match rest {
        "*" => WorkspaceSpecifier::Any,
        "^" => WorkspaceSpecifier::Caret,
        "~" => WorkspaceSpecifier::Tilde,
        v => WorkspaceSpecifier::Exact(v.to_string()),
    }
}

/// Check if a specifier is a workspace: reference
pub fn is_workspace_spec(spec: &str) -> bool {
    spec.starts_with("workspace:")
}

// ---- Workspace package map --------------------------------------------------

impl WorkspaceRoot {
    /// Build a name -> WorkspacePackage map for quick lookups
    pub fn package_map(&self) -> HashMap<String, &WorkspacePackage> {
        self.packages.iter().map(|p| (p.name.clone(), p)).collect()
    }

    /// Find a workspace package by name
    pub fn find_package(&self, name: &str) -> Option<&WorkspacePackage> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Select workspaces using npm's name, exact directory, or parent-directory forms.
    /// Results preserve declaration/glob order and never include the workspace root.
    pub fn select_packages<'a>(
        &'a self,
        selectors: &[String],
        all: bool,
    ) -> Result<Vec<&'a WorkspacePackage>, String> {
        if all && selectors.is_empty() {
            return Ok(self.packages.iter().collect());
        }
        if selectors.is_empty() {
            return Ok(Vec::new());
        }

        let mut selected = Vec::new();
        for selector in selectors {
            let selector_path = {
                let candidate = PathBuf::from(selector);
                if candidate.is_absolute() {
                    candidate
                } else {
                    self.root.join(candidate)
                }
            };
            let normalized = selector_path.canonicalize().unwrap_or(selector_path);
            let mut matched = false;
            for package in &self.packages {
                let package_path = package
                    .path
                    .canonicalize()
                    .unwrap_or_else(|_| package.path.clone());
                if package.name == *selector
                    || package_path == normalized
                    || package_path.starts_with(&normalized)
                {
                    matched = true;
                    if !selected
                        .iter()
                        .any(|existing: &&WorkspacePackage| existing.path == package.path)
                    {
                        selected.push(package);
                    }
                }
            }
            if !matched {
                return Err(format!("no workspace matched {selector}"));
            }
        }
        if all {
            for package in &self.packages {
                if !selected
                    .iter()
                    .any(|existing| existing.path == package.path)
                {
                    selected.push(package);
                }
            }
        }
        Ok(selected)
    }

    /// Collect all external (non-workspace) dependencies across all packages
    /// Returns a merged HashMap<name, spec> with workspace:* entries stripped out.
    /// Workspace deps are returned separately as a Vec<(consumer_name, dep_name)>.
    #[allow(clippy::type_complexity)]
    pub fn collect_external_deps(
        &self,
        include_dev: bool,
    ) -> (HashMap<String, String>, Vec<(String, String, String)>) {
        self.collect_external_deps_for_packages(include_dev, true)
    }

    /// Collect dependencies for the packages in this `WorkspaceRoot`, optionally
    /// including the root manifest. This is used by filtered npm workspace commands.
    #[allow(clippy::type_complexity)]
    pub fn collect_external_deps_for_packages(
        &self,
        include_dev: bool,
        include_root: bool,
    ) -> (HashMap<String, String>, Vec<(String, String, String)>) {
        let pkg_map: HashMap<String, &WorkspacePackage> = self.package_map();
        let mut external: HashMap<String, String> = HashMap::new();
        let mut workspace_links: Vec<(String, String, String)> = Vec::new();

        // Also include root package.json deps if it exists
        let root_pkg_json = self.root.join("package.json");
        let root_manifest: Option<Manifest> = std::fs::read_to_string(&root_pkg_json)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok());

        // We need to handle root manifest separately (owned value)
        let root_deps;
        let root_dev_deps;
        if include_root && let Some(ref rm) = root_manifest {
            root_deps = rm.dependencies.clone();
            root_dev_deps = rm.dev_dependencies.clone();
            // Process root separately below
            for (name, spec) in &root_deps {
                process_dep(
                    "root",
                    name,
                    spec,
                    &pkg_map,
                    &mut external,
                    &mut workspace_links,
                );
            }
            if include_dev {
                for (name, spec) in &root_dev_deps {
                    process_dep(
                        "root",
                        name,
                        spec,
                        &pkg_map,
                        &mut external,
                        &mut workspace_links,
                    );
                }
            }
        }

        for pkg in &self.packages {
            let m = &pkg.package_json;
            for (name, spec) in &m.dependencies {
                process_dep(
                    &pkg.name,
                    name,
                    spec,
                    &pkg_map,
                    &mut external,
                    &mut workspace_links,
                );
            }
            if include_dev {
                for (name, spec) in &m.dev_dependencies {
                    process_dep(
                        &pkg.name,
                        name,
                        spec,
                        &pkg_map,
                        &mut external,
                        &mut workspace_links,
                    );
                }
            }
        }

        (external, workspace_links)
    }
}

/// Helper: classify one dep as external or workspace link
fn process_dep(
    consumer: &str,
    dep_name: &str,
    spec: &str,
    pkg_map: &HashMap<String, &WorkspacePackage>,
    external: &mut HashMap<String, String>,
    workspace_links: &mut Vec<(String, String, String)>,
) {
    if is_workspace_spec(spec) {
        // It's an explicit workspace: reference
        if let Some(ws_pkg) = pkg_map.get(dep_name) {
            workspace_links.push((
                consumer.to_string(),
                dep_name.to_string(),
                ws_pkg.path.to_string_lossy().into_owned(),
            ));
        }
    } else if pkg_map.contains_key(dep_name) {
        // Plain specifier that matches a local workspace package name
        // (yarn classic behavior: intercept before registry)
        workspace_links.push((
            consumer.to_string(),
            dep_name.to_string(),
            pkg_map[dep_name].path.to_string_lossy().into_owned(),
        ));
    } else {
        // External registry dep -- merge, keeping the first seen spec
        external
            .entry(dep_name.to_string())
            .or_insert_with(|| spec.to_string());
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_pkg(dir: &Path, name: &str, version: &str, extra: &str) {
        fs::create_dir_all(dir).unwrap();
        let content = format!(r#"{{"name":"{name}","version":"{version}"{extra}}}"#);
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn test_parse_workspace_spec() {
        assert_eq!(parse_workspace_spec("workspace:*"), WorkspaceSpecifier::Any);
        assert_eq!(
            parse_workspace_spec("workspace:^"),
            WorkspaceSpecifier::Caret
        );
        assert_eq!(
            parse_workspace_spec("workspace:~"),
            WorkspaceSpecifier::Tilde
        );
        assert_eq!(
            parse_workspace_spec("workspace:1.2.3"),
            WorkspaceSpecifier::Exact("1.2.3".to_string())
        );
        assert_eq!(
            parse_workspace_spec("^1.0.0"),
            WorkspaceSpecifier::NotWorkspace
        );
        assert_eq!(parse_workspace_spec("*"), WorkspaceSpecifier::NotWorkspace);
    }

    #[test]
    fn test_detect_pnpm_workspace_yaml() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Write pnpm-workspace.yaml
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - 'apps/*'\n",
        )
        .unwrap();

        // Root package.json (not required for pnpm but good practice)
        write_pkg(root, "my-monorepo", "0.0.0", r#","private":true"#);

        // Write workspace packages
        write_pkg(
            &root.join("packages/ui"),
            "@repo/ui",
            "0.0.0",
            r#","dependencies":{"react":"^18.0.0"}"#,
        );
        write_pkg(&root.join("packages/utils"), "@repo/utils", "0.0.0", "");
        write_pkg(
            &root.join("apps/web"),
            "web",
            "0.0.0",
            r#","dependencies":{"@repo/ui":"workspace:*","react":"^18.0.0"}"#,
        );

        let ws = detect_workspace_root(root).expect("should detect workspace");
        assert_eq!(ws.root, root);
        assert_eq!(ws.packages.len(), 3);

        let names: Vec<_> = ws.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"@repo/ui"));
        assert!(names.contains(&"@repo/utils"));
        assert!(names.contains(&"web"));
    }

    #[test]
    fn test_detect_package_json_workspaces() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Write root package.json with workspaces field
        let content = r#"{"name":"my-repo","version":"0.0.0","private":true,"workspaces":["packages/*","apps/*"]}"#;
        fs::write(root.join("package.json"), content).unwrap();

        write_pkg(&root.join("packages/core"), "@repo/core", "1.0.0", "");
        write_pkg(&root.join("apps/web"), "web", "0.0.0", "");

        let ws = detect_workspace_root(root).expect("should detect workspace");
        assert_eq!(ws.packages.len(), 2);
    }

    #[test]
    fn workspace_selection_accepts_name_directory_and_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("package.json"),
            r#"{"name":"repo","private":true,"workspaces":["packages/*","apps/*"]}"#,
        )
        .unwrap();
        write_pkg(&root.join("packages/core"), "@repo/core", "1.0.0", "");
        write_pkg(&root.join("packages/ui"), "@repo/ui", "1.0.0", "");
        write_pkg(&root.join("apps/web"), "web", "1.0.0", "");
        let workspace = detect_workspace_root(root).unwrap();

        let by_name = workspace
            .select_packages(&["@repo/core".to_owned()], false)
            .unwrap();
        assert_eq!(by_name[0].name, "@repo/core");

        let by_directory = workspace
            .select_packages(&["apps/web".to_owned()], false)
            .unwrap();
        assert_eq!(by_directory[0].name, "web");

        let by_parent = workspace
            .select_packages(&["packages".to_owned()], false)
            .unwrap();
        assert_eq!(by_parent.len(), 2);
        assert!(
            workspace
                .select_packages(&["missing".to_owned()], false)
                .is_err()
        );
    }

    #[test]
    fn test_expand_workspace_globs_negation() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create dirs
        write_pkg(&root.join("packages/a"), "a", "1.0.0", "");
        write_pkg(&root.join("packages/b"), "b", "1.0.0", "");
        // node_modules should be excluded
        write_pkg(&root.join("packages/node_modules/c"), "c", "1.0.0", "");

        let patterns = vec!["packages/*".to_string()];
        let dirs = expand_workspace_globs(root, &patterns);

        // Should find a and b but NOT node_modules/c
        assert_eq!(dirs.len(), 2);
        let names: Vec<_> = dirs
            .iter()
            .map(|d| d.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(!names.contains(&"node_modules"));
    }

    #[test]
    fn test_collect_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - 'apps/*'\n",
        )
        .unwrap();

        write_pkg(root, "root", "0.0.0", "");
        write_pkg(
            &root.join("packages/ui"),
            "@repo/ui",
            "0.0.0",
            r#","dependencies":{"react":"^18.0.0"}"#,
        );
        write_pkg(
            &root.join("apps/web"),
            "web",
            "0.0.0",
            r#","dependencies":{"@repo/ui":"workspace:*","react":"^18.0.0","lodash":"^4.0.0"}"#,
        );

        let ws = detect_workspace_root(root).unwrap();
        let (external, ws_links) = ws.collect_external_deps(true);

        // react and lodash are external
        assert!(external.contains_key("react"), "react should be external");
        assert!(external.contains_key("lodash"), "lodash should be external");
        // @repo/ui is a workspace link
        assert!(
            ws_links.iter().any(|(_, dep, _)| dep == "@repo/ui"),
            "should have workspace link for @repo/ui"
        );
    }
}
