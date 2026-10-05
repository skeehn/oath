//! Import an existing `package-lock.json` into an oath dependency graph.
//!
//! This is the migration path: an existing repo should "just work" on its first
//! `oath install` -- honouring the versions it already locked instead of
//! re-resolving ranges to newer versions. We read npm's lockfileVersion 2/3
//! `packages` map (path -> entry) and reproduce node's nearest-ancestor
//! resolution to turn each dependency range into the exact installed version.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::graph::{DepGraph, DepNode, PeerReport};

/// Convert a lockfileVersion 1 `dependencies` tree into a `packages` map.
///
/// v1 nests dependencies (`dependencies.foo.dependencies.bar`); v2/v3 flattens
/// them into paths (`node_modules/foo`, `node_modules/foo/node_modules/bar`).
/// This walks the tree depth-first, building the flat map npm itself produces
/// on upgrade.
fn convert_v1_to_packages(mut root: Value) -> Result<Value> {
    let mut packages = Map::new();
    // Root entry: v1 has no packages[""], synthesize it from name/version.
    let mut root_entry = Map::new();
    if let Some(name) = root.get("name").cloned() {
        root_entry.insert("name".to_string(), name);
    }
    if let Some(version) = root.get("version").cloned() {
        root_entry.insert("version".to_string(), version);
    }
    packages.insert(String::new(), Value::Object(root_entry));

    if let Some(deps) = root.get("dependencies").and_then(Value::as_object).cloned() {
        convert_v1_deps(&deps, "node_modules", &mut packages);
    }
    if let Some(obj) = root.as_object_mut() {
        obj.insert("packages".to_string(), Value::Object(packages));
        obj.insert("lockfileVersion".to_string(), Value::from(3));
    }
    Ok(root)
}

fn convert_v1_deps(deps: &Map<String, Value>, prefix: &str, packages: &mut Map<String, Value>) {
    for (name, entry) in deps {
        let path = format!("{prefix}/{name}");
        if let Some(entry_obj) = entry.as_object() {
            let mut flat = entry_obj.clone();
            // Nested dependencies become their own packages entries; synthesize
            // the dependency edge (v1 nests the objects directly, no ranges).
            if let Some(nested) = flat.remove("dependencies")
                && let Some(nested_obj) = nested.as_object()
            {
                let mut synth = Map::new();
                for (dep_name, dep_entry) in nested_obj {
                    if let Some(v) = dep_entry.get("version").and_then(Value::as_str) {
                        synth.insert(dep_name.clone(), Value::String(v.to_string()));
                    }
                }
                if !synth.is_empty() {
                    flat.insert("dependencies".to_string(), Value::Object(synth));
                }
                convert_v1_deps(nested_obj, &format!("{path}/node_modules"), packages);
            }
            // v1 `bundled: true` means the dep was bundled; keep the flag.
            packages.insert(path, Value::Object(flat));
        }
    }
}

/// Parse a `package-lock.json` (npm lockfileVersion 1, 2 or 3) into a DepGraph.
pub fn import_npm_lockfile(path: &Path) -> Result<DepGraph> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut root: Value =
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;

    // lockfileVersion 1 uses a nested `dependencies` tree instead of the flat
    // `packages` map; convert it in memory so the rest of the importer sees
    // a uniform shape (npm itself upgrades v1 on read).
    let version = root
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    if version == 1 {
        root = convert_v1_to_packages(root)?;
    }

    let packages = root.get("packages").and_then(Value::as_object).context(
        "package-lock.json has no `packages` map (run `npm install` once with npm 7+ to upgrade it)",
    )?;

    // First pass: build path -> key and the node skeletons.
    let mut path_to_key: HashMap<String, String> = HashMap::new();
    let mut nodes: HashMap<String, DepNode> = HashMap::new();

    for (pkg_path, entry) in packages {
        if pkg_path.is_empty() {
            continue; // the project root itself
        }
        let entry = match entry.as_object() {
            Some(e) => e,
            None => continue,
        };
        // Skip workspace/link entries and anything without a concrete version.
        if entry.get("link").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let version = match entry.get("version").and_then(Value::as_str) {
            Some(v) => v.to_string(),
            None => continue,
        };

        // Skip optional platform packages for other OS/CPU (e.g. esbuild's
        // win32/linux binaries on a mac), exactly as npm does -- otherwise we
        // over-download tens of MB of binaries that will never be used.
        if !platform_matches(entry) {
            continue;
        }

        let name = name_from_path(pkg_path).to_string();
        let key = format!("{name}@{version}");

        let dev_optional = entry
            .get("devOptional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let node = DepNode {
            name,
            alias: None,
            version,
            resolved: entry
                .get("resolved")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            integrity: entry
                .get("integrity")
                .and_then(Value::as_str)
                .map(String::from),
            dependencies: HashMap::new(), // filled in the second pass
            has_install_script: entry
                .get("hasInstallScript")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            dev: entry.get("dev").and_then(Value::as_bool).unwrap_or(false) || dev_optional,
            optional: entry
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || dev_optional,
            peer_dependencies: range_map(entry.get("peerDependencies")),
            optional_peers: Default::default(),
            resolved_peers: HashMap::new(),
        };
        path_to_key.insert(pkg_path.clone(), key.clone());
        nodes.insert(key, node);
    }

    // Second pass: resolve each package's dependency ranges to concrete keys.
    for (pkg_path, entry) in packages {
        let entry = match entry.as_object() {
            Some(e) => e,
            None => continue,
        };
        let Some(self_key) = (if pkg_path.is_empty() {
            None
        } else {
            path_to_key.get(pkg_path).cloned()
        }) else {
            continue;
        };

        let mut resolved: HashMap<String, String> = HashMap::new();
        for field in ["dependencies", "optionalDependencies"] {
            if let Some(deps) = entry.get(field).and_then(Value::as_object) {
                for dep_name in deps.keys() {
                    if let Some(dep_path) = resolve_dep_path(packages, pkg_path, dep_name)
                        && let Some(dep_key) = path_to_key.get(&dep_path)
                    {
                        resolved.insert(dep_name.clone(), dep_key.clone());
                    }
                }
            }
        }
        if let Some(node) = nodes.get_mut(&self_key) {
            node.dependencies = resolved;
        }
    }

    // Roots: the project's direct deps (packages[""]).
    let mut roots = Vec::new();
    if let Some(root_entry) = packages.get("").and_then(Value::as_object) {
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(deps) = root_entry.get(field).and_then(Value::as_object) {
                for dep_name in deps.keys() {
                    if let Some(dep_path) = resolve_dep_path(packages, "", dep_name)
                        && let Some(dep_key) = path_to_key.get(&dep_path)
                        && !roots.contains(dep_key)
                    {
                        roots.push(dep_key.clone());
                    }
                }
            }
        }
    }

    if nodes.is_empty() {
        bail!("package-lock.json contained no installable packages");
    }

    Ok(DepGraph {
        nodes,
        roots,
        peer_report: PeerReport::default(),
    })
}

/// The package name encoded in a lockfile path: the part after the final
/// `node_modules/` segment (keeps `@scope/name` intact).
pub fn name_from_path(pkg_path: &str) -> &str {
    const NM: &str = "node_modules/";
    match pkg_path.rfind(NM) {
        Some(idx) => &pkg_path[idx + NM.len()..],
        None => pkg_path,
    }
}

/// Reproduce node's nearest-ancestor resolution: from `from_path`, look for
/// `<ancestor>/node_modules/<dep>` walking up to the project root.
fn resolve_dep_path(packages: &Map<String, Value>, from_path: &str, dep: &str) -> Option<String> {
    let mut prefix = from_path.to_string();
    loop {
        let cand = if prefix.is_empty() {
            format!("node_modules/{dep}")
        } else {
            format!("{prefix}/node_modules/{dep}")
        };
        if packages.contains_key(&cand) {
            return Some(cand);
        }
        if prefix.is_empty() {
            return None;
        }
        match prefix.rfind("/node_modules/") {
            Some(idx) => prefix.truncate(idx),
            None => prefix.clear(), // a top-level package -> next iteration checks the root
        }
    }
}

/// Does this lockfile entry's `os`/`cpu` constraint match the current platform?
/// Mirrors npm: an empty/absent list matches everything; otherwise the current
/// value must be allowed (and not negated with `!`).
pub fn platform_matches(entry: &Map<String, Value>) -> bool {
    matches_list(entry.get("os"), current_npm_os())
        && matches_list(entry.get("cpu"), current_npm_cpu())
}

fn matches_list(field: Option<&Value>, current: &str) -> bool {
    let list = match field.and_then(Value::as_array) {
        Some(l) if !l.is_empty() => l,
        _ => return true, // no constraint
    };
    let mut has_positive = false;
    let mut included = false;
    for item in list.iter().filter_map(Value::as_str) {
        if let Some(neg) = item.strip_prefix('!') {
            if neg == current {
                return false;
            }
        } else {
            has_positive = true;
            if item == current {
                included = true;
            }
        }
    }
    !has_positive || included
}

fn current_npm_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other, // linux, freebsd, ... match npm directly
    }
}

fn current_npm_cpu() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other, // arm, ...
    }
}

/// Extract a name->range map from a JSON object field (peerDependencies, etc.).
fn range_map(v: Option<&Value>) -> HashMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_nested_and_hoisted() {
        // a depends on c@1 (hoisted) and b; b depends on c@2 (nested under b).
        let lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "a": "^1.0.0" } },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://r/a/-/a-1.0.0.tgz",
                    "dependencies": { "b": "^1.0.0", "c": "^1.0.0" }
                },
                "node_modules/b": {
                    "version": "1.0.0",
                    "resolved": "https://r/b/-/b-1.0.0.tgz",
                    "dependencies": { "c": "^2.0.0" }
                },
                "node_modules/c": { "version": "1.5.0", "resolved": "https://r/c/-/c-1.5.0.tgz" },
                "node_modules/b/node_modules/c": {
                    "version": "2.1.0", "resolved": "https://r/c/-/c-2.1.0.tgz"
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("package-lock.json");
        std::fs::write(&p, serde_json::to_string(&lock).unwrap()).unwrap();

        let g = import_npm_lockfile(&p).unwrap();
        assert_eq!(g.nodes.len(), 4);
        assert_eq!(g.roots, vec!["a@1.0.0".to_string()]);
        // a's c resolves to the hoisted c@1.5.0; b's c resolves to the nested c@2.1.0.
        assert_eq!(g.nodes["a@1.0.0"].dependencies["c"], "c@1.5.0");
        assert_eq!(g.nodes["a@1.0.0"].dependencies["b"], "b@1.0.0");
        assert_eq!(g.nodes["b@1.0.0"].dependencies["c"], "c@2.1.0");
    }

    #[test]
    fn scoped_names_preserved() {
        assert_eq!(name_from_path("node_modules/@types/node"), "@types/node");
        assert_eq!(name_from_path("node_modules/a/node_modules/@s/b"), "@s/b");
        assert_eq!(name_from_path("node_modules/express"), "express");
    }

    #[test]
    fn os_cpu_filtering() {
        use serde_json::json;
        let darwin = json!(["darwin"]);
        let win = json!(["win32"]);
        let not_win = json!(["!win32"]);
        assert!(matches_list(None, "darwin")); // no constraint
        assert!(matches_list(Some(&darwin), "darwin"));
        assert!(!matches_list(Some(&win), "darwin"));
        assert!(matches_list(Some(&not_win), "darwin")); // negation allows others
        assert!(!matches_list(Some(&not_win), "win32"));
    }

    #[test]
    fn skips_foreign_platform_optional_packages() {
        // A linux-only optional binary must not be imported on a non-linux host.
        let other = if current_npm_os() == "linux" {
            "win32"
        } else {
            "linux"
        };
        let lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "tool": "^1.0.0" } },
                "node_modules/tool": { "version": "1.0.0", "resolved": "https://r/t.tgz" },
                "node_modules/@tool/bin-foreign": {
                    "version": "1.0.0", "resolved": "https://r/f.tgz",
                    "optional": true, "os": [other]
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("package-lock.json");
        std::fs::write(&p, serde_json::to_string(&lock).unwrap()).unwrap();
        let g = import_npm_lockfile(&p).unwrap();
        assert!(g.nodes.contains_key("tool@1.0.0"));
        assert!(!g.nodes.contains_key("@tool/bin-foreign@1.0.0"));
    }

    #[test]
    fn imports_lockfile_v1() {
        // v1 nests dependencies; the importer flattens them like npm does.
        let lock = serde_json::json!({
            "name": "p", "version": "1.0.0", "lockfileVersion": 1,
            "dependencies": {
                "a": {
                    "version": "1.0.0",
                    "resolved": "https://r/a/-/a-1.0.0.tgz",
                    "dependencies": {
                        "b": {
                            "version": "2.0.0",
                            "resolved": "https://r/b/-/b-2.0.0.tgz"
                        }
                    }
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("package-lock.json");
        std::fs::write(&p, serde_json::to_string(&lock).unwrap()).unwrap();
        let g = import_npm_lockfile(&p).unwrap();
        assert!(g.nodes.contains_key("a@1.0.0"));
        assert!(g.nodes.contains_key("b@2.0.0"));
        // b is nested under a, not hoisted.
        let a = &g.nodes["a@1.0.0"];
        assert_eq!(a.dependencies.get("b"), Some(&"b@2.0.0".to_string()));
    }
}
