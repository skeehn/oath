//! npm `package-lock.json` (lockfileVersion 3) writer.
//!
//! Serializes a [`PlacementPlan`] together with its [`DepGraph`] into the
//! lockfile format npm itself reads: a `packages` map keyed by install path
//! (`""` for the project root, `node_modules/<name>` for each package),
//! carrying `version`/`resolved`/`integrity`, `dev`/`optional` flags,
//! `hasInstallScript`, and peer metadata.
//!
//! This is the write half of the roadmap's L-01 (npm daily install parity):
//! making `package-lock.json` the frozen-install source of truth and wiring
//! it into `install`/`ci` lands separately. The output is deliberately shaped
//! so [`import_npm_lockfile`](crate::import_npm_lockfile) — which implements
//! npm's own reading rules — round-trips it; the round-trip test below is the
//! format-conformance check until the differential harness compares against
//! npm directly.
//!
//! Known deviations from npm's own output (tracked for the T-04
//! normalization work):
//!
//! - Per-package `dependencies` carry **resolved versions**, not the
//!   requested ranges from each package's `package.json` (the ranges are not
//!   in the plan/graph model yet). npm ignores these values on `ci` — it
//!   installs the locked tree — so frozen installs are unaffected.
//! - `license`, `bin`, `engines`, and `funding` are omitted (not in the
//!   model). npm tolerates their absence.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::graph::DepGraph;
use crate::placement::PlacementPlan;

/// The project-root side of the lockfile: identity plus the requested
/// dependency ranges exactly as the root `package.json` declares them.
#[derive(Debug, Clone, Default)]
pub struct PackageLockRoot {
    pub name: String,
    pub version: String,
    pub dependencies: BTreeMap<String, String>,
    pub dev_dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub peer_dependencies: BTreeMap<String, String>,
}

/// Serialize `plan` (install paths) and `graph` (resolved versions,
/// dependency edges, peer ranges) as an npm `package-lock.json` document
/// with `lockfileVersion: 3`.
pub fn to_package_lock_v3(plan: &PlacementPlan, graph: &DepGraph, root: &PackageLockRoot) -> Value {
    let mut packages = Map::new();

    // The project root itself, keyed "".
    {
        let mut entry = Map::new();
        entry.insert("name".to_string(), Value::String(root.name.clone()));
        entry.insert("version".to_string(), Value::String(root.version.clone()));
        insert_range_map(&mut entry, "dependencies", &root.dependencies);
        insert_range_map(&mut entry, "devDependencies", &root.dev_dependencies);
        insert_range_map(
            &mut entry,
            "optionalDependencies",
            &root.optional_dependencies,
        );
        insert_range_map(&mut entry, "peerDependencies", &root.peer_dependencies);
        packages.insert(String::new(), Value::Object(entry));
    }

    for node in &plan.nodes {
        let key = normalize_location(&node.location);
        if key.is_empty() {
            continue;
        }
        let mut entry = Map::new();
        if node.link {
            // npm's link-entry shape: {"resolved": "<lockfile-relative target>",
            // "link": true} — no version. The planner reports the target as an
            // absolute path; relativize it against the project root the way
            // npm does.
            if let Some(target) = node.target.as_deref().filter(|s| !s.is_empty()) {
                let rel = relativize_target(&plan.project, target);
                entry.insert("resolved".to_string(), Value::String(rel.clone()));
                entry.insert("link".to_string(), Value::Bool(true));
                packages.insert(key, Value::Object(entry));
                // npm also records the link target itself (e.g. "packages/tool")
                // with the workspace package's metadata, or a later Arborist
                // run fails with "Missing target in lock file".
                let mut target_entry = Map::new();
                target_entry.insert("name".to_string(), Value::String(node.name.clone()));
                target_entry.insert("version".to_string(), Value::String(node.version.clone()));
                // Workspace package dependencies from the plan's edges.
                let mut target_deps = Map::new();
                for edge in &node.edges {
                    // edge.spec is the range; resolve via graph if available.
                    target_deps.insert(edge.name.clone(), Value::String(edge.spec.clone()));
                }
                if !target_deps.is_empty() {
                    target_entry.insert("dependencies".to_string(), Value::Object(target_deps));
                }
                packages.insert(rel, Value::Object(target_entry));
            } else {
                entry.insert("link".to_string(), Value::Bool(true));
                packages.insert(key, Value::Object(entry));
            }
            continue;
        }
        entry.insert("version".to_string(), Value::String(node.version.clone()));
        // Aliased installs (`"number-check": "npm:is-number@7.0.0"`): npm
        // records the real package name so the lockfile stays resolvable.
        // Without it, a later Arborist run reads `node_modules/number-check`
        // as a package literally named `number-check` and misplans.
        if node.install_name != node.name {
            entry.insert("name".to_string(), Value::String(node.name.clone()));
        }
        if let Some(resolved) = node.resolved.as_deref().filter(|s| !s.is_empty()) {
            entry.insert("resolved".to_string(), Value::String(resolved.to_string()));
        }
        if let Some(integrity) = node.integrity.as_deref().filter(|s| !s.is_empty()) {
            entry.insert(
                "integrity".to_string(),
                Value::String(integrity.to_string()),
            );
        }
        match (node.dev, node.optional) {
            (true, true) => {
                entry.insert("devOptional".to_string(), Value::Bool(true));
            }
            (true, false) => {
                entry.insert("dev".to_string(), Value::Bool(true));
            }
            (false, true) => {
                entry.insert("optional".to_string(), Value::Bool(true));
            }
            (false, false) => {}
        }
        if node.has_install_script {
            entry.insert("hasInstallScript".to_string(), Value::Bool(true));
        }

        if let Some(dep_node) = find_graph_node(graph, node) {
            // Resolved versions, not requested ranges (see module docs).
            // Edge types come from the plan: optional edges belong under
            // `optionalDependencies`, the rest under `dependencies`. When the
            // plan carries no edges (synthetic graphs), fall back to the
            // graph's collapsed map, all under `dependencies`.
            let mut deps = Map::new();
            let mut opt_deps = Map::new();
            if node.edges.is_empty() {
                let mut names: Vec<&String> = dep_node.dependencies.keys().collect();
                names.sort();
                for name in names {
                    let target = &dep_node.dependencies[name];
                    if let Some(version) = version_for_target(plan, graph, target) {
                        deps.insert(name.clone(), Value::String(version));
                    }
                }
            } else {
                let mut edges: Vec<&crate::placement::PlacementEdge> = node
                    .edges
                    .iter()
                    .filter(|e| !e.dependency_type.starts_with("peer"))
                    .collect();
                edges.sort_by(|a, b| a.name.cmp(&b.name));
                for edge in edges {
                    let Some(target) = edge.target_location.as_deref() else {
                        continue;
                    };
                    let Some(version) = version_for_target(plan, graph, target) else {
                        continue;
                    };
                    let map = if edge.dependency_type == "optional" {
                        &mut opt_deps
                    } else {
                        &mut deps
                    };
                    map.insert(edge.name.clone(), Value::String(version));
                }
            }
            if !deps.is_empty() {
                entry.insert("dependencies".to_string(), Value::Object(deps));
            }
            if !opt_deps.is_empty() {
                entry.insert("optionalDependencies".to_string(), Value::Object(opt_deps));
            }
            if !dep_node.peer_dependencies.is_empty() {
                let mut peers = Map::new();
                let mut names: Vec<&String> = dep_node.peer_dependencies.keys().collect();
                names.sort();
                for name in names {
                    peers.insert(
                        name.clone(),
                        Value::String(dep_node.peer_dependencies[name].clone()),
                    );
                }
                entry.insert("peerDependencies".to_string(), Value::Object(peers));
            }
            if !dep_node.optional_peers.is_empty() {
                let mut meta = Map::new();
                let mut names: Vec<&String> = dep_node.optional_peers.iter().collect();
                names.sort();
                for name in names {
                    let mut flags = Map::new();
                    flags.insert("optional".to_string(), Value::Bool(true));
                    meta.insert(name.clone(), Value::Object(flags));
                }
                entry.insert("peerDependenciesMeta".to_string(), Value::Object(meta));
            }
        }

        packages.insert(key, Value::Object(entry));
    }

    let mut lock = Map::new();
    lock.insert("name".to_string(), Value::String(root.name.clone()));
    lock.insert("version".to_string(), Value::String(root.version.clone()));
    lock.insert("lockfileVersion".to_string(), Value::Number(3.into()));
    lock.insert("requires".to_string(), Value::Bool(true));
    lock.insert("packages".to_string(), Value::Object(packages));
    Value::Object(lock)
}

/// Render the value with npm's two-space indentation.
pub fn to_package_lock_json(
    plan: &PlacementPlan,
    graph: &DepGraph,
    root: &PackageLockRoot,
) -> String {
    let value = to_package_lock_v3(plan, graph, root);
    serde_json::to_string_pretty(&value).expect("package-lock.json serialization cannot fail")
}

/// npm lockfile keys are forward-slash relative paths (`node_modules/foo`,
/// `node_modules/a/node_modules/b`). Normalize planner locations into that
/// shape so npm and [`import_npm_lockfile`](crate::import_npm_lockfile)
/// resolve them identically.
fn normalize_location(location: &str) -> String {
    let forward = location.replace('\\', "/");
    forward
        .strip_prefix("./")
        .unwrap_or(&forward)
        .trim_end_matches('/')
        .to_string()
}

fn insert_range_map(
    entry: &mut Map<String, Value>,
    field: &str,
    ranges: &BTreeMap<String, String>,
) {
    if ranges.is_empty() {
        return;
    }
    let mut map = Map::new();
    for (name, range) in ranges {
        map.insert(name.clone(), Value::String(range.clone()));
    }
    entry.insert(field.to_string(), Value::Object(map));
}

/// Find the graph node for a plan node. Graphs built by
/// [`PlacementPlan::to_dep_graph`] are keyed by install location, so try
/// that first; other graphs use `name@version` keys (aliased installs key by
/// the install name).
fn find_graph_node<'a>(
    graph: &'a DepGraph,
    node: &crate::placement::PlacementNode,
) -> Option<&'a crate::graph::DepNode> {
    graph
        .get(&node.location)
        .or_else(|| graph.get(&DepGraph::key(&node.install_name, &node.version)))
        .or_else(|| graph.get(&DepGraph::key(&node.name, &node.version)))
}

/// Make a link target lockfile-relative: npm records link targets as paths
/// relative to the lockfile (e.g. `"packages/foo"`), not absolute paths.
fn relativize_target(project: &str, target: &str) -> String {
    let project = project.trim_end_matches('/');
    if let Some(rest) = target
        .strip_prefix(project)
        .and_then(|r| r.strip_prefix('/'))
    {
        if rest.is_empty() {
            return ".".to_string();
        }
        return rest.replace('\\', "/");
    }
    target.replace('\\', "/")
}

/// Resolve the version for a dependency target. Targets are install
/// locations in plan-derived graphs (`node_modules/b`) and `name@version`
/// keys in others. Link nodes are omitted from `to_dep_graph` output, so
/// fall back to the plan itself — which still carries them — rather than
/// emitting a garbage version.
fn version_for_target(plan: &PlacementPlan, graph: &DepGraph, target: &str) -> Option<String> {
    if let Some(node) = graph.get(target) {
        return Some(node.version.clone());
    }
    let wanted = normalize_location(target);
    if let Some(node) = plan
        .nodes
        .iter()
        .find(|n| normalize_location(&n.location) == wanted)
    {
        return Some(node.version.clone());
    }
    // Last resort for `name@version` keys.
    if target
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('@'))
    {
        return Some(version_from_key(target));
    }
    None
}
fn version_from_key(key: &str) -> String {
    key.rsplit('@').next().unwrap_or(key).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DepGraph, DepNode, PeerReport};
    use crate::placement::{PlacementNode, PlacementPlan};
    use std::collections::{HashMap, HashSet};

    fn test_plan(nodes: Vec<PlacementNode>) -> PlacementPlan {
        PlacementPlan {
            schema_version: 2,
            planner: crate::placement::PlannerIdentity {
                name: "test".to_string(),
                npm: "11.0.0".to_string(),
            },
            project: "/tmp/proj".to_string(),
            nodes,
            removed_locations: vec![],
            invalid_edges: vec![],
            root_manifest: None,
            added: vec![],
        }
    }

    fn plan_node(location: &str, name: &str, version: &str) -> PlacementNode {
        PlacementNode {
            location: location.to_string(),
            install_name: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            resolved: Some(format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz")),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            dev: false,
            optional: false,
            has_install_script: false,
            reuse_existing: false,
            link: false,
            target: None,
            edges: vec![],
        }
    }

    fn graph_node(name: &str, version: &str) -> DepNode {
        DepNode {
            name: name.to_string(),
            alias: None,
            version: version.to_string(),
            resolved: format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            dependencies: HashMap::new(),
            has_install_script: false,
            dev: false,
            optional: false,
            peer_dependencies: HashMap::new(),
            optional_peers: HashSet::new(),
            resolved_peers: HashMap::new(),
        }
    }

    fn test_graph(nodes: Vec<DepNode>) -> DepGraph {
        let mut graph_nodes = HashMap::new();
        for node in nodes {
            graph_nodes.insert(DepGraph::key(&node.name, &node.version), node);
        }
        DepGraph {
            nodes: graph_nodes,
            roots: vec![],
            peer_report: PeerReport::default(),
        }
    }

    fn root() -> PackageLockRoot {
        PackageLockRoot {
            name: "my-proj".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_plan_produces_root_only_lockfile() {
        let value = to_package_lock_v3(&test_plan(vec![]), &test_graph(vec![]), &root());
        assert_eq!(value["lockfileVersion"], 3);
        assert_eq!(value["name"], "my-proj");
        assert!(value["requires"].as_bool().unwrap());
        let packages = value["packages"].as_object().unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[""]["name"], "my-proj");
    }

    #[test]
    fn single_dependency_shape_matches_npm() {
        let plan = test_plan(vec![plan_node("node_modules/foo", "foo", "1.2.3")]);
        let graph = test_graph(vec![graph_node("foo", "1.2.3")]);
        let entry = &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/foo"];
        assert_eq!(entry["version"], "1.2.3");
        assert_eq!(
            entry["resolved"],
            "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz"
        );
        assert!(entry["integrity"].as_str().unwrap().starts_with("sha512-"));
        assert!(entry.get("dev").is_none());
        assert!(entry.get("link").is_none());
    }

    #[test]
    fn nested_paths_are_preserved_verbatim() {
        let plan = test_plan(vec![
            plan_node("node_modules/a", "a", "1.0.0"),
            plan_node("node_modules/a/node_modules/b", "b", "2.0.0"),
        ]);
        let graph = test_graph(vec![graph_node("a", "1.0.0"), graph_node("b", "2.0.0")]);
        let packages = to_package_lock_v3(&plan, &graph, &root())["packages"]
            .as_object()
            .unwrap()
            .clone();
        assert!(packages.contains_key("node_modules/a"));
        assert!(packages.contains_key("node_modules/a/node_modules/b"));
        assert_eq!(
            packages["node_modules/a/node_modules/b"]["version"],
            "2.0.0"
        );
    }

    #[test]
    fn dev_optional_and_install_script_flags() {
        let mut node = plan_node("node_modules/devfoo", "devfoo", "0.1.0");
        node.dev = true;
        node.has_install_script = true;
        let mut opt = plan_node("node_modules/optbar", "optbar", "0.2.0");
        opt.optional = true;
        let mut dev_opt = plan_node("node_modules/dev_opt", "dev_opt", "0.3.0");
        dev_opt.dev = true;
        dev_opt.optional = true;
        let plan = test_plan(vec![node, opt, dev_opt]);
        let graph = test_graph(vec![
            graph_node("devfoo", "0.1.0"),
            graph_node("optbar", "0.2.0"),
            graph_node("dev_opt", "0.3.0"),
        ]);
        let packages = to_package_lock_v3(&plan, &graph, &root())["packages"].clone();
        assert_eq!(packages["node_modules/devfoo"]["dev"], true);
        assert_eq!(packages["node_modules/devfoo"]["hasInstallScript"], true);
        assert_eq!(packages["node_modules/optbar"]["optional"], true);
        assert!(packages["node_modules/optbar"].get("dev").is_none());
        assert_eq!(packages["node_modules/dev_opt"]["devOptional"], true);
        assert!(packages["node_modules/dev_opt"].get("dev").is_none());
        assert!(packages["node_modules/dev_opt"].get("optional").is_none());
    }

    #[test]
    fn link_nodes_emit_npm_link_shape() {
        let mut node = plan_node("node_modules/w", "w", "1.0.0");
        node.link = true;
        node.target = Some("/tmp/proj/packages/w".to_string());
        let plan = test_plan(vec![node]);
        let graph = test_graph(vec![graph_node("w", "1.0.0")]);
        let packages = &to_package_lock_v3(&plan, &graph, &root())["packages"];
        let entry = &packages["node_modules/w"];
        assert_eq!(entry["link"], true);
        assert_eq!(entry["resolved"], "packages/w");
        assert!(entry.get("version").is_none());
        assert!(entry.get("integrity").is_none());
        // The link target itself is also recorded, or Arborist fails on
        // the next run with "Missing target in lock file".
        let target = &packages["packages/w"];
        assert_eq!(target["name"], "w");
        assert_eq!(target["version"], "1.0.0");
    }

    #[test]
    fn link_target_outside_project_stays_absolute() {
        let mut node = plan_node("node_modules/w", "w", "1.0.0");
        node.link = true;
        node.target = Some("/elsewhere/w".to_string());
        let plan = test_plan(vec![node]);
        let graph = test_graph(vec![]);
        let entry = &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/w"];
        assert_eq!(entry["resolved"], "/elsewhere/w");
    }

    #[test]
    fn peer_dependencies_and_meta_come_from_graph() {
        let plan = test_plan(vec![plan_node(
            "node_modules/needs-peer",
            "needs-peer",
            "3.0.0",
        )]);
        let mut gnode = graph_node("needs-peer", "3.0.0");
        gnode
            .peer_dependencies
            .insert("react".to_string(), "^18.0.0".to_string());
        gnode.optional_peers.insert("react".to_string());
        let graph = test_graph(vec![gnode]);
        let entry =
            &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/needs-peer"];
        assert_eq!(entry["peerDependencies"]["react"], "^18.0.0");
        assert_eq!(entry["peerDependenciesMeta"]["react"]["optional"], true);
    }

    #[test]
    fn dependency_edges_carry_resolved_versions() {
        let plan = test_plan(vec![
            plan_node("node_modules/a", "a", "1.0.0"),
            plan_node("node_modules/b", "b", "2.0.0"),
        ]);
        let mut anode = graph_node("a", "1.0.0");
        anode
            .dependencies
            .insert("b".to_string(), "b@2.0.0".to_string());
        let graph = test_graph(vec![anode, graph_node("b", "2.0.0")]);
        let entry = &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/a"];
        assert_eq!(entry["dependencies"]["b"], "2.0.0");
    }

    #[test]
    fn backslash_locations_are_normalized() {
        let plan = test_plan(vec![plan_node("node_modules\\win", "win", "1.0.0")]);
        let graph = test_graph(vec![graph_node("win", "1.0.0")]);
        let packages = to_package_lock_v3(&plan, &graph, &root())["packages"]
            .as_object()
            .unwrap()
            .clone();
        assert!(packages.contains_key("node_modules/win"));
    }

    #[test]
    fn location_keyed_graph_from_to_dep_graph() {
        // The natural caller pairs the writer with `plan.to_dep_graph()`,
        // which keys nodes by install location and stores dependency targets
        // as locations — not `name@version` keys.
        use crate::placement::PlacementEdge;
        let mut anode = plan_node("node_modules/a", "a", "1.0.0");
        anode.edges = vec![PlacementEdge {
            name: "b".to_string(),
            spec: "^2.0.0".to_string(),
            dependency_type: "prod".to_string(),
            target_location: Some("node_modules/b".to_string()),
            valid: true,
        }];
        let plan = test_plan(vec![anode, plan_node("node_modules/b", "b", "2.0.0")]);
        let graph = plan.to_dep_graph().unwrap();
        let value = to_package_lock_v3(&plan, &graph, &root());
        let entry = &value["packages"]["node_modules/a"];
        assert_eq!(entry["dependencies"]["b"], "2.0.0");
        assert_eq!(value["packages"]["node_modules/b"]["version"], "2.0.0");
    }

    #[test]
    fn optional_edges_go_under_optional_dependencies() {
        use crate::placement::PlacementEdge;
        let mut anode = plan_node("node_modules/a", "a", "1.0.0");
        anode.edges = vec![
            PlacementEdge {
                name: "b".to_string(),
                spec: "^2.0.0".to_string(),
                dependency_type: "prod".to_string(),
                target_location: Some("node_modules/b".to_string()),
                valid: true,
            },
            PlacementEdge {
                name: "c".to_string(),
                spec: "^3.0.0".to_string(),
                dependency_type: "optional".to_string(),
                target_location: Some("node_modules/c".to_string()),
                valid: true,
            },
        ];
        let plan = test_plan(vec![
            anode,
            plan_node("node_modules/b", "b", "2.0.0"),
            plan_node("node_modules/c", "c", "3.0.0"),
        ]);
        let graph = plan.to_dep_graph().unwrap();
        let entry = &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/a"];
        assert_eq!(entry["dependencies"]["b"], "2.0.0");
        assert!(entry["dependencies"].get("c").is_none());
        assert_eq!(entry["optionalDependencies"]["c"], "3.0.0");
    }

    #[test]
    fn edge_to_link_target_resolves_version_from_plan() {
        // to_dep_graph omits link nodes, but the plan still carries them: an
        // edge at a link target must resolve to the linked version, never to
        // a garbage spec derived from the path.
        use crate::placement::PlacementEdge;
        let mut anode = plan_node("node_modules/a", "a", "1.0.0");
        anode.edges = vec![PlacementEdge {
            name: "w".to_string(),
            spec: "file:../w".to_string(),
            dependency_type: "prod".to_string(),
            target_location: Some("node_modules/w".to_string()),
            valid: true,
        }];
        let mut link = plan_node("node_modules/w", "w", "9.9.9");
        link.link = true;
        link.target = Some("/tmp/proj/packages/w".to_string());
        let plan = test_plan(vec![anode, link]);
        let graph = plan.to_dep_graph().unwrap();
        let value = to_package_lock_v3(&plan, &graph, &root());
        assert_eq!(
            value["packages"]["node_modules/a"]["dependencies"]["w"],
            "9.9.9"
        );
        // And the link entry itself keeps npm's shape.
        let link_entry = &value["packages"]["node_modules/w"];
        assert_eq!(link_entry["link"], true);
        assert_eq!(link_entry["resolved"], "packages/w");
    }

    #[test]
    fn aliased_install_records_real_name() {
        // npm: `"number-check": "npm:is-number@7.0.0"` installs to
        // node_modules/number-check but records name: is-number, or a later
        // Arborist run misresolves the entry.
        let mut node = plan_node("node_modules/number-check", "is-number", "7.0.0");
        node.install_name = "number-check".to_string();
        let plan = test_plan(vec![node]);
        let graph = test_graph(vec![graph_node("is-number", "7.0.0")]);
        let entry =
            &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/number-check"];
        assert_eq!(entry["name"], "is-number");
        assert_eq!(entry["version"], "7.0.0");
    }

    #[test]
    fn non_aliased_install_omits_name() {
        let plan = test_plan(vec![plan_node("node_modules/foo", "foo", "1.2.3")]);
        let graph = test_graph(vec![graph_node("foo", "1.2.3")]);
        let entry = &to_package_lock_v3(&plan, &graph, &root())["packages"]["node_modules/foo"];
        assert!(entry.get("name").is_none());
    }

    #[test]
    fn output_round_trips_through_the_npm_importer() {
        // The importer implements npm's reading rules; if it reconstructs
        // the same package set from our output, the format is conformant.
        let plan = test_plan(vec![
            plan_node("node_modules/a", "a", "1.0.0"),
            plan_node("node_modules/a/node_modules/b", "b", "2.0.0"),
            plan_node("node_modules/@scope/c", "@scope/c", "3.0.0"),
        ]);
        let mut anode = graph_node("a", "1.0.0");
        anode
            .dependencies
            .insert("b".to_string(), "b@2.0.0".to_string());
        let graph = test_graph(vec![
            anode,
            graph_node("b", "2.0.0"),
            graph_node("@scope/c", "3.0.0"),
        ]);
        let mut r = root();
        r.dependencies.insert("a".to_string(), "^1.0.0".to_string());
        r.dependencies
            .insert("@scope/c".to_string(), "^3.0.0".to_string());

        let json = to_package_lock_json(&plan, &graph, &r);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        std::fs::write(&path, &json).unwrap();

        let imported = crate::import_npm_lockfile(&path).unwrap();
        for (name, version) in [("a", "1.0.0"), ("b", "2.0.0"), ("@scope/c", "3.0.0")] {
            let node = imported
                .get(&DepGraph::key(name, version))
                .unwrap_or_else(|| panic!("{name}@{version} missing after round-trip"));
            assert_eq!(node.version, version);
            assert!(node.integrity.as_deref().unwrap().starts_with("sha512-"));
        }
        // Dependency edge survived via ancestor-path resolution.
        let a = imported.get(&DepGraph::key("a", "1.0.0")).unwrap();
        assert_eq!(a.dependencies.get("b").map(String::as_str), Some("b@2.0.0"));
        // Roots came from packages[""].
        assert!(imported.roots.contains(&DepGraph::key("a", "1.0.0")));
        assert!(imported.roots.contains(&DepGraph::key("@scope/c", "3.0.0")));
    }
}
