//! Dependency resolver
//!
//! Level-parallel BFS: all packages at the same depth are fetched concurrently.
//! This turns N serial HTTP requests into ceil(depth) parallel batches.

use anyhow::{Context, Result};
use futures::future::join_all;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use node_semver::{Range, Version};
use oath_fetch::{Packument, RegistryClient, resolve_version};

use crate::git::{git_cache_file_name, is_git_spec, parse_git_spec, resolve_git_spec};
use crate::graph::{DepGraph, DepNode, PeerReport, PeerResolution};

/// Check if a package is compatible with the current platform.
/// os field uses npm convention: ["darwin", "linux"] = only these, ["!win32"] = all except win32
/// cpu field uses: ["x64", "arm64"] = only these, ["!ia32"] = all except ia32
fn is_platform_compatible(os: &[String], cpu: &[String]) -> bool {
    let current_os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "win32"
    } else {
        "unknown"
    };

    let current_cpu = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else {
        "unknown"
    };

    // Check OS compatibility
    if !os.is_empty() {
        let has_exclusions = os.iter().any(|s| s.starts_with('!'));
        if has_exclusions {
            // Exclusion mode: skip if current OS is excluded
            if os.iter().any(|s| s == &format!("!{}", current_os)) {
                return false;
            }
        } else {
            // Inclusion mode: must be in the list
            if !os.iter().any(|s| s == current_os) {
                return false;
            }
        }
    }

    // Check CPU compatibility
    if !cpu.is_empty() {
        let has_exclusions = cpu.iter().any(|s| s.starts_with('!'));
        if has_exclusions {
            if cpu.iter().any(|s| s == &format!("!{}", current_cpu)) {
                return false;
            }
        } else {
            if !cpu.iter().any(|s| s == current_cpu) {
                return false;
            }
        }
    }

    true
}

/// Resolution options
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// Include dev dependencies
    pub include_dev: bool,
    /// Include optional dependencies
    pub include_optional: bool,
    /// Maximum depth (prevent infinite recursion)
    pub max_depth: u32,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            include_dev: true,
            include_optional: true,
            max_depth: 256,
        }
    }
}

/// A dependency to resolve
#[derive(Debug, Clone)]
struct PendingDep {
    name: String,
    specifier: String,
    depth: u32,
    dev: bool,
    optional: bool,
    /// If this dep was specified via npm: alias, this is the alias name
    alias: Option<String>,
}

/// Find the highest resolved node whose install name and version satisfy a dependency.
fn find_matching_key(graph: &DepGraph, dep_name: &str, dep_spec: &str) -> Option<String> {
    let version_spec = parse_alias_spec(dep_spec)
        .map(|(_, spec)| spec)
        .unwrap_or_else(|| dep_spec.to_string());
    let range = version_spec.parse::<Range>().ok();

    let mut candidates: Vec<(&String, Version)> = graph
        .nodes
        .iter()
        .filter_map(|(key, node)| {
            let matches_name = node.alias.as_deref() == Some(dep_name) || node.name == dep_name;
            if !matches_name {
                return None;
            }

            let version = node.version.parse::<Version>().ok()?;
            if range
                .as_ref()
                .is_some_and(|range| !range.satisfies(&version))
            {
                return None;
            }

            Some((key, version))
        })
        .collect();

    candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));
    candidates.last().map(|(key, _)| (*key).clone())
}

#[cfg(test)]
fn test_node(name: &str, version: &str, alias: Option<&str>) -> DepNode {
    DepNode {
        name: name.to_string(),
        alias: alias.map(str::to_string),
        version: version.to_string(),
        resolved: format!("https://registry.example/{name}-{version}.tgz"),
        integrity: None,
        dependencies: HashMap::new(),
        has_install_script: false,
        dev: false,
        optional: false,
        peer_dependencies: HashMap::new(),
        optional_peers: HashSet::new(),
        resolved_peers: HashMap::new(),
    }
}

/// Parse an npm alias specifier like "npm:real-package@^1.0.0"
/// Returns (real_name, version_spec) or None if not an alias
fn parse_alias_spec(specifier: &str) -> Option<(String, String)> {
    let rest = specifier.strip_prefix("npm:")?; // after "npm:"
    // Handle scoped: npm:@scope/pkg@version
    if let Some(stripped) = rest.strip_prefix('@') {
        // Find second @ (version separator)
        if let Some(at_pos) = stripped.find('@').map(|p| p + 1) {
            let real_name = rest[..at_pos].to_string();
            let version = rest[at_pos + 1..].to_string();
            return Some((real_name, version));
        }
        // No version specified
        return Some((rest.to_string(), "latest".to_string()));
    }
    // Non-scoped: npm:pkg@version
    if let Some(at_pos) = rest.rfind('@')
        && at_pos > 0
    {
        let real_name = rest[..at_pos].to_string();
        let version = rest[at_pos + 1..].to_string();
        return Some((real_name, version));
    }
    Some((rest.to_string(), "latest".to_string()))
}

/// The dependency resolver
pub struct Resolver {
    client: RegistryClient,
    options: ResolveOptions,
    /// Cache of fetched packuments to avoid redundant requests
    packument_cache: Arc<RwLock<HashMap<String, Packument>>>,
    /// HTTP client for git dependency downloads
    http: reqwest::Client,
}

impl Resolver {
    pub fn new(client: RegistryClient, options: ResolveOptions) -> Self {
        let http = oath_fetch::http::client_builder()
            .and_then(|builder| {
                builder
                    .timeout(std::time::Duration::from_secs(60))
                    .build()
                    .map_err(Into::into)
            })
            .expect("failed to build reqwest client");
        Self {
            client,
            options,
            packument_cache: Arc::new(RwLock::new(HashMap::new())),
            http,
        }
    }

    /// Resolve all dependencies starting from a map of direct dependencies.
    ///
    /// Uses level-parallel BFS: all packages at depth N are fetched concurrently,
    /// then their deps form the batch for depth N+1.
    pub async fn resolve(
        &mut self,
        dependencies: &HashMap<String, String>,
        dev_dependencies: &HashMap<String, String>,
    ) -> Result<DepGraph> {
        let mut graph = DepGraph::new();
        let mut resolved: HashSet<String> = HashSet::new();

        // Current level of deps to process
        let mut current_level: Vec<PendingDep> = Vec::new();

        // Seed with direct dependencies
        for (name, spec) in dependencies {
            let (real_name, real_spec, alias) = if let Some((real, ver)) = parse_alias_spec(spec) {
                (real, ver, Some(name.clone()))
            } else {
                (name.clone(), spec.clone(), None)
            };
            current_level.push(PendingDep {
                name: real_name,
                specifier: real_spec,
                depth: 0,
                dev: false,
                optional: false,
                alias,
            });
        }

        if self.options.include_dev {
            for (name, spec) in dev_dependencies {
                let (real_name, real_spec, alias) =
                    if let Some((real, ver)) = parse_alias_spec(spec) {
                        (real, ver, Some(name.clone()))
                    } else {
                        (name.clone(), spec.clone(), None)
                    };
                current_level.push(PendingDep {
                    name: real_name,
                    specifier: real_spec,
                    depth: 0,
                    dev: true,
                    optional: false,
                    alias,
                });
            }
        }

        let mut packages_resolved = 0u32;

        // Process level by level
        while !current_level.is_empty() {
            // Deduplicate fetch targets: only fetch names we haven't cached yet
            let mut names_to_fetch: Vec<String> = Vec::new();
            {
                let cache = self.packument_cache.read().await;
                let mut seen = HashSet::new();
                for dep in &current_level {
                    if dep.depth > self.options.max_depth {
                        continue;
                    }
                    // Skip git deps -- they don't come from the npm registry
                    if is_git_spec(&dep.specifier) {
                        continue;
                    }
                    if !cache.contains_key(&dep.name) && seen.insert(dep.name.clone()) {
                        names_to_fetch.push(dep.name.clone());
                    }
                }
            }

            // Fetch all uncached packuments in parallel
            if !names_to_fetch.is_empty() {
                let fetches: Vec<_> = names_to_fetch
                    .iter()
                    .map(|name| {
                        let client = self.client.clone();
                        let name = name.clone();
                        async move {
                            let result = client.fetch_packument(&name).await;
                            (name, result)
                        }
                    })
                    .collect();

                let results = join_all(fetches).await;

                let mut cache = self.packument_cache.write().await;
                for (name, result) in results {
                    match result {
                        Ok(packument) => {
                            cache.insert(name, packument);
                        }
                        Err(e) => {
                            // Store error later when we try to use it
                            debug!("failed to fetch {name}: {e}");
                        }
                    }
                }
            }

            // Now resolve all deps in this level using cached packuments
            let mut next_level: Vec<PendingDep> = Vec::new();

            for pending in current_level {
                if pending.depth > self.options.max_depth {
                    warn!("max depth exceeded for {}", pending.name);
                    continue;
                }

                // Handle git dependencies (github:, git+https://, etc.)
                if is_git_spec(&pending.specifier) {
                    match self
                        .resolve_git_dep(
                            &pending,
                            &mut graph,
                            &mut resolved,
                            &mut next_level,
                            packages_resolved,
                        )
                        .await
                    {
                        Ok(count) => {
                            packages_resolved = count;
                        }
                        Err(e) => {
                            if pending.optional {
                                debug!("skipping optional git dep {}: {e}", pending.name);
                            } else {
                                return Err(e).with_context(|| {
                                    format!(
                                        "resolving git dep {}@{}",
                                        pending.name, pending.specifier
                                    )
                                });
                            }
                        }
                    }
                    continue;
                }

                // Get packument from cache
                let cache = self.packument_cache.read().await;
                let packument = match cache.get(&pending.name) {
                    Some(p) => p.clone(),
                    None => {
                        if pending.optional {
                            debug!("skipping optional dep {}: fetch failed", pending.name);
                            continue;
                        }
                        return Err(anyhow::anyhow!(
                            "failed to fetch packument for {}",
                            pending.name
                        ));
                    }
                };
                drop(cache);

                // Resolve version
                let resolved_version = match resolve_version(&packument, &pending.specifier) {
                    Ok(v) => v,
                    Err(e) => {
                        if pending.optional {
                            debug!("skipping optional dep {}: {e}", pending.name);
                            continue;
                        }
                        return Err(e).with_context(|| {
                            format!("resolving {}@{}", pending.name, pending.specifier)
                        });
                    }
                };

                let key = DepGraph::key(
                    pending.alias.as_deref().unwrap_or(&pending.name),
                    resolved_version.version,
                );

                // Skip if already resolved
                if resolved.contains(&key) {
                    continue;
                }
                resolved.insert(key.clone());

                // Track root deps
                if pending.depth == 0 {
                    graph.roots.push(key.clone());
                }

                packages_resolved += 1;
                if packages_resolved.is_multiple_of(50) {
                    info!("resolved {packages_resolved} packages...");
                }

                let info = resolved_version.info;

                // Skip platform-incompatible packages (only for optional deps)
                if pending.optional && !is_platform_compatible(&info.os, &info.cpu) {
                    debug!(
                        "skipping {} (platform mismatch: os={:?} cpu={:?})",
                        pending.name, info.os, info.cpu
                    );
                    continue;
                }

                // Build dependency map for this node
                let mut node_deps = HashMap::new();

                // Queue production dependencies for next level
                for (dep_name, dep_spec) in &info.dependencies {
                    node_deps.insert(dep_name.clone(), dep_spec.clone());

                    let (real_dep_name, real_dep_spec, dep_alias) =
                        if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                            (real, ver, Some(dep_name.clone()))
                        } else {
                            (dep_name.clone(), dep_spec.clone(), None)
                        };

                    next_level.push(PendingDep {
                        name: real_dep_name,
                        specifier: real_dep_spec,
                        depth: pending.depth + 1,
                        dev: pending.dev,
                        optional: false,
                        alias: dep_alias,
                    });
                }

                // Queue optional dependencies
                if self.options.include_optional {
                    for (dep_name, dep_spec) in &info.optional_dependencies {
                        node_deps.insert(dep_name.clone(), dep_spec.clone());

                        let (real_dep_name, real_dep_spec, dep_alias) =
                            if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                                (real, ver, Some(dep_name.clone()))
                            } else {
                                (dep_name.clone(), dep_spec.clone(), None)
                            };

                        next_level.push(PendingDep {
                            name: real_dep_name,
                            specifier: real_dep_spec,
                            depth: pending.depth + 1,
                            dev: pending.dev,
                            optional: true,
                            alias: dep_alias,
                        });
                    }
                }

                // Capture peer dependency declarations for the post-BFS pass
                let peer_dependencies: std::collections::HashMap<String, String> =
                    info.peer_dependencies.clone();
                let optional_peers: std::collections::HashSet<String> = info
                    .peer_dependencies_meta
                    .iter()
                    .filter(|(_, meta)| meta.optional)
                    .map(|(name, _)| name.clone())
                    .collect();

                // Insert node into graph
                graph.nodes.insert(
                    key,
                    DepNode {
                        name: pending.name.clone(),
                        alias: pending.alias.clone(),
                        version: resolved_version.version.to_string(),
                        resolved: info.dist.tarball.clone(),
                        integrity: info.dist.integrity.clone(),
                        dependencies: node_deps,
                        has_install_script: info.has_install_script,
                        dev: pending.dev,
                        optional: pending.optional,
                        peer_dependencies,
                        optional_peers,
                        resolved_peers: std::collections::HashMap::new(),
                    },
                );
            }

            current_level = next_level;
        }

        // Fix up dependency maps: resolve spec strings to actual "name@version" keys.
        // Multiple versions of one package may coexist, so each edge must retain
        // the version constraint declared by its parent.
        let mut fixups: Vec<(String, HashMap<String, String>)> = Vec::new();

        for (node_key, node) in &graph.nodes {
            let mut resolved_deps: HashMap<String, String> = HashMap::new();
            for (dep_name, dep_spec) in &node.dependencies {
                // The dep_spec might be a semver range like "~2.0.0" or "^1.3.8"
                // Find the node in the graph that has this name and satisfies the spec
                let resolved_key = find_matching_key(&graph, dep_name, dep_spec);
                if let Some(rk) = resolved_key {
                    resolved_deps.insert(dep_name.clone(), rk);
                }
                // If not found (optional dep that was skipped), just drop it
            }
            fixups.push((node_key.clone(), resolved_deps));
        }

        for (key, deps) in fixups {
            if let Some(node) = graph.nodes.get_mut(&key) {
                node.dependencies = deps;
            }
        }

        info!("resolution complete: {} packages", graph.package_count());

        // Post-BFS peer resolution pass
        graph.peer_report = resolve_peers(&mut graph);

        Ok(graph)
    }

    /// Resolve a git dependency and add it to the graph.
    /// Returns the updated packages_resolved count.
    async fn resolve_git_dep(
        &self,
        pending: &PendingDep,
        graph: &mut DepGraph,
        resolved: &mut HashSet<String>,
        next_level: &mut Vec<PendingDep>,
        mut packages_resolved: u32,
    ) -> Result<u32> {
        let spec = match parse_git_spec(&pending.specifier) {
            Some(s) => s,
            None => {
                anyhow::bail!("failed to parse git spec: {}", pending.specifier);
            }
        };

        info!("resolving git dep {}@{}", pending.name, pending.specifier);

        let git_resolved = resolve_git_spec(&spec, &self.http)
            .await
            .with_context(|| format!("fetching git dep {}@{}", pending.name, pending.specifier))?;

        // Use the resolved name from package.json (may differ from the dep name in package.json)
        // but use pending.name (or alias) as the install name for the node
        let install_name = pending.alias.as_deref().unwrap_or(&pending.name);
        let key = DepGraph::key(install_name, &git_resolved.version);

        // Skip if already resolved
        if resolved.contains(&key) {
            return Ok(packages_resolved);
        }
        resolved.insert(key.clone());

        if pending.depth == 0 {
            graph.roots.push(key.clone());
        }

        packages_resolved += 1;
        if packages_resolved.is_multiple_of(50) {
            info!("resolved {packages_resolved} packages...");
        }

        // Build dependency map for this node (raw specs, will be fixed up later)
        let mut node_deps = HashMap::new();
        for (dep_name, dep_spec) in &git_resolved.dependencies {
            node_deps.insert(dep_name.clone(), dep_spec.clone());
            let (real_dep_name, real_dep_spec, dep_alias) =
                if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                    (real, ver, Some(dep_name.clone()))
                } else {
                    (dep_name.clone(), dep_spec.clone(), None)
                };
            next_level.push(PendingDep {
                name: real_dep_name,
                specifier: real_dep_spec,
                depth: pending.depth + 1,
                dev: pending.dev,
                optional: false,
                alias: dep_alias,
            });
        }

        if self.options.include_optional {
            for (dep_name, dep_spec) in &git_resolved.optional_dependencies {
                node_deps.insert(dep_name.clone(), dep_spec.clone());
                let (real_dep_name, real_dep_spec, dep_alias) =
                    if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                        (real, ver, Some(dep_name.clone()))
                    } else {
                        (dep_name.clone(), dep_spec.clone(), None)
                    };
                next_level.push(PendingDep {
                    name: real_dep_name,
                    specifier: real_dep_spec,
                    depth: pending.depth + 1,
                    dev: pending.dev,
                    optional: true,
                    alias: dep_alias,
                });
            }
        }

        // Insert node with resolved_url set to the git URL (used later for download)
        graph.nodes.insert(
            key,
            DepNode {
                name: git_resolved.name.clone(),
                alias: pending.alias.clone(),
                version: git_resolved.version.clone(),
                resolved: git_resolved.resolved_url.clone(),
                integrity: None,
                dependencies: node_deps,
                has_install_script: git_resolved.has_install_script,
                dev: pending.dev,
                optional: pending.optional,
                peer_dependencies: HashMap::new(),
                optional_peers: std::collections::HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );

        // Save the tarball bytes to a local git cache so the CLI download loop can use them
        // without re-fetching from the network.
        // Path: ~/.oath/git-cache/{safe_name}-{version}.tgz
        let home = oath_core::home_dir().unwrap_or_else(std::env::temp_dir);
        let cache_dir = home.join(".oath").join("git-cache");
        std::fs::create_dir_all(&cache_dir).ok();
        let cache_file = cache_dir.join(git_cache_file_name(
            &git_resolved.name,
            &git_resolved.version,
            &git_resolved.resolved_url,
        ));
        if !cache_file.exists() {
            std::fs::write(&cache_file, &git_resolved.tarball_data).with_context(|| {
                format!("failed to cache git tarball at {}", cache_file.display())
            })?;
        }

        Ok(packages_resolved)
    }
}

// ---------------------------------------------------------------------------
// Peer dependency resolution helpers
// ---------------------------------------------------------------------------

/// Check if a version string satisfies a semver range string.
/// Returns true if the range is unparseable (be lenient).
fn semver_satisfies(version: &str, range: &str) -> bool {
    // Strip pre-release build metadata before parsing
    let version_clean = version.split('+').next().unwrap_or(version);
    let v = match version_clean.parse::<Version>() {
        Ok(v) => v,
        Err(_) => return true, // unparseable version -> assume ok
    };
    let r = match range.parse::<Range>() {
        Ok(r) => r,
        Err(_) => return true, // unparseable range -> assume ok
    };
    r.satisfies(&v)
}

/// Build a map of child_key -> list of parent_keys that directly depend on it.
fn build_parent_map(graph: &DepGraph) -> HashMap<String, Vec<String>> {
    let mut parents: HashMap<String, Vec<String>> = HashMap::new();
    for (parent_key, parent_node) in &graph.nodes {
        for dep_key in parent_node.dependencies.values() {
            parents
                .entry(dep_key.clone())
                .or_default()
                .push(parent_key.clone());
        }
    }
    parents
}

enum PeerLookupResult {
    Found(String),    // peer key that satisfies the range
    Conflict(String), // peer found but version doesn't satisfy
    Missing,
}

/// Walk up the dependency chain from `pkg_key` looking for `peer_name`.
fn find_peer_in_context(
    graph: &DepGraph,
    parents: &HashMap<String, Vec<String>>,
    pkg_key: &str,
    peer_name: &str,
    peer_range: &str,
) -> PeerLookupResult {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Start by looking at direct parents of pkg_key
    if let Some(parent_keys) = parents.get(pkg_key) {
        for p in parent_keys {
            queue.push_back(p.clone());
        }
    }

    // Also check the roots directly (consumer's direct deps)
    // because root packages may not appear as another node's dependency
    for root_key in &graph.roots {
        queue.push_back(root_key.clone());
    }

    while let Some(ancestor_key) = queue.pop_front() {
        if !visited.insert(ancestor_key.clone()) {
            continue;
        }

        let ancestor = match graph.nodes.get(&ancestor_key) {
            Some(n) => n,
            None => continue,
        };

        // Does this ancestor have peer_name as a resolved dependency?
        if let Some(resolved_key) = ancestor.dependencies.get(peer_name) {
            // Extract version from "name@version" or "@scope/name@version"
            let found_version = extract_version_from_key(resolved_key);
            if semver_satisfies(found_version, peer_range) {
                return PeerLookupResult::Found(resolved_key.clone());
            } else {
                return PeerLookupResult::Conflict(found_version.to_string());
            }
        }

        // Walk further up
        if let Some(grandparents) = parents.get(&ancestor_key) {
            for gp in grandparents {
                if !visited.contains(gp) {
                    queue.push_back(gp.clone());
                }
            }
        }
    }

    // Check roots by name directly (peer_name matches install_name or node.name)
    for root_key in &graph.roots {
        let root_node = match graph.nodes.get(root_key) {
            Some(n) => n,
            None => continue,
        };
        let install_name = root_node.alias.as_deref().unwrap_or(&root_node.name);
        if install_name == peer_name || root_node.name == peer_name {
            if semver_satisfies(&root_node.version, peer_range) {
                return PeerLookupResult::Found(root_key.clone());
            } else {
                return PeerLookupResult::Conflict(root_node.version.clone());
            }
        }
    }

    PeerLookupResult::Missing
}

/// Extract the version portion from a "name@version" or "@scope/name@version" key
fn extract_version_from_key(key: &str) -> &str {
    // For scoped packages like "@scope/name@1.0.0", the last '@' splits name from version
    if let Some(at) = key.rfind('@')
        && at > 0
    {
        return &key[at + 1..];
    }
    key
}

/// Run the post-BFS peer resolution pass. Populates `resolved_peers` on each DepNode
/// and returns a PeerReport describing what was found/missing/conflicting.
fn resolve_peers(graph: &mut DepGraph) -> PeerReport {
    let mut report = PeerReport::default();
    let parents = build_parent_map(graph);

    // Collect all (key, peer_name, peer_range, is_optional) tuples to avoid borrow issues
    let work: Vec<(String, String, String, bool)> = graph
        .nodes
        .iter()
        .flat_map(|(key, node)| {
            node.peer_dependencies.iter().map(move |(pname, prange)| {
                let optional = node.optional_peers.contains(pname);
                (key.clone(), pname.clone(), prange.clone(), optional)
            })
        })
        .collect();

    for (pkg_key, peer_name, peer_range, is_optional) in work {
        let result = find_peer_in_context(graph, &parents, &pkg_key, &peer_name, &peer_range);
        match result {
            PeerLookupResult::Found(peer_key) => {
                if let Some(node) = graph.nodes.get_mut(&pkg_key) {
                    node.resolved_peers
                        .insert(peer_name.clone(), peer_key.clone());
                }
                report.satisfied.push(PeerResolution::Satisfied {
                    required_by: pkg_key.clone(),
                    peer_name,
                    peer_key,
                });
            }
            PeerLookupResult::Missing => {
                if is_optional {
                    report.optional_missing.push(peer_name);
                } else {
                    report.missing.push(PeerResolution::Missing {
                        required_by: pkg_key,
                        peer_name,
                        range: peer_range,
                    });
                }
            }
            PeerLookupResult::Conflict(found_version) => {
                if is_optional {
                    // Conflict on an optional peer: warn but don't error
                    report.conflicts.push(PeerResolution::Conflict {
                        required_by: pkg_key,
                        peer_name,
                        range: peer_range,
                        found_version,
                    });
                } else {
                    report.conflicts.push(PeerResolution::Conflict {
                        required_by: pkg_key,
                        peer_name,
                        range: peer_range,
                        found_version,
                    });
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_edges_select_the_version_that_satisfies_the_parent_spec() {
        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "@esbuild/darwin-arm64@0.28.1".to_string(),
            test_node("@esbuild/darwin-arm64", "0.28.1", None),
        );
        graph.nodes.insert(
            "@esbuild/darwin-arm64@0.27.0".to_string(),
            test_node("@esbuild/darwin-arm64", "0.27.0", None),
        );

        assert_eq!(
            find_matching_key(&graph, "@esbuild/darwin-arm64", "0.27.0").as_deref(),
            Some("@esbuild/darwin-arm64@0.27.0")
        );
        assert_eq!(
            find_matching_key(&graph, "@esbuild/darwin-arm64", "0.28.1").as_deref(),
            Some("@esbuild/darwin-arm64@0.28.1")
        );
    }

    #[test]
    fn dependency_edges_choose_highest_satisfying_version_and_preserve_aliases() {
        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "tool@1.2.0".to_string(),
            test_node("real-tool", "1.2.0", Some("tool")),
        );
        graph.nodes.insert(
            "tool@1.9.0".to_string(),
            test_node("real-tool", "1.9.0", Some("tool")),
        );
        graph.nodes.insert(
            "tool@2.0.0".to_string(),
            test_node("real-tool", "2.0.0", Some("tool")),
        );

        assert_eq!(
            find_matching_key(&graph, "tool", "npm:real-tool@^1.0.0").as_deref(),
            Some("tool@1.9.0")
        );
    }
}
