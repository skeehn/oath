//! Linker: hardlink from global store into project node_modules
//!
//! Creates the pnpm-style layout:
//!   node_modules/
//!     .oath/           <- hidden dir with the real packages
//!       express@4.18.2/
//!         node_modules/
//!           express/ -> hardlinks to store files
//!           accepts/ -> hardlinks to its dep
//!     express/        <- symlink to .oath/express@4.18.2/node_modules/express
//!
//! Supports nested node_modules for version conflicts:
//!   node_modules/
//!     foo/            <- hoisted (most common version)
//!     bar/
//!       node_modules/
//!         foo/        <- nested (different version required by bar)

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::cas::ContentStore;
use oath_resolve::graph::{DepGraph, DepNode};
use oath_resolve::placement::PlacementPlan;

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn collect_junction_rebase_plan(root: &Path) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    fn visit(
        root: &Path,
        canonical_root: &Path,
        dir: &Path,
        plan: &mut Vec<(PathBuf, PathBuf)>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                let target = std::fs::read_link(&path)?.canonicalize()?;
                if let (Ok(link), Ok(target)) =
                    (path.strip_prefix(root), target.strip_prefix(canonical_root))
                {
                    plan.push((link.to_path_buf(), target.to_path_buf()));
                }
            } else if file_type.is_dir() {
                visit(root, canonical_root, &path, plan)?;
            }
        }
        Ok(())
    }

    let mut plan = Vec::new();
    let canonical_root = root.canonicalize()?;
    visit(root, &canonical_root, root, &mut plan)?;
    Ok(plan)
}

#[cfg(windows)]
fn rebase_junctions(root: &Path, plan: &[(PathBuf, PathBuf)]) -> std::io::Result<()> {
    for (link, target) in plan {
        let link = root.join(link);
        std::fs::remove_dir(&link)?;
        symlink_dir(&root.join(target), &link)?;
    }
    Ok(())
}

#[cfg(windows)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link.parent().unwrap_or_else(|| Path::new(".")).join(target)
    };
    let target = target.canonicalize()?;
    let target_text = target.to_string_lossy();
    let target = target_text
        .strip_prefix(r"\\?\")
        .unwrap_or(&target_text)
        .replace('/', r"\");
    let link = link.to_string_lossy().replace('/', r"\");
    let output = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "failed to create junction: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    oath_resolve::placement::link_package_binary(target, link)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

/// Links resolved packages into a project's node_modules
pub struct Linker {
    store: ContentStore,
}

/// Plan for how to lay out packages in node_modules
struct LinkPlan {
    /// install_name -> key of the version to hoist to top-level
    hoisted: BTreeMap<String, String>,
    /// (parent_key, install_name, child_key) for nested deps
    nested: Vec<(String, String, String)>,
}

fn recover_link_transaction(live: &Path, stage: &Path, backup: &Path) -> Result<()> {
    if backup.exists() {
        if live.exists() {
            std::fs::remove_dir_all(backup)
                .context("failed to remove committed node_modules backup")?;
        } else {
            std::fs::rename(backup, live)
                .context("failed to restore interrupted node_modules transaction")?;
        }
    }
    if stage.exists() {
        std::fs::remove_dir_all(stage).context("failed to clean interrupted node_modules stage")?;
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        #[cfg(windows)]
        if std::fs::metadata(path).is_ok_and(|target| target.is_dir()) {
            return std::fs::remove_dir(path);
        }
        return std::fs::remove_file(path);
    }
    if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn validated_workspace_target(project_dir: &Path, target: &Path) -> Result<PathBuf> {
    let project = std::fs::canonicalize(project_dir).context("resolve workspace project root")?;
    let candidate = if target.is_absolute() {
        target.to_path_buf()
    } else {
        project_dir.join(target)
    };

    match std::fs::canonicalize(&candidate) {
        Ok(canonical) => {
            anyhow::ensure!(
                canonical.starts_with(&project),
                "workspace link escapes project: {}",
                target.display()
            );
            Ok(canonical)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut ancestor = candidate.parent();
            while let Some(path) = ancestor {
                match std::fs::canonicalize(path) {
                    Ok(canonical) => {
                        anyhow::ensure!(
                            canonical.starts_with(&project),
                            "workspace link escapes project: {}",
                            target.display()
                        );
                        return Ok(candidate);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ancestor = path.parent();
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("resolve workspace link ancestor {}", path.display())
                        });
                    }
                }
            }
            anyhow::bail!("workspace link has no existing project ancestor")
        }
        Err(error) => Err(error)
            .with_context(|| format!("resolve workspace link target {}", target.display())),
    }
}

impl Linker {
    pub fn new(store: ContentStore) -> Self {
        Self { store }
    }

    /// Materialize Arborist's exact physical locations from verified CAS entries.
    /// Arborist never writes package contents; Oath retains the atomic link boundary.
    pub fn link_placement_plan(
        &self,
        plan: &PlacementPlan,
        project_dir: &Path,
    ) -> Result<LinkResult> {
        self.link_placement_plan_inner(plan, project_dir, true)
    }

    /// Materialize Arborist's locations without preserving an existing
    /// node_modules tree. Used by `oath ci`, which must behave like a clean
    /// install and remove extraneous entries.
    pub fn link_placement_plan_clean(
        &self,
        plan: &PlacementPlan,
        project_dir: &Path,
    ) -> Result<LinkResult> {
        self.link_placement_plan_inner(plan, project_dir, false)
    }

    fn link_placement_plan_inner(
        &self,
        plan: &PlacementPlan,
        project_dir: &Path,
        preserve_existing: bool,
    ) -> Result<LinkResult> {
        let live = project_dir.join("node_modules");
        let stage = project_dir.join(".oath-node_modules-stage");
        let backup = project_dir.join(".oath-node_modules-backup");
        recover_link_transaction(&live, &stage, &backup)?;
        if preserve_existing && live.exists() {
            // npm's reifier preserves package contents it classifies as
            // unchanged (notably checked-in root bundles). Seed the atomic
            // stage from the live tree, then apply Arborist's explicit
            // remove/add/change plan below.
            hardlink_dir(&live, &stage)?;
        }
        std::fs::create_dir_all(stage.join(".oath"))?;
        for location in &plan.removed_locations {
            let relative = Path::new(location)
                .strip_prefix("node_modules")
                .with_context(|| format!("invalid removal location {location}"))?;
            remove_existing_path(&stage.join(relative))
                .with_context(|| format!("remove stale placement {location}"))?;
        }
        let mut result = LinkResult::default();
        for node in &plan.nodes {
            let relative = Path::new(&node.location)
                .strip_prefix("node_modules")
                .with_context(|| format!("invalid placement location {}", node.location))?;
            anyhow::ensure!(
                !relative.as_os_str().is_empty()
                    && relative.components().all(|part| !matches!(
                        part,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )),
                "unsafe placement location {}",
                node.location
            );
            let destination = stage.join(relative);
            if node.link {
                remove_existing_path(&destination).with_context(|| {
                    format!("replace existing workspace link {}", node.location)
                })?;
                let target = node
                    .target
                    .as_ref()
                    .context("Arborist link node has no target")?;
                let target = validated_workspace_target(project_dir, Path::new(target))?;
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                symlink_dir(&target, &destination)?;
                result.symlinks += 1;
                continue;
            }
            if preserve_existing && node.reuse_existing {
                let existing = live.join(relative);
                anyhow::ensure!(
                    existing.is_dir(),
                    "Arborist marked missing placement unchanged: {}",
                    node.location
                );
                remove_existing_path(&destination)
                    .with_context(|| format!("restore unchanged placement {}", node.location))?;
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                hardlink_dir(&existing, &destination)?;
                result.linked += 1;
            } else {
                remove_existing_path(&destination)
                    .with_context(|| format!("replace changed placement {}", node.location))?;
                let source = self.store.package_dir_for(
                    &node.name,
                    &node.version,
                    node.resolved.as_deref(),
                    node.integrity.as_deref(),
                );
                anyhow::ensure!(
                    source.exists(),
                    "planned package missing from verified store: {}@{}",
                    node.name,
                    node.version
                );
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                hardlink_dir(&source, &destination)?;
                result.linked += 1;
            }

            let install_name = node.install_name.as_str();
            let bins = read_bin_entries(&destination.join("package.json"), install_name);
            let node_modules = destination
                .parent()
                .context("placement has no node_modules parent")?;
            let bin_dir = node_modules.join(".bin");
            for (bin_name, bin_path) in bins {
                let target = destination.join(&bin_path);
                if !target.exists() {
                    continue;
                }
                std::fs::create_dir_all(&bin_dir)?;
                let link = bin_dir.join(bin_name);
                if !link.exists() {
                    symlink_file(&pathdiff_relative(&link, &target), &link)?;
                    result.bins += 1;
                }
            }
        }
        std::fs::write(
            stage.join(".oath").join("placement-plan.json"),
            serde_json::to_vec(plan)?,
        )?;
        if live.exists() {
            std::fs::rename(&live, &backup).context("failed to stage existing node_modules")?;
        }
        if let Err(error) = std::fs::rename(&stage, &live) {
            if backup.exists() && !live.exists() {
                let _ = std::fs::rename(&backup, &live);
            }
            return Err(error).context("failed to promote Arborist placement");
        }
        if backup.exists() {
            std::fs::remove_dir_all(&backup).context("failed to remove node_modules backup")?;
        }
        Ok(result)
    }

    /// Analyze the graph and build a hoisting plan.
    /// Groups packages by install_name, picks the most commonly depended-on
    /// version to hoist, and nests the rest under their dependents.
    fn build_plan(&self, graph: &DepGraph) -> LinkPlan {
        // Step 1: Group all nodes by install_name -> list of keys
        let mut by_install_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, node) in &graph.nodes {
            let install_name = node.alias.as_deref().unwrap_or(&node.name).to_string();
            by_install_name
                .entry(install_name)
                .or_default()
                .push(key.clone());
        }

        // Step 2: For each install_name, pick the most common version to hoist.
        // "Most common" = referenced by the most packages in their dependencies.
        let mut hoisted: BTreeMap<String, String> = BTreeMap::new();

        // Count how many times each key is referenced as a dependency
        let mut ref_counts: HashMap<String, usize> = HashMap::new();
        for node in graph.nodes.values() {
            for dep_key in node.dependencies.values() {
                *ref_counts.entry(dep_key.clone()).or_insert(0) += 1;
            }
        }
        // Root deps also count
        for root_key in &graph.roots {
            *ref_counts.entry(root_key.clone()).or_insert(0) += 1;
        }

        for (install_name, keys) in &by_install_name {
            if keys.len() == 1 {
                // No conflict, hoist the only version
                hoisted.insert(install_name.clone(), keys[0].clone());
            } else {
                // Multiple versions: pick the one with highest ref count.
                // Ties break lexicographically so layout is deterministic.
                let best = keys
                    .iter()
                    .max_by(|a, b| {
                        let a_count = ref_counts.get(*a).copied().unwrap_or(0);
                        let b_count = ref_counts.get(*b).copied().unwrap_or(0);
                        a_count.cmp(&b_count).then_with(|| b.cmp(a))
                    })
                    .unwrap()
                    .clone();
                hoisted.insert(install_name.clone(), best);
            }
        }

        // Step 3: Build nested list. For each dependency reference that points
        // to a non-hoisted version, nest it under the parent.
        let mut nested: Vec<(String, String, String)> = Vec::new();

        for (parent_key, parent_node) in &graph.nodes {
            for (dep_name, dep_key) in &parent_node.dependencies {
                // Determine the install_name for this dep
                let dep_install_name = if let Some(dep_node) = graph.nodes.get(dep_key) {
                    dep_node
                        .alias
                        .as_deref()
                        .unwrap_or(&dep_node.name)
                        .to_string()
                } else {
                    dep_name.clone()
                };

                // Check if this dep_key is the hoisted version
                let is_hoisted = hoisted
                    .get(&dep_install_name)
                    .map(|h| h == dep_key)
                    .unwrap_or(false);

                if !is_hoisted {
                    // This dep needs to be nested under parent
                    nested.push((parent_key.clone(), dep_install_name, dep_key.clone()));
                }
            }
        }

        nested.sort();

        LinkPlan { hoisted, nested }
    }

    /// Link an entire resolved dependency graph into project_dir/node_modules
    pub fn link_all(&self, graph: &DepGraph, project_dir: &Path) -> Result<LinkResult> {
        validate_graph_path_names(graph)?;

        let live_nm_dir = project_dir.join("node_modules");
        let stage_nm_dir = project_dir.join(".oath-node_modules-stage");
        let backup_nm_dir = project_dir.join(".oath-node_modules-backup");

        // Recover a commit interrupted between moving the old tree aside and
        // promoting the verified staged tree. A live tree always wins; without
        // one, the backup is restored before any new work starts.
        recover_link_transaction(&live_nm_dir, &stage_nm_dir, &backup_nm_dir)?;

        // No-op fast path: if the previous link's manifest matches this graph
        // exactly and node_modules is present, skip the nuke-and-rebuild.
        let live_manifest_path = live_nm_dir.join(".oath").join(".link-manifest");
        let manifest = link_manifest(graph);
        if live_nm_dir.exists()
            && std::fs::read_to_string(&live_manifest_path)
                .map(|prev| prev == manifest)
                .unwrap_or(false)
        {
            return Ok(LinkResult {
                linked: graph.nodes.len(),
                ..Default::default()
            });
        }

        // Construct the complete replacement away from the live path. Package
        // contents, links, shims, and manifest must all succeed before commit.
        let nm_dir = stage_nm_dir.clone();
        let oath_dir = nm_dir.join(".oath");
        let manifest_path = oath_dir.join(".link-manifest");
        std::fs::create_dir_all(&oath_dir).context("failed to create node_modules/.oath")?;

        let mut result = LinkResult::default();

        // Build the hoisting plan
        let plan = self.build_plan(graph);

        // Phase 1: Link each package into .oath/{key}/node_modules/{install_name}
        for (key, node) in &graph.nodes {
            let pkg_store_dir = self.store.package_dir_for(
                &node.name,
                &node.version,
                Some(&node.resolved),
                node.integrity.as_deref(),
            );
            if !pkg_store_dir.exists() {
                tracing::warn!("package not in store: {key}");
                result.missing += 1;
                continue;
            }

            let install_name = node.alias.as_deref().unwrap_or(&node.name);
            let virtual_key = virtual_key_component(key);
            let virtual_dir = oath_dir
                .join(&virtual_key)
                .join("node_modules")
                .join(install_name);
            std::fs::create_dir_all(virtual_dir.parent().unwrap())?;

            // Hardlink all files from store into virtual dir
            hardlink_dir(&pkg_store_dir, &virtual_dir)?;
            result.linked += 1;
        }

        // Phase 2: Create top-level symlinks for hoisted packages
        for (install_name, key) in &plan.hoisted {
            if !graph.nodes.contains_key(key) {
                continue;
            }

            // Scoped packages (@scope/name) live at node_modules/@scope/name,
            // so the symlink's parent dir is node_modules/@scope/ -- one level deeper.
            // Relative symlink target must go up one extra level with "../"
            let symlink_target = if install_name.contains('/') {
                PathBuf::from("..")
                    .join(".oath")
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(install_name)
            } else {
                PathBuf::from(".oath")
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(install_name)
            };
            let symlink_path = nm_dir.join(install_name);

            // Handle scoped packages: ensure @scope dir exists
            if install_name.contains('/')
                && let Some(scope) = install_name.split('/').next()
            {
                std::fs::create_dir_all(nm_dir.join(scope))?;
            }

            // Create relative symlink
            symlink_dir(&symlink_target, &symlink_path).with_context(|| {
                format!(
                    "failed to symlink {} -> {}",
                    symlink_path.display(),
                    symlink_target.display()
                )
            })?;
            result.symlinks += 1;
        }

        // Phase 3: Create nested node_modules for version conflicts
        for (parent_key, install_name, child_key) in &plan.nested {
            let parent_node = match graph.nodes.get(parent_key) {
                Some(n) => n,
                None => continue,
            };
            if !graph.nodes.contains_key(child_key) {
                continue;
            }

            let parent_install_name = parent_node.alias.as_deref().unwrap_or(&parent_node.name);

            // Create the nested dependency inside the package's real virtual dir.
            // The top-level package symlink exposes the same path to callers, while
            // this avoids hand-counting relative paths through an intermediate symlink.
            let parent_pkg_dir = oath_dir
                .join(virtual_key_component(parent_key))
                .join("node_modules")
                .join(parent_install_name);
            if !parent_pkg_dir.exists() {
                continue;
            }
            let nested_nm_dir = parent_pkg_dir.join("node_modules");
            // Handle scoped nested dependency packages
            if install_name.contains('/') {
                if let Some(scope) = install_name.split('/').next() {
                    std::fs::create_dir_all(nested_nm_dir.join(scope))?;
                }
            } else {
                std::fs::create_dir_all(&nested_nm_dir)?;
            }

            let nested_symlink = nested_nm_dir.join(install_name);
            let source = oath_dir
                .join(virtual_key_component(child_key))
                .join("node_modules")
                .join(install_name);
            if !source.exists() {
                continue;
            }
            let rel_target = pathdiff_relative(&nested_symlink, &source);

            if !nested_symlink.exists() {
                symlink_dir(&rel_target, &nested_symlink).with_context(|| {
                    format!(
                        "failed to create nested symlink {} -> {}",
                        nested_symlink.display(),
                        rel_target.display()
                    )
                })?;
                result.nested += 1;
            }
        }

        // Phase 4: Link transitive deps within each package's .oath node_modules
        for (key, node) in &graph.nodes {
            for (dep_name, dep_key) in &node.dependencies {
                // Determine install name for the dep
                let dep_install_name = if let Some(dep_node) = graph.nodes.get(dep_key) {
                    dep_node
                        .alias
                        .as_deref()
                        .unwrap_or(&dep_node.name)
                        .to_string()
                } else {
                    dep_name.clone()
                };

                let source = oath_dir
                    .join(virtual_key_component(dep_key))
                    .join("node_modules")
                    .join(&dep_install_name);
                let target = oath_dir
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(&dep_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped packages in dep name
                    if dep_install_name.contains('/')
                        && let Some(scope) = dep_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir
                                .join(virtual_key_component(key))
                                .join("node_modules")
                                .join(scope),
                        )?;
                    }
                    // Symlink to the dep's virtual package
                    let relative = pathdiff_relative(&target, &source);
                    symlink_dir(&relative, &target).with_context(|| {
                        format!(
                            "failed to symlink dependency {} -> {}",
                            target.display(),
                            relative.display()
                        )
                    })?;
                    result.symlinks += 1;
                }
            }
        }

        // Phase 4b: Create peer dep symlinks within each package's .oath node_modules
        for (key, node) in &graph.nodes {
            for peer_key in node.resolved_peers.values() {
                let peer_node = match graph.nodes.get(peer_key) {
                    Some(n) => n,
                    None => continue,
                };
                let peer_install_name = peer_node.alias.as_deref().unwrap_or(&peer_node.name);

                let source = oath_dir
                    .join(virtual_key_component(peer_key))
                    .join("node_modules")
                    .join(peer_install_name);
                let target = oath_dir
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(peer_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped peer package
                    if peer_install_name.contains('/')
                        && let Some(scope) = peer_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir
                                .join(virtual_key_component(key))
                                .join("node_modules")
                                .join(scope),
                        )?;
                    }
                    let relative = pathdiff_relative(&target, &source);
                    symlink_dir(&relative, &target).with_context(|| {
                        format!(
                            "failed to symlink peer dependency {} -> {}",
                            target.display(),
                            relative.display()
                        )
                    })?;
                    result.symlinks += 1;
                }
            }
        }

        // Phase 5: Create .bin symlinks for packages with bin entries
        let bin_dir = nm_dir.join(".bin");
        std::fs::create_dir_all(&bin_dir)?;

        for (install_name, key) in &plan.hoisted {
            if !graph.nodes.contains_key(key) {
                continue;
            }

            // Read package.json from the linked location to get bin field
            let pkg_json_path = nm_dir.join(install_name).join("package.json");
            let bins = read_bin_entries(&pkg_json_path, install_name);

            for (bin_name, bin_path) in &bins {
                let target = nm_dir.join(install_name).join(bin_path);
                let link_path = bin_dir.join(bin_name);

                if target.exists() && !link_path.exists() {
                    // Create relative symlink from .bin/name -> ../pkg/bin/path
                    let rel = PathBuf::from("..").join(install_name).join(bin_path);
                    symlink_file(&rel, &link_path).with_context(|| {
                        format!(
                            "failed to symlink bin {} -> {}",
                            link_path.display(),
                            rel.display()
                        )
                    })?;

                    // Make executable
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(meta) = std::fs::metadata(&target) {
                            let mut perms = meta.permissions();
                            let mode = perms.mode() | 0o111; // +x
                            perms.set_mode(mode);
                            std::fs::set_permissions(&target, perms).ok();
                        }
                    }

                    result.bins += 1;
                }
            }
        }

        // Record the manifest so an unchanged re-install can skip the rebuild.
        std::fs::write(&manifest_path, &manifest).context("failed to write link manifest")?;

        #[cfg(windows)]
        let junction_rebase_plan = collect_junction_rebase_plan(&stage_nm_dir)
            .context("failed to record staged Windows junctions")?;

        // Commit with rename boundaries. If promotion fails, restore the old
        // tree before returning the error. A crash is recovered on the next run.
        if live_nm_dir.exists() {
            std::fs::rename(&live_nm_dir, &backup_nm_dir)
                .context("failed to stage existing node_modules for replacement")?;
        }
        if let Err(error) = std::fs::rename(&stage_nm_dir, &live_nm_dir) {
            if backup_nm_dir.exists() && !live_nm_dir.exists() {
                let _ = std::fs::rename(&backup_nm_dir, &live_nm_dir);
            }
            return Err(error).context("failed to atomically promote staged node_modules");
        }
        #[cfg(windows)]
        if let Err(error) = rebase_junctions(&live_nm_dir, &junction_rebase_plan) {
            let _ = std::fs::remove_dir_all(&live_nm_dir);
            if backup_nm_dir.exists() {
                let _ = std::fs::rename(&backup_nm_dir, &live_nm_dir);
            }
            return Err(error).context("failed to rebase promoted Windows junctions");
        }
        if backup_nm_dir.exists()
            && let Err(error) = std::fs::remove_dir_all(&backup_nm_dir)
        {
            tracing::warn!("node_modules committed but backup cleanup failed: {error}");
        }

        Ok(result)
    }
}

/// A stable fingerprint of the graph layout inputs, used to skip relinking an
/// unchanged node_modules.
fn link_manifest(graph: &DepGraph) -> String {
    let mut out = String::new();

    let mut roots = graph.roots.clone();
    roots.sort();
    for root in roots {
        out.push_str("root\t");
        out.push_str(&root);
        out.push('\n');
    }

    let mut keys: Vec<&str> = graph.nodes.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    for key in keys {
        if let Some(node) = graph.nodes.get(key) {
            out.push_str("pkg\t");
            out.push_str(key);
            out.push('\t');
            out.push_str(&node.name);
            out.push('\t');
            out.push_str(node.alias.as_deref().unwrap_or(""));
            out.push('\t');
            out.push_str(&node.version);
            out.push('\n');

            let mut deps: Vec<(&String, &String)> = node.dependencies.iter().collect();
            deps.sort_by(|(a_name, a_key), (b_name, b_key)| {
                a_name.cmp(b_name).then_with(|| a_key.cmp(b_key))
            });
            for (name, dep_key) in deps {
                out.push_str("dep\t");
                out.push_str(key);
                out.push('\t');
                out.push_str(name);
                out.push('\t');
                out.push_str(dep_key);
                out.push('\n');
            }

            let mut peers: Vec<(&String, &String)> = node.resolved_peers.iter().collect();
            peers.sort_by(|(a_name, a_key), (b_name, b_key)| {
                a_name.cmp(b_name).then_with(|| a_key.cmp(b_key))
            });
            for (name, peer_key) in peers {
                out.push_str("peer\t");
                out.push_str(key);
                out.push('\t');
                out.push_str(name);
                out.push('\t');
                out.push_str(peer_key);
                out.push('\n');
            }
        }
    }

    out
}

/// Result of a link operation
#[derive(Debug, Default)]
pub struct LinkResult {
    /// Number of packages hardlinked from store
    pub linked: usize,
    /// Number of top-level symlinks created
    pub symlinks: usize,
    /// Number of nested symlinks created (version conflicts)
    pub nested: usize,
    /// Number of .bin symlinks created
    pub bins: usize,
    /// Number of packages missing from store
    pub missing: usize,
}

/// Read bin entries from a package.json file
/// Returns Vec<(bin_name, relative_path)>
fn read_bin_entries(pkg_json_path: &Path, install_name: &str) -> Vec<(String, PathBuf)> {
    let content = match std::fs::read_to_string(pkg_json_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut bins = Vec::new();

    if let Some(bin) = json.get("bin") {
        match bin {
            serde_json::Value::String(path) => {
                // Single bin: use package name (last segment) as bin name
                let bin_name = install_name.split('/').next_back().unwrap_or(install_name);
                if is_safe_bin_name(bin_name)
                    && let Some(safe_path) = sanitize_package_relative_path(path)
                {
                    bins.push((bin_name.to_string(), safe_path));
                }
            }
            serde_json::Value::Object(map) => {
                for (name, path) in map {
                    if let Some(p) = path.as_str()
                        && is_safe_bin_name(name)
                        && let Some(safe_path) = sanitize_package_relative_path(p)
                    {
                        bins.push((name.clone(), safe_path));
                    }
                }
            }
            _ => {}
        }
    }

    // Also check "directories.bin" (less common)
    if bins.is_empty()
        && let Some(dirs) = json.get("directories")
        && let Some(bin_dir) = dirs.get("bin").and_then(|v| v.as_str())
    {
        // Would need to list files in that dir - skip for now
        let _ = bin_dir;
    }

    bins
}

/// Hardlink all files from src to dst recursively
fn hardlink_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            hardlink_dir(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            // Try hardlink first (saves disk), fall back to copy
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }
    Ok(())
}

/// Find a dependency node in the graph by name and specifier
#[allow(dead_code)]
fn find_dep_in_graph<'a>(graph: &'a DepGraph, name: &str, _spec: &str) -> Option<&'a DepNode> {
    // Simple: find any node with this name (could be smarter about version matching)
    graph.nodes.values().find(|n| n.name == name)
}

fn validate_graph_path_names(graph: &DepGraph) -> Result<()> {
    for node in graph.nodes.values() {
        let install_name = node.alias.as_deref().unwrap_or(&node.name);
        validate_install_name(install_name)?;

        for dep_name in node.dependencies.keys() {
            validate_install_name(dep_name)?;
        }

        for peer_name in node.resolved_peers.keys() {
            validate_install_name(peer_name)?;
        }
    }

    Ok(())
}

pub fn validate_install_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("invalid empty package install name");
    }

    let parts: Vec<&str> = name.split('/').collect();
    if name.starts_with('@') {
        if parts.len() != 2
            || parts[0].len() == 1
            || !is_safe_path_name_part(parts[0])
            || !is_safe_path_name_part(parts[1])
        {
            bail!("invalid scoped package install name: {name}");
        }
    } else if parts.len() != 1 || !is_safe_path_name_part(parts[0]) {
        bail!("invalid package install name: {name}");
    }

    Ok(())
}

fn is_safe_path_name_part(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains('\\') && !part.contains('\0')
}

fn is_safe_bin_name(name: &str) -> bool {
    is_safe_path_name_part(name) && !name.contains('/')
}

fn sanitize_package_relative_path(path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    let mut safe = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::Normal(part) if is_safe_os_part(part) => safe.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }

    (!safe.as_os_str().is_empty()).then_some(safe)
}

fn is_safe_os_part(part: &OsStr) -> bool {
    let Some(part) = part.to_str() else {
        return false;
    };
    is_safe_path_name_part(part)
}

fn virtual_key_component(key: &str) -> String {
    safe_fs_component(key)
}

fn safe_fs_component(input: &str) -> String {
    if input.is_empty() {
        return "_".to_string();
    }

    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'@' | b'+' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }

    match out.as_str() {
        "." => "%2E".to_string(),
        ".." => "%2E%2E".to_string(),
        _ => out,
    }
}

/// Compute a relative path from `from` (symlink location) to `to` (symlink target).
///
/// For a symlink at `/a/b/c/link` pointing at `/a/b/d/e/target`:
/// - Go up from the symlink's parent dir (/a/b/c) to the common ancestor (/a/b)
/// - Then descend into d/e/target
///
/// Both paths should be absolute. `from` is the path of the symlink itself
/// (not its parent directory).
fn pathdiff_relative(from: &Path, to: &Path) -> PathBuf {
    // We compute relative from the *parent* of `from` (the dir containing the symlink)
    let from_dir = from.parent().unwrap_or(from);

    // Collect components
    let from_parts: Vec<_> = from_dir.components().collect();
    let to_parts: Vec<_> = to.components().collect();

    // Find the length of the common prefix
    let common_len = from_parts
        .iter()
        .zip(to_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut rel = PathBuf::new();
    // Go up from from_dir to the common ancestor
    for _ in common_len..from_parts.len() {
        rel.push("..");
    }
    // Descend into the target
    for part in &to_parts[common_len..] {
        rel.push(part);
    }

    // If the result is empty (same dir), use "."
    if rel.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oath_resolve::graph::{DepGraph, DepNode};
    use oath_resolve::placement::{PlacementNode, PlacementPlan, PlannerIdentity};
    use std::collections::{HashMap, HashSet};

    fn node(name: &str, version: &str, dependencies: HashMap<String, String>) -> DepNode {
        DepNode {
            name: name.to_string(),
            alias: None,
            version: version.to_string(),
            resolved: format!("https://registry.example/{name}-{version}.tgz"),
            integrity: None,
            dependencies,
            has_install_script: false,
            dev: false,
            optional: false,
            peer_dependencies: HashMap::new(),
            optional_peers: HashSet::new(),
            resolved_peers: HashMap::new(),
        }
    }

    #[test]
    fn link_manifest_changes_when_edges_change() {
        let mut deps = HashMap::new();
        deps.insert("dep".to_string(), "dep@1.0.0".to_string());

        let mut graph_a = DepGraph::new();
        graph_a.roots.push("app@1.0.0".to_string());
        graph_a
            .nodes
            .insert("app@1.0.0".to_string(), node("app", "1.0.0", deps));
        graph_a.nodes.insert(
            "dep@1.0.0".to_string(),
            node("dep", "1.0.0", HashMap::new()),
        );

        let mut graph_b = graph_a.clone();
        graph_b
            .nodes
            .get_mut("app@1.0.0")
            .unwrap()
            .dependencies
            .clear();

        assert_ne!(link_manifest(&graph_a), link_manifest(&graph_b));
    }

    #[test]
    fn transaction_recovery_restores_backup_and_discards_partial_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("node_modules");
        let stage = tmp.path().join(".oath-node_modules-stage");
        let backup = tmp.path().join(".oath-node_modules-backup");
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("previous.txt"), "previous").unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("partial.txt"), "partial").unwrap();

        recover_link_transaction(&live, &stage, &backup).unwrap();

        assert_eq!(
            std::fs::read_to_string(live.join("previous.txt")).unwrap(),
            "previous"
        );
        assert!(!stage.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn placement_plan_materializes_exact_nested_locations() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        for (name, version) in [("dep", "1.0.0"), ("dep", "2.0.0")] {
            let extracted = tmp.path().join(format!("{name}-{version}"));
            std::fs::create_dir_all(&extracted).unwrap();
            std::fs::write(
                extracted.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
            store.store_package(name, version, &extracted).unwrap();
        }
        let node = |location: &str, version: &str| PlacementNode {
            location: location.into(),
            install_name: "dep".into(),
            name: "dep".into(),
            version: version.into(),
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
        };
        let plan = PlacementPlan {
            schema_version: 2,
            planner: PlannerIdentity {
                name: "@npmcli/arborist".into(),
                npm: "11.12.1".into(),
            },
            project: tmp.path().display().to_string(),
            nodes: vec![
                node("node_modules/dep", "2.0.0"),
                node("node_modules/parent/node_modules/dep", "1.0.0"),
            ],
            removed_locations: vec![],
            invalid_edges: vec![],
        };
        Linker::new(store)
            .link_placement_plan(&plan, tmp.path())
            .unwrap();
        assert!(tmp.path().join("node_modules/dep/package.json").exists());
        assert!(
            tmp.path()
                .join("node_modules/parent/node_modules/dep/package.json")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn placement_plan_preserves_safe_dangling_workspace_links() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let missing = project.join("packages/missing");
        let plan = PlacementPlan {
            schema_version: 2,
            planner: PlannerIdentity {
                name: "@npmcli/arborist".into(),
                npm: "11.12.1".into(),
            },
            project: project.display().to_string(),
            nodes: vec![PlacementNode {
                location: "node_modules/missing".into(),
                install_name: "missing".into(),
                name: "missing".into(),
                version: "0.0.0".into(),
                resolved: None,
                integrity: None,
                dev: false,
                optional: false,
                peer: false,
                has_install_script: false,
                reuse_existing: false,
                link: true,
                target: Some(missing.display().to_string()),
                edges: vec![],
            }],
            removed_locations: vec![],
            invalid_edges: vec![],
        };

        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        Linker::new(store)
            .link_placement_plan(&plan, &project)
            .unwrap();
        let link = project.join("node_modules/missing");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_link(link).unwrap(), missing);
    }

    #[test]
    fn workspace_link_rejects_parent_directory_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let error = validated_workspace_target(&project, Path::new("../outside")).unwrap_err();
        assert!(error.to_string().contains("workspace link escapes project"));
    }

    #[cfg(windows)]
    #[test]
    fn workspace_link_accepts_equivalent_windows_drive_case() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let target = project.join("packages/tool");
        std::fs::create_dir_all(&target).unwrap();

        let mut target_text = target.to_string_lossy().into_owned();
        let drive = target_text.as_bytes()[0] as char;
        let alternate_drive_case = if drive.is_ascii_lowercase() {
            drive.to_ascii_uppercase()
        } else {
            drive.to_ascii_lowercase()
        };
        target_text.replace_range(0..1, &alternate_drive_case.to_string());

        assert_eq!(
            validated_workspace_target(&project, Path::new(&target_text)).unwrap(),
            target.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_workspace_link_rejects_symlinked_ancestor_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project.join("escaped")).unwrap();

        let target = project.join("escaped/missing");
        let error = validated_workspace_target(&project, &target).unwrap_err();
        assert!(error.to_string().contains("workspace link escapes project"));
    }

    #[test]
    fn placement_plan_preserves_only_arborist_unchanged_content() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("node_modules");
        std::fs::create_dir_all(live.join("kept")).unwrap();
        std::fs::write(
            live.join("kept/package.json"),
            r#"{"name":"kept","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(live.join("kept/checked-in.txt"), "exact bytes").unwrap();
        std::fs::write(live.join(".gitignore"), "tracked root file").unwrap();
        std::fs::create_dir_all(live.join("stale")).unwrap();
        std::fs::write(live.join("stale/package.json"), r#"{"name":"stale"}"#).unwrap();
        std::fs::create_dir_all(live.join("parent/node_modules/child")).unwrap();
        std::fs::write(
            live.join("parent/node_modules/child/package.json"),
            r#"{"name":"child","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            live.join("parent/node_modules/child/checked-in.txt"),
            "preserve me",
        )
        .unwrap();

        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let changed_parent = tmp.path().join("changed-parent");
        std::fs::create_dir_all(changed_parent.join("node_modules/child")).unwrap();
        std::fs::write(
            changed_parent.join("package.json"),
            r#"{"name":"parent","version":"2.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            changed_parent.join("node_modules/child/registry-only.txt"),
            "must be replaced by unchanged bytes",
        )
        .unwrap();
        store
            .store_package("parent", "2.0.0", &changed_parent)
            .unwrap();
        let placement_node = |location: &str,
                              install_name: &str,
                              name: &str,
                              version: &str,
                              reuse_existing: bool| PlacementNode {
            location: location.into(),
            install_name: install_name.into(),
            name: name.into(),
            version: version.into(),
            resolved: None,
            integrity: None,
            dev: false,
            optional: false,
            peer: false,
            has_install_script: false,
            reuse_existing,
            link: false,
            target: None,
            edges: vec![],
        };
        let plan = PlacementPlan {
            schema_version: 2,
            planner: PlannerIdentity {
                name: "@npmcli/arborist".into(),
                npm: "11.12.1".into(),
            },
            project: tmp.path().display().to_string(),
            nodes: vec![
                placement_node("node_modules/kept", "kept", "kept", "1.0.0", true),
                placement_node("node_modules/parent", "parent", "parent", "2.0.0", false),
                placement_node(
                    "node_modules/parent/node_modules/child",
                    "child",
                    "child",
                    "1.0.0",
                    true,
                ),
            ],
            removed_locations: vec!["node_modules/stale".into()],
            invalid_edges: vec![],
        };

        Linker::new(store)
            .link_placement_plan(&plan, tmp.path())
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(live.join("kept/checked-in.txt")).unwrap(),
            "exact bytes"
        );
        assert_eq!(
            std::fs::read_to_string(live.join(".gitignore")).unwrap(),
            "tracked root file"
        );
        assert_eq!(
            std::fs::read_to_string(live.join("parent/node_modules/child/checked-in.txt")).unwrap(),
            "preserve me"
        );
        assert!(
            !live
                .join("parent/node_modules/child/registry-only.txt")
                .exists()
        );
        assert!(!live.join("stale").exists());
    }

    #[test]
    fn clean_placement_plan_removes_stale_entries_and_ignores_reuse() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("node_modules");
        std::fs::create_dir_all(live.join("kept")).unwrap();
        std::fs::write(
            live.join("kept/package.json"),
            r#"{"name":"kept","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(live.join("kept/checked-in.txt"), "must not survive ci").unwrap();
        std::fs::create_dir_all(live.join("stale")).unwrap();
        std::fs::write(live.join("stale/should-disappear"), "stale").unwrap();

        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let extracted = tmp.path().join("kept-store");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(
            extracted.join("package.json"),
            r#"{"name":"kept","version":"1.0.0"}"#,
        )
        .unwrap();
        store.store_package("kept", "1.0.0", &extracted).unwrap();

        let plan = PlacementPlan {
            schema_version: 2,
            planner: PlannerIdentity {
                name: "@npmcli/arborist".into(),
                npm: "11.12.1".into(),
            },
            project: tmp.path().display().to_string(),
            nodes: vec![PlacementNode {
                location: "node_modules/kept".into(),
                install_name: "kept".into(),
                name: "kept".into(),
                version: "1.0.0".into(),
                resolved: None,
                integrity: None,
                dev: false,
                optional: false,
                peer: false,
                has_install_script: false,
                reuse_existing: true,
                link: false,
                target: None,
                edges: vec![],
            }],
            removed_locations: vec![],
            invalid_edges: vec![],
        };

        Linker::new(store)
            .link_placement_plan_clean(&plan, tmp.path())
            .unwrap();
        assert!(live.join("kept/package.json").exists());
        assert!(!live.join("kept/checked-in.txt").exists());
        assert!(!live.join("stale/should-disappear").exists());
    }

    #[test]
    fn transaction_recovery_keeps_promoted_tree_and_cleans_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("node_modules");
        let stage = tmp.path().join(".oath-node_modules-stage");
        let backup = tmp.path().join(".oath-node_modules-backup");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("current.txt"), "current").unwrap();
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("previous.txt"), "previous").unwrap();

        recover_link_transaction(&live, &stage, &backup).unwrap();

        assert_eq!(
            std::fs::read_to_string(live.join("current.txt")).unwrap(),
            "current"
        );
        assert!(!backup.exists());
    }

    #[test]
    fn build_plan_breaks_ref_count_ties_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let linker = Linker::new(store);

        let mut graph = DepGraph::new();
        graph.roots.push("pkg@2.0.0".to_string());
        graph.roots.push("pkg@1.0.0".to_string());
        graph.nodes.insert(
            "pkg@2.0.0".to_string(),
            node("pkg", "2.0.0", HashMap::new()),
        );
        graph.nodes.insert(
            "pkg@1.0.0".to_string(),
            node("pkg", "1.0.0", HashMap::new()),
        );

        let plan = linker.build_plan(&graph);

        assert_eq!(plan.hoisted.get("pkg").unwrap(), "pkg@1.0.0");
    }

    #[test]
    fn link_all_rejects_unsafe_install_names_before_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let project = tmp.path().join("project");
        let sentinel = project.join("node_modules").join("keep.txt");
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        std::fs::write(&sentinel, "keep").unwrap();

        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "../evil@1.0.0".to_string(),
            node("../evil", "1.0.0", HashMap::new()),
        );

        let err = Linker::new(store).link_all(&graph, &project).unwrap_err();

        assert!(err.to_string().contains("invalid package install name"));
        assert!(
            sentinel.exists(),
            "linker cleaned node_modules before validation"
        );
    }

    #[test]
    fn link_all_creates_scoped_transitive_links_under_scoped_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        for (name, version) in [("@scope/parent", "1.0.0"), ("@scope/child", "1.0.0")] {
            let resolved = format!("https://registry.example/{name}-{version}.tgz");
            let dir = store.package_dir_for(name, version, Some(&resolved), None);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), "{}").unwrap();
        }

        let mut parent_deps = HashMap::new();
        parent_deps.insert("@scope/child".to_string(), "@scope/child@1.0.0".to_string());
        let mut graph = DepGraph::new();
        graph.roots.push("@scope/parent@1.0.0".to_string());
        graph.nodes.insert(
            "@scope/parent@1.0.0".to_string(),
            node("@scope/parent", "1.0.0", parent_deps),
        );
        graph.nodes.insert(
            "@scope/child@1.0.0".to_string(),
            node("@scope/child", "1.0.0", HashMap::new()),
        );

        let project = tmp.path().join("project");
        Linker::new(store).link_all(&graph, &project).unwrap();

        let transitive_link = project
            .join("node_modules")
            .join(".oath")
            .join("@scope%2Fparent@1.0.0")
            .join("node_modules")
            .join("@scope")
            .join("child");
        assert!(
            transitive_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "scoped transitive dependency link was not created"
        );
    }

    #[test]
    fn link_all_creates_working_nested_conflict_link_for_scoped_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        for (name, version) in [
            ("@scope/parent", "1.0.0"),
            ("dep", "1.0.0"),
            ("dep", "2.0.0"),
        ] {
            let resolved = format!("https://registry.example/{name}-{version}.tgz");
            let dir = store.package_dir_for(name, version, Some(&resolved), None);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let mut parent_deps = HashMap::new();
        parent_deps.insert("dep".to_string(), "dep@2.0.0".to_string());
        let mut graph = DepGraph::new();
        graph.roots.push("@scope/parent@1.0.0".to_string());
        graph.roots.push("dep@1.0.0".to_string());
        graph.roots.push("dep@1.0.0".to_string());
        graph.nodes.insert(
            "@scope/parent@1.0.0".to_string(),
            node("@scope/parent", "1.0.0", parent_deps),
        );
        graph.nodes.insert(
            "dep@1.0.0".to_string(),
            node("dep", "1.0.0", HashMap::new()),
        );
        graph.nodes.insert(
            "dep@2.0.0".to_string(),
            node("dep", "2.0.0", HashMap::new()),
        );

        let project = tmp.path().join("project");
        Linker::new(store).link_all(&graph, &project).unwrap();

        let nested_pkg = project
            .join("node_modules")
            .join("@scope")
            .join("parent")
            .join("node_modules")
            .join("dep")
            .join("package.json");
        let content = std::fs::read_to_string(nested_pkg).unwrap();
        assert!(content.contains(r#""version":"2.0.0""#));
    }

    #[test]
    fn read_bin_entries_filters_unsafe_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_json = tmp.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{
              "bin": {
                "../owned": "bin/owned.js",
                "escape": "../escape.js",
                "safe": "bin/safe.js"
              }
            }"#,
        )
        .unwrap();

        let bins = read_bin_entries(&pkg_json, "pkg");

        assert_eq!(
            bins,
            vec![("safe".to_string(), PathBuf::from("bin/safe.js"))]
        );
    }

    #[test]
    fn virtual_keys_are_single_safe_components() {
        assert_eq!(
            virtual_key_component("@scope/pkg@1.0.0"),
            "@scope%2Fpkg@1.0.0"
        );
        assert_eq!(virtual_key_component("../pkg@1.0.0"), "..%2Fpkg@1.0.0");
    }
}
