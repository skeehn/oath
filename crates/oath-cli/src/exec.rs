//! `oath exec` / `oath x`: npx and bunx behavior with assessment in front.
//!
//! Resolution follows libnpmexec: a bin of the local project, then a
//! `node_modules/.bin` found walking up from the project, then Oath's global
//! bin directory, then a package spec. Specs already satisfied by the local
//! tree run from it; anything else is installed into the persistent exec
//! cache (`~/.oath/cache/_npx/<key>`) through the Arborist planner, Oath's
//! verified store, and the transactional linker, exactly as `oath install`
//! installs a project. The requested package is scanned and gated before
//! its lifecycle scripts or bin run, every run reserves stdout for the
//! program, and the first run of a spec is the only one that asks.

use crate::exec_cache::NpxCache;
use crate::exec_spec::{ExecSpec, SpecKind, bin_from_manifest};
use crate::launch::{self, Launch};
use crate::{
    EXEC_EXIT_AGE, EXEC_EXIT_GRADE, EXEC_EXIT_USER, ExecSandboxDecision, ExecSandboxMode,
    approvals, exec_assessment, manifest::PackageJsonDocument,
};
use anyhow::{Context, Result, bail};
use oath_analyze::{
    FindingKind, PackageScanner, RiskLevel, ScoreContext, compute_safety_score_contextual,
};
use oath_core::policy::OathPolicy;
use oath_fetch::RegistryClient;
use oath_resolve::placement::{AddedSpec, ArboristPlanner, PlacementPlan, PlacementRequest};
use oath_resolve::{DepGraph, Lockfile};
use oath_store::{ContentStore, Linker};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a cached install of a tag, range, or git spec is trusted before
/// the registry is asked again (bunx's rule; npx asks on every run).
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct ExecOptions {
    /// Positional arguments: the command (or package spec) and its args.
    pub args: Vec<String>,
    /// `--package` / `-p`, repeatable.
    pub packages: Vec<String>,
    /// `--call` / `-c`: a shell script to run instead of a command.
    pub call: Option<String>,
    pub yes: bool,
    /// `--no-install` / `-n`: refuse to install anything.
    pub no_install: bool,
    pub min_release_age: Option<String>,
    pub min_release_age_exclude: Vec<String>,
    pub json: bool,
    pub json_file: Option<PathBuf>,
    pub schema_version: u32,
    pub require_grade: Option<String>,
    pub dry_run: bool,
    pub sandbox: bool,
    pub sandbox_mode: ExecSandboxMode,
    pub deny_network: bool,
    pub allow_degraded_sandbox: bool,
    pub remember: bool,
    pub offline: bool,
    pub prefer_offline: bool,
    pub prefer_online: bool,
    pub ignore_scripts: bool,
}

/// Oath's record of an exec-cache entry: which specs it was installed for,
/// which package each resolved to, and the assessment the user approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRecords {
    pub schema_version: u32,
    pub installed_at: u64,
    pub packages: Vec<String>,
    pub added: Vec<AddedSpec>,
    /// The release-age cooldown the entry was resolved under. A different
    /// cooldown changes which versions are eligible, so the entry is
    /// re-planned when it changes.
    #[serde(default)]
    pub cooldown: Option<CooldownRecord>,
    /// Whether the install's lifecycle scripts are still owed: set when the
    /// entry is linked and cleared only after they ran, so a `--dry-run`, a
    /// declined prompt, or a blocked run does not lose them.
    #[serde(default)]
    pub scripts_pending: bool,
    #[serde(default)]
    pub records: BTreeMap<String, PackageRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CooldownRecord {
    pub min_age_secs: u64,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRecord {
    pub version: String,
    pub integrity: Option<String>,
    pub grade: String,
    pub score: u8,
    pub capabilities: Vec<String>,
    pub findings: Vec<String>,
    pub published_at: Option<String>,
    /// Whether the run that produced this record passed the gate (prompt,
    /// grade, policy). An unapproved record is re-assessed on the next run.
    pub approved: bool,
}

const RECORDS_VERSION: u32 = 1;

/// Path of the entry's `exec-records.json`.
fn records_path(entry: &Path) -> PathBuf {
    entry.join(".oath").join("exec-records.json")
}

/// The entry's records, when the file exists and parses.
fn read_records(entry: &Path) -> Option<ExecRecords> {
    let text = std::fs::read_to_string(records_path(entry)).ok()?;
    let records: ExecRecords = serde_json::from_str(&text).ok()?;
    (records.schema_version == RECORDS_VERSION).then_some(records)
}

/// Serialize the entry's records to `exec-records.json`.
fn write_records(entry: &Path, records: &ExecRecords) -> Result<()> {
    let path = records_path(entry);
    std::fs::create_dir_all(path.parent().expect("records path has a parent"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(records)?)?;
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))
}

/// The spec-to-package mapping recorded for a cache entry, for `cache npx info`.
pub fn recorded_names(entry: &Path) -> Vec<AddedSpec> {
    read_records(entry)
        .map(|records| records.added)
        .unwrap_or_default()
}

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run-wide settings every path shares.
struct ExecContext {
    cwd: PathBuf,
    prefix: PathBuf,
    sandbox: ExecSandboxDecision,
    deny_network: bool,
    /// npm's prompt rule: a terminal on stdin, outside CI, and not agent mode.
    interactive: bool,
    policy: OathPolicy,
    min_release_age: Option<MinReleaseAge>,
}

#[derive(Debug, Clone)]
struct MinReleaseAge {
    age: Duration,
    exclude: Vec<String>,
    /// The value as the user or config wrote it, for messages.
    display: String,
}

/// A package to assess: where it is and what the registry said about it.
struct Target {
    name: String,
    version: String,
    dir: PathBuf,
    integrity: Option<String>,
}

#[derive(Default, Clone)]
struct RegistryInfo {
    published_at: Option<String>,
    age_days: Option<u64>,
    publisher: Option<String>,
    repository: Option<String>,
    version_diff: Option<exec_assessment::VersionDiff>,
    weekly_downloads: Option<u64>,
    fetched: bool,
}

/// What the gate decided for a target.
enum Gate {
    Proceed(PackageRecord),
    Exit(i32),
}

/// Run `oath x`: resolve the command in libnpmexec's order (project bin,
/// walk-up `.bin`, global bin, package spec), install into the exec cache
/// when nothing local satisfies the specs, pass the gate, then launch.
/// Returns the exit code to report.
pub async fn run(opts: ExecOptions) -> Result<i32> {
    anyhow::ensure!(
        matches!(opts.schema_version, 2 | 3),
        "unsupported exec assessment schema {}; supported versions are 2 and 3",
        opts.schema_version
    );
    // JSON mode reserves stdout for exactly one assessment document; a program
    // that then wrote to the same stream would corrupt it. Agents assess with
    // --dry-run --json, then execute with the plain command (or --json-file).
    anyhow::ensure!(
        !opts.json || opts.dry_run,
        "oath exec --json is an assessment-only interface and requires --dry-run; use --json-file to record the assessment of a real run"
    );
    if opts.call.is_some() && !opts.args.is_empty() {
        bail!(
            "oath exec --call takes a script, not positional arguments; put the command inside the --call string"
        );
    }
    if opts.call.is_none() && opts.args.is_empty() && opts.packages.is_empty() {
        bail!(
            "oath exec: specify a package or command (an interactive npm shell is not supported); try `oath x <package> [args]`"
        );
    }
    if opts.offline && opts.prefer_online {
        bail!("--offline and --prefer-online are mutually exclusive");
    }
    let cwd = std::env::current_dir().context("failed to read the current directory")?;
    let prefix = launch::find_local_prefix(&cwd);
    let sandbox =
        crate::resolve_exec_sandbox(opts.sandbox, opts.sandbox_mode, opts.allow_degraded_sandbox)?;
    let policy = OathPolicy::load();
    let min_release_age = resolve_min_release_age(&opts, &prefix, &policy)?;
    let ctx = ExecContext {
        deny_network: opts.deny_network || sandbox.agent_mode,
        interactive: launch::stdin_is_tty() && !launch::is_ci() && !sandbox.agent_mode,
        cwd,
        prefix,
        sandbox,
        policy,
        min_release_age,
    };

    let mut packages = opts.packages.clone();
    let mut args = opts.args.clone();
    let swap = packages.is_empty() && !args.is_empty();
    if swap {
        let cmd = args[0].clone();
        if let Some(file) = project_bin(&ctx.prefix, &cmd)? {
            // The project's own bin: user code, no assessment, like npm (which
            // installs the project into its cache with --yes to link the bin).
            let bin_dirs = vec![ctx.prefix.join("node_modules").join(".bin")];
            return launch_command(&ctx, &opts, &file, &args[1..], &bin_dirs, None, &cmd, false)
                .await;
        }
        if let Some(bin_dir) = launch::walk_up_bin(&ctx.prefix, &cmd) {
            return run_installed_bin(&ctx, &opts, &bin_dir, &cmd, &args[1..]).await;
        }
        if let Some(bin_dir) = global_bin_dir()
            && launch::command_in_dir(&bin_dir, &cmd).is_some()
        {
            return run_installed_bin(&ctx, &opts, &bin_dir, &cmd, &args[1..]).await;
        }
        packages.push(cmd);
    }

    if packages.is_empty() {
        // `--call` alone: run the script in the project's npm environment,
        // with its own bins on PATH and nothing to install or assess.
        let bin_dirs = vec![ctx.prefix.join("node_modules").join(".bin")];
        return run_resolved(&ctx, &opts, &args, &bin_dirs, "project", false).await;
    }
    let specs = packages
        .iter()
        .map(|package| ExecSpec::parse(package, &ctx.cwd))
        .collect::<Result<Vec<_>>>()?;

    // Already satisfied by the local tree: run from it, no download.
    if let Some(local) = local_tree_match(&ctx, &opts, &specs).await? {
        let first = &local[0];
        if swap {
            swap_command(&mut args, &first.manifest, &opts)?;
        }
        let target = Target {
            name: first.name.clone(),
            version: first.version.clone(),
            dir: first.dir.clone(),
            integrity: lock_integrity(&ctx.prefix, &first.name),
        };
        let bin_dirs = vec![ctx.prefix.join("node_modules").join(".bin")];
        let registry = registry_info_for(&opts, &target, false).await;
        let record = match gate(
            &ctx,
            &opts,
            &target,
            &registry,
            false,
            command_name_of(&args),
        )? {
            Gate::Exit(code) => return Ok(code),
            Gate::Proceed(record) => record,
        };
        let needs_network = record.capabilities.iter().any(|c| c == "network");
        return run_resolved(&ctx, &opts, &args, &bin_dirs, &target.name, needs_network).await;
    }

    // The persistent exec cache.
    let components: Vec<String> = specs.iter().map(ExecSpec::cache_component).collect();
    let cache = NpxCache::default_cache()?;
    let key = NpxCache::key(&components);
    let entry = cache.entry_dir(&key);

    let state = entry_state(&entry, &specs, &components, &opts, cooldown_record(&ctx)).await?;
    let (mut records, pending_scripts) = match state {
        EntryState::Hit(records) => (records, None),
        EntryState::Install { reason } => {
            if opts.no_install {
                let missing: Vec<&str> = packages.iter().map(String::as_str).collect();
                bail!(
                    "oath exec canceled due to missing packages and no YES option: {}",
                    serde_json::to_string(&missing)?
                );
            }
            if opts.offline {
                bail!(
                    "oath exec --offline: {} {} not in the exec cache ({reason})",
                    packages.join(", "),
                    if packages.len() == 1 { "is" } else { "are" }
                );
            }
            std::fs::create_dir_all(&entry)
                .with_context(|| format!("creating {}", entry.display()))?;
            let _lock = EntryLock::acquire(&entry)?;
            let (plan, graph, added) =
                match install_entry(&ctx, &opts, &entry, &specs, &components).await {
                    Ok(installed) => installed,
                    Err(error) if error.downcast_ref::<AgeBlocked>().is_some() => {
                        return Ok(EXEC_EXIT_AGE);
                    }
                    Err(error) => return Err(error),
                };
            let records = ExecRecords {
                schema_version: RECORDS_VERSION,
                installed_at: now_secs(),
                packages: components.clone(),
                added,
                cooldown: cooldown_record(&ctx),
                scripts_pending: true,
                records: BTreeMap::new(),
            };
            write_records(&entry, &records)?;
            // Lifecycle scripts wait for the gate below.
            (records, Some((plan, graph)))
        }
    };
    let fresh_install = pending_scripts.is_some();

    let names = map_added(&specs, &records.added, &entry)?;
    let command_name = names[0].clone();
    let command_dir = entry.join("node_modules").join(&command_name);
    let command_manifest = read_manifest(&command_dir)?;
    if swap {
        swap_command(&mut args, &command_manifest, &opts)?;
    }
    let bin_dirs = vec![entry.join("node_modules").join(".bin")];
    let version = command_manifest["version"]
        .as_str()
        .unwrap_or("0.0.0")
        .to_string();
    let target = Target {
        name: command_name.clone(),
        version: version.clone(),
        dir: command_dir,
        integrity: plan_integrity(&entry, &command_name),
    };

    let recorded = records.records.get(&command_name).cloned();
    // An entry without an approved record for this package is still being
    // installed from the user's point of view: a declined prompt, a dry run,
    // or a blocked run must not turn the next run into a silent cache hit.
    let installing = fresh_install || recorded.as_ref().is_none_or(|record| !record.approved);
    let needs_assessment = fresh_install
        || opts.dry_run
        || opts.json
        || opts.json_file.is_some()
        || opts.require_grade.is_some()
        || recorded.as_ref().is_none_or(|record| {
            !record.approved || record.version != version || record.integrity != target.integrity
        });
    let record = if needs_assessment {
        let registry = registry_info_for(&opts, &target, installing || opts.dry_run).await;
        // A cached entry may predate the cooldown; a fresh install already
        // resolved under it.
        if !fresh_install
            && let Some(days) =
                cooldown_violation(&ctx, &command_name, registry.published_at.as_deref())
        {
            eprintln!(
                "oath exec: BLOCKED -- {}@{} is {days}d old (min-release-age {})",
                command_name,
                version,
                ctx.min_release_age
                    .as_ref()
                    .map(|a| a.display.as_str())
                    .unwrap_or("")
            );
            return Ok(EXEC_EXIT_AGE);
        }
        match gate(
            &ctx,
            &opts,
            &target,
            &registry,
            installing,
            command_name_of(&args),
        )? {
            Gate::Exit(code) => return Ok(code),
            Gate::Proceed(record) => {
                records.records.insert(command_name.clone(), record.clone());
                write_records(&entry, &records)?;
                record
            }
        }
    } else {
        let record = recorded.expect("approved record exists when assessment is skipped");
        if let Some(days) = cooldown_violation(&ctx, &command_name, record.published_at.as_deref())
        {
            eprintln!(
                "oath exec: BLOCKED -- {}@{} is {days}d old (min-release-age {})",
                command_name,
                version,
                ctx.min_release_age
                    .as_ref()
                    .map(|a| a.display.as_str())
                    .unwrap_or("")
            );
            return Ok(EXEC_EXIT_AGE);
        }
        record
    };

    if records.scripts_pending && !opts.ignore_scripts {
        // Scripts owed by this install, or by an earlier run of it that
        // ended before the gate passed: rebuild the plan if needed.
        let owed = match pending_scripts {
            Some(pending) => Some(pending),
            None => {
                let plan = PlacementPlan::read(&entry.join(".oath").join("placement-plan.json"))?;
                let graph = plan.to_dep_graph()?;
                Some((plan, graph))
            }
        };
        if let Some((plan, graph)) = owed {
            run_entry_scripts(&ctx, &opts, &entry, &plan, &graph, &names)?;
        }
        records.scripts_pending = false;
        write_records(&entry, &records)?;
    }
    let needs_network = record.capabilities.iter().any(|c| c == "network");
    run_resolved(&ctx, &opts, &args, &bin_dirs, &command_name, needs_network).await
}

/// The release-age cooldown this run resolves under, as stored in the
/// entry's records so a later run with a different cooldown re-plans.
fn cooldown_record(ctx: &ExecContext) -> Option<CooldownRecord> {
    ctx.min_release_age.as_ref().map(|age| CooldownRecord {
        min_age_secs: age.age.as_secs(),
        exclude: age.exclude.clone(),
    })
}

/// Days of age by which a package violates the configured cooldown, if it
/// does. Unknown publish dates never block: the cooldown is enforced at
/// resolution time for fresh installs, and this check only covers cache
/// entries that predate it.
fn cooldown_violation(ctx: &ExecContext, name: &str, published_at: Option<&str>) -> Option<u64> {
    let age = ctx.min_release_age.as_ref()?;
    if age.exclude.iter().any(|excluded| excluded == name) {
        return None;
    }
    let secs = crate::parse_iso_age_secs(published_at?)?;
    (Duration::from_secs(secs) < age.age).then_some(secs / 86_400)
}

// ---- resolution -------------------------------------------------------------

/// Replace the package spec in `args[0]` with the bin npm's rule selects. An
/// assessment-only run (`--dry-run`) may inspect a package that declares no
/// usable bin, such as a library; the command is then left empty.
fn swap_command(
    args: &mut [String],
    manifest: &serde_json::Value,
    opts: &ExecOptions,
) -> Result<()> {
    match bin_from_manifest(manifest) {
        Ok(bin) => {
            args[0] = bin;
            Ok(())
        }
        Err(_) if opts.dry_run => {
            args[0].clear();
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The command named by the positional arguments, if any.
fn command_name_of(args: &[String]) -> Option<&str> {
    args.first()
        .map(String::as_str)
        .filter(|cmd| !cmd.is_empty())
}

/// A bin the local project itself declares.
fn project_bin(prefix: &Path, cmd: &str) -> Result<Option<PathBuf>> {
    let manifest_path = prefix.join("package.json");
    let Ok(text) = std::fs::read_to_string(&manifest_path) else {
        return Ok(None);
    };
    let manifest: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let name = manifest["name"].as_str().unwrap_or("");
    let bare = name.rsplit('/').next().unwrap_or(name);
    let path = match manifest.get("bin") {
        Some(serde_json::Value::String(path)) if cmd == bare => Some(path.clone()),
        Some(serde_json::Value::Object(map)) => {
            map.get(cmd).and_then(|p| p.as_str()).map(String::from)
        }
        _ => None,
    };
    let Some(path) = path else {
        return Ok(None);
    };
    let file = prefix.join(&path);
    // Compare canonical paths: `starts_with` is component-wise, so it would
    // accept a `..` escape or a symlink that leaves the project.
    let inside = match (std::fs::canonicalize(&file), std::fs::canonicalize(prefix)) {
        (Ok(real), Ok(root)) => real.is_file() && real.starts_with(&root),
        _ => false,
    };
    anyhow::ensure!(
        inside,
        "package.json bin \"{cmd}\" points at {} which is not a file inside the project",
        file.display()
    );
    Ok(Some(file))
}

/// Oath's global bin directory, `~/.oath/global/bin`.
fn global_bin_dir() -> Option<PathBuf> {
    oath_core::home_dir().map(|home| home.join(".oath").join("global").join("bin"))
}

/// A package the local tree already provides for a spec.
struct LocalPackage {
    name: String,
    version: String,
    dir: PathBuf,
    manifest: serde_json::Value,
}

/// libnpmexec's `missingFromTree` over the local project: every spec must be
/// satisfied for the local tree to be used at all.
async fn local_tree_match(
    ctx: &ExecContext,
    opts: &ExecOptions,
    specs: &[ExecSpec],
) -> Result<Option<Vec<LocalPackage>>> {
    let mut found = Vec::new();
    for spec in specs {
        let SpecKind::Registry { name, kind, .. } = &spec.kind else {
            return Ok(None);
        };
        let dir = ctx.prefix.join("node_modules").join(name);
        let Ok(manifest) = read_manifest(&dir) else {
            return Ok(None);
        };
        let version = manifest["version"].as_str().unwrap_or("").to_string();
        let satisfied = match spec.satisfied_by(&version) {
            Some(satisfied) => satisfied,
            None => {
                // A dist-tag: only the registry knows what it points at.
                if opts.offline || opts.prefer_offline {
                    true
                } else {
                    let crate::exec_spec::RegistryKind::Tag(tag) = kind else {
                        unreachable!("only tags defer to the registry")
                    };
                    match resolve_tag(name, tag).await {
                        Ok(resolved) => resolved == version,
                        Err(_) => false,
                    }
                }
            }
        };
        if !satisfied {
            return Ok(None);
        }
        found.push(LocalPackage {
            name: name.clone(),
            version,
            dir,
            manifest,
        });
    }
    Ok(Some(found))
}

/// The version a dist-tag of `name` points at right now.
async fn resolve_tag(name: &str, tag: &str) -> Result<String> {
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(name).await?;
    let resolved = oath_fetch::resolve_version(&packument, tag)?;
    Ok(resolved.version.to_string())
}

/// Parse the `package.json` in `dir`.
fn read_manifest(dir: &Path) -> Result<serde_json::Value> {
    let path = dir.join("package.json");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("no package.json at {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

/// The integrity the project lockfile records for a top-level package.
fn lock_integrity(prefix: &Path, name: &str) -> Option<String> {
    let lock = Lockfile::read(&prefix.join("oath-lock.json")).ok()?;
    lock.packages
        .get(&format!("node_modules/{name}"))
        .or_else(|| {
            lock.packages
                .values()
                .find(|entry| entry.name.as_deref() == Some(name))
        })
        .and_then(|entry| entry.integrity.clone())
}

/// The integrity the cache entry's placement plan records for a package.
fn plan_integrity(entry: &Path, name: &str) -> Option<String> {
    let plan = PlacementPlan::read(&entry.join(".oath").join("placement-plan.json")).ok()?;
    let location = format!("node_modules/{name}");
    plan.nodes
        .iter()
        .find(|node| node.location == location)
        .and_then(|node| node.integrity.clone())
}

// ---- the exec cache ---------------------------------------------------------

enum EntryState {
    Hit(ExecRecords),
    Install { reason: &'static str },
}

/// Decide whether a cache entry can serve these specs as is. A tag, range,
/// or git spec is re-resolved after the TTL (or always with
/// --prefer-online, never with --prefer-offline / --offline).
async fn entry_state(
    entry: &Path,
    specs: &[ExecSpec],
    components: &[String],
    opts: &ExecOptions,
    cooldown: Option<CooldownRecord>,
) -> Result<EntryState> {
    let Some(mut records) = read_records(entry) else {
        return Ok(EntryState::Install {
            reason: "no previous install",
        });
    };
    if records.packages != components {
        return Ok(EntryState::Install {
            reason: "entry was installed for different specs",
        });
    }
    if records.cooldown != cooldown {
        return Ok(EntryState::Install {
            reason: "the release-age cooldown changed",
        });
    }
    if !entry.join("node_modules").is_dir() {
        return Ok(EntryState::Install {
            reason: "node_modules is missing",
        });
    }
    let Ok(names) = map_added(specs, &records.added, entry) else {
        return Ok(EntryState::Install {
            reason: "entry records do not name every spec",
        });
    };
    let age = Duration::from_secs(now_secs().saturating_sub(records.installed_at));
    let stale = opts.prefer_online || age > CACHE_TTL;
    let revalidate = stale && !opts.prefer_offline && !opts.offline;
    let mut refreshed = false;
    for (spec, name) in specs.iter().zip(&names) {
        let dir = entry.join("node_modules").join(name);
        let Ok(manifest) = read_manifest(&dir) else {
            return Ok(EntryState::Install {
                reason: "an installed package is missing",
            });
        };
        if !spec.revalidates() || !revalidate {
            continue;
        }
        match &spec.kind {
            SpecKind::Registry { name, kind, .. } => {
                let wanted = match kind {
                    crate::exec_spec::RegistryKind::Tag(tag) => tag.clone(),
                    crate::exec_spec::RegistryKind::Range(range) => range.clone(),
                    crate::exec_spec::RegistryKind::Version(_) => continue,
                };
                let installed = manifest["version"].as_str().unwrap_or("");
                match resolve_tag(name, &wanted).await {
                    Ok(resolved) if resolved == installed => refreshed = true,
                    Ok(_) => {
                        return Ok(EntryState::Install {
                            reason: "a newer version is available",
                        });
                    }
                    Err(error) => {
                        // Offline or registry trouble: the cached copy still runs.
                        tracing::debug!("could not revalidate {name}@{wanted}: {error:#}");
                    }
                }
            }
            SpecKind::Git(_) => {
                return Ok(EntryState::Install {
                    reason: "git spec is older than the cache TTL",
                });
            }
            _ => {}
        }
    }
    if refreshed {
        records.installed_at = now_secs();
        write_records(entry, &records)?;
    }
    Ok(EntryState::Hit(records))
}

/// Match each spec to the package name the planner resolved for it.
fn map_added(specs: &[ExecSpec], added: &[AddedSpec], entry: &Path) -> Result<Vec<String>> {
    let mut remaining: Vec<&AddedSpec> = added.iter().collect();
    let mut names = Vec::with_capacity(specs.len());
    let mut unresolved: Vec<usize> = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let position = match &spec.kind {
            SpecKind::Registry { name, .. } => remaining.iter().position(|a| &a.name == name),
            SpecKind::Directory(path) | SpecKind::File(path) => remaining.iter().position(|a| {
                // Compare canonical forms on both sides: the spec path has its
                // Windows verbatim prefix stripped, the planner's `file:` path
                // is relative to the entry.
                let wanted = std::fs::canonicalize(path).ok();
                a.raw
                    .strip_prefix("file:")
                    .map(|rel| entry.join(rel))
                    .and_then(|p| std::fs::canonicalize(p).ok())
                    .is_some_and(|resolved| Some(resolved) == wanted)
                    || a.raw == spec.raw
            }),
            SpecKind::Git(raw) | SpecKind::Remote(raw) => {
                remaining.iter().position(|a| &a.raw == raw)
            }
        };
        match position {
            Some(position) => names.push(remaining.remove(position).name.clone()),
            None => {
                names.push(String::new());
                unresolved.push(index);
            }
        }
    }
    // Arborist rewrites the raw form of nameless specs; when exactly one is
    // left on each side they belong together.
    if unresolved.len() == 1 && remaining.len() == 1 {
        names[unresolved[0]] = remaining[0].name.clone();
        unresolved.clear();
    }
    if let Some(index) = unresolved.first() {
        bail!(
            "could not determine which package {} resolved to",
            specs[*index].raw
        );
    }
    Ok(names)
}

/// Install (or refresh) a cache entry through the planner, store, and linker.
async fn install_entry(
    ctx: &ExecContext,
    opts: &ExecOptions,
    entry: &Path,
    specs: &[ExecSpec],
    components: &[String],
) -> Result<(PlacementPlan, DepGraph, Vec<AddedSpec>)> {
    let manifest_path = entry.join("package.json");
    if !manifest_path.exists() {
        std::fs::write(&manifest_path, "{}\n")?;
    }
    let mut request =
        PlacementRequest::add(specs.iter().map(ExecSpec::planner_spec).collect(), false);
    if let Some(age) = &ctx.min_release_age {
        request = request.with_min_release_age(age.age, age.exclude.clone());
    }
    if !opts.json {
        let label = specs
            .iter()
            .map(|spec| spec.raw.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("oath exec: resolving {label}...");
    }
    let mut plan = match ArboristPlanner::plan_with(entry, &request) {
        Ok(plan) => plan,
        Err(error)
            if ctx.min_release_age.is_some()
                && format!("{error:#}").contains("with a date before") =>
        {
            let age = ctx.min_release_age.as_ref().expect("checked above");
            eprintln!(
                "oath exec: BLOCKED -- no version of {} was published at least {} ago (min-release-age)",
                specs
                    .iter()
                    .map(|s| s.raw.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                age.display
            );
            return Err(AgeBlocked.into());
        }
        Err(error) => return Err(error),
    };
    let added = plan.added.clone();

    let mut document = PackageJsonDocument::load(&manifest_path)?;
    if let Some(root_manifest) = &plan.root_manifest {
        root_manifest.apply_to(&mut document.value);
    }
    document.value["_npx"] = serde_json::json!({ "packages": components });
    document.save()?;

    crate::hydrate_missing_registry_metadata(&mut plan).await?;
    let mut graph = plan.to_dep_graph()?;
    crate::enforce_banned_packages(&ctx.policy, &graph)
        .map_err(|error| anyhow::anyhow!("{error}").context("exec blocked by policy"))?;
    let store = Arc::new(ContentStore::default_store()?);
    let registry = Arc::new(RegistryClient::default_client()?);
    let (summary, _) = crate::download_and_prune(&mut plan, &mut graph, &store, registry).await?;
    if !opts.json && summary.downloaded > 0 {
        eprintln!(
            "oath exec: downloaded {} package(s) ({} KB)",
            summary.downloaded,
            summary.bytes / 1024
        );
    }
    // The linker compares canonical paths; on Windows those carry the `\\?\`
    // prefix the spec dropped for the planner, so canonicalize again here.
    let external: HashSet<PathBuf> = specs
        .iter()
        .filter_map(|spec| match &spec.kind {
            SpecKind::Directory(path) => {
                Some(std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
            }
            _ => None,
        })
        .collect();
    let linker = Linker::new((*store).clone()).with_external_link_targets(external);
    linker.link_placement_plan(&plan, entry)?;
    plan.write(&entry.join(".oath").join("placement-plan.json"))?;
    let deps: HashMap<String, String> = plan
        .root_manifest
        .as_ref()
        .and_then(|m| m.dependencies.as_ref())
        .map(|deps| {
            deps.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("*").to_string()))
                .collect()
        })
        .unwrap_or_default();
    Lockfile::from_graph_with_manifest(&graph, "oath-npx", "0.0.0", &deps, &HashMap::new())
        .write(&entry.join("oath-lock.json"))?;
    Ok((plan, graph, added))
}

/// Marker error for a planner refusal caused by the release-age cutoff.
#[derive(Debug)]
pub struct AgeBlocked;

impl std::fmt::Display for AgeBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("blocked by min-release-age")
    }
}

impl std::error::Error for AgeBlocked {}

/// A `concurrency.lock` file, as npm keeps per entry, so two execs of the
/// same specs do not install into one directory at once.
struct EntryLock {
    path: PathBuf,
}

impl EntryLock {
    /// Take the entry's `concurrency.lock`, waiting briefly for another run
    /// to release it and failing when it does not.
    fn acquire(entry: &Path) -> Result<Self> {
        let path = entry.join("concurrency.lock");
        let started = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age > Duration::from_secs(600));
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() > Duration::from_secs(120) {
                        bail!(
                            "another oath exec is still installing into {}; remove {} if it is stale",
                            entry.display(),
                            path.display()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("locking {}", path.display()));
                }
            }
        }
    }
}

impl Drop for EntryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---- min-release-age --------------------------------------------------------

/// Command line, then `.npmrc`, then Oath policy.
fn resolve_min_release_age(
    opts: &ExecOptions,
    prefix: &Path,
    policy: &OathPolicy,
) -> Result<Option<MinReleaseAge>> {
    let npmrc = npmrc_values(prefix);
    let raw = opts
        .min_release_age
        .clone()
        .or_else(|| npmrc.get("min-release-age").cloned())
        .or_else(|| policy.min_release_age.clone());
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.trim().to_string();
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }
    let secs = raw
        .parse::<u64>()
        .ok()
        .map(|days| days * 86_400)
        .or_else(|| crate::parse_duration_secs(&raw))
        .with_context(|| format!("invalid min-release-age {raw:?}: use a day count like 7 or a duration like 7d / 24h"))?;
    let mut exclude: Vec<String> = opts.min_release_age_exclude.clone();
    for key in ["min-release-age-exclude", "min-release-age-exclude[]"] {
        if let Some(value) = npmrc.get(key) {
            exclude.extend(
                value
                    .split(['\n', ','])
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(String::from),
            );
        }
    }
    exclude.extend(policy.min_release_age_exclude.iter().cloned());
    exclude.sort();
    exclude.dedup();
    Ok(Some(MinReleaseAge {
        age: Duration::from_secs(secs),
        exclude,
        display: raw,
    }))
}

/// The `.npmrc` keys relevant here, user file first then project file, with
/// repeated `key[]` lines joined by newlines as npm does.
fn npmrc_values(prefix: &Path) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut files = Vec::new();
    if let Some(home) = oath_core::home_dir() {
        files.push(home.join(".npmrc"));
    }
    if let Some(user_config) = std::env::var_os("NPM_CONFIG_USERCONFIG") {
        files.push(PathBuf::from(user_config));
    }
    files.push(prefix.join(".npmrc"));
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if !key.starts_with("min-release-age") {
                continue;
            }
            let value = value.trim().trim_matches('"').to_string();
            if key.ends_with("[]") {
                values
                    .entry(key.to_string())
                    .and_modify(|existing: &mut String| {
                        existing.push('\n');
                        existing.push_str(&value);
                    })
                    .or_insert(value);
            } else {
                values.insert(key.to_string(), value);
            }
        }
    }
    if let Ok(value) = std::env::var("npm_config_min_release_age") {
        values.insert("min-release-age".into(), value);
    }
    values
}

// ---- assessment and the gate ------------------------------------------------

/// Registry context for the card and the assessment. Skipped offline, and
/// skipped on cache hits unless the run needs a fresh document.
async fn registry_info_for(opts: &ExecOptions, target: &Target, wanted: bool) -> RegistryInfo {
    if opts.offline || !(wanted || opts.dry_run || opts.json || opts.json_file.is_some()) {
        return RegistryInfo::default();
    }
    let Ok(client) = RegistryClient::default_client() else {
        return RegistryInfo::default();
    };
    let Ok(full) = client.fetch_packument_full(&target.name).await else {
        return RegistryInfo::default();
    };
    let published_at = full
        .get("time")
        .and_then(|t| t.get(&target.version))
        .and_then(|s| s.as_str())
        .map(String::from);
    let age_days = published_at
        .as_deref()
        .and_then(crate::parse_iso_age_secs)
        .map(|secs| secs / 86_400);
    let publisher = full
        .get("versions")
        .and_then(|vs| vs.get(&target.version))
        .and_then(|ver| ver.get("_npmUser"))
        .and_then(|u| u.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
        .or_else(|| {
            full.get("maintainers")
                .and_then(|m| m.as_array())
                .and_then(|a| a.first())
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from)
        });
    let repository = full.get("repository").and_then(|r| {
        r.get("url")
            .and_then(|u| u.as_str())
            .or_else(|| r.as_str())
            .map(String::from)
    });
    let has_hooks = read_manifest(&target.dir)
        .ok()
        .and_then(|m| m.get("scripts").cloned())
        .and_then(|s| s.as_object().cloned())
        .is_some_and(|scripts| {
            scripts
                .keys()
                .any(|k| matches!(k.as_str(), "preinstall" | "install" | "postinstall"))
        });
    let version_diff =
        crate::previous_release_diff(&full, &target.version, publisher.as_deref(), has_hooks);
    let weekly_downloads =
        match oath_fetch::http::client_builder().and_then(|b| b.build().map_err(Into::into)) {
            Ok(http) => oath_fetch::fetch_package_metadata(&http, &target.name)
                .await
                .ok()
                .and_then(|meta| meta.weekly_downloads),
            Err(_) => None,
        };
    RegistryInfo {
        published_at,
        age_days,
        publisher,
        repository,
        version_diff,
        weekly_downloads,
        fetched: true,
    }
}

struct Assessment {
    assessment: exec_assessment::ExecAssessment,
    grade: String,
    score: u8,
    perms: Vec<String>,
    serious: Vec<String>,
    obfuscated: bool,
    unpacked_kb: u64,
    approval: approvals::ExecApproval,
    previously_approved: bool,
    sandbox_plan: Option<oath_sandbox::SandboxPlan>,
}

/// The capabilities the chosen sandbox mode can enforce: the native backend
/// proves its own, the Node permission model is fixed, and off has none.
fn sandbox_capabilities(mode: ExecSandboxMode) -> oath_sandbox::BackendCapabilities {
    match mode {
        ExecSandboxMode::Native => oath_sandbox::verified_native_capabilities(),
        ExecSandboxMode::Node => oath_sandbox::BackendCapabilities {
            backend: "node-permissions".into(),
            available: true,
            filesystem_isolation: true,
            network_isolation: true,
            process_isolation: false,
            resource_limits: false,
            degraded_reason: Some("Node permissions are not an OS process sandbox".into()),
        },
        _ => oath_sandbox::BackendCapabilities {
            backend: "off".into(),
            available: true,
            filesystem_isolation: false,
            network_isolation: false,
            process_isolation: false,
            resource_limits: false,
            degraded_reason: Some("sandbox disabled".into()),
        },
    }
}

/// The sandbox plan for running a bin from `install_dir` in the user's cwd:
/// the cwd is the working directory and writable (tools like formatters
/// write there), the install tree and the temp dir are granted, and
/// network follows the deny flag unless the package needs it.
fn sandbox_plan_for(
    ctx: &ExecContext,
    name: &str,
    install_dir: &Path,
    needs_network: bool,
) -> Option<oath_sandbox::SandboxPlan> {
    if ctx.sandbox.effective_mode == ExecSandboxMode::Off {
        return None;
    }
    let mut plan = oath_sandbox::SandboxPlan::strict(name.to_string(), ctx.cwd.clone());
    if !plan.read_only_paths.contains(&install_dir.to_path_buf()) {
        plan.read_only_paths.push(install_dir.to_path_buf());
    }
    let tmp = std::env::temp_dir();
    if !plan.writable_paths.contains(&tmp) {
        plan.writable_paths.push(tmp);
    }
    if !ctx.deny_network && needs_network {
        plan.network = oath_sandbox::NetworkMode::Inherit;
    }
    Some(plan)
}

/// Scan and score a target, producing the assessment document and the
/// integrity-bound approval it would be remembered under.
fn assess(
    ctx: &ExecContext,
    opts: &ExecOptions,
    target: &Target,
    registry: &RegistryInfo,
    binary: Option<&str>,
) -> Result<Assessment> {
    let report = PackageScanner::scan(&target.name, &target.version, &target.dir)?;
    let caps = &report.capabilities;
    // Popularity and age context so widely used packages are graded as such.
    let score_ctx = ScoreContext {
        is_dev: false,
        weekly_downloads: registry.weekly_downloads.unwrap_or(0),
        age_days: registry.age_days.map(|d| d as u32).unwrap_or(0),
    };
    let score = compute_safety_score_contextual(&report, &target.dir, &score_ctx);
    let obfuscated = report.findings.iter().any(|f| {
        f.kind == FindingKind::Obfuscation
            && matches!(f.risk, RiskLevel::High | RiskLevel::Critical)
    });
    let serious = if matches!(report.overall_risk, RiskLevel::High | RiskLevel::Critical) {
        report.verdict_reasons.clone()
    } else {
        Vec::new()
    };
    let mut perms: Vec<String> = Vec::new();
    for (flag, label) in [
        (caps.network, "network"),
        (caps.filesystem, "filesystem"),
        (caps.env_access, "env"),
        (caps.subprocess, "subprocess"),
        (caps.dynamic_exec, "eval"),
        (caps.has_install_scripts, "install-scripts"),
    ] {
        if flag {
            perms.push(label.to_string());
        }
    }
    let unpacked_bytes = crate::dir_size(&target.dir);
    let grade_blocked = opts
        .require_grade
        .as_deref()
        .map(|g| {
            crate::grade_rank(score.grade) < crate::grade_rank(g.chars().next().unwrap_or('A'))
        })
        .unwrap_or(false);
    let install_dir = target
        .dir
        .ancestors()
        .find(|dir| dir.file_name().is_some_and(|n| n == "node_modules"))
        .and_then(Path::parent)
        .unwrap_or(&target.dir)
        .to_path_buf();
    let sandbox_plan = sandbox_plan_for(ctx, &target.name, &install_dir, caps.network);
    let native_code = ["binding.gyp", "prebuilds"]
        .iter()
        .any(|p| target.dir.join(p).exists());
    let dependency_count = Lockfile::read(&install_dir.join("oath-lock.json"))
        .map(|lock| lock.packages.len())
        .unwrap_or(0);
    let assessment = exec_assessment::ExecAssessment {
        schema_version: exec_assessment::EXEC_ASSESSMENT_VERSION,
        identity: exec_assessment::PackageIdentity {
            name: target.name.clone(),
            version: target.version.clone(),
            binary: binary.map(String::from),
            registry: "https://registry.npmjs.org".into(),
            integrity: target.integrity.clone(),
            publisher: registry.publisher.clone(),
            publish_age_days: registry.age_days,
            repository: registry.repository.clone(),
        },
        evidence: exec_assessment::PackageEvidence {
            unpacked_bytes,
            dependency_count,
            readable_source: !obfuscated,
            obfuscated,
            native_code,
            lifecycle_hooks: caps.has_install_scripts,
            capabilities: perms.clone(),
            findings: serious.clone(),
            limitations: vec![
                "Static analysis cannot prove safety",
                "Remote second-stage payloads and opaque binaries may evade inspection",
            ],
            version_diff: registry.version_diff.clone(),
        },
        policy: exec_assessment::PolicyDecision {
            decision: if grade_blocked { "block" } else { "allow" },
            reason_code: if grade_blocked {
                oath_contracts::ReasonCode::ExecGradeBelowRequired
            } else {
                oath_contracts::ReasonCode::ExecAllowed
            },
            grade: score.grade.to_string(),
            score: score.score,
        },
        sandbox: sandbox_capabilities(ctx.sandbox.effective_mode),
        sandbox_plan: sandbox_plan.clone(),
    };
    let approval = approvals::ExecApproval {
        package: target.name.clone(),
        version: target.version.clone(),
        integrity: target.integrity.clone().unwrap_or_default(),
        capabilities: perms.clone(),
        sandbox_backend: assessment.sandbox.backend.clone(),
        deny_network: ctx.deny_network,
    };
    let previously_approved = !approval.integrity.is_empty()
        && approvals::ApprovalStore::default_store()?.contains(&approval)?;
    Ok(Assessment {
        assessment,
        grade: score.grade.to_string(),
        score: score.score,
        perms,
        serious,
        obfuscated,
        unpacked_kb: unpacked_bytes / 1024,
        approval,
        previously_approved,
        sandbox_plan,
    })
}

/// Build the signed `ExecAssessment` document for `--json` and `--json-file`.
fn verdict_json(
    ctx: &ExecContext,
    opts: &ExecOptions,
    target: &Target,
    registry: &RegistryInfo,
    assessed: &Assessment,
    command: Option<&str>,
) -> Result<serde_json::Value> {
    let grade_blocked = assessed.assessment.policy.decision == "block";
    let policy_digest = oath_contracts::digest_json(&serde_json::json!({
        "require_grade": opts.require_grade,
        "min_age": ctx.min_release_age.as_ref().map(|a| a.display.clone()),
        "sandbox_mode": ctx.sandbox.effective_mode.as_str(),
        "deny_network": ctx.deny_network,
        "allow_degraded_sandbox": opts.allow_degraded_sandbox,
    }))?;
    let assessment_value = if opts.schema_version == 2 {
        serde_json::to_value(&assessed.assessment)?
    } else {
        serde_json::to_value(exec_assessment::signed_v3(
            &assessed.assessment,
            now_secs(),
            policy_digest,
        )?)?
    };
    Ok(serde_json::json!({
        "assessment": assessment_value,
        "approval": { "integrity_bound": true, "previously_approved": assessed.previously_approved },
        "name": target.name,
        "version": target.version,
        "integrity": target.integrity,
        "command": command,
        "grade": assessed.grade,
        "score": assessed.score,
        "age_days": registry.age_days,
        "last_publisher": registry.publisher,
        "open_source": registry.repository.is_some(),
        "repository": registry.repository,
        "obfuscated": assessed.obfuscated,
        "unpacked_kb": assessed.unpacked_kb,
        "permissions": assessed.perms,
        "sandbox_mode": ctx.sandbox.requested_mode.as_str(),
        "sandbox_effective": ctx.sandbox.effective_mode.as_str(),
        "sandbox_degraded_allowed": opts.allow_degraded_sandbox,
        "network_denied": ctx.deny_network,
        "verdict": if assessed.serious.is_empty() { "ok" } else { "serious" },
        "findings": assessed.serious,
        "decision": if grade_blocked { "block" } else { "allow" },
        "reason": if grade_blocked { "require-grade" } else { "" },
    }))
}

/// The rich pre-run card: what npx's "Need to install the following
/// packages" line would say, with the evidence Oath gathered.
fn print_card(
    out: &mut dyn Write,
    ctx: &ExecContext,
    target: &Target,
    registry: &RegistryInfo,
    assessed: &Assessment,
    installing: bool,
) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "  {}@{}{}",
        target.name,
        target.version,
        if installing {
            "  (not installed yet)"
        } else {
            ""
        }
    )?;
    if let Some(integrity) = &target.integrity {
        writeln!(out, "  integrity    {}", shorten(integrity, 32))?;
    }
    writeln!(
        out,
        "  grade        {} ({}/100)",
        assessed.grade, assessed.score
    )?;
    match (
        &registry.published_at,
        registry.age_days,
        &registry.publisher,
    ) {
        (Some(when), Some(days), Some(who)) => writeln!(
            out,
            "  published    {} ({days} days ago) by {who}",
            &when[..when.len().min(10)]
        )?,
        (Some(when), Some(days), None) => writeln!(
            out,
            "  published    {} ({days} days ago)",
            &when[..when.len().min(10)]
        )?,
        (None, Some(days), _) => writeln!(out, "  published    {days} days ago")?,
        _ if registry.fetched => writeln!(out, "  published    unknown")?,
        _ => {}
    }
    if let Some(diff) = &registry.version_diff {
        writeln!(
            out,
            "  last change  {} -> {}: {}, install hooks {}",
            diff.previous_version,
            target.version,
            match diff.publisher_changed {
                Some(true) => "publisher changed",
                Some(false) => "same publisher",
                None => "publisher unknown",
            },
            if diff.lifecycle_hooks_changed {
                "changed"
            } else {
                "unchanged"
            }
        )?;
    }
    let mut size = format!("{} KB", assessed.unpacked_kb);
    if let Some(downloads) = registry.weekly_downloads {
        size.push_str(&format!(
            " · {} weekly downloads",
            group_thousands(downloads)
        ));
    }
    writeln!(out, "  size         {size}")?;
    writeln!(
        out,
        "  open source  {}",
        if registry.repository.is_some() {
            "yes"
        } else {
            "unknown"
        }
    )?;
    writeln!(
        out,
        "  source       {}",
        if assessed.obfuscated {
            "obfuscated"
        } else {
            "readable"
        }
    )?;
    writeln!(
        out,
        "  permissions  {}",
        if assessed.perms.is_empty() {
            "none".to_string()
        } else {
            assessed.perms.join(", ")
        }
    )?;
    match &assessed.sandbox_plan {
        Some(plan) => writeln!(
            out,
            "  sandbox      {} (cwd read-write, install tree read-only, network {})",
            ctx.sandbox.effective_mode.as_str(),
            match plan.network {
                oath_sandbox::NetworkMode::Deny => "denied",
                oath_sandbox::NetworkMode::Inherit => "allowed",
            }
        )?,
        None => writeln!(out, "  sandbox      off")?,
    }
    if !assessed.serious.is_empty() {
        writeln!(out, "\n  findings:")?;
        for finding in assessed.serious.iter().take(5) {
            writeln!(out, "    {finding}")?;
        }
    }
    Ok(())
}

/// Truncate a card value to `max` bytes with an ellipsis.
fn shorten(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}…", &value[..max])
    }
}

/// Format a count with thousands separators for the card.
fn group_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Assess a target and apply every gate: the grade requirement, JSON and
/// dry-run output, npm's prompt rule for fresh installs, Oath's prompt for
/// serious findings, and `--remember`.
fn gate(
    ctx: &ExecContext,
    opts: &ExecOptions,
    target: &Target,
    registry: &RegistryInfo,
    installing: bool,
    command: Option<&str>,
) -> Result<Gate> {
    let assessed = assess(ctx, opts, target, registry, command)?;
    let grade_blocked = assessed.assessment.policy.decision == "block";
    let record = PackageRecord {
        version: target.version.clone(),
        integrity: target.integrity.clone(),
        grade: assessed.grade.clone(),
        score: assessed.score,
        capabilities: assessed.perms.clone(),
        findings: assessed.serious.clone(),
        published_at: registry.published_at.clone(),
        approved: false,
    };
    if opts.json || opts.json_file.is_some() {
        let verdict = verdict_json(ctx, opts, target, registry, &assessed, command)?;
        let text = serde_json::to_string_pretty(&verdict)?;
        if let Some(path) = &opts.json_file {
            std::fs::write(path, format!("{text}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
        }
        if opts.json {
            println!("{text}");
            return Ok(Gate::Exit(if grade_blocked { EXEC_EXIT_GRADE } else { 0 }));
        }
    }
    if opts.dry_run {
        let mut stdout = std::io::stdout().lock();
        print_card(&mut stdout, ctx, target, registry, &assessed, installing)?;
        if grade_blocked {
            eprintln!(
                "\n  BLOCKED -- grade {} is below required {}",
                assessed.grade,
                opts.require_grade.as_deref().unwrap_or("")
            );
            return Ok(Gate::Exit(EXEC_EXIT_GRADE));
        }
        return Ok(Gate::Exit(0));
    }
    if grade_blocked {
        eprintln!(
            "oath exec: BLOCKED -- {}@{} grade {} is below required {}",
            target.name,
            target.version,
            assessed.grade,
            opts.require_grade.as_deref().unwrap_or("")
        );
        return Ok(Gate::Exit(EXEC_EXIT_GRADE));
    }

    let allow_all = std::env::var_os("OATH_ALLOW_ALL").is_some();
    let waived = opts.yes || assessed.previously_approved || allow_all;
    let serious = !assessed.serious.is_empty();
    if !waived && (installing || serious) {
        let mut stderr = std::io::stderr().lock();
        if ctx.interactive {
            if installing {
                writeln!(
                    stderr,
                    "oath exec: {}@{} needs to be installed",
                    target.name, target.version
                )?;
            } else {
                writeln!(
                    stderr,
                    "oath exec: {}@{} has serious findings",
                    target.name, target.version
                )?;
            }
            print_card(&mut stderr, ctx, target, registry, &assessed, installing)?;
            let default_yes = !serious;
            write!(
                stderr,
                "\n  Ok to proceed? [{}] ",
                if default_yes { "Y/n" } else { "y/N" }
            )?;
            stderr.flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let answer = input.trim().to_ascii_lowercase();
            let accepted = match answer.as_str() {
                "" => default_yes,
                other => other.starts_with('y'),
            };
            if !accepted {
                writeln!(stderr, "oath exec: canceled")?;
                return Ok(Gate::Exit(EXEC_EXIT_USER));
            }
        } else if serious {
            writeln!(
                stderr,
                "oath exec: BLOCKED -- {}@{} has serious findings and no terminal is available to confirm; pass --yes to run anyway",
                target.name, target.version
            )?;
            print_card(&mut stderr, ctx, target, registry, &assessed, installing)?;
            return Ok(Gate::Exit(EXEC_EXIT_USER));
        } else {
            writeln!(
                stderr,
                "oath exec: {}@{} was not found and will be installed (grade {}, {})",
                target.name,
                target.version,
                assessed.grade,
                if assessed.perms.is_empty() {
                    "no capabilities detected".to_string()
                } else {
                    assessed.perms.join(", ")
                }
            )?;
        }
    }
    if opts.remember {
        anyhow::ensure!(
            !assessed.approval.integrity.is_empty(),
            "cannot remember an approval without registry integrity"
        );
        approvals::ApprovalStore::default_store()?.remember(assessed.approval.clone())?;
    }
    Ok(Gate::Proceed(PackageRecord {
        approved: true,
        ..record
    }))
}

// ---- installed bins ---------------------------------------------------------

/// Run a bin found in a `node_modules/.bin` (local walk-up or global): the
/// owning package is scanned and gated, nothing is downloaded.
async fn run_installed_bin(
    ctx: &ExecContext,
    opts: &ExecOptions,
    bin_dir: &Path,
    cmd: &str,
    args: &[String],
) -> Result<i32> {
    // Only the bin directory that was found is searched, never the host PATH.
    let file = launch::command_in_dir(bin_dir, cmd)
        .with_context(|| format!("{cmd} is not in {}", bin_dir.display()))?;
    let resolved = std::fs::canonicalize(&file)?;
    let (package_dir, manifest) = owning_package(&resolved)
        .with_context(|| format!("no named package.json above {}", resolved.display()))?;
    let name = manifest["name"].as_str().unwrap_or(cmd).to_string();
    let version = manifest["version"].as_str().unwrap_or("0.0.0").to_string();
    let install_root = bin_dir.parent().and_then(Path::parent).unwrap_or(bin_dir);
    let target = Target {
        name: name.clone(),
        version,
        dir: package_dir,
        integrity: lock_integrity(install_root, &name),
    };
    let registry = registry_info_for(opts, &target, false).await;
    let record = match gate(ctx, opts, &target, &registry, false, Some(cmd))? {
        Gate::Exit(code) => return Ok(code),
        Gate::Proceed(record) => record,
    };
    let needs_network = record.capabilities.iter().any(|c| c == "network");
    let mut full_args = vec![cmd.to_string()];
    full_args.extend(args.iter().cloned());
    run_resolved(
        ctx,
        opts,
        &full_args,
        &[bin_dir.to_path_buf()],
        &name,
        needs_network,
    )
    .await
}

/// The package a bin file belongs to: the nearest ancestor whose
/// `package.json` names a package. Packages such as rimraf keep a
/// `{"type": "module"}` stub next to their `dist/esm` bin, which is not the
/// package root.
fn owning_package(file: &Path) -> Option<(PathBuf, serde_json::Value)> {
    file.ancestors().skip(1).find_map(|dir| {
        let manifest = read_manifest(dir).ok()?;
        manifest["name"].as_str()?;
        Some((dir.to_path_buf(), manifest))
    })
}

// ---- lifecycle scripts ------------------------------------------------------

/// Run the lifecycle scripts of a freshly installed entry under install's
/// trust rules: the requested packages (the user chose to run their code),
/// the policy allow-list, and packages a requested package trusts run;
/// `block_install_scripts` stops everything else; `--yes` approves the rest.
fn run_entry_scripts(
    ctx: &ExecContext,
    opts: &ExecOptions,
    entry: &Path,
    plan: &PlacementPlan,
    graph: &DepGraph,
    requested: &[String],
) -> Result<()> {
    let targets = crate::install_script_targets(Some(plan), graph, entry);
    if targets.is_empty() {
        return Ok(());
    }
    let mut trusted: HashSet<String> = requested.iter().cloned().collect();
    for name in requested {
        if let Ok(manifest) = read_manifest(&entry.join("node_modules").join(name))
            && let Some(list) = manifest
                .get("trustedDependencies")
                .and_then(|v| v.as_array())
        {
            trusted.extend(list.iter().filter_map(|v| v.as_str().map(String::from)));
        }
    }
    let mut skipped = Vec::new();
    for target in targets {
        if !target.dir.exists() {
            continue;
        }
        let allowed = trusted.contains(&target.name)
            || ctx.policy.allows_install_script(&target.name)
            || (!ctx.policy.block_install_scripts && opts.yes);
        if !allowed {
            skipped.push(format!("{}@{}", target.name, target.version));
            continue;
        }
        run_lifecycle_scripts(ctx, entry, &target.name, &target.dir)?;
    }
    if !skipped.is_empty() && !opts.json {
        eprintln!(
            "oath exec: skipped install scripts of {} (add to allow_install_scripts in oath-policy.toml{})",
            skipped.join(", "),
            if ctx.policy.block_install_scripts {
                ""
            } else {
                " or pass --yes"
            }
        );
    }
    Ok(())
}

/// Run preinstall/install/postinstall of one package in its install
/// location, inside the native sandbox when one is active (the install tree
/// writable, network as the run allows), otherwise plainly.
fn run_lifecycle_scripts(
    ctx: &ExecContext,
    entry: &Path,
    name: &str,
    pkg_dir: &Path,
) -> Result<()> {
    let manifest = read_manifest(pkg_dir)?;
    let Some(scripts) = manifest.get("scripts").and_then(|s| s.as_object()).cloned() else {
        return Ok(());
    };
    let node = launch::active_node_executable().ok();
    for hook in ["preinstall", "install", "postinstall"] {
        let Some(cmd) = scripts.get(hook).and_then(|v| v.as_str()) else {
            continue;
        };
        let mut env = launch::exec_env(
            pkg_dir,
            entry,
            &[entry.join("node_modules").join(".bin")],
            cmd,
            node.as_deref(),
        );
        env.retain(|(k, _)| k != "npm_lifecycle_event" && k != "npm_package_json");
        env.push(("npm_lifecycle_event".into(), hook.to_string()));
        env.push((
            "npm_package_json".into(),
            pkg_dir.join("package.json").display().to_string(),
        ));
        env.extend(crate::npm_package_env(&manifest));
        let launch = launch::shell_launch(cmd);
        let status = if ctx.sandbox.effective_mode == ExecSandboxMode::Native {
            let mut plan =
                oath_sandbox::SandboxPlan::strict(name.to_string(), pkg_dir.to_path_buf());
            plan.read_only_paths = vec![entry.to_path_buf()];
            plan.writable_paths = vec![entry.to_path_buf(), std::env::temp_dir()];
            if let Some(node) = &node
                && !is_system_path(node)
            {
                plan.read_only_paths.push(node.clone());
            }
            // Install scripts routinely fetch prebuilt binaries, so they keep
            // the network unless the run denies it. The Windows backend has
            // no outbound grant and refuses any plan that asks for one.
            if !ctx.deny_network && !cfg!(windows) {
                plan.network = oath_sandbox::NetworkMode::Inherit;
            }
            run_native(&plan, &launch, &env)?
        } else {
            launch::spawn_plain(&launch, pkg_dir, &env)?
        };
        if !status.success() {
            eprintln!(
                "oath exec: warning -- {hook} for {name} exited with {}",
                status.code().unwrap_or(-1)
            );
        }
    }
    Ok(())
}

/// Whether a path lives under a system prefix the sandbox plan already
/// grants read access to.
fn is_system_path(path: &Path) -> bool {
    ["/usr", "/bin", "/lib", "/lib64"]
        .iter()
        .any(|root| path.starts_with(root))
}

// ---- launching --------------------------------------------------------------

/// Resolve `args[0]` (or the `--call` script) on the bin paths and run it.
async fn run_resolved(
    ctx: &ExecContext,
    opts: &ExecOptions,
    args: &[String],
    bin_dirs: &[PathBuf],
    package_name: &str,
    needs_network: bool,
) -> Result<i32> {
    if let Some(script) = &opts.call {
        let launch = launch::shell_launch(script);
        return spawn(
            ctx,
            opts,
            &launch,
            bin_dirs,
            script,
            package_name,
            None,
            needs_network,
        )
        .await;
    }
    let cmd = args.first().context("no command to run")?;
    let file = match launch::find_command(cmd, bin_dirs, &ctx.cwd) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("oath exec: {error}");
            return Ok(127);
        }
    };
    launch_command(
        ctx,
        opts,
        &file,
        &args[1..],
        bin_dirs,
        Some(package_name),
        cmd,
        needs_network,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn launch_command(
    ctx: &ExecContext,
    opts: &ExecOptions,
    file: &Path,
    args: &[String],
    bin_dirs: &[PathBuf],
    package_name: Option<&str>,
    cmd: &str,
    needs_network: bool,
) -> Result<i32> {
    if opts.dry_run {
        // Only reachable for the project's own bin; the gated paths exit earlier.
        eprintln!("oath exec: would run {} (project bin)", file.display());
        return Ok(0);
    }
    let launch = launch::plan_launch(file, args)?;
    let script = std::iter::once(cmd.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    spawn(
        ctx,
        opts,
        &launch,
        bin_dirs,
        &script,
        package_name.unwrap_or(cmd),
        Some(file),
        needs_network,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn spawn(
    ctx: &ExecContext,
    _opts: &ExecOptions,
    launch: &Launch,
    bin_dirs: &[PathBuf],
    script: &str,
    package_name: &str,
    file: Option<&Path>,
    needs_network: bool,
) -> Result<i32> {
    let node = launch::active_node_executable().ok();
    let env = launch::exec_env(&ctx.cwd, &ctx.prefix, bin_dirs, script, node.as_deref());
    let status = match ctx.sandbox.effective_mode {
        ExecSandboxMode::Off | ExecSandboxMode::Auto => {
            launch::spawn_plain(launch, &ctx.cwd, &env)?
        }
        ExecSandboxMode::Native => {
            anyhow::ensure!(
                launch.raw_command_line.is_none(),
                "the Windows native sandbox cannot run shell scripts or .cmd shims; run `{script}` without --sandbox-mode native"
            );
            let install_dir = bin_dirs
                .first()
                .and_then(|bin| bin.parent())
                .and_then(Path::parent)
                .unwrap_or(&ctx.cwd)
                .to_path_buf();
            let mut plan = sandbox_plan_for(ctx, package_name, &install_dir, needs_network)
                .context("native sandbox requires a plan")?;
            if !is_system_path(&launch.program)
                && !plan
                    .read_only_paths
                    .iter()
                    .any(|p| launch.program.starts_with(p))
            {
                plan.read_only_paths.push(launch.program.clone());
            }
            if let Some(file) = file
                && let Ok(target) = std::fs::canonicalize(file)
                && !plan.read_only_paths.iter().any(|p| target.starts_with(p))
            {
                plan.read_only_paths.push(target);
            }
            run_native(&plan, launch, &env)?
        }
        ExecSandboxMode::Node => {
            let Some(node) = &node else {
                bail!("Node permission sandbox requires node on PATH");
            };
            anyhow::ensure!(
                launch.program == *node,
                "the Node permission sandbox only applies to JavaScript bins; {} runs {}",
                script,
                launch.program.display()
            );
            let flag = crate::node_permission_flag()
                .context("Node permission sandbox is unavailable on this Node runtime")?;
            let install_dir = bin_dirs
                .first()
                .and_then(|bin| bin.parent())
                .and_then(Path::parent)
                .unwrap_or(&ctx.cwd)
                .to_path_buf();
            let tmp = std::env::temp_dir();
            let mut args = vec![
                flag.to_string(),
                format!("--allow-fs-read={}", ctx.cwd.display()),
                format!("--allow-fs-read={}", install_dir.display()),
                format!("--allow-fs-read={}", tmp.display()),
                format!("--allow-fs-write={}", ctx.cwd.display()),
                format!("--allow-fs-write={}", tmp.display()),
            ];
            args.extend(launch.args.iter().cloned());
            let launch = Launch {
                program: node.clone(),
                args,
                raw_command_line: None,
            };
            launch::spawn_plain(&launch, &ctx.cwd, &env)?
        }
    };
    Ok(status.code().unwrap_or(1))
}

#[cfg(target_os = "linux")]
fn run_native(
    plan: &oath_sandbox::SandboxPlan,
    launch: &Launch,
    env: &[(String, String)],
) -> Result<std::process::ExitStatus> {
    oath_sandbox::linux::run_with_env(plan, &launch.program, &launch.args, env)
}

#[cfg(target_os = "macos")]
fn run_native(
    plan: &oath_sandbox::SandboxPlan,
    launch: &Launch,
    env: &[(String, String)],
) -> Result<std::process::ExitStatus> {
    oath_sandbox::macos::run_with_env(plan, &launch.program, &launch.args, env)
}

#[cfg(target_os = "windows")]
fn run_native(
    plan: &oath_sandbox::SandboxPlan,
    launch: &Launch,
    env: &[(String, String)],
) -> Result<std::process::ExitStatus> {
    oath_sandbox::windows::run_with_env(plan, &launch.program, &launch.args, env)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_native(
    _plan: &oath_sandbox::SandboxPlan,
    _launch: &Launch,
    _env: &[(String, String)],
) -> Result<std::process::ExitStatus> {
    bail!("native sandbox is not available on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(raw: &str) -> ExecSpec {
        ExecSpec::parse(raw, Path::new("/")).unwrap()
    }

    #[test]
    fn added_specs_map_by_name_raw_and_remainder() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("local");
        std::fs::create_dir_all(&local).unwrap();
        let entry = dir.path().join("entry");
        std::fs::create_dir_all(&entry).unwrap();
        let specs = vec![
            spec("cowsay@1"),
            ExecSpec::parse(local.to_str().unwrap(), dir.path()).unwrap(),
            spec("github:user/repo"),
        ];
        let added = vec![
            AddedSpec {
                raw: "github:user/repo".into(),
                name: "repo".into(),
            },
            AddedSpec {
                raw: "cowsay@1".into(),
                name: "cowsay".into(),
            },
            AddedSpec {
                raw: "file:../local".into(),
                name: "local-tool".into(),
            },
        ];
        assert_eq!(
            map_added(&specs, &added, &entry).unwrap(),
            vec!["cowsay", "local-tool", "repo"]
        );
        // Two nameless specs with rewritten raws cannot be told apart.
        let specs = vec![spec("github:a/b"), spec("github:c/d")];
        let added = vec![
            AddedSpec {
                raw: "x".into(),
                name: "b".into(),
            },
            AddedSpec {
                raw: "y".into(),
                name: "d".into(),
            },
        ];
        assert!(map_added(&specs, &added, &entry).is_err());
    }

    #[test]
    fn records_round_trip_and_names_are_exposed() {
        let dir = tempfile::tempdir().unwrap();
        let records = ExecRecords {
            schema_version: RECORDS_VERSION,
            installed_at: 1,
            packages: vec!["cowsay".into()],
            added: vec![AddedSpec {
                raw: "cowsay".into(),
                name: "cowsay".into(),
            }],
            cooldown: None,
            scripts_pending: false,
            records: BTreeMap::new(),
        };
        write_records(dir.path(), &records).unwrap();
        assert_eq!(read_records(dir.path()).unwrap().packages, vec!["cowsay"]);
        assert_eq!(recorded_names(dir.path())[0].name, "cowsay");
    }

    #[test]
    fn project_bin_requires_a_file_inside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"demo","bin":{"hello":"./hello.js","escape":"../outside.js","gone":"./missing.js"}}"#,
        )
        .unwrap();
        std::fs::write(project.join("hello.js"), "").unwrap();
        // The escape target exists, so only the containment check can refuse it.
        std::fs::write(dir.path().join("outside.js"), "").unwrap();
        assert_eq!(
            project_bin(&project, "hello").unwrap(),
            Some(project.join("./hello.js"))
        );
        assert!(project_bin(&project, "escape").is_err());
        assert!(project_bin(&project, "gone").is_err());
        assert_eq!(project_bin(&project, "missing").unwrap(), None);
    }

    #[test]
    fn entry_lock_is_exclusive_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let lock = EntryLock::acquire(dir.path()).unwrap();
        assert!(dir.path().join("concurrency.lock").exists());
        drop(lock);
        assert!(!dir.path().join("concurrency.lock").exists());
    }

    fn options() -> ExecOptions {
        ExecOptions {
            args: vec![],
            packages: vec![],
            call: None,
            yes: false,
            no_install: false,
            min_release_age: None,
            min_release_age_exclude: vec![],
            json: false,
            json_file: None,
            schema_version: 3,
            require_grade: None,
            dry_run: false,
            sandbox: false,
            sandbox_mode: ExecSandboxMode::Off,
            deny_network: false,
            allow_degraded_sandbox: false,
            remember: false,
            offline: false,
            prefer_offline: false,
            prefer_online: false,
            ignore_scripts: false,
        }
    }

    #[test]
    fn min_release_age_comes_from_flag_then_npmrc_then_policy() {
        let dir = tempfile::tempdir().unwrap();
        let policy = OathPolicy {
            min_release_age: Some("3d".into()),
            min_release_age_exclude: vec!["from-policy".into()],
            ..OathPolicy::default()
        };
        let resolved = resolve_min_release_age(&options(), dir.path(), &policy)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.age, Duration::from_secs(3 * 86_400));
        assert_eq!(resolved.exclude, vec!["from-policy"]);

        std::fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\nmin-release-age=7\nmin-release-age-exclude[]=a\nmin-release-age-exclude[]=b\n",
        )
        .unwrap();
        let resolved = resolve_min_release_age(&options(), dir.path(), &policy)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.age, Duration::from_secs(7 * 86_400));
        assert_eq!(resolved.display, "7");
        assert_eq!(resolved.exclude, vec!["a", "b", "from-policy"]);

        let flag = ExecOptions {
            min_release_age: Some("36h".into()),
            min_release_age_exclude: vec!["cli".into()],
            ..options()
        };
        let resolved = resolve_min_release_age(&flag, dir.path(), &policy)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.age, Duration::from_secs(36 * 3_600));
        assert!(resolved.exclude.contains(&"cli".to_string()));

        let zero = ExecOptions {
            min_release_age: Some("0".into()),
            ..options()
        };
        assert!(
            resolve_min_release_age(&zero, dir.path(), &policy)
                .unwrap()
                .is_none()
        );
        let bad = ExecOptions {
            min_release_age: Some("soon".into()),
            ..options()
        };
        assert!(resolve_min_release_age(&bad, dir.path(), &policy).is_err());
    }

    #[test]
    fn cooldown_violation_uses_recorded_publish_dates() {
        let ctx = ExecContext {
            cwd: PathBuf::from("/"),
            prefix: PathBuf::from("/"),
            sandbox: crate::resolve_exec_sandbox(false, ExecSandboxMode::Off, false).unwrap(),
            deny_network: false,
            interactive: false,
            policy: OathPolicy::default(),
            min_release_age: Some(MinReleaseAge {
                age: Duration::from_secs(30 * 86_400),
                exclude: vec!["exempt".into()],
                display: "30".into(),
            }),
        };
        assert!(cooldown_violation(&ctx, "fresh", Some("2000-01-01T00:00:00.000Z")).is_none());
        let yesterday = crate::rfc3339_days_ago(1);
        assert_eq!(cooldown_violation(&ctx, "fresh", Some(&yesterday)), Some(1));
        assert!(cooldown_violation(&ctx, "exempt", Some(&yesterday)).is_none());
        assert!(cooldown_violation(&ctx, "fresh", None).is_none());
    }

    #[test]
    fn thousands_are_grouped() {
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_234_567), "1,234,567");
    }
}
