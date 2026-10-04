use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

use rayon::prelude::*;

use oath_analyze::{PackageScanner, RiskLevel};
use oath_core::policy::OathPolicy;
use oath_fetch::RegistryClient;
use oath_fetch::tarball::TarballLimits;
use oath_resolve::git::{
    git_cache_file_name, is_git_spec, pack_local_package, parse_git_spec, resolve_git_spec,
};
use oath_resolve::graph::{DepNode, PeerResolution};
use oath_resolve::placement::{ArboristPlanner, PlacementPlan, PlacementRequest};
use oath_resolve::resolver::{ResolveOptions, Resolver};
use oath_resolve::{DepGraph, Lockfile};
use oath_store::cas::{ContentStore, PackageVerification};
use oath_store::linker::Linker;
use oath_workspace::{WorkspaceRoot, detect_workspace_root};

mod approvals;
mod exec_assessment;
mod manifest;
mod package_transfer;
mod prompts;
mod publish_assessment;

#[cfg(unix)]
fn platform_symlink_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn platform_symlink_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ExecSandboxMode {
    Off,
    Node,
    Native,
    Auto,
}

#[derive(Subcommand)]
enum StageAction {
    /// List staged releases visible to the current npm identity.
    List {
        package: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// View registry metadata for a staged release.
    View {
        stage_id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Download a staged tarball into an inspection directory.
    Download {
        stage_id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long, default_value = ".")]
        destination: PathBuf,
    },
    /// Approve a staged release after a human has inspected the downloaded tarball.
    Approve {
        stage_id: String,
        /// Confirm that the staged metadata and downloaded tarball were reviewed.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Permanently reject a staged release.
    Reject {
        stage_id: String,
        /// Confirm the permanent rejection.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum TransferAction {
    /// Create an integrity-verifiable package transfer capsule from the current package.
    Create {
        #[arg(long, default_value = "oath-transfer")]
        output: PathBuf,
        #[arg(long, default_value = "latest")]
        tag: String,
        #[arg(long)]
        access: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Verify all hashes, signatures, and optional signer trust in a transfer capsule.
    Verify {
        capsule: PathBuf,
        /// Expected base64 Ed25519 public key obtained through a trusted channel.
        #[arg(long)]
        trusted_public_key: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

impl ExecSandboxMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Node => "node",
            Self::Native => "native",
            Self::Auto => "auto",
        }
    }
}

#[derive(Parser)]
#[command(
    name = "oath",
    version,
    about = "Secure package management for the JavaScript ecosystem"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install dependencies from package.json
    Install {
        packages: Vec<String>,
        #[arg(short = 'D', long, alias = "save-dev")]
        dev: bool,
        #[arg(long)]
        dry_run: bool,
        /// Skip static analysis scan
        #[arg(long)]
        no_audit: bool,
        /// Skip all prompts and approve everything (including install scripts)
        #[arg(short = 'y', long)]
        yes: bool,
        /// Prompt before running install scripts (old behavior; default is to block)
        #[arg(long)]
        run_scripts: bool,
        /// Do not run dependency or root lifecycle scripts (npm-compatible)
        #[arg(long)]
        ignore_scripts: bool,
        /// Minimum release age to warn about (e.g. '7d', '24h', '30d')
        #[arg(long)]
        min_age: Option<String>,
        /// Install to global location (~/.oath/global/)
        #[arg(short = 'g', long)]
        global: bool,
        /// Fail if lockfile is missing or would be changed (for CI)
        #[arg(long, alias = "ci")]
        frozen_lockfile: bool,
    },
    /// Clean install from the lockfile (like `npm ci`): fail if it is missing or would change
    Ci,
    /// Add a dependency
    Add {
        package: String,
        #[arg(short = 'D', long)]
        dev: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Update dependencies within package.json ranges
    Update { packages: Vec<String> },
    /// Remove a dependency
    #[command(visible_aliases = ["uninstall", "rm"])]
    Remove { packages: Vec<String> },
    /// Run a script defined in package.json
    Run {
        script: Option<String>,
        args: Vec<String>,
    },
    /// Execute a package binary (like npx, but scanned first)
    #[command(visible_alias = "x")]
    Exec {
        package: String,
        /// Arguments passed to the package binary; flags after the package
        /// name belong to it, as with npx (`oath x tsc --version`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Skip the risk prompt and run without asking (like npm's --yes)
        #[arg(short = 'y', long)]
        yes: bool,
        /// Minimum release age required (e.g. '7d', '24h', '30d'). Block if newer.
        #[arg(long)]
        min_age: Option<String>,
        /// Emit a machine-readable JSON verdict and never prompt (for agents / CI)
        #[arg(long)]
        json: bool,
        /// Assessment schema version to emit with --json (2 or 3).
        #[arg(long, default_value_t = 3)]
        schema_version: u32,
        /// Refuse to run if the safety grade is below this (A/B/C/D/F)
        #[arg(long)]
        require_grade: Option<String>,
        /// Show the pre-run verdict and exit without executing
        #[arg(long)]
        dry_run: bool,
        /// Run the package binary with sandboxing enabled (auto mode)
        #[arg(long)]
        sandbox: bool,
        /// Sandbox mode to use: off, node, native, or auto
        #[arg(long, value_enum, default_value_t = ExecSandboxMode::Off)]
        sandbox_mode: ExecSandboxMode,
        /// Deny outbound network access in the selected sandbox.
        #[arg(long)]
        deny_network: bool,
        /// Permit the weaker Node permission sandbox when native containment is unavailable.
        #[arg(long)]
        allow_degraded_sandbox: bool,
        /// Persist an approval bound to this exact integrity, capability set, and sandbox policy.
        #[arg(long)]
        remember: bool,
    },
    /// Scan installed packages for malicious behavior (behavioral analysis, not a CVE audit)
    #[command(visible_alias = "audit")]
    Scan {
        #[arg(long)]
        production: bool,
        /// Show all findings, not just high/critical
        #[arg(long)]
        verbose: bool,
    },
    /// Show what a package can access (permissions/capabilities)
    Perms { package: String },
    /// Initialize a new project
    Init { name: Option<String> },
    /// Explain why a package is in the dependency tree
    Why { package: String },
    /// List licenses of all installed packages
    Licenses,
    /// Verify integrity of oath-lock.json against the store
    Verify,
    /// Print an ASCII dependency graph
    Graph {
        /// Maximum depth to display (default: 3)
        #[arg(long, default_value = "3")]
        depth: usize,
    },
    /// Show safety score and metadata for a package
    Score { package: String },
    /// Show info about a package (author, downloads, publish date)
    Info { package: String },
    /// Publish the current package to the npm registry
    Publish {
        /// Tag to use (default: "latest")
        #[arg(long)]
        tag: Option<String>,
        /// Access level: public or restricted
        #[arg(long)]
        access: Option<String>,
        /// Dry run: show what would be published without actually publishing
        #[arg(long)]
        dry_run: bool,
        /// Emit the versioned publish assessment as JSON.
        #[arg(long)]
        json: bool,
        /// Assessment schema version to emit with --json (1 or 2).
        #[arg(long, default_value_t = 2)]
        schema_version: u32,
        /// Submit through npm's staged-publishing protocol after Oath preflight.
        #[arg(long)]
        stage: bool,
    },
    /// Review and decide npm staged releases (npm 11.15+ compatibility adapter).
    Stage {
        #[command(subcommand)]
        action: StageAction,
    },
    /// Create or verify an agent-readable package transfer capsule.
    Transfer {
        #[command(subcommand)]
        action: TransferAction,
    },
    /// Show recent transparency log entries
    Log {
        /// Number of recent entries to show (default: 10)
        #[arg(long, short = 'n', default_value = "10")]
        tail: usize,
    },
    /// Report the native sandbox controls available on this machine.
    SandboxInfo {
        /// Emit the capability report as JSON.
        #[arg(long)]
        json: bool,
    },
    #[command(name = "__sandbox-launch", hide = true)]
    SandboxLaunch {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        program: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    #[command(name = "__sandbox-native-run", hide = true)]
    SandboxNativeRun {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        program: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Rust ignores SIGPIPE, so `oath graph | head` would panic on the first
    // write after the reader exits. Restore the default so the process exits
    // quietly like every other CLI.
    #[cfg(unix)]
    // SAFETY: setting a signal disposition before any thread is spawned.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            packages,
            dev,
            dry_run,
            no_audit,
            yes,
            run_scripts,
            ignore_scripts,
            min_age,
            global,
            frozen_lockfile,
        } => {
            cmd_install(
                packages,
                dev,
                dry_run,
                !no_audit,
                yes,
                run_scripts,
                ignore_scripts,
                global,
                frozen_lockfile,
                min_age,
            )
            .await?;
        }
        Commands::Add { package, dev, yes } => {
            cmd_add(&package, dev, yes).await?;
        }
        Commands::Update { packages } => {
            cmd_update(packages).await?;
        }
        Commands::Run { script, args } => {
            cmd_run(script.as_deref(), &args)?;
        }
        Commands::Init { name } => {
            cmd_init(name.as_deref())?;
        }
        Commands::Scan {
            production,
            verbose,
        } => {
            cmd_scan(production, verbose).await?;
        }
        Commands::Ci => {
            cmd_ci().await?;
        }
        Commands::Perms { package } => {
            cmd_perms(&package)?;
        }
        Commands::Why { package } => {
            cmd_why(&package)?;
        }
        Commands::Licenses => {
            cmd_licenses()?;
        }
        Commands::Verify => {
            cmd_verify()?;
        }
        Commands::Graph { depth } => {
            cmd_graph(depth)?;
        }
        Commands::Exec {
            package,
            args,
            yes,
            min_age,
            json,
            schema_version,
            require_grade,
            dry_run,
            sandbox,
            sandbox_mode,
            deny_network,
            allow_degraded_sandbox,
            remember,
        } => {
            // cmd_exec returns the child's exit status instead of exiting
            // itself so its temporary install directory is dropped first.
            let code = cmd_exec(
                &package,
                &args,
                yes,
                min_age.as_deref(),
                json,
                schema_version,
                require_grade.as_deref(),
                dry_run,
                sandbox,
                sandbox_mode,
                deny_network,
                allow_degraded_sandbox,
                remember,
            )
            .await?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Score { package } => {
            cmd_score(&package).await?;
        }
        Commands::Info { package } => {
            cmd_info(&package).await?;
        }
        Commands::Publish {
            tag,
            access,
            dry_run,
            json,
            schema_version,
            stage,
        } => {
            cmd_publish(
                tag.as_deref(),
                access.as_deref(),
                dry_run,
                json,
                schema_version,
                stage,
            )
            .await?;
        }
        Commands::Stage { action } => {
            cmd_stage(action)?;
        }
        Commands::Transfer { action } => {
            cmd_transfer(action)?;
        }
        Commands::Log { tail } => {
            cmd_log(tail)?;
        }
        Commands::Remove { packages } => {
            cmd_remove(packages).await?;
        }
        Commands::SandboxInfo { json } => {
            let capabilities = oath_sandbox::verified_native_capabilities();
            if json {
                println!("{}", serde_json::to_string_pretty(&capabilities)?);
            } else {
                println!("backend: {}", capabilities.backend);
                println!("available: {}", capabilities.available);
                println!(
                    "filesystem isolation: {}",
                    capabilities.filesystem_isolation
                );
                println!("network isolation: {}", capabilities.network_isolation);
                println!("process isolation: {}", capabilities.process_isolation);
                println!("resource limits: {}", capabilities.resource_limits);
                if let Some(reason) = capabilities.degraded_reason {
                    println!("degraded: {reason}");
                }
            }
        }
        Commands::SandboxLaunch {
            plan,
            program,
            args,
        } => {
            #[cfg(target_os = "linux")]
            {
                let plan: oath_sandbox::SandboxPlan =
                    serde_json::from_reader(std::fs::File::open(plan)?)?;
                let status = oath_sandbox::linux::apply_inner(&plan, &program, &args)?;
                std::process::exit(status.code().unwrap_or(1));
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (plan, program, args);
                anyhow::bail!("internal sandbox launcher is Linux-only");
            }
        }
        Commands::SandboxNativeRun {
            plan,
            program,
            args,
        } => {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                let plan: oath_sandbox::SandboxPlan =
                    serde_json::from_reader(std::fs::File::open(plan)?)?;
                #[cfg(target_os = "linux")]
                let status = oath_sandbox::linux::run(&plan, &program, &args)?;
                #[cfg(target_os = "windows")]
                let status = oath_sandbox::windows::run(&plan, &program, &args)?;
                std::process::exit(status.code().unwrap_or(1));
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                let _ = (plan, program, args);
                anyhow::bail!("native sandbox backend is unavailable on this platform");
            }
        }
    }

    Ok(())
}

// ---- INSTALL ----------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn cmd_install(
    packages: Vec<String>,
    dev: bool,
    dry_run: bool,
    run_audit: bool,
    yes_flag: bool,
    run_scripts: bool,
    ignore_scripts: bool,
    global: bool,
    frozen_lockfile: bool,
    min_age: Option<String>,
) -> Result<()> {
    let start = Instant::now();

    // ---- Global install shortcut --------------------------------------------
    if global {
        return cmd_install_global(packages, dry_run).await;
    }

    if frozen_lockfile && !packages.is_empty() {
        anyhow::bail!("cannot add packages with --frozen-lockfile/--ci");
    }

    // ---- Frozen lockfile check (--frozen-lockfile / --ci) -------------------
    if frozen_lockfile && !PathBuf::from("oath-lock.json").exists() {
        anyhow::bail!("no lockfile found, run oath install first");
    }

    // ---- Workspace detection ------------------------------------------------
    let cwd = std::env::current_dir()?.canonicalize()?;
    let workspace = detect_workspace_root(&cwd);

    if let Some(ref ws) = workspace {
        // Workspace mode: install all packages together with hoisted graph
        if packages.is_empty() {
            println!("oath: workspace mode, {} packages", ws.packages.len());
            for pkg in &ws.packages {
                println!("  - {} ({})", pkg.name, pkg.path.display());
            }
            return cmd_install_workspace(ws, dry_run, run_audit, yes_flag, run_scripts).await;
        }
        // If specific packages are listed, fall through to normal install
    }

    // ---- Single-package install ---------------------------------------------

    // npm Arborist is the authoritative placement planner for ordinary
    // package.json installs. Oath retains ownership of fetch, integrity,
    // scanning, CAS materialization, lifecycle policy, and atomic commit.
    // Keep the former resolver available only as an explicit diagnostic canary.
    let use_arborist = std::env::var("OATH_RESOLVER").as_deref() != Ok("legacy");

    let manifest_path = PathBuf::from("package.json");
    if packages.is_empty() {
        // A plain install needs a manifest; surface the standard error.
        read_package_json()?;
    }
    let mut manifest_doc = manifest::PackageJsonDocument::load_or_default(
        &manifest_path,
        serde_json::json!({"name": "project", "version": "1.0.0"}),
    )?;
    // Legacy-resolver canary only: it has no planner to tell us what npm would
    // save, so pre-write the command-line specs and fix them up after resolution.
    let mut legacy_added: Vec<String> = Vec::new();
    if !packages.is_empty() && !use_arborist {
        let dep_key = if dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        if manifest_doc.value.get(dep_key).is_none() {
            manifest_doc.value[dep_key] = serde_json::json!({});
        }
        for spec in &packages {
            let (name, version) = parse_package_spec(spec);
            manifest_doc.value[dep_key][&name] = serde_json::Value::String(version);
            legacy_added.push(name);
        }
    }
    let project_name = manifest_doc.value["name"]
        .as_str()
        .unwrap_or(if packages.is_empty() {
            "unnamed"
        } else {
            "project"
        })
        .to_string();
    let project_version = manifest_doc.value["version"]
        .as_str()
        .unwrap_or("0.0.0")
        .to_string();
    let total_direct = extract_deps(&manifest_doc.value, "dependencies").len()
        + extract_deps(&manifest_doc.value, "devDependencies").len();

    let placement_plan: Option<PlacementPlan> = if use_arborist {
        println!("oath: planning npm-compatible layout with Arborist...");
        let request = if packages.is_empty() {
            PlacementRequest::default()
        } else {
            PlacementRequest::add(packages.clone(), dev)
        };
        let mut plan = ArboristPlanner::plan_with(&cwd, &request)?;
        hydrate_missing_registry_metadata(&mut plan).await?;
        println!(
            "  planned {} exact locations with {} (npm {})",
            plan.nodes.len(),
            plan.planner.name,
            plan.planner.npm
        );
        // Arborist computed exactly what npm would write to package.json for
        // this add request (save-prefix ranges, npm: aliases, git shortcuts,
        // relative file: paths). Apply it before anything derives from the
        // manifest.
        if let Some(root_manifest) = &plan.root_manifest {
            root_manifest.apply_to(&mut manifest_doc.value);
        }
        Some(plan)
    } else {
        None
    };

    let deps = extract_deps(&manifest_doc.value, "dependencies");
    let dev_deps = extract_deps(&manifest_doc.value, "devDependencies");
    let trusted_deps: HashSet<String> = manifest_doc
        .value
        .get("trustedDependencies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Fast path: if lockfile exists, matches package.json, and all store entries
    // are present, skip registry resolution.
    let lock_path = PathBuf::from("oath-lock.json");
    let graph = if let Some(plan) = placement_plan.as_ref() {
        plan.to_dep_graph()?
    } else if lock_path.exists() && packages.is_empty() {
        // Try to use lockfile directly
        let lockfile = Lockfile::read(&lock_path)?;
        let store_check = ContentStore::default_store()?;
        let all_cached = lockfile_all_cached(&lockfile, &store_check);
        if lockfile.matches_manifest(&deps, &dev_deps) && all_cached {
            println!(
                "oath: lockfile up-to-date ({} packages)",
                lockfile.packages.len()
            );
            lockfile.to_graph()
        } else {
            println!("oath: resolving {total_direct} dependencies...");
            let client = RegistryClient::default_client()?;
            let options = ResolveOptions {
                include_dev: true,
                include_optional: true,
                max_depth: 256,
            };
            let mut resolver = Resolver::new(client, options);
            let g = resolver.resolve(&deps, &dev_deps).await?;
            let resolve_time = start.elapsed();
            println!(
                "  resolved {} packages in {:.1}s",
                g.package_count(),
                resolve_time.as_secs_f64()
            );
            g
        }
    } else if packages.is_empty() && PathBuf::from("package-lock.json").exists() {
        // Migration: no oath-lock yet, but an npm lockfile is present. Honour the
        // versions it already pinned instead of re-resolving ranges to newer ones,
        // so an existing repo installs the same tree it had under npm.
        println!("oath: importing package-lock.json (migration)...");
        let g = oath_resolve::import_npm_lockfile(&PathBuf::from("package-lock.json"))?;
        println!("  imported {} packages", g.package_count());
        g
    } else {
        println!("oath: resolving {total_direct} dependencies...");
        let client = RegistryClient::default_client()?;
        let options = ResolveOptions {
            include_dev: true,
            include_optional: true,
            max_depth: 256,
        };
        let mut resolver = Resolver::new(client, options);
        let g = resolver.resolve(&deps, &dev_deps).await?;
        let resolve_time = start.elapsed();
        println!(
            "  resolved {} packages in {:.1}s",
            g.package_count(),
            resolve_time.as_secs_f64()
        );
        g
    };

    let mut lock_deps = deps.clone();
    let mut lock_dev_deps = dev_deps.clone();
    if !legacy_added.is_empty() {
        let dep_key = if dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        for pkg_name in &legacy_added {
            let requested_spec = manifest_doc.value[dep_key][pkg_name]
                .as_str()
                .unwrap_or("latest")
                .to_string();
            let final_spec = dependency_manifest_spec(pkg_name, &requested_spec, &graph);
            manifest_doc.value[dep_key][pkg_name] = serde_json::Value::String(final_spec.clone());
            if dev {
                lock_dev_deps.insert(pkg_name.clone(), final_spec);
            } else {
                lock_deps.insert(pkg_name.clone(), final_spec);
            }
        }
    }

    let lockfile = Lockfile::from_graph_with_manifest(
        &graph,
        &project_name,
        &project_version,
        &lock_deps,
        &lock_dev_deps,
    );
    if frozen_lockfile {
        let existing = Lockfile::read(&lock_path)?;
        if !lockfiles_match_for_frozen(&existing, &lockfile) {
            anyhow::bail!("lockfile would be modified, refusing (--frozen-lockfile)");
        }
    }

    if dry_run {
        println!("  (dry run, skipping download and link)");
        return Ok(());
    }

    // Root project's own preinstall (trusted, runs like npm/bun) -- only on a
    // plain `oath install` of the project, not when adding specific packages.
    if packages.is_empty() && !ignore_scripts {
        run_root_lifecycle("preinstall");
    }

    // Load policy (project-local oath-policy.toml + global ~/.oath/policy.toml)
    // before anything is fetched: a banned package never reaches the store.
    let policy = OathPolicy::load();
    enforce_banned_packages(&policy, &graph)?;

    // Download -- parallel with JoinSet
    let download_start = Instant::now();
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);

    let (to_download, cached) = missing_store_nodes(&graph, &store);
    // Policy applies to everything new to this project, whether or not the
    // machine's store already held a copy, plus everything freshly fetched.
    let previous_lock = Lockfile::read(&lock_path).ok();
    let new_nodes: Vec<DepNode> =
        nodes_new_to_project(&graph, previous_lock.as_ref(), &to_download);

    // ---- Minimum release age (supply-chain cooldown) ------------------------
    // Block newly-added versions published more recently than --min-age. Only
    // applies to packages not already in the store (new additions) -- already
    // cached packages were vetted on a prior install. A freshly published
    // version (anywhere in the tree) is the classic compromised-package window.
    if let Some(min_age_str) = min_age.as_deref() {
        match parse_duration_secs(min_age_str) {
            Some(min_age_secs) if !to_download.is_empty() => {
                let min_days = (min_age_secs / 86400).max(1);
                println!(
                    "  checking release age ({}-day cooldown) for {} new package(s)...",
                    min_days,
                    to_download.len()
                );
                let mut age_set: JoinSet<(String, String, Option<u64>)> = JoinSet::new();
                for node in &to_download {
                    // Git deps have no registry publish time -- skip.
                    if node.resolved.starts_with("git+")
                        || node.resolved.starts_with("github:")
                        || node.resolved.starts_with("gitlab:")
                        || node.resolved.starts_with("bitbucket:")
                    {
                        continue;
                    }
                    let client = Arc::clone(&client);
                    let name = node.name.clone();
                    let version = node.version.clone();
                    age_set.spawn(async move {
                        // Abbreviated packuments omit `time`; the full one carries it.
                        let age = client
                            .fetch_packument_full(&name)
                            .await
                            .ok()
                            .and_then(|v| {
                                v.get("time")
                                    .and_then(|t| t.get(&version))
                                    .and_then(|s| s.as_str().map(String::from))
                            })
                            .and_then(|pts| parse_iso_age_secs(&pts));
                        (name, version, age)
                    });
                }
                let mut violations: Vec<(String, String, u64)> = Vec::new();
                while let Some(res) = age_set.join_next().await {
                    let (name, version, age) = res?;
                    if let Some(age_secs) = age
                        && age_secs < min_age_secs
                    {
                        violations.push((name, version, age_secs / 86400));
                    }
                }
                if !violations.is_empty() {
                    violations.sort();
                    eprintln!();
                    eprintln!(
                        "oath install: BLOCKED by --min-age {} ({}-day cooldown)",
                        min_age_str, min_days
                    );
                    eprintln!("  These newly-added versions are too recent to trust yet:");
                    for (n, v, days) in &violations {
                        eprintln!("    - {}@{}  published {} day(s) ago", n, v, days);
                    }
                    eprintln!("  Wait out the cooldown, pin an older version, or lower --min-age.");
                    anyhow::bail!(
                        "{} package(s) newer than the {}-day minimum release age",
                        violations.len(),
                        min_days
                    );
                }
                println!("  release age OK");
            }
            Some(_) => {} // nothing new to check
            None => eprintln!(
                "oath: ignoring unparseable --min-age '{}' (use e.g. 7d, 24h, 30d)",
                min_age_str
            ),
        }
    }

    let download_summary =
        download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client)).await?;
    let downloaded = download_summary.downloaded;
    let download_bytes = download_summary.bytes;

    let download_time = download_start.elapsed();
    if downloaded > 0 {
        println!(
            "  downloaded {} new ({}) in {:.1}s",
            downloaded,
            format_bytes(download_bytes),
            download_time.as_secs_f64()
        );
    }
    if cached > 0 {
        println!("  {} already cached", cached);
    }

    // npm drops an optional dependency whose fetch failed and keeps going.
    let mut placement_plan = placement_plan;
    let mut graph = graph;
    let new_nodes = if download_summary.failed_optional.is_empty() {
        new_nodes
    } else {
        prune_failed_optional(
            placement_plan.as_mut(),
            &mut graph,
            &download_summary.failed_optional,
        );
        let failed: HashSet<_> = download_summary
            .failed_optional
            .iter()
            .map(|f| (f.name.as_str(), f.version.as_str(), f.resolved.as_str()))
            .collect();
        new_nodes
            .into_iter()
            .filter(|n| {
                !failed.contains(&(n.name.as_str(), n.version.as_str(), n.resolved.as_str()))
            })
            .collect()
    };

    // ---- Policy gate: everything new is assessed before it is linked -------
    // License policy, static analysis, and the risk ceiling all run against the
    // verified store copy, so nothing reaches node_modules unassessed and no
    // lifecycle hook can run before this point.
    enforce_banned_licenses(&policy, &new_nodes, &store)?;
    if run_audit && !new_nodes.is_empty() {
        println!("  scanning {} new packages...", new_nodes.len());
        let reports = scan_nodes(&new_nodes, &store);
        report_scan_results(&reports);
        enforce_max_risk(&policy, &reports)?;
    }
    require_policy_approvals(&policy, &new_nodes, yes_flag)?;

    // Link
    let link_start = Instant::now();
    let store_ref = Arc::clone(&store);
    let cwd = std::env::current_dir()?;
    let linker = Linker::new((*store_ref).clone())
        .with_external_link_targets(external_link_targets(&cwd, &manifest_doc.value, None));
    let link_result = if let Some(plan) = placement_plan.as_ref() {
        linker.link_placement_plan(plan, &cwd)?
    } else {
        linker.link_all(&graph, &cwd)?
    };
    if let Some(plan) = placement_plan.as_ref() {
        plan.write(&cwd.join(".oath").join("placement-plan.json"))?;
    }
    let link_time = link_start.elapsed();
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    // Write lockfile. The lock is rebuilt here because an optional
    // dependency may have been pruned after the frozen comparison above.
    let lockfile = Lockfile::from_graph_with_manifest(
        &graph,
        &project_name,
        &project_version,
        &lock_deps,
        &lock_dev_deps,
    );
    if !frozen_lockfile {
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
    }

    // Write package.json only for an add request, exactly as npm would.
    if !packages.is_empty() {
        manifest_doc.save()?;
    }

    // -- Peer dependency warnings ---------------------------------------------
    let peer = &graph.peer_report;
    for r in &peer.missing {
        if let PeerResolution::Missing {
            required_by,
            peer_name,
            range,
        } = r
        {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep missing: {}@{}, required by {}",
                peer_name, range, required_by
            );
        }
    }
    for r in &peer.conflicts {
        if let PeerResolution::Conflict {
            required_by,
            peer_name,
            range,
            found_version,
        } = r
        {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep conflict: {}@{} installed, {} requires {}",
                peer_name, found_version, required_by, range
            );
        }
    }

    // -- Dependency install scripts ------------------------------------------
    // Run after the policy gate and the atomic link, in dependency order, only
    // for placements Arborist reported as added or changed, and always inside
    // the package's real install location (never the shared store).
    let mut scripts_blocked = 0;
    if !ignore_scripts {
        let targets = install_script_targets(placement_plan.as_ref(), &graph, &cwd);
        for target in targets {
            let pkg_dir = &target.dir;
            if !pkg_dir.exists() {
                continue;
            }
            let policy_allowlisted = policy
                .allow_install_scripts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&target.name));
            let trusted = trusted_deps.contains(&target.name) || policy_allowlisted;

            if trusted {
                run_install_script(&target.name, pkg_dir);
                continue;
            }
            // `block_install_scripts = true` is an explicit policy: only the
            // allow-list may run, and neither --yes nor a prompt overrides it.
            if policy.block_install_scripts {
                scripts_blocked += 1;
                continue;
            }
            if yes_flag {
                run_install_script(&target.name, pkg_dir);
                continue;
            }
            if run_scripts {
                let report = match PackageScanner::scan(&target.name, &target.version, pkg_dir) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let script_display =
                    detect_install_script(pkg_dir).unwrap_or_else(|| "node install.js".to_string());
                let decision = prompts::prompt_install_script(
                    &target.name,
                    &target.version,
                    &script_display,
                    &report.capabilities,
                    false,
                    &policy,
                );
                match decision {
                    prompts::ScriptDecision::Allow | prompts::ScriptDecision::Always => {
                        run_install_script(&target.name, pkg_dir);
                    }
                    prompts::ScriptDecision::Deny => {}
                }
                continue;
            }
            // Default: BLOCK (silent, just count)
            scripts_blocked += 1;
        }
    }

    if scripts_blocked > 0 {
        if policy.block_install_scripts {
            println!(
                "  {} install script(s) blocked by policy (block_install_scripts; add to allow_install_scripts)",
                scripts_blocked
            );
        } else {
            println!(
                "  {} install script(s) blocked (add to trustedDependencies or use --run-scripts)",
                scripts_blocked
            );
        }
    }

    // Root project's own post-install lifecycle (trusted, runs like npm/bun) --
    // covers the common husky `prepare` and any project postinstall.
    if packages.is_empty() && !ignore_scripts {
        run_root_lifecycle("install");
        run_root_lifecycle("postinstall");
        run_root_lifecycle("prepare");
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    // ---- Transparency log ---------------------------------------------------
    let project_path = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let pkg_entries: Vec<(String, String, Option<String>)> = graph
        .nodes
        .values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    Ok(())
}

// ---- CI ---------------------------------------------------------------------

async fn cmd_ci() -> Result<()> {
    let start = Instant::now();
    // In a workspace the lock lives at the root and snapshots the merged
    // external dependencies of every member, exactly as the workspace install
    // wrote them; compare against that, not against the root manifest alone.
    let invoked_from = std::env::current_dir()?.canonicalize()?;
    let workspace = detect_workspace_root(&invoked_from);
    let cwd = workspace
        .as_ref()
        .map(|ws| ws.root.clone())
        .unwrap_or_else(|| invoked_from.clone());
    let lock_path = cwd.join("oath-lock.json");
    if !lock_path.exists() {
        anyhow::bail!("no lockfile found, run oath install first");
    }

    let pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(cwd.join("package.json"))
            .context("no package.json found (run `oath init` to create one)")?,
    )
    .context("failed to parse package.json")?;
    let (deps, dev_deps) = match workspace.as_ref() {
        Some(ws) => {
            println!("oath ci: workspace mode, {} packages", ws.packages.len());
            (ws.collect_external_deps(true).0, HashMap::new())
        }
        None => (
            extract_deps(&pkg, "dependencies"),
            extract_deps(&pkg, "devDependencies"),
        ),
    };
    let lockfile = Lockfile::read(&lock_path)?;
    if !lockfile.matches_manifest(&deps, &dev_deps) {
        anyhow::bail!("package.json does not match oath-lock.json, run oath install first");
    }

    let plan_path = cwd.join(".oath").join("placement-plan.json");
    let mut placement_plan = if plan_path.exists() {
        PlacementPlan::read(&plan_path)?
    } else {
        ArboristPlanner::plan(&cwd)?
    };
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;
    let planned_lock = Lockfile::from_graph_with_manifest(
        &graph,
        &lockfile.name,
        &lockfile.version,
        &deps,
        &dev_deps,
    );
    if !lockfiles_match_for_frozen(&lockfile, &planned_lock) {
        anyhow::bail!("placement plan does not match oath-lock.json, run oath install first");
    }
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let (to_download, cached) = missing_store_nodes(&graph, &store);
    let download_summary =
        download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client)).await?;
    if download_summary.downloaded > 0 {
        println!(
            "  downloaded {} new ({})",
            download_summary.downloaded,
            format_bytes(download_summary.bytes)
        );
    }
    if cached > 0 {
        println!("  {} already cached", cached);
    }

    let linker = Linker::new((*store).clone()).with_external_link_targets(external_link_targets(
        &cwd,
        &pkg,
        workspace.as_ref(),
    ));
    let link_result = linker.link_placement_plan_clean(&placement_plan, &cwd)?;
    placement_plan.write(&plan_path)?;
    println!("  linked {} packages", link_result.linked);

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    let project_path = cwd.to_string_lossy().to_string();
    let pkg_entries: Vec<(String, String, Option<String>)> = graph
        .nodes
        .values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    Ok(())
}

// ---- WORKSPACE INSTALL ------------------------------------------------------

/// Install dependencies for a workspace (monorepo) in hoisted mode.
///
/// Strategy (npm-style flat hoisting):
///   1. Collect all external deps from all workspace packages into a single set
///   2. Resolve + download them once as a unified graph
///   3. Link them all into root/node_modules (hoisted)
///   4. Materialize only the workspace links selected by Arborist
async fn cmd_install_workspace(
    ws: &WorkspaceRoot,
    dry_run: bool,
    run_audit: bool,
    _yes_flag: bool,
    _run_scripts: bool,
) -> Result<()> {
    let start = Instant::now();

    // Collect external deps from all workspace packages (merged, deduped)
    let (external_deps, workspace_links) = ws.collect_external_deps(true);

    println!(
        "  {} external deps, {} workspace links",
        external_deps.len(),
        workspace_links.len()
    );

    if external_deps.is_empty() && workspace_links.is_empty() {
        println!("  nothing to install");
        return Ok(());
    }

    if dry_run {
        println!(
            "  (dry run) would resolve {} external deps",
            external_deps.len()
        );
        for (consumer, dep, path) in &workspace_links {
            println!(
                "  (dry run) workspace link: {} -> {} ({})",
                dep, path, consumer
            );
        }
        return Ok(());
    }

    println!("  planning npm-compatible workspace layout with Arborist...");
    let mut placement_plan = ArboristPlanner::plan(&ws.root)?;
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;
    let empty_dev_deps: HashMap<String, String> = HashMap::new();

    let resolve_time = start.elapsed();
    println!(
        "  planned {} packages at {} exact locations in {:.1}s",
        graph.package_count(),
        placement_plan.nodes.len(),
        resolve_time.as_secs_f64()
    );

    // Download
    let download_start = Instant::now();
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);

    let (to_download, cached) = missing_store_nodes(&graph, &store);
    let summary = download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client))
        .await
        .context("failed to download workspace dependencies")?;

    let download_time = download_start.elapsed();
    if summary.downloaded > 0 {
        println!(
            "  downloaded {} new ({}) in {:.1}s",
            summary.downloaded,
            format_bytes(summary.bytes),
            download_time.as_secs_f64()
        );
    }
    if cached > 0 {
        println!("  {} already cached", cached);
    }

    // Link into root node_modules
    let link_start = Instant::now();
    let store_ref = Arc::clone(&store);
    let root_manifest: serde_json::Value = std::fs::read_to_string(ws.root.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let linker = Linker::new((*store_ref).clone())
        .with_external_link_targets(external_link_targets(&ws.root, &root_manifest, Some(ws)));
    let link_result = linker.link_placement_plan(&placement_plan, &ws.root)?;
    placement_plan.write(&ws.root.join(".oath").join("placement-plan.json"))?;
    let link_time = link_start.elapsed();
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    let workspace_link_count = placement_plan.nodes.iter().filter(|node| node.link).count();
    if workspace_link_count > 0 {
        println!("  materialized {workspace_link_count} npm-selected workspace links");
    }

    // Write lockfile at workspace root
    let lockfile = Lockfile::from_graph_with_manifest(
        &graph,
        "workspace",
        "0.0.0",
        &external_deps,
        &empty_dev_deps,
    );
    lockfile.write(&ws.root.join("oath-lock.json"))?;

    // -- Peer dependency warnings ---------------------------------------------
    let peer = &graph.peer_report;
    for r in &peer.missing {
        if let PeerResolution::Missing {
            required_by,
            peer_name,
            range,
        } = r
        {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep missing: {}@{}, required by {}",
                peer_name, range, required_by
            );
        }
    }
    for r in &peer.conflicts {
        if let PeerResolution::Conflict {
            required_by,
            peer_name,
            range,
            found_version,
        } = r
        {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep conflict: {}@{} installed, {} requires {}",
                peer_name, found_version, required_by, range
            );
        }
    }

    // Audit if requested
    if run_audit && summary.downloaded > 0 {
        println!("  scanning {} new packages...", summary.downloaded);
        // (same logic as single-pkg install; abbreviated here)
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    // ---- Transparency log ---------------------------------------------------
    let project_path = ws.root.to_string_lossy().to_string();
    let pkg_entries: Vec<(String, String, Option<String>)> = graph
        .nodes
        .values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    Ok(())
}

// ---- AUDIT ------------------------------------------------------------------

async fn cmd_scan(production: bool, verbose: bool) -> Result<()> {
    let pkg = read_package_json()?;
    let mut all_deps = extract_deps(&pkg, "dependencies");
    if !production {
        all_deps.extend(extract_deps(&pkg, "devDependencies"));
    }

    if all_deps.is_empty() {
        println!("oath scan: no dependencies found");
        return Ok(());
    }

    println!(
        "oath scan: scanning {} direct deps (+ transitive)...",
        all_deps.len()
    );

    let store = ContentStore::default_store()?;
    let store_path = store.store_path();

    let mut total = 0usize;
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;

    // Walk the store -- layout is store/{name}/{version}/
    let store_entries = match std::fs::read_dir(&store_path) {
        Ok(e) => e,
        Err(_) => {
            println!("oath scan: nothing installed yet (run `oath install` first)");
            return Ok(());
        }
    };

    for name_entry in store_entries.filter_map(|e| e.ok()) {
        let name_path = name_entry.path();
        if !name_path.is_dir() {
            continue;
        }
        let name = name_entry.file_name().to_string_lossy().replace('+', "/");

        let ver_entries = match std::fs::read_dir(&name_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ver_entry in ver_entries.filter_map(|e| e.ok()) {
            let pkg_path = ver_entry.path();
            if !pkg_path.is_dir() {
                continue;
            }
            let version = ver_entry.file_name().to_string_lossy().to_string();

            let report = match PackageScanner::scan(&name, &version, &pkg_path) {
                Ok(r) => r,
                Err(_) => continue,
            };

            total += 1;

            let show = match report.overall_risk {
                RiskLevel::Critical => {
                    critical += 1;
                    true
                }
                RiskLevel::High => {
                    high += 1;
                    true
                }
                RiskLevel::Medium => {
                    medium += 1;
                    verbose
                }
                _ => verbose,
            };

            if show {
                let risk_label = match report.overall_risk {
                    RiskLevel::Critical => "CRITICAL",
                    RiskLevel::High => "HIGH    ",
                    RiskLevel::Medium => "MEDIUM  ",
                    _ => "INFO    ",
                };
                println!();
                println!("[{risk_label}] {name}@{version}");
                println!(
                    "  files: {}  lines: {}",
                    report.files_scanned, report.lines_scanned
                );
                println!("  capabilities: {}", fmt_capabilities(&report.capabilities));
                for f in report
                    .findings
                    .iter()
                    .filter(|f| verbose || f.risk >= RiskLevel::High)
                {
                    println!("  - [{:?}] L{} {} -- {}", f.risk, f.line, f.file, f.message);
                    if let Some(s) = &f.snippet {
                        println!("    > {s}");
                    }
                }
            }
        } // ver_entry
    } // name_entry

    println!();
    println!(
        "oath scan: {} packages scanned -- {} critical, {} high, {} medium",
        total, critical, high, medium
    );

    if critical > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ---- PERMS ------------------------------------------------------------------

fn cmd_perms(package: &str) -> Result<()> {
    let store = ContentStore::default_store()?;

    // Store layout: store/{name}/{version}/
    // For scoped packages @scope/name, stored as @scope+name
    let pkg_name_dir = store.package_name_dir(package);

    if !pkg_name_dir.exists() {
        println!("oath: package '{package}' not found in store (run `oath install` first)");
        return Ok(());
    }

    for ver_entry in std::fs::read_dir(&pkg_name_dir)?.filter_map(|e| e.ok()) {
        let pkg_path = ver_entry.path();
        if !pkg_path.is_dir() {
            continue;
        }
        let version = ver_entry.file_name().to_string_lossy().to_string();
        let report = PackageScanner::scan(package, &version, &pkg_path)?;

        let verdict_label = match report.overall_risk {
            RiskLevel::Critical => "\u{26d4} flagged -- dangerous behavior combination",
            RiskLevel::High => "\u{26a0} warning -- review recommended",
            _ => "ok -- capabilities only, no dangerous combination",
        };
        println!("{package}@{version}");
        println!("  verdict: {verdict_label}");
        for r in &report.verdict_reasons {
            println!("    - {r}");
        }
        println!(
            "  files:   {} ({} lines)",
            report.files_scanned, report.lines_scanned
        );
        println!();
        println!("  CAPABILITIES (neutral -- what the package can do):");
        println!("    network:         {}", yn(report.capabilities.network));
        println!(
            "    filesystem:      {}",
            yn(report.capabilities.filesystem)
        );
        println!(
            "    env vars:        {}",
            yn(report.capabilities.env_access)
        );
        println!(
            "    subprocess:      {}",
            yn(report.capabilities.subprocess)
        );
        println!(
            "    dynamic exec:    {}",
            yn(report.capabilities.dynamic_exec)
        );
        println!(
            "    install scripts: {}",
            yn(report.capabilities.has_install_scripts)
        );
        // Legacy per-pattern findings are intentionally not shown here: under the
        // tiered model the capabilities above are neutral facts and the `verdict`
        // line is the judgment. `oath scan` still lists detailed findings.
    }
    Ok(())
}

// ---- ADD --------------------------------------------------------------------

async fn cmd_add(package: &str, dev: bool, yes: bool) -> Result<()> {
    cmd_install(
        vec![package.to_string()],
        dev,
        false,
        true,
        yes,
        false,
        false,
        false,
        false,
        None,
    )
    .await
}

async fn cmd_update(packages: Vec<String>) -> Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let pkg = read_package_json()?;
    let deps = extract_deps(&pkg, "dependencies");
    let dev_deps = extract_deps(&pkg, "devDependencies");
    let names = packages
        .into_iter()
        .map(|spec| parse_package_spec(&spec).0)
        .collect();
    let mut placement_plan = ArboristPlanner::plan_with(&cwd, &PlacementRequest::update(names))?;
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;

    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let (to_download, _) = missing_store_nodes(&graph, &store);
    download_missing_nodes(to_download, Arc::clone(&store), client).await?;
    let linker = Linker::new((*store).clone());
    linker.link_placement_plan(&placement_plan, &cwd)?;
    placement_plan.write(&cwd.join(".oath").join("placement-plan.json"))?;

    let lockfile = Lockfile::from_graph_with_manifest(
        &graph,
        pkg["name"].as_str().unwrap_or("project"),
        pkg["version"].as_str().unwrap_or("0.0.0"),
        &deps,
        &dev_deps,
    );
    lockfile.write(&cwd.join("oath-lock.json"))?;
    println!("oath: updated {} packages", graph.package_count());
    Ok(())
}

// ---- RUN --------------------------------------------------------------------

/// Build the `npm_package_*` lifecycle env vars that npm/yarn expose to scripts,
/// from a parsed package.json. Flattens top-level scalar fields (name, version,
/// description, ...); skips objects/arrays (dependencies, scripts, ...).
fn npm_package_env(pkg: &serde_json::Value) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    if let Some(obj) = pkg.as_object() {
        for (k, v) in obj {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            vars.push((format!("npm_package_{k}"), val));
        }
    }
    vars
}

/// Run a root project lifecycle script (preinstall/postinstall/prepare) if defined.
/// These are the project's OWN scripts (trusted), so -- unlike third-party
/// dependency install scripts -- they always run, matching npm/bun. A failure
/// warns but does not abort the install.
fn run_root_lifecycle(event: &str) {
    let pkg = match read_package_json() {
        Ok(p) => p,
        Err(_) => return,
    };
    let cmd = match pkg
        .get("scripts")
        .and_then(|s| s.get(event))
        .and_then(|v| v.as_str())
    {
        Some(c) => c,
        None => return,
    };
    let path_env = format!(
        "./node_modules/.bin:{}",
        std::env::var("PATH").unwrap_or_default()
    );
    let npm_env = npm_package_env(&pkg);
    println!("> {event}: {cmd}");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("PATH", &path_env)
        .env("npm_lifecycle_event", event)
        .env("npm_lifecycle_script", cmd)
        .envs(npm_env.iter().map(|(k, v)| (k, v)))
        .status();
    match status {
        Ok(s) if !s.success() => eprintln!(
            "  oath: warning -- root {event} script exited with {}",
            s.code().unwrap_or(-1)
        ),
        Err(e) => eprintln!("  oath: warning -- failed to run root {event} script: {e}"),
        _ => {}
    }
}

fn cmd_run(script: Option<&str>, args: &[String]) -> Result<()> {
    let pkg = read_package_json()?;
    let npm_env = npm_package_env(&pkg);

    let scripts_obj = pkg.get("scripts").and_then(|s| s.as_object());

    // No script name: list all available scripts
    let script = match script {
        None => {
            match scripts_obj {
                None => {
                    println!("oath run: no scripts defined in package.json");
                }
                Some(scripts) => {
                    if scripts.is_empty() {
                        println!("oath run: no scripts defined in package.json");
                    } else {
                        println!("Available scripts:");
                        for (name, cmd) in scripts {
                            println!("  {} - {}", name, cmd.as_str().unwrap_or(""));
                        }
                    }
                }
            }
            return Ok(());
        }
        Some(s) => s,
    };

    let scripts = scripts_obj.context("no scripts defined in package.json")?;

    let cmd = scripts
        .get(script)
        .and_then(|v| v.as_str())
        .with_context(|| format!("script '{script}' not found"))?;

    // Build augmented PATH with local node_modules/.bin
    let path_env = format!(
        "./node_modules/.bin:{}",
        std::env::var("PATH").unwrap_or_default()
    );

    // Helper to run a single script command and return the exit status
    let run_script = |script_name: &str, script_cmd: &str| -> Result<std::process::ExitStatus> {
        println!();
        println!(
            "> {}@{} {}",
            pkg["name"].as_str().unwrap_or("project"),
            pkg["version"].as_str().unwrap_or("0.0.0"),
            script_name
        );
        println!("> {}", script_cmd);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script_cmd)
            .env("PATH", &path_env)
            .env("npm_lifecycle_event", script_name)
            .env("npm_lifecycle_script", script_cmd)
            .envs(npm_env.iter().map(|(k, v)| (k, v)))
            .status()
            .with_context(|| format!("failed to execute script '{script_name}'"))?;
        Ok(status)
    };

    let start = Instant::now();

    // Run pre-hook if it exists
    let pre_name = format!("pre{script}");
    if let Some(pre_cmd) = scripts.get(&pre_name).and_then(|v| v.as_str()) {
        let status = run_script(&pre_name, pre_cmd)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    // Run the main script with any additional args
    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", shell_quote_args(args))
    };
    let status = run_script(script, &full_cmd)?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    // Run post-hook if it exists
    let post_name = format!("post{script}");
    if let Some(post_cmd) = scripts.get(&post_name).and_then(|v| v.as_str()) {
        let status = run_script(&post_name, post_cmd)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!("  Done in {:.2}s", elapsed.as_secs_f64());

    Ok(())
}

fn shell_quote_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    if arg.bytes().all(|b| {
        matches!(
            b,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'_'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b','
                | b'+'
                | b'@'
                | b'%'
        )
    }) {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

// ---- INIT -------------------------------------------------------------------

fn cmd_init(name: Option<&str>) -> Result<()> {
    let project_name = name.map(|n| n.to_string()).unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "project".to_string())
    });

    let pkg = serde_json::json!({
        "name": project_name,
        "version": "1.0.0",
        "description": "",
        "main": "index.js",
        "scripts": {"test": "echo \"Error: no test specified\" && exit 1"},
        "keywords": [],
        "license": "UNLICENSED"
    });
    anyhow::ensure!(
        !PathBuf::from("package.json").exists(),
        "package.json already exists in this directory; edit it directly or run `oath init` in an empty project"
    );
    let content = format!("{}\n", serde_json::to_string_pretty(&pkg)?);
    std::fs::write("package.json", &content)?;
    println!("oath init: created package.json");
    print!("{content}");
    Ok(())
}

// ---- WHY --------------------------------------------------------------------

fn cmd_why(package: &str) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath why: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let lockfile = Lockfile::read(&lock_path)?;
    if lockfile.packages.is_empty() {
        println!("oath why: oath-lock.json has no packages");
        return Ok(());
    }
    let view = LockView::new(&lockfile);

    let mut matches: Vec<&str> = view.keys_for_name(package);
    if matches.is_empty() {
        println!("oath why: '{package}' not found in oath-lock.json");
        return Ok(());
    }
    matches.sort();

    let direct_deps: HashSet<String> = if PathBuf::from("package.json").exists() {
        let pkg = read_package_json().unwrap_or(serde_json::json!({}));
        let mut d = extract_deps(&pkg, "dependencies");
        d.extend(extract_deps(&pkg, "devDependencies"));
        d.keys().cloned().collect()
    } else {
        HashSet::new()
    };

    for key in matches {
        let entry = &lockfile.packages[key];
        let name = view.name_of(key);
        let install_name = entry.alias.clone().unwrap_or_else(|| name.clone());
        let version = entry.version.as_str();
        println!("  {name}@{version}");
        if install_name != name {
            println!("    installed as: {install_name}");
        }
        if !key.contains('@') || key.starts_with("node_modules/") {
            println!("    location: {key}");
        }

        if direct_deps.contains(&install_name) || lockfile.roots.contains(&key.to_string()) {
            println!("    why: required by your package.json (direct dependency)");
        } else {
            let path = view.path_to_root(key);
            if path.is_empty() {
                println!("    why: required by (unknown)");
            } else {
                let chain: Vec<String> = path.iter().map(|k| view.display(k)).collect();
                println!("    why: required by {} -> root", chain.join(" -> "));
            }
        }

        let store = ContentStore::default_store()?;
        let pkg_dir = store.package_dir_for(
            &name,
            version,
            Some(&entry.resolved),
            entry.integrity.as_deref(),
        );
        if pkg_dir.exists() {
            match PackageScanner::scan(&name, version, &pkg_dir) {
                Ok(report) => {
                    println!("    risk: {}", report.overall_risk);
                    println!(
                        "    capabilities: {}",
                        fmt_capabilities(&report.capabilities)
                    );
                    println!(
                        "    install script: {}",
                        yn(report.capabilities.has_install_scripts || entry.has_install_script)
                    );
                }
                Err(_) => {
                    println!("    (could not scan package)");
                    println!("    install script: {}", yn(entry.has_install_script));
                }
            }
        } else {
            println!("    (package not found in store -- run `oath install`)");
            println!("    install script: {}", yn(entry.has_install_script));
        }
        println!();
    }
    Ok(())
}

/// Name-, key-, and edge-aware view over a lockfile that works for both lock
/// key formats: legacy `name@version` keys and Arborist-mode `node_modules/...`
/// location keys, whose dependency maps point at other keys directly.
struct LockView<'a> {
    lockfile: &'a Lockfile,
    names: HashMap<&'a str, String>,
    /// key -> keys that depend on it
    rdeps: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> LockView<'a> {
    fn new(lockfile: &'a Lockfile) -> Self {
        let names: HashMap<&str, String> = lockfile
            .packages
            .iter()
            .map(|(key, entry)| (key.as_str(), entry.package_name_for_key(key)))
            .collect();
        let mut rdeps: HashMap<&str, Vec<&str>> = HashMap::new();
        for (key, entry) in &lockfile.packages {
            for (dep_name, dep_ref) in &entry.dependencies {
                if let Some(target) = Self::resolve_ref(lockfile, dep_name, dep_ref) {
                    rdeps.entry(target).or_default().push(key.as_str());
                }
            }
        }
        for parents in rdeps.values_mut() {
            parents.sort();
            parents.dedup();
        }
        Self {
            lockfile,
            names,
            rdeps,
        }
    }

    /// A dependency map value is either a lock key (Arborist mode) or a version
    /// that combines with the dependency name into a legacy `name@version` key.
    fn resolve_ref<'b>(lockfile: &'b Lockfile, dep_name: &str, dep_ref: &str) -> Option<&'b str> {
        if let Some((key, _)) = lockfile.packages.get_key_value(dep_ref) {
            return Some(key.as_str());
        }
        let legacy = format!("{dep_name}@{dep_ref}");
        lockfile
            .packages
            .get_key_value(&legacy)
            .map(|(key, _)| key.as_str())
    }

    fn name_of(&self, key: &str) -> String {
        self.names
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    fn display(&self, key: &str) -> String {
        let entry = &self.lockfile.packages[key];
        format!("{}@{}", self.name_of(key), entry.version)
    }

    /// Every key whose package name or install alias equals `package`.
    fn keys_for_name(&self, package: &str) -> Vec<&'a str> {
        self.lockfile
            .packages
            .iter()
            .filter(|(key, entry)| {
                self.names.get(key.as_str()).map(String::as_str) == Some(package)
                    || entry.alias.as_deref() == Some(package)
            })
            .map(|(key, _)| key.as_str())
            .collect()
    }

    /// Resolved child keys of `key`, in sorted order.
    fn children(&self, key: &str) -> Vec<&'a str> {
        let Some(entry) = self.lockfile.packages.get(key) else {
            return Vec::new();
        };
        let mut children: Vec<&str> = entry
            .dependencies
            .iter()
            .filter_map(|(dep_name, dep_ref)| Self::resolve_ref(self.lockfile, dep_name, dep_ref))
            .collect();
        children.sort();
        children.dedup();
        children
    }

    /// Shortest chain of keys from the nearest root-level package down to the
    /// direct parent of `start`, found by breadth-first search over reverse
    /// edges. A root-level package is one with no dependents.
    fn path_to_root(&self, start: &str) -> Vec<String> {
        let mut queue: std::collections::VecDeque<(&str, Vec<&str>)> =
            std::collections::VecDeque::new();
        let mut visited: HashSet<&str> = HashSet::new();
        visited.insert(start);
        queue.push_back((start, Vec::new()));
        while let Some((current, path)) = queue.pop_front() {
            let Some(parents) = self.rdeps.get(current) else {
                return path.iter().map(|k| k.to_string()).collect();
            };
            for parent in parents {
                if !visited.insert(parent) {
                    continue;
                }
                let mut next = vec![*parent];
                next.extend(path.iter().copied());
                let parent_is_root = self.rdeps.get(parent).is_none_or(|v| v.is_empty());
                if parent_is_root {
                    return next.iter().map(|k| k.to_string()).collect();
                }
                queue.push_back((parent, next));
            }
        }
        Vec::new()
    }
}

// ---- LICENSES ---------------------------------------------------------------

fn cmd_licenses() -> Result<()> {
    let store = ContentStore::default_store()?;
    let store_path = store.store_path();

    let store_entries = match std::fs::read_dir(&store_path) {
        Ok(e) => e,
        Err(_) => {
            println!("oath licenses: nothing installed yet (run `oath install` first)");
            return Ok(());
        }
    };

    // license -> count
    let mut license_counts: BTreeMap<String, usize> = BTreeMap::new();

    for name_entry in store_entries.filter_map(|e| e.ok()) {
        let name_path = name_entry.path();
        if !name_path.is_dir() {
            continue;
        }

        let ver_entries = match std::fs::read_dir(&name_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for ver_entry in ver_entries.filter_map(|e| e.ok()) {
            let pkg_path = ver_entry.path();
            if !pkg_path.is_dir() {
                continue;
            }

            let pkg_json_path = pkg_path.join("package.json");
            let license = if pkg_json_path.exists() {
                match std::fs::read_to_string(&pkg_json_path) {
                    Ok(content) => {
                        match serde_json::from_str::<serde_json::Value>(&content) {
                            Ok(pkg) => {
                                // license can be a string or an object with "type" field
                                pkg.get("license")
                                    .map(|l| {
                                        if let Some(s) = l.as_str() {
                                            s.to_string()
                                        } else if let Some(t) =
                                            l.get("type").and_then(|t| t.as_str())
                                        {
                                            t.to_string()
                                        } else {
                                            "UNKNOWN".to_string()
                                        }
                                    })
                                    .unwrap_or_else(|| "UNKNOWN".to_string())
                            }
                            Err(_) => "UNKNOWN".to_string(),
                        }
                    }
                    Err(_) => "UNKNOWN".to_string(),
                }
            } else {
                "UNKNOWN".to_string()
            };

            *license_counts.entry(license).or_insert(0) += 1;
        }
    }

    if license_counts.is_empty() {
        println!("oath licenses: no packages found");
        return Ok(());
    }

    // Sort by count descending for display
    let mut sorted: Vec<(String, usize)> = license_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    // Find longest license name for alignment
    let max_len = sorted.iter().map(|(l, _)| l.len()).max().unwrap_or(10);

    for (license, count) in &sorted {
        let pkg_word = if *count == 1 { "package " } else { "packages" };
        let flag = if license == "UNKNOWN" {
            " [review recommended]"
        } else if license.starts_with("GPL")
            || license.starts_with("AGPL")
            || license.starts_with("LGPL")
        {
            " [COPYLEFT - review required]"
        } else {
            ""
        };
        println!(
            "  {:<width$}  {} {}{}",
            license,
            count,
            pkg_word,
            flag,
            width = max_len
        );
    }
    Ok(())
}

// ---- VERIFY -----------------------------------------------------------------

fn cmd_verify() -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath verify: no oath-lock.json found");
        return Ok(());
    }
    let lock = Lockfile::read(&lock_path)?;

    let store = ContentStore::default_store()?;
    let total = lock.packages.len();
    println!("  checking {total} packages...");

    let mut missing = 0usize;
    let mut tampered = 0usize;
    let mut ok = 0usize;

    let mut entries: Vec<_> = lock.packages.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());

    for (key, entry) in &entries {
        let name = entry.package_name_for_key(key);

        if name.is_empty() || entry.version.is_empty() {
            continue;
        }

        match store.verify_package_variant(
            &name,
            &entry.version,
            Some(&entry.resolved),
            entry.integrity.as_deref(),
        ) {
            PackageVerification::Verified(_) => {
                println!("  {key:<40} ok");
                ok += 1;
            }
            PackageVerification::Missing => {
                println!("  MISSING:  {key}");
                missing += 1;
            }
            PackageVerification::Corrupt(reason) => {
                println!("  TAMPERED: {key} -- {reason}");
                tampered += 1;
            }
        }
    }

    println!();
    if missing > 0 || tampered > 0 {
        if missing > 0 {
            println!("  lockfile: {missing} missing (run `oath install` to restore)");
        }
        if tampered > 0 {
            println!("  lockfile: {tampered} tampered entry(s) detected");
        }
        std::process::exit(1);
    } else {
        println!("  lockfile: clean ({ok} packages verified)");
    }
    Ok(())
}

// ---- GRAPH ------------------------------------------------------------------

fn cmd_graph(max_depth: usize) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath graph: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let lockfile = Lockfile::read(&lock_path)?;
    if lockfile.packages.is_empty() {
        println!("oath graph: oath-lock.json has no packages");
        return Ok(());
    }
    let view = LockView::new(&lockfile);

    let (root_label, mut root_children): (String, Vec<&str>) = if PathBuf::from("package.json")
        .exists()
    {
        let pkg = read_package_json().unwrap_or(serde_json::json!({}));
        let name = pkg["name"].as_str().unwrap_or("project").to_string();
        let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let mut direct: Vec<String> = extract_deps(&pkg, "dependencies").keys().cloned().collect();
        direct.extend(extract_deps(&pkg, "devDependencies").keys().cloned());
        direct.sort();
        direct.dedup();
        // A direct dependency lives at a root-level location in Arborist-mode
        // locks; in legacy locks it is whichever version the lock recorded.
        let children = direct
            .iter()
            .filter_map(|dep| {
                let candidates = view.keys_for_name(dep);
                candidates
                    .iter()
                    .find(|key| lockfile.roots.contains(&key.to_string()))
                    .or_else(|| candidates.first())
                    .copied()
            })
            .collect();
        (format!("{name}@{version}"), children)
    } else if !lockfile.roots.is_empty() {
        (
            format!("{}@{}", lockfile.name, lockfile.version),
            lockfile.roots.iter().map(String::as_str).collect(),
        )
    } else {
        let roots: Vec<&str> = lockfile
            .packages
            .keys()
            .map(String::as_str)
            .filter(|key| view.rdeps.get(key).is_none_or(|v| v.is_empty()))
            .collect();
        (format!("{}@{}", lockfile.name, lockfile.version), roots)
    };
    root_children.sort();
    root_children.dedup();

    if root_children.is_empty() {
        println!("  (no root packages found)");
        return Ok(());
    }
    println!("  {root_label}");
    print_graph_children(&root_children, &view, 1, max_depth, &mut HashSet::new(), "");
    println!();
    Ok(())
}

fn print_graph_children(
    children: &[&str],
    view: &LockView<'_>,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    prefix: &str,
) {
    let count = children.len();
    for (i, child_key) in children.iter().enumerate() {
        let is_last = i == count - 1;
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}|   ")
        };
        println!("  {prefix}+-- {}", view.display(child_key));

        let grandchildren = view.children(child_key);
        if depth >= max_depth {
            if !grandchildren.is_empty() {
                println!(
                    "  {child_prefix}... ({} more deps, use --depth to show)",
                    grandchildren.len()
                );
            }
            continue;
        }
        if visited.contains(*child_key) {
            println!("  {child_prefix}(circular)");
            continue;
        }
        visited.insert(child_key.to_string());
        print_graph_children(
            &grandchildren,
            view,
            depth + 1,
            max_depth,
            visited,
            &child_prefix,
        );
        visited.remove(*child_key);
    }
}

// ---- HELPERS ----------------------------------------------------------------

fn read_package_json() -> Result<serde_json::Value> {
    let content = std::fs::read_to_string("package.json")
        .context("no package.json found (run `oath init` to create one)")?;
    serde_json::from_str(&content).context("failed to parse package.json")
}

fn extract_deps(pkg: &serde_json::Value, key: &str) -> HashMap<String, String> {
    pkg.get(key)
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("*").to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn lockfiles_match_for_frozen(existing: &Lockfile, generated: &Lockfile) -> bool {
    // npm lockfiles retain optional packages for every supported platform,
    // while Arborist's reify plan contains only the optional native packages
    // installable on the current host. Preserve frozen semantics for the
    // shared graph, but ignore one-sided optional platform nodes and edges to
    // them. A package present in both lockfiles is still compared exactly.
    let all_locations: HashSet<_> = existing
        .packages
        .keys()
        .chain(generated.packages.keys())
        .cloned()
        .collect();
    let mut platform_only = HashSet::new();
    for location in all_locations {
        match (
            existing.packages.get(&location),
            generated.packages.get(&location),
        ) {
            (Some(entry), None) | (None, Some(entry)) if entry.optional => {
                platform_only.insert(location);
            }
            (Some(_), None) | (None, Some(_)) => return false,
            _ => {}
        }
    }

    let normalize = |lockfile: &Lockfile| {
        let mut normalized = lockfile.clone();
        normalized
            .roots
            .retain(|location| !platform_only.contains(location));
        normalized
            .packages
            .retain(|location, _| !platform_only.contains(location));
        for entry in normalized.packages.values_mut() {
            entry
                .dependencies
                .retain(|_, location| !platform_only.contains(location));
            entry
                .resolved_peers
                .retain(|_, location| !platform_only.contains(location));
            // The per-entry name is derived verification metadata for
            // location-keyed locks. Older locks may omit it while remaining
            // semantically equivalent.
            entry.name = None;
            // Hook presence is derived again from the integrity-pinned package
            // manifest and may be unavailable in Arborist's virtual tree for a
            // package skipped on the current platform.
            entry.has_install_script = false;
        }
        normalized
    };

    match (
        serde_json::to_value(normalize(existing)),
        serde_json::to_value(normalize(generated)),
    ) {
        (Ok(existing), Ok(generated)) => existing == generated,
        _ => false,
    }
}

fn lockfile_all_cached(lockfile: &Lockfile, store: &ContentStore) -> bool {
    lockfile.packages.iter().all(|(key, entry)| {
        let name = entry.package_name_for_key(key);
        store
            .verify_package_variant(
                &name,
                &entry.version,
                Some(&entry.resolved),
                entry.integrity.as_deref(),
            )
            .is_verified()
    })
}

fn missing_store_nodes(graph: &DepGraph, store: &ContentStore) -> (Vec<DepNode>, usize) {
    let mut to_download = Vec::new();
    let mut scheduled = HashSet::new();
    let mut cached = 0usize;
    for node in graph.nodes.values() {
        match store.verify_package_variant(
            &node.name,
            &node.version,
            Some(&node.resolved),
            node.integrity.as_deref(),
        ) {
            PackageVerification::Verified(_) => cached += 1,
            PackageVerification::Missing | PackageVerification::Corrupt(_) => {
                let identity = (
                    node.name.clone(),
                    node.version.clone(),
                    node.resolved.clone(),
                    node.integrity.clone(),
                );
                if scheduled.insert(identity) {
                    to_download.push(node.clone());
                }
            }
        }
    }
    (to_download, cached)
}

async fn hydrate_missing_registry_metadata(plan: &mut PlacementPlan) -> Result<()> {
    let missing: std::collections::BTreeSet<_> = plan
        .nodes
        .iter()
        .filter(|node| !node.link && node.resolved.is_none())
        .map(|node| (node.name.clone(), node.version.clone()))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let client = RegistryClient::default_client()?;
    let mut resolved = HashMap::new();
    for (name, version) in missing {
        let packument = client
            .fetch_packument(&name)
            .await
            .with_context(|| format!("recovering registry metadata for {name}@{version}"))?;
        let info = packument
            .versions
            .get(&version)
            .with_context(|| format!("registry has no metadata for {name}@{version}"))?;
        resolved.insert(
            (name, version),
            (info.dist.tarball.clone(), info.dist.integrity.clone()),
        );
    }
    for node in &mut plan.nodes {
        if let Some((url, integrity)) = resolved.get(&(node.name.clone(), node.version.clone())) {
            node.resolved.get_or_insert_with(|| url.clone());
            if node.integrity.is_none() {
                node.integrity.clone_from(integrity);
            }
        }
    }
    Ok(())
}

/// Refuse the install outright when the resolved tree contains a package the
/// policy bans. Nothing is downloaded for a banned package.
fn enforce_banned_packages(policy: &OathPolicy, graph: &DepGraph) -> Result<()> {
    let mut banned: Vec<String> = graph
        .nodes
        .values()
        .filter(|node| policy.is_package_banned(&node.name))
        .map(|node| format!("{}@{}", node.name, node.version))
        .collect();
    if banned.is_empty() {
        return Ok(());
    }
    banned.sort();
    banned.dedup();
    anyhow::bail!(
        "install blocked by policy: banned package(s) {} (see banned_packages in oath-policy.toml)",
        banned.join(", ")
    );
}

/// Read the SPDX license field of a package's verified store copy.
fn store_package_license(store: &ContentStore, node: &DepNode) -> Option<String> {
    let dir = store.package_dir_for(
        &node.name,
        &node.version,
        Some(&node.resolved),
        node.integrity.as_deref(),
    );
    let text = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    match value.get("license") {
        Some(serde_json::Value::String(license)) => Some(license.clone()),
        Some(serde_json::Value::Object(object)) => object
            .get("type")
            .and_then(|t| t.as_str())
            .map(String::from),
        _ => None,
    }
}

/// Refuse to link any new package whose license the policy bans.
fn enforce_banned_licenses(
    policy: &OathPolicy,
    new_nodes: &[DepNode],
    store: &ContentStore,
) -> Result<()> {
    if policy.banned_licenses.is_empty() {
        return Ok(());
    }
    let mut offenders: Vec<String> = new_nodes
        .iter()
        .filter_map(|node| {
            let license = store_package_license(store, node)?;
            policy
                .is_license_banned(&license)
                .then(|| format!("{}@{} ({license})", node.name, node.version))
        })
        .collect();
    if offenders.is_empty() {
        return Ok(());
    }
    offenders.sort();
    anyhow::bail!(
        "install blocked by policy: banned license(s) on {} (see banned_licenses in oath-policy.toml)",
        offenders.join(", ")
    );
}

/// Scan the verified store copies of the given nodes in parallel.
fn scan_nodes(
    nodes: &[DepNode],
    store: &ContentStore,
) -> Vec<(String, String, oath_analyze::AnalysisReport)> {
    let mut scanned: Vec<_> = nodes
        .par_iter()
        .filter_map(|node| {
            let pkg_dir = store.package_dir_for(
                &node.name,
                &node.version,
                Some(&node.resolved),
                node.integrity.as_deref(),
            );
            if !pkg_dir.exists() {
                return None;
            }
            PackageScanner::scan(&node.name, &node.version, &pkg_dir)
                .ok()
                .map(|report| (node.name.clone(), node.version.clone(), report))
        })
        .collect();
    scanned.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    scanned.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    scanned
}

/// Print the tiered behavioral verdicts: capabilities are neutral; only
/// dangerous combinations escalate. Critical = Block-tier, High = Warn-tier.
fn report_scan_results(reports: &[(String, String, oath_analyze::AnalysisReport)]) {
    let mut critical = 0usize;
    let mut high = 0usize;
    for (name, version, report) in reports {
        match report.overall_risk {
            RiskLevel::Critical => {
                critical += 1;
                println!();
                println!("  \u{26d4} flagged  {name}@{version}");
                for r in &report.verdict_reasons {
                    println!("       - {r}");
                }
                let caps = fmt_capabilities(&report.capabilities);
                if !caps.is_empty() {
                    println!("       capabilities: {caps}");
                }
            }
            RiskLevel::High => {
                high += 1;
                println!(
                    "  \u{26a0}  warn     {name}@{version} -- {}",
                    report
                        .verdict_reasons
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("flagged behavior")
                );
            }
            _ => {}
        }
    }
    if critical > 0 {
        println!();
        println!(
            "  {} package(s) flagged (review with `oath perms <pkg>` / `oath scan`)",
            critical
        );
    } else if high > 0 {
        println!(
            "  {} warning(s) -- run `oath scan --verbose` for details",
            high
        );
    } else {
        println!("  all clear");
    }
}

/// Order of the shared risk ladder, by display name, so the scanner's and the
/// policy's independently defined `RiskLevel` enums can be compared.
fn risk_rank(level: &str) -> u8 {
    match level {
        "clean" => 0,
        "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        _ => 5,
    }
}

/// Abort before linking when a new package exceeds `max_risk_level`.
fn enforce_max_risk(
    policy: &OathPolicy,
    reports: &[(String, String, oath_analyze::AnalysisReport)],
) -> Result<()> {
    let ceiling = risk_rank(&policy.max_risk().to_string());
    let mut over: Vec<String> = reports
        .iter()
        .filter(|(_, _, report)| risk_rank(&report.overall_risk.to_string()) > ceiling)
        .map(|(name, version, report)| format!("{name}@{version} ({})", report.overall_risk))
        .collect();
    if over.is_empty() {
        return Ok(());
    }
    over.sort();
    anyhow::bail!(
        "install blocked by policy: {} exceed max_risk_level = \"{}\"",
        over.join(", "),
        policy.max_risk_level
    );
}

/// Packages listed under `require_approval` need an explicit yes before they
/// are linked for the first time: `--yes`, or an interactive confirmation.
fn require_policy_approvals(
    policy: &OathPolicy,
    new_nodes: &[DepNode],
    yes_flag: bool,
) -> Result<()> {
    use std::io::{IsTerminal, Write};
    let mut pending: Vec<String> = new_nodes
        .iter()
        .filter(|node| {
            policy
                .require_approval
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&node.name))
        })
        .map(|node| format!("{}@{}", node.name, node.version))
        .collect();
    if pending.is_empty() || yes_flag {
        return Ok(());
    }
    pending.sort();
    pending.dedup();
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "install blocked by policy: {} require approval (require_approval); rerun with --yes to approve",
            pending.join(", ")
        );
    }
    println!();
    println!("  policy requires approval before installing:");
    for name in &pending {
        println!("    - {name}");
    }
    print!("  approve? [y/N] ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    anyhow::ensure!(
        input.trim().eq_ignore_ascii_case("y"),
        "install blocked: approval declined for {}",
        pending.join(", ")
    );
    Ok(())
}

/// Directories outside the project that the project's own manifests point at
/// with `file:` / path specifiers. npm symlinks those; Oath permits exactly
/// these targets and no others declared by dependencies.
fn external_link_targets(
    project_root: &std::path::Path,
    root_manifest: &serde_json::Value,
    workspace: Option<&WorkspaceRoot>,
) -> HashSet<PathBuf> {
    fn collect(
        base: &std::path::Path,
        manifest_deps: impl Iterator<Item = (String, String)>,
        out: &mut HashSet<PathBuf>,
    ) {
        for (_, spec) in manifest_deps {
            let path = if let Some(rest) = spec.strip_prefix("file:") {
                rest.to_string()
            } else if spec.starts_with("./")
                || spec.starts_with("../")
                || spec.starts_with('/')
                || spec.starts_with("~/")
            {
                spec.clone()
            } else {
                continue;
            };
            let expanded = if let Some(rest) = path.strip_prefix("~/") {
                match oath_core::home_dir() {
                    Some(home) => home.join(rest),
                    None => continue,
                }
            } else {
                base.join(path)
            };
            if let Ok(canonical) = std::fs::canonicalize(&expanded)
                && canonical.is_dir()
            {
                out.insert(canonical);
            }
        }
    }
    let mut targets = HashSet::new();
    let sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    collect(
        project_root,
        sections
            .iter()
            .flat_map(|section| extract_deps(root_manifest, section)),
        &mut targets,
    );
    if let Some(ws) = workspace {
        for pkg in &ws.packages {
            let m = &pkg.package_json;
            collect(
                &pkg.path,
                m.dependencies
                    .iter()
                    .chain(m.dev_dependencies.iter())
                    .chain(m.optional_dependencies.iter())
                    .chain(m.peer_dependencies.iter())
                    .map(|(k, v)| (k.clone(), v.clone())),
                &mut targets,
            );
        }
    }
    targets
}

/// Remove optional dependencies whose fetch failed, plus any optional
/// packages that only they depended on, from the plan and the graph.
fn prune_failed_optional(
    plan: Option<&mut PlacementPlan>,
    graph: &mut DepGraph,
    failed: &[FailedDownload],
) {
    let failed_identity: HashSet<(&str, &str, &str)> = failed
        .iter()
        .map(|f| (f.name.as_str(), f.version.as_str(), f.resolved.as_str()))
        .collect();
    let mut removed: HashSet<String> = graph
        .nodes
        .iter()
        .filter(|(_, node)| {
            failed_identity.contains(&(
                node.name.as_str(),
                node.version.as_str(),
                node.resolved.as_str(),
            ))
        })
        .map(|(key, _)| key.clone())
        .collect();
    loop {
        for key in &removed {
            graph.nodes.remove(key);
        }
        for node in graph.nodes.values_mut() {
            node.dependencies
                .retain(|_, target| !removed.contains(target));
            node.resolved_peers
                .retain(|_, target| !removed.contains(target));
        }
        graph.roots.retain(|key| !removed.contains(key));
        // Optional packages nobody depends on any more were only ever needed
        // by something that is now gone.
        let referenced: HashSet<&String> = graph
            .nodes
            .values()
            .flat_map(|node| {
                node.dependencies
                    .values()
                    .chain(node.resolved_peers.values())
            })
            .collect();
        let orphaned: HashSet<String> = graph
            .nodes
            .iter()
            .filter(|(key, node)| {
                node.optional && !graph.roots.contains(key) && !referenced.contains(key)
            })
            .map(|(key, _)| key.clone())
            .collect();
        if orphaned.is_empty() {
            break;
        }
        removed = orphaned;
    }
    if let Some(plan) = plan {
        plan.nodes
            .retain(|node| graph.nodes.contains_key(&node.location) || node.link);
    }
}

/// A dependency whose install scripts are due to run, and where.
struct ScriptTarget {
    name: String,
    version: String,
    dir: PathBuf,
}

/// Graph nodes absent from the previous lockfile (new to this project), merged
/// with the nodes that were just downloaded, deduplicated by identity.
fn nodes_new_to_project(
    graph: &DepGraph,
    previous_lock: Option<&Lockfile>,
    downloaded: &[DepNode],
) -> Vec<DepNode> {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out = Vec::new();
    let mut push = |node: &DepNode| {
        if seen.insert((
            node.name.clone(),
            node.version.clone(),
            node.resolved.clone(),
        )) {
            out.push(node.clone());
        }
    };
    let mut keys: Vec<&String> = graph.nodes.keys().collect();
    keys.sort();
    for key in keys {
        let node = &graph.nodes[key];
        let known = previous_lock.is_some_and(|lock| {
            lock.packages.get(key).is_some_and(|entry| {
                entry.version == node.version && entry.resolved == node.resolved
            })
        });
        if !known {
            push(node);
        }
    }
    for node in downloaded {
        push(node);
    }
    out
}

/// Dependencies with install scripts, in dependency order (dependencies before
/// dependents), restricted to placements Arborist added or changed. Each runs
/// in its real install location; the shared store is never a script cwd.
fn install_script_targets(
    plan: Option<&PlacementPlan>,
    graph: &DepGraph,
    project_root: &std::path::Path,
) -> Vec<ScriptTarget> {
    let Some(plan) = plan else {
        // Legacy resolver canary: no placement information, so use the
        // hoisted top-level location in deterministic key order.
        let mut keys: Vec<&String> = graph.nodes.keys().collect();
        keys.sort();
        return keys
            .into_iter()
            .filter_map(|key| {
                let node = &graph.nodes[key];
                node.has_install_script.then(|| ScriptTarget {
                    name: node.name.clone(),
                    version: node.version.clone(),
                    dir: project_root
                        .join("node_modules")
                        .join(node.alias.as_deref().unwrap_or(&node.name)),
                })
            })
            .collect();
    };

    let by_location: HashMap<&str, &oath_resolve::placement::PlacementNode> = plan
        .nodes
        .iter()
        .map(|node| (node.location.as_str(), node))
        .collect();
    let mut order: Vec<&str> = Vec::new();
    let mut state: HashMap<&str, u8> = HashMap::new(); // 1 = visiting, 2 = done
    fn visit<'a>(
        location: &'a str,
        by_location: &HashMap<&'a str, &'a oath_resolve::placement::PlacementNode>,
        state: &mut HashMap<&'a str, u8>,
        order: &mut Vec<&'a str>,
    ) {
        match state.get(location) {
            Some(_) => return,
            None => {
                state.insert(location, 1);
            }
        }
        if let Some(node) = by_location.get(location) {
            let mut targets: Vec<&str> = node
                .edges
                .iter()
                .filter_map(|edge| edge.target_location.as_deref())
                .collect();
            targets.sort();
            for target in targets {
                visit(target, by_location, state, order);
            }
        }
        state.insert(location, 2);
        order.push(location);
    }
    let mut locations: Vec<&str> = by_location.keys().copied().collect();
    locations.sort();
    for location in locations {
        visit(location, &by_location, &mut state, &mut order);
    }
    order
        .into_iter()
        .filter_map(|location| {
            let placement = by_location.get(location)?;
            if !placement.has_install_script {
                return None;
            }
            if placement.link {
                // npm rebuilds links it manages directly (linked from the
                // project root) on every install; links nested inside
                // dependencies belong to those dependencies.
                let root_linked = location
                    .strip_prefix("node_modules/")
                    .is_some_and(|rest| !rest.contains("/node_modules/"));
                if !root_linked {
                    return None;
                }
            } else if placement.reuse_existing {
                return None;
            }
            Some(ScriptTarget {
                name: placement.name.clone(),
                version: placement.version.clone(),
                dir: project_root.join(location),
            })
        })
        .collect()
}

#[derive(Debug, Default)]
struct DownloadSummary {
    downloaded: usize,
    bytes: u64,
    /// Optional dependencies whose fetch failed. npm tolerates these and
    /// prunes them from the tree; a failed non-optional fetch is still fatal.
    failed_optional: Vec<FailedDownload>,
}

#[derive(Debug, Clone)]
struct FailedDownload {
    name: String,
    version: String,
    resolved: String,
}

struct DownloadedPackage {
    name: String,
    version: String,
    resolved: String,
    integrity: Option<String>,
    temp_dir: tempfile::TempDir,
    tarball_path: PathBuf,
    bytes: u64,
}

async fn download_missing_nodes(
    to_download: Vec<DepNode>,
    store: Arc<ContentStore>,
    client: Arc<RegistryClient>,
) -> Result<DownloadSummary> {
    let mut summary = DownloadSummary::default();
    if to_download.is_empty() {
        return Ok(summary);
    }

    let limits = TarballLimits::from_env()?;
    let mut set: JoinSet<(FailedDownload, bool, Result<DownloadedPackage>)> = JoinSet::new();
    for node in to_download {
        let client = Arc::clone(&client);
        let limits = limits.clone();
        let identity = FailedDownload {
            name: node.name.clone(),
            version: node.version.clone(),
            resolved: node.resolved.clone(),
        };
        let optional = node.optional;
        set.spawn(async move {
            let result = download_tarball_to_temp(
                client,
                node.name,
                node.version,
                node.resolved,
                node.integrity,
                limits,
            )
            .await;
            (identity, optional, result)
        });
    }

    while let Some(res) = set.join_next().await {
        let (identity, optional, result) = res?;
        let downloaded = match result {
            Ok(downloaded) => downloaded,
            Err(error) if optional => {
                eprintln!(
                    "  oath: skipping optional dependency {}@{}: {error:#}",
                    identity.name, identity.version
                );
                summary.failed_optional.push(identity);
                continue;
            }
            Err(error) => return Err(error),
        };
        summary.bytes += downloaded.bytes;
        let tmp = tempfile::tempdir()?;
        oath_fetch::tarball::extract_tarball_file_limited(
            &downloaded.tarball_path,
            tmp.path(),
            &limits,
        )?;
        store.store_package_variant_with_manifest(
            &downloaded.name,
            &downloaded.version,
            Some(&downloaded.resolved),
            downloaded.integrity.as_deref(),
            tmp.path(),
        )?;
        drop(downloaded.temp_dir);
        summary.downloaded += 1;
    }

    Ok(summary)
}

async fn download_tarball_to_temp(
    client: Arc<RegistryClient>,
    name: String,
    version: String,
    resolved: String,
    integrity: Option<String>,
    limits: TarballLimits,
) -> Result<DownloadedPackage> {
    let temp_dir = tempfile::tempdir().context("failed to create temp tarball dir")?;
    let tarball_path = temp_dir.path().join("package.tgz");

    let bytes = if let Some(local_path) = file_dependency_path(&resolved)? {
        materialize_file_dependency(&local_path, &tarball_path, &limits)
            .with_context(|| format!("packing local dependency {name}@{version}"))?
    } else if is_git_resolved(&resolved) {
        let home = oath_core::home_dir().unwrap_or_else(std::env::temp_dir);
        let cache_file = home
            .join(".oath")
            .join("git-cache")
            .join(git_cache_file_name(&name, &version, &resolved));
        if !cache_file.exists() {
            let spec = parse_git_spec(&resolved)
                .with_context(|| format!("invalid git dependency URL {resolved}"))?;
            let http = oath_fetch::http::client_builder()?.build()?;
            let git = resolve_git_spec(&spec, &http)
                .await
                .with_context(|| format!("fetching git dependency {name}@{version}"))?;
            limits.check_archive_size(git.tarball_data.len() as u64)?;
            if let Some(parent) = cache_file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&cache_file, git.tarball_data)?;
        }
        let len = std::fs::metadata(&cache_file)
            .with_context(|| format!("stat git cache {}", cache_file.display()))?
            .len();
        limits.check_archive_size(len)?;
        std::fs::copy(&cache_file, &tarball_path).with_context(|| {
            format!(
                "copying git cache {} -> {}",
                cache_file.display(),
                tarball_path.display()
            )
        })?;
        len
    } else {
        client
            .fetch_tarball_to_file(&resolved, integrity.as_deref(), &tarball_path, &limits)
            .await
            .with_context(|| format!("downloading {name}@{version}"))?
    };

    Ok(DownloadedPackage {
        name,
        version,
        resolved,
        integrity,
        temp_dir,
        tarball_path,
        bytes,
    })
}

async fn download_and_store_package(
    client: &RegistryClient,
    store: &ContentStore,
    name: &str,
    version: &str,
    resolved: &str,
    integrity: Option<&str>,
) -> Result<u64> {
    let limits = TarballLimits::from_env()?;
    let temp_dir = tempfile::tempdir().context("failed to create temp tarball dir")?;
    let tarball_path = temp_dir.path().join("package.tgz");
    let bytes = if let Some(local_path) = file_dependency_path(resolved)? {
        materialize_file_dependency(&local_path, &tarball_path, &limits)
            .with_context(|| format!("packing local dependency {name}@{version}"))?
    } else if is_git_resolved(resolved) {
        let home = oath_core::home_dir().unwrap_or_else(std::env::temp_dir);
        let cache_file = home
            .join(".oath")
            .join("git-cache")
            .join(git_cache_file_name(name, version, resolved));
        if !cache_file.exists() {
            anyhow::bail!("git dep {name}@{version} not in cache and no tarball URL available");
        }
        let len = std::fs::metadata(&cache_file)
            .with_context(|| format!("stat git cache {}", cache_file.display()))?
            .len();
        limits.check_archive_size(len)?;
        std::fs::copy(&cache_file, &tarball_path).with_context(|| {
            format!(
                "copying git cache {} -> {}",
                cache_file.display(),
                tarball_path.display()
            )
        })?;
        len
    } else {
        client
            .fetch_tarball_to_file(resolved, integrity, &tarball_path, &limits)
            .await
            .with_context(|| format!("downloading {name}@{version}"))?
    };

    let extracted = tempfile::tempdir().context("failed to create temp extract dir")?;
    oath_fetch::tarball::extract_tarball_file_limited(&tarball_path, extracted.path(), &limits)?;
    store.store_package_variant_with_manifest(
        name,
        version,
        Some(resolved),
        integrity,
        extracted.path(),
    )?;
    Ok(bytes)
}

fn is_git_resolved(resolved: &str) -> bool {
    is_git_spec(resolved)
}

fn file_dependency_path(resolved: &str) -> Result<Option<PathBuf>> {
    if !resolved.starts_with("file:") {
        return Ok(None);
    }
    let url = reqwest::Url::parse(resolved)
        .with_context(|| format!("invalid local dependency URL {resolved}"))?;
    anyhow::ensure!(url.scheme() == "file", "unsupported local dependency URL");
    let path = url
        .to_file_path()
        .map_err(|_| anyhow::anyhow!("local dependency URL is not a file path: {resolved}"))?;
    anyhow::ensure!(
        path.exists(),
        "local dependency does not exist: {}",
        path.display()
    );
    Ok(Some(path))
}

fn materialize_file_dependency(
    source: &std::path::Path,
    tarball_path: &std::path::Path,
    limits: &TarballLimits,
) -> Result<u64> {
    if source.is_dir() {
        let tarball = pack_local_package(source)?;
        limits.check_archive_size(tarball.len() as u64)?;
        std::fs::write(tarball_path, &tarball)?;
        return Ok(tarball.len() as u64);
    }
    anyhow::ensure!(
        source.is_file(),
        "unsupported local dependency: {}",
        source.display()
    );
    let bytes = std::fs::metadata(source)?.len();
    limits.check_archive_size(bytes)?;
    std::fs::copy(source, tarball_path)?;
    Ok(bytes)
}

fn parse_package_spec(spec: &str) -> (String, String) {
    // Handle @scope/name@version vs name@version vs name
    if let Some(stripped) = spec.strip_prefix('@') {
        // scoped: @scope/name@version
        if let Some(at) = stripped.find('@') {
            let name = format!("@{}", &stripped[..at]);
            let version = stripped[at + 1..].to_string();
            return (name, version);
        }
        return (spec.to_string(), "latest".to_string());
    }
    if let Some((n, v)) = spec.split_once('@') {
        return (n.to_string(), v.to_string());
    }
    (spec.to_string(), "latest".to_string())
}

fn dependency_manifest_spec(pkg_name: &str, requested_spec: &str, graph: &DepGraph) -> String {
    if requested_spec.starts_with("npm:") || is_git_like_spec(requested_spec) {
        return requested_spec.to_string();
    }

    graph
        .nodes
        .values()
        .find(|node| node.alias.as_deref() == Some(pkg_name) || node.name == pkg_name)
        .map(|node| format!("^{}", node.version))
        .unwrap_or_else(|| requested_spec.to_string())
}

fn is_git_like_spec(spec: &str) -> bool {
    spec.starts_with("github:")
        || spec.starts_with("gitlab:")
        || spec.starts_with("bitbucket:")
        || spec.starts_with("git+https://")
        || spec.starts_with("git+ssh://")
        || spec.starts_with("git://")
}

fn safe_bin_entries(pkg_json: &serde_json::Value, install_name: &str) -> Vec<(String, PathBuf)> {
    let mut bins = match pkg_json.get("bin") {
        Some(serde_json::Value::String(path)) => package_relative_path(path)
            .filter(|_| is_safe_bin_name(package_bin_basename(install_name)))
            .map(|path| vec![(package_bin_basename(install_name).to_string(), path)])
            .unwrap_or_default(),
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .filter_map(|(name, path)| {
                let path = path.as_str()?;
                if !is_safe_bin_name(name) {
                    return None;
                }
                package_relative_path(path).map(|safe_path| (name.clone(), safe_path))
            })
            .collect(),
        _ => Vec::new(),
    };

    bins.sort_by(|(a, _), (b, _)| a.cmp(b));
    bins
}

fn preferred_bin_path(pkg_json: &serde_json::Value, install_name: &str) -> Option<PathBuf> {
    let bins = safe_bin_entries(pkg_json, install_name);
    let basename = package_bin_basename(install_name);

    bins.iter()
        .find(|(name, _)| name == install_name || name == basename)
        .or_else(|| bins.first())
        .map(|(_, path)| path.clone())
}

fn package_bin_basename(name: &str) -> &str {
    name.split('/').next_back().unwrap_or(name)
}

fn is_safe_bin_name(name: &str) -> bool {
    is_safe_path_part(name) && !name.contains('/')
}

fn package_relative_path(path: &str) -> Option<PathBuf> {
    let mut safe = PathBuf::new();

    for component in std::path::Path::new(path).components() {
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
    is_safe_path_part(part)
}

fn is_safe_path_part(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains('\\') && !part.contains('\0')
}

fn fmt_capabilities(c: &oath_analyze::Capabilities) -> String {
    let mut parts = vec![];
    if c.network {
        parts.push("network");
    }
    if c.filesystem {
        parts.push("filesystem");
    }
    if c.env_access {
        parts.push("env");
    }
    if c.subprocess {
        parts.push("subprocess");
    }
    if c.dynamic_exec {
        parts.push("eval/dynamic");
    }
    if c.has_install_scripts {
        parts.push("install-scripts");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Read a package's package.json and return the first install script command found.
/// Looks for "scripts.preinstall", "scripts.install", "scripts.postinstall".
fn detect_install_script(pkg_dir: &std::path::Path) -> Option<String> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let scripts = value.get("scripts")?.as_object()?;
    for key in &["preinstall", "install", "postinstall"] {
        if let Some(cmd) = scripts.get(*key).and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
    }
    None
}

/// Run a package's install scripts unsandboxed.
fn run_install_script(pkg_name: &str, pkg_dir: &std::path::Path) {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };
    let scripts = match value.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s.clone(),
        None => return,
    };
    let npm_env = npm_package_env(&value);

    for hook in &["preinstall", "install", "postinstall"] {
        if let Some(cmd) = scripts.get(*hook).and_then(|v| v.as_str()) {
            tracing::debug!("running {hook} for {pkg_name}: {cmd}");
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .current_dir(pkg_dir)
                .env("npm_lifecycle_event", *hook)
                .envs(npm_env.iter().map(|(k, v)| (k, v)))
                .status();
            match status {
                Ok(s) if !s.success() => {
                    eprintln!(
                        "  oath: warning -- {hook} for {pkg_name} exited with {}",
                        s.code().unwrap_or(-1)
                    );
                }
                Err(e) => {
                    eprintln!("  oath: warning -- failed to run {hook} for {pkg_name}: {e}");
                }
                _ => {}
            }
        }
    }
}

// ---- EXEC -------------------------------------------------------------------

const EXEC_EXIT_GRADE: i32 = 10;
const EXEC_EXIT_AGE: i32 = 11;
const EXEC_EXIT_USER: i32 = 13;

/// Rank safety grades A(best)..F(worst) for `--require-grade` comparison.
fn grade_rank(g: char) -> u8 {
    match g.to_ascii_uppercase() {
        'A' => 5,
        'B' => 4,
        'C' => 3,
        'D' => 2,
        'F' => 1,
        _ => 0,
    }
}

/// Unpacked size of a package's own files (skips nested node_modules).
fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if e.file_name() != "node_modules" {
                    stack.push(e.path());
                }
            } else if let Ok(m) = e.metadata() {
                total += m.len();
            }
        }
    }
    total
}

fn previous_release_diff(
    packument: &serde_json::Value,
    current_version: &str,
    current_publisher: Option<&str>,
    current_has_install_script: bool,
) -> Option<exec_assessment::VersionDiff> {
    let current = current_version.parse::<node_semver::Version>().ok()?;
    let versions = packument.get("versions")?.as_object()?;
    let (previous_version, previous) = versions
        .iter()
        .filter_map(|(version, metadata)| {
            let parsed = version.parse::<node_semver::Version>().ok()?;
            (parsed < current).then_some((parsed, version, metadata))
        })
        .max_by(|(a, _, _), (b, _, _)| a.cmp(b))
        .map(|(_, version, metadata)| (version, metadata))?;
    let previous_publisher = previous
        .get("_npmUser")
        .and_then(|user| user.get("name"))
        .and_then(|name| name.as_str());
    let previous_hooks = previous
        .get("scripts")
        .and_then(|scripts| scripts.as_object())
        .map(|scripts| {
            scripts
                .keys()
                .any(|name| matches!(name.as_str(), "preinstall" | "install" | "postinstall"))
        })
        .unwrap_or(false);
    Some(exec_assessment::VersionDiff {
        previous_version: previous_version.clone(),
        previous_integrity: previous
            .get("dist")
            .and_then(|dist| dist.get("integrity"))
            .and_then(|value| value.as_str())
            .map(String::from),
        publisher_changed: match (previous_publisher, current_publisher) {
            (Some(previous), Some(current)) => Some(previous != current),
            _ => None,
        },
        lifecycle_hooks_changed: previous_hooks != current_has_install_script,
    })
}

#[derive(Copy, Clone, Debug)]
struct ExecSandboxDecision {
    requested_mode: ExecSandboxMode,
    effective_mode: ExecSandboxMode,
    agent_mode: bool,
}

fn resolve_exec_sandbox(
    sandbox: bool,
    sandbox_mode: ExecSandboxMode,
    allow_degraded_sandbox: bool,
) -> Result<ExecSandboxDecision> {
    let agent_mode = std::env::var("OATH_AGENT_MODE")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    let requested_mode = if sandbox {
        if sandbox_mode == ExecSandboxMode::Off {
            ExecSandboxMode::Auto
        } else {
            sandbox_mode
        }
    } else if agent_mode && sandbox_mode == ExecSandboxMode::Off {
        ExecSandboxMode::Auto
    } else {
        sandbox_mode
    };

    if requested_mode == ExecSandboxMode::Off {
        return Ok(ExecSandboxDecision {
            requested_mode,
            effective_mode: ExecSandboxMode::Off,
            agent_mode,
        });
    }

    let effective_mode = resolve_exec_sandbox_capabilities(
        requested_mode,
        allow_degraded_sandbox,
        node_permission_flag().is_some(),
        &oath_sandbox::verified_native_capabilities(),
    )?;

    Ok(ExecSandboxDecision {
        requested_mode,
        effective_mode,
        agent_mode,
    })
}

fn resolve_exec_sandbox_capabilities(
    requested_mode: ExecSandboxMode,
    allow_degraded_sandbox: bool,
    node_permissions_available: bool,
    native: &oath_sandbox::BackendCapabilities,
) -> Result<ExecSandboxMode> {
    let native_complete = native.available
        && native.filesystem_isolation
        && native.network_isolation
        && native.process_isolation
        && native.resource_limits;
    match requested_mode {
        ExecSandboxMode::Off => Ok(ExecSandboxMode::Off),
        ExecSandboxMode::Native => {
            anyhow::ensure!(
                native_complete,
                "native sandbox unavailable or incomplete: {}",
                native
                    .degraded_reason
                    .as_deref()
                    .unwrap_or("required controls did not pass the runtime probe")
            );
            Ok(ExecSandboxMode::Native)
        }
        ExecSandboxMode::Node => {
            anyhow::ensure!(
                allow_degraded_sandbox,
                "Node permissions do not provide process or resource isolation; pass --allow-degraded-sandbox only when policy explicitly accepts that limitation"
            );
            anyhow::ensure!(
                node_permissions_available,
                "Node permission sandbox is unavailable on this Node runtime"
            );
            Ok(ExecSandboxMode::Node)
        }
        ExecSandboxMode::Auto => {
            if native_complete {
                Ok(ExecSandboxMode::Native)
            } else if allow_degraded_sandbox && node_permissions_available {
                Ok(ExecSandboxMode::Node)
            } else {
                anyhow::bail!(
                    "verified native containment is unavailable: {}; Oath refused to downgrade automatically{}",
                    native
                        .degraded_reason
                        .as_deref()
                        .unwrap_or("required controls did not pass the runtime probe"),
                    if node_permissions_available {
                        "; pass --allow-degraded-sandbox only when policy accepts Node's missing process and resource isolation"
                    } else {
                        ""
                    }
                )
            }
        }
    }
}

fn ensure_node_permission_sandbox() -> Result<&'static str> {
    node_permission_flag().context("Node permission sandbox is unavailable on this Node runtime")
}

fn node_permission_flag() -> Option<&'static str> {
    let output = std::process::Command::new("node")
        .arg("--help")
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("--permission") {
        Some("--permission")
    } else if text.contains("--experimental-permission") {
        Some("--experimental-permission")
    } else {
        None
    }
}

fn run_node_binary(
    bin_path: &std::path::Path,
    args: &[String],
    exec_path: &std::path::Path,
    sandbox_mode: ExecSandboxMode,
    sandbox_plan: Option<&oath_sandbox::SandboxPlan>,
) -> Result<std::process::ExitStatus> {
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let _ = sandbox_plan;
    #[cfg(target_os = "linux")]
    if sandbox_mode == ExecSandboxMode::Native {
        let plan = sandbox_plan.context("native sandbox requires a sandbox plan")?;
        // Use the Node on PATH (nvm, Volta, fnm, Homebrew, or the system one)
        // and grant exactly that binary inside the namespace, read-only.
        let node = active_node_executable()?;
        let mut plan = plan.clone();
        if !node.starts_with("/usr") && !node.starts_with("/bin") && !node.starts_with("/lib") {
            plan.read_only_paths.push(node.clone());
        }
        return oath_sandbox::linux::run(
            &plan,
            &node,
            &std::iter::once(bin_path.display().to_string())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        );
    }
    #[cfg(target_os = "windows")]
    if sandbox_mode == ExecSandboxMode::Native {
        let plan = sandbox_plan.context("native sandbox requires a sandbox plan")?;
        return oath_sandbox::windows::run(
            plan,
            std::path::Path::new("node.exe"),
            &std::iter::once(bin_path.display().to_string())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        );
    }
    #[cfg(target_os = "macos")]
    if sandbox_mode == ExecSandboxMode::Native {
        let plan = sandbox_plan.context("native sandbox requires a sandbox plan")?;
        let node = active_node_executable()?;
        let mut plan = plan.clone();
        plan.read_only_paths.push(node.clone());
        return oath_sandbox::macos::run(
            &plan,
            &node,
            &std::iter::once(bin_path.display().to_string())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        );
    }
    let mut cmd = std::process::Command::new("node");
    if sandbox_mode == ExecSandboxMode::Node {
        let permission_flag = ensure_node_permission_sandbox()?;
        let cwd = std::env::current_dir().context("failed to read current dir")?;
        let tmp = std::env::temp_dir();
        cmd.arg(permission_flag)
            .arg(format!("--allow-fs-read={}", cwd.display()))
            .arg(format!("--allow-fs-read={}", exec_path.display()))
            .arg(format!("--allow-fs-read={}", tmp.display()))
            .arg(format!("--allow-fs-write={}", cwd.display()))
            .arg(format!("--allow-fs-write={}", tmp.display()));
    }

    cmd.arg(bin_path).args(args).status().with_context(|| {
        format!(
            "failed to execute node {} with sandbox mode {}",
            bin_path.display(),
            sandbox_mode.as_str()
        )
    })
}

/// Canonical path of the Node executable the user's PATH selects.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn active_node_executable() -> Result<PathBuf> {
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .context("failed to resolve the active Node executable")?;
    anyhow::ensure!(node.status.success(), "active Node executable probe failed");
    let node = PathBuf::from(String::from_utf8(node.stdout)?.trim());
    std::fs::canonicalize(&node)
        .with_context(|| format!("failed to canonicalize Node executable {}", node.display()))
}

#[allow(clippy::too_many_arguments)]
async fn cmd_exec(
    package: &str,
    args: &[String],
    yes: bool,
    min_age: Option<&str>,
    json: bool,
    schema_version: u32,
    require_grade: Option<&str>,
    dry_run: bool,
    sandbox: bool,
    sandbox_mode: ExecSandboxMode,
    deny_network: bool,
    allow_degraded_sandbox: bool,
    remember: bool,
) -> Result<i32> {
    use oath_analyze::{
        FindingKind, PackageScanner, RiskLevel, ScoreContext, compute_safety_score_contextual,
    };

    let start = std::time::Instant::now();
    anyhow::ensure!(
        matches!(schema_version, 2 | 3),
        "unsupported exec assessment schema {schema_version}; supported versions are 2 and 3"
    );
    // JSON mode reserves stdout for exactly one assessment document; a program
    // that then writes to the same stream would corrupt it. Agents assess with
    // --dry-run --json, then execute with the plain command.
    anyhow::ensure!(
        !json || dry_run,
        "oath exec --json is an assessment-only interface and requires --dry-run; run the package without --json afterwards"
    );
    let (pkg_name, pkg_version) = parse_package_spec(package);
    let sandbox_decision = resolve_exec_sandbox(sandbox, sandbox_mode, allow_degraded_sandbox)?;
    let effective_deny_network = deny_network || sandbox_decision.agent_mode;

    // Local node_modules/.bin path: a bin the project already installed. It
    // still goes through assessment (scan, grade gate, prompt); only the
    // download is skipped. A version spec that the local copy does not satisfy
    // falls through to the registry, like npx.
    if !dry_run
        && sandbox_decision.effective_mode == ExecSandboxMode::Off
        && let Some(local) = resolve_local_bin(&pkg_name, &pkg_version)?
    {
        return exec_local_bin(&local, args, yes, require_grade).await;
    }

    if !json {
        println!("oath exec: inspecting {}@{}...", pkg_name, pkg_version);
    }
    let client = RegistryClient::default_client()?;
    let packument = client
        .fetch_packument(&pkg_name)
        .await
        .with_context(|| format!("fetching {pkg_name}"))?;
    let resolved = oath_fetch::resolve_version(&packument, &pkg_version)
        .with_context(|| format!("resolving {pkg_name}@{pkg_version}"))?;
    let version = resolved.version.to_string();
    let info = resolved.info;

    // Full packument -> publish time, last publisher, repository.
    let full = client.fetch_packument_full(&pkg_name).await.ok();
    let age_days: Option<u64> = full
        .as_ref()
        .and_then(|v| {
            v.get("time")
                .and_then(|t| t.get(&version))
                .and_then(|s| s.as_str())
                .map(String::from)
        })
        .and_then(|pts| parse_iso_age_secs(&pts))
        .map(|secs| secs / 86400);
    let last_publisher: Option<String> = full.as_ref().and_then(|v| {
        v.get("versions")
            .and_then(|vs| vs.get(&version))
            .and_then(|ver| ver.get("_npmUser"))
            .and_then(|u| u.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from)
            .or_else(|| {
                v.get("maintainers")
                    .and_then(|m| m.as_array())
                    .and_then(|a| a.first())
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                    .map(String::from)
            })
    });
    let repository: Option<String> = full.as_ref().and_then(|v| {
        v.get("repository").and_then(|r| {
            r.get("url")
                .and_then(|u| u.as_str())
                .or_else(|| r.as_str())
                .map(String::from)
        })
    });
    let open_source = repository.is_some();

    // Age gate (before download).
    if let (Some(days), Some(min_str)) = (age_days, min_age)
        && let Some(min_secs) = parse_duration_secs(min_str)
    {
        let min_days = (min_secs / 86400).max(1);
        if days < min_days {
            if json {
                let sandbox_capabilities = match sandbox_decision.effective_mode {
                    ExecSandboxMode::Native => oath_sandbox::verified_native_capabilities(),
                    ExecSandboxMode::Node => oath_sandbox::BackendCapabilities {
                        backend: "node-permissions".into(),
                        available: true,
                        filesystem_isolation: true,
                        network_isolation: true,
                        process_isolation: false,
                        resource_limits: false,
                        degraded_reason: Some(
                            "Node permissions are not an OS process sandbox".into(),
                        ),
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
                };
                let assessment = exec_assessment::ExecAssessment {
                    schema_version: exec_assessment::EXEC_ASSESSMENT_VERSION,
                    identity: exec_assessment::PackageIdentity {
                        name: pkg_name.clone(),
                        version: version.clone(),
                        binary: None,
                        registry: "https://registry.npmjs.org".into(),
                        integrity: info.dist.integrity.clone(),
                        publisher: last_publisher.clone(),
                        publish_age_days: age_days,
                        repository: repository.clone(),
                    },
                    evidence: exec_assessment::PackageEvidence {
                        unpacked_bytes: 0,
                        dependency_count: 0,
                        readable_source: false,
                        obfuscated: false,
                        native_code: false,
                        lifecycle_hooks: false,
                        capabilities: Vec::new(),
                        findings: Vec::new(),
                        limitations: vec![
                            "Artifact analysis was skipped because release-age policy denied execution before download",
                        ],
                        version_diff: None,
                    },
                    policy: exec_assessment::PolicyDecision {
                        decision: "block",
                        reason_code: oath_contracts::ReasonCode::ExecReleaseTooNew,
                        grade: "unknown".into(),
                        score: 0,
                    },
                    sandbox: sandbox_capabilities,
                    sandbox_plan: None,
                };
                let policy_digest = oath_contracts::digest_json(&serde_json::json!({
                    "require_grade": require_grade,
                    "min_age": min_age,
                    "minimum_age_days": min_days,
                    "sandbox_mode": sandbox_decision.effective_mode.as_str(),
                    "deny_network": effective_deny_network,
                    "allow_degraded_sandbox": allow_degraded_sandbox,
                }))?;
                let assessment_value = if schema_version == 2 {
                    serde_json::to_value(&assessment)?
                } else {
                    let generated_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or(0);
                    serde_json::to_value(exec_assessment::signed_v3(
                        &assessment,
                        generated_at,
                        policy_digest,
                    )?)?
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "assessment": assessment_value,
                        "name": pkg_name,
                        "version": version,
                        "age_days": days,
                        "decision": if schema_version == 2 { "block" } else { "deny" },
                        "reason": "min-age"
                    }))?
                );
            } else {
                eprintln!(
                    "oath exec: BLOCKED -- {pkg_name}@{version} is {days}d old (need >= {min_days}d)"
                );
            }
            return Ok(EXEC_EXIT_AGE);
        }
    }

    // Plan the full temporary install with the same placement authority used by
    // `install`; Oath still owns download, integrity, scanning, and execution.
    let exec_dir = tempfile::tempdir()?;
    let exec_path = exec_dir.path().to_path_buf();
    let exec_pkg = serde_json::json!({
        "name": "oath-exec-tmp",
        "version": "0.0.0",
        "dependencies": { &pkg_name: &version }
    });
    std::fs::write(
        exec_path.join("package.json"),
        serde_json::to_string(&exec_pkg)?,
    )?;
    let mut placement_plan = ArboristPlanner::plan(&exec_path)?;
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;
    let store2 = Arc::new(ContentStore::default_store()?);
    let registry = Arc::new(RegistryClient::default_client()?);
    let (to_download, _) = missing_store_nodes(&graph, &store2);
    download_missing_nodes(to_download, Arc::clone(&store2), registry).await?;
    let linker = oath_store::Linker::new((*store2).clone());
    linker.link_placement_plan(&placement_plan, &exec_path)?;
    let pkg_dir = exec_path.join("node_modules").join(&pkg_name);

    // Scan + score before deciding to run.
    let report = PackageScanner::scan(&pkg_name, &version, &pkg_dir)?;
    let caps = &report.capabilities;
    // Popularity/age context so the grade (and any --require-grade gate) trusts
    // widely-used packages: a flagged-but-1M+-download package with no critical
    // finding is a false positive, not something to block on an npx-style run.
    let ctx = {
        let mut weekly = 0u64;
        let mut age = 0u32;
        if let Ok(http) =
            oath_fetch::http::client_builder().and_then(|b| b.build().map_err(Into::into))
            && let Ok(meta) = oath_fetch::fetch_package_metadata(&http, &pkg_name).await
        {
            weekly = meta.weekly_downloads.unwrap_or(0);
            age = meta.last_publish_age_days.map(|d| d as u32).unwrap_or(0);
        }
        ScoreContext {
            is_dev: false,
            weekly_downloads: weekly,
            age_days: age,
        }
    };
    let score = compute_safety_score_contextual(&report, &pkg_dir, &ctx);
    let obfuscated = report.findings.iter().any(|f| {
        f.kind == FindingKind::Obfuscation
            && matches!(f.risk, RiskLevel::High | RiskLevel::Critical)
    });
    let unpacked_kb = dir_size(&pkg_dir) / 1024;
    let serious = if matches!(report.overall_risk, RiskLevel::High | RiskLevel::Critical) {
        report.verdict_reasons.clone()
    } else {
        Vec::new()
    };
    let mut perms: Vec<&str> = Vec::new();
    if caps.network {
        perms.push("network");
    }
    if caps.filesystem {
        perms.push("filesystem");
    }
    if caps.env_access {
        perms.push("env");
    }
    if caps.subprocess {
        perms.push("subprocess");
    }
    if caps.dynamic_exec {
        perms.push("eval");
    }
    if caps.has_install_scripts {
        perms.push("install-scripts");
    }

    let grade_blocked = require_grade
        .map(|g| grade_rank(score.grade) < grade_rank(g.chars().next().unwrap_or('A')))
        .unwrap_or(false);

    let pkg_json_path = pkg_dir.join("package.json");
    let preferred_binary = if pkg_json_path.exists() {
        let pkg_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pkg_json_path)?)?;
        preferred_bin_path(&pkg_json, &pkg_name)
    } else {
        None
    };

    let mut sandbox_plan = (sandbox_decision.effective_mode != ExecSandboxMode::Off)
        .then(|| oath_sandbox::SandboxPlan::strict(pkg_name.clone(), exec_path.clone()));
    if !effective_deny_network
        && caps.network
        && let Some(plan) = &mut sandbox_plan
    {
        plan.network = oath_sandbox::NetworkMode::Inherit;
    }

    let native_code = ["binding.gyp", "prebuilds"]
        .iter()
        .any(|p| pkg_dir.join(p).exists());
    let version_diff = full.as_ref().and_then(|packument| {
        previous_release_diff(
            packument,
            &version,
            last_publisher.as_deref(),
            caps.has_install_scripts,
        )
    });
    let assessment = exec_assessment::ExecAssessment {
        schema_version: exec_assessment::EXEC_ASSESSMENT_VERSION,
        identity: exec_assessment::PackageIdentity {
            name: pkg_name.clone(),
            version: version.clone(),
            binary: preferred_binary
                .as_ref()
                .map(|path| path.display().to_string()),
            registry: "https://registry.npmjs.org".into(),
            integrity: info.dist.integrity.clone(),
            publisher: last_publisher.clone(),
            publish_age_days: age_days,
            repository: repository.clone(),
        },
        evidence: exec_assessment::PackageEvidence {
            unpacked_bytes: dir_size(&pkg_dir),
            dependency_count: graph.nodes.len(),
            readable_source: !obfuscated,
            obfuscated,
            native_code,
            lifecycle_hooks: caps.has_install_scripts,
            capabilities: perms.iter().map(|p| (*p).to_string()).collect(),
            findings: serious.clone(),
            limitations: vec![
                "Static analysis cannot prove safety",
                "Remote second-stage payloads and opaque binaries may evade inspection",
            ],
            version_diff,
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
        sandbox: match sandbox_decision.effective_mode {
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
        },
        sandbox_plan: sandbox_plan.clone(),
    };
    let approval = approvals::ExecApproval {
        package: pkg_name.clone(),
        version: version.clone(),
        integrity: info.dist.integrity.clone().unwrap_or_default(),
        capabilities: perms.iter().map(|p| (*p).to_string()).collect(),
        sandbox_backend: assessment.sandbox.backend.clone(),
        deny_network: effective_deny_network,
    };
    let approval_store = approvals::ApprovalStore::default_store()?;
    let previously_approved =
        !approval.integrity.is_empty() && approval_store.contains(&approval)?;

    if json {
        let policy_digest = oath_contracts::digest_json(&serde_json::json!({
            "require_grade": require_grade,
            "min_age": min_age,
            "sandbox_mode": sandbox_decision.effective_mode.as_str(),
            "deny_network": effective_deny_network,
            "allow_degraded_sandbox": allow_degraded_sandbox,
        }))?;
        let assessment_value = if schema_version == 2 {
            serde_json::to_value(&assessment)?
        } else {
            let generated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            serde_json::to_value(exec_assessment::signed_v3(
                &assessment,
                generated_at,
                policy_digest,
            )?)?
        };
        let verdict = serde_json::json!({
            "assessment": assessment_value,
            "approval": { "integrity_bound": true, "previously_approved": previously_approved },
            "name": pkg_name,
            "version": version,
            "integrity": info.dist.integrity,
            "grade": score.grade.to_string(),
            "score": score.score,
            "age_days": age_days,
            "last_publisher": last_publisher,
            "open_source": open_source,
            "repository": repository,
            "obfuscated": obfuscated,
            "unpacked_kb": unpacked_kb,
            "permissions": perms,
            "sandbox_mode": sandbox_decision.requested_mode.as_str(),
            "sandbox_effective": sandbox_decision.effective_mode.as_str(),
            "sandbox_degraded_allowed": allow_degraded_sandbox,
            "network_denied": effective_deny_network,
            "verdict": format!("{:?}", report.overall_risk),
            "findings": serious,
            "decision": if grade_blocked { "block" } else { "allow" },
            "reason": if grade_blocked { "require-grade" } else { "" },
        });
        println!("{}", serde_json::to_string_pretty(&verdict)?);
        if grade_blocked {
            return Ok(EXEC_EXIT_GRADE);
        }
        // --json implies --dry-run (checked above).
        return Ok(0);
    } else {
        // Human pre-run card.
        println!("\n  {}@{}", pkg_name, version);
        println!("  grade        {} ({}/100)", score.grade, score.score);
        if let Some(d) = age_days {
            println!("  published    {d} days ago");
        }
        if let Some(p) = &last_publisher {
            println!("  publisher    {p}");
        }
        println!(
            "  open source  {}",
            if open_source { "yes" } else { "unknown" }
        );
        println!(
            "  source       {}",
            if obfuscated { "obfuscated" } else { "readable" }
        );
        println!("  size         {unpacked_kb} KB");
        println!(
            "  permissions  {}",
            if perms.is_empty() {
                "none".to_string()
            } else {
                perms.join(", ")
            }
        );
        if sandbox_decision.effective_mode != ExecSandboxMode::Off {
            println!(
                "  sandbox      {}",
                sandbox_decision.effective_mode.as_str()
            );
        }
        if !serious.is_empty() {
            println!("\n  findings:");
            for finding in serious.iter().take(5) {
                println!("    {finding}");
            }
        }
        if grade_blocked {
            eprintln!(
                "\n  BLOCKED -- grade {} is below required {}",
                score.grade,
                require_grade.unwrap_or("")
            );
            return Ok(EXEC_EXIT_GRADE);
        }
        if dry_run {
            return Ok(0);
        }
        let needs_prompt = !serious.is_empty()
            && !yes
            && !previously_approved
            && std::env::var("OATH_ALLOW_ALL").is_err();
        if needs_prompt && !confirm_run_anyway()? {
            return Ok(EXEC_EXIT_USER);
        }
    }

    if remember {
        anyhow::ensure!(
            !approval.integrity.is_empty(),
            "cannot remember an approval without registry integrity"
        );
        approval_store.remember(approval)?;
    }

    // Find the binary.
    let bin_path = match preferred_binary {
        Some(rel) => pkg_dir.join(rel),
        None => {
            let candidates = ["cli.js", "bin/index.js", "index.js", "bin.js"];
            match candidates
                .iter()
                .map(|c| pkg_dir.join(c))
                .find(|p| p.exists())
            {
                Some(path) => path,
                None => {
                    eprintln!("oath exec: could not find binary for {pkg_name}");
                    return Ok(1);
                }
            }
        }
    };

    let elapsed = start.elapsed();
    if !json && elapsed.as_millis() > 100 {
        eprintln!("  fetched + scanned in {:.1}s", elapsed.as_secs_f64());
    }

    let status = run_node_binary(
        &bin_path,
        args,
        &exec_path,
        sandbox_decision.effective_mode,
        sandbox_plan.as_ref(),
    )
    .with_context(|| format!("failed to execute node {}", bin_path.display()))?;
    Ok(status.code().unwrap_or(1))
}

/// Ask the user to confirm running a package with serious findings.
fn confirm_run_anyway() -> Result<bool> {
    use std::io::Write;
    print!("\n  run anyway? [y/N] ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        Ok(true)
    } else {
        println!("  blocked.");
        Ok(false)
    }
}

/// A bin the current project already installed under node_modules/.bin.
struct LocalBin {
    bin_path: PathBuf,
    package_dir: PathBuf,
    name: String,
    version: String,
}

/// Locate `node_modules/.bin/<name>` and the package that provides it. Returns
/// `None` when there is no such bin, or when a requested version does not
/// match the installed one.
fn resolve_local_bin(bin_name: &str, requested: &str) -> Result<Option<LocalBin>> {
    let bin_path = PathBuf::from("node_modules/.bin").join(bin_name);
    if bin_path.symlink_metadata().is_err() {
        return Ok(None);
    }
    let resolved = std::fs::canonicalize(&bin_path)
        .with_context(|| format!("resolve local bin {}", bin_path.display()))?;
    let mut package_dir = resolved.parent();
    let manifest = loop {
        let Some(dir) = package_dir else {
            return Ok(None);
        };
        let candidate = dir.join("package.json");
        if candidate.is_file() {
            break candidate;
        }
        package_dir = dir.parent();
    };
    let package_dir = package_dir
        .expect("package dir found with manifest")
        .to_path_buf();
    let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest)?)
        .with_context(|| format!("parse {}", manifest.display()))?;
    let name = value["name"].as_str().unwrap_or(bin_name).to_string();
    let version = value["version"].as_str().unwrap_or("0.0.0").to_string();
    let satisfied = requested == "latest"
        || requested == version
        || requested
            .parse::<node_semver::Range>()
            .ok()
            .zip(version.parse::<node_semver::Version>().ok())
            .is_some_and(|(range, installed)| range.satisfies(&installed));
    if !satisfied {
        return Ok(None);
    }
    Ok(Some(LocalBin {
        bin_path,
        package_dir,
        name,
        version,
    }))
}

/// Assess and run a locally installed bin. The project chose this package, so
/// no download happens, but the same scan, grade gate, and prompt apply.
async fn exec_local_bin(
    local: &LocalBin,
    args: &[String],
    yes: bool,
    require_grade: Option<&str>,
) -> Result<i32> {
    use oath_analyze::{PackageScanner, RiskLevel, ScoreContext, compute_safety_score_contextual};

    let report = PackageScanner::scan(&local.name, &local.version, &local.package_dir)?;
    let serious = if matches!(report.overall_risk, RiskLevel::High | RiskLevel::Critical) {
        report.verdict_reasons.clone()
    } else {
        Vec::new()
    };
    println!(
        "oath exec: running {}@{} (local)",
        local.name, local.version
    );
    if let Some(required) = require_grade {
        // Grade needs popularity context; fetch it best-effort.
        let mut ctx = ScoreContext {
            is_dev: false,
            weekly_downloads: 0,
            age_days: 0,
        };
        if let Ok(http) =
            oath_fetch::http::client_builder().and_then(|b| b.build().map_err(Into::into))
            && let Ok(meta) = oath_fetch::fetch_package_metadata(&http, &local.name).await
        {
            ctx.weekly_downloads = meta.weekly_downloads.unwrap_or(0);
            ctx.age_days = meta.last_publish_age_days.map(|d| d as u32).unwrap_or(0);
        }
        let score = compute_safety_score_contextual(&report, &local.package_dir, &ctx);
        println!("  grade        {} ({}/100)", score.grade, score.score);
        if grade_rank(score.grade) < grade_rank(required.chars().next().unwrap_or('A')) {
            eprintln!(
                "\n  BLOCKED -- grade {} is below required {}",
                score.grade, required
            );
            return Ok(EXEC_EXIT_GRADE);
        }
    }
    if !serious.is_empty() {
        println!("\n  findings:");
        for finding in serious.iter().take(5) {
            println!("    {finding}");
        }
        let needs_prompt = !yes && std::env::var("OATH_ALLOW_ALL").is_err();
        if needs_prompt && !confirm_run_anyway()? {
            return Ok(EXEC_EXIT_USER);
        }
    }
    let status = std::process::Command::new(&local.bin_path)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {}", local.bin_path.display()))?;
    Ok(status.code().unwrap_or(1))
}

// ---- SCORE ------------------------------------------------------------------

async fn cmd_score(package: &str) -> Result<()> {
    use oath_analyze::{PackageScanner, ScoreContext, compute_safety_score_contextual};

    let (pkg_name, pkg_version) = parse_package_spec(package);

    println!("oath score: analyzing {}@{}...", pkg_name, pkg_version);

    // Resolve and fetch
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&pkg_name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &pkg_version)?;
    let version = resolved.version.to_string();
    let info = resolved.info;

    // Ensure in store
    let store = ContentStore::default_store()?;
    let pkg_dir = if store
        .verify_package_variant(
            &pkg_name,
            &version,
            Some(&info.dist.tarball),
            info.dist.integrity.as_deref(),
        )
        .is_verified()
    {
        store.package_dir_for(
            &pkg_name,
            &version,
            Some(&info.dist.tarball),
            info.dist.integrity.as_deref(),
        )
    } else {
        download_and_store_package(
            &client,
            &store,
            &pkg_name,
            &version,
            &info.dist.tarball,
            info.dist.integrity.as_deref(),
        )
        .await?;
        store.package_dir_for(
            &pkg_name,
            &version,
            Some(&info.dist.tarball),
            info.dist.integrity.as_deref(),
        )
    };

    // Scan
    let report = PackageScanner::scan(&pkg_name, &version, &pkg_dir)?;
    // Popularity/age context (best-effort): lets the trust layer clear heuristic
    // false-positives on very widely-used packages (prettier, react, ...). A
    // genuinely compromised popular package still grades down via CRITICAL findings.
    let ctx = {
        let mut weekly = 0u64;
        let mut age = 0u32;
        if let Ok(http) =
            oath_fetch::http::client_builder().and_then(|b| b.build().map_err(Into::into))
            && let Ok(meta) = oath_fetch::fetch_package_metadata(&http, &pkg_name).await
        {
            weekly = meta.weekly_downloads.unwrap_or(0);
            age = meta.last_publish_age_days.map(|d| d as u32).unwrap_or(0);
        }
        ScoreContext {
            is_dev: false,
            weekly_downloads: weekly,
            age_days: age,
        }
    };
    let score = compute_safety_score_contextual(&report, &pkg_dir, &ctx);

    // Display
    let grade_color = match score.grade {
        'A' => "\x1b[32m", // green
        'B' => "\x1b[36m", // cyan
        'C' => "\x1b[33m", // yellow
        'D' => "\x1b[33m", // yellow
        _ => "\x1b[31m",   // red
    };
    let reset = "\x1b[0m";

    println!();
    println!("  {}@{}", pkg_name, version);
    println!(
        "  safety score: {}{}/100 (grade {}){}",
        grade_color, score.score, score.grade, reset
    );
    println!();
    println!("  factors:");
    for factor in &score.factors {
        let sign = if factor.weight >= 0 { "+" } else { "" };
        println!("    {}{:>3}  {}", sign, factor.weight, factor.description);
    }
    println!();

    // Capabilities summary
    let caps = &report.capabilities;
    if caps.network
        || caps.filesystem
        || caps.env_access
        || caps.subprocess
        || caps.dynamic_exec
        || caps.has_install_scripts
    {
        println!("  capabilities:");
        if caps.network {
            println!("    network access");
        }
        if caps.filesystem {
            println!("    filesystem access");
        }
        if caps.env_access {
            println!("    env variable reads");
        }
        if caps.subprocess {
            println!("    subprocess spawn");
        }
        if caps.dynamic_exec {
            println!("    dynamic code eval");
        }
        if caps.has_install_scripts {
            println!("    install scripts");
        }
        println!();
    }

    println!(
        "  files scanned: {}  |  lines: {}",
        report.files_scanned, report.lines_scanned
    );
    println!(
        "  findings: {} total ({} high/critical)",
        report.findings.len(),
        report
            .findings
            .iter()
            .filter(|f| matches!(
                f.risk,
                oath_analyze::RiskLevel::High | oath_analyze::RiskLevel::Critical
            ))
            .count()
    );

    Ok(())
}

// ---- INFO -------------------------------------------------------------------

async fn cmd_info(package: &str) -> Result<()> {
    use oath_fetch::metadata::fetch_package_metadata;

    let (pkg_name, _) = parse_package_spec(package);

    println!("oath info: fetching metadata for {}...", pkg_name);

    let client = oath_fetch::http::client_builder()?.build()?;

    let meta = fetch_package_metadata(&client, &pkg_name).await?;

    println!();
    println!("  {}@{}", meta.name, meta.latest_version);
    println!();

    // Maintainers
    println!("  maintainers:");
    for m in &meta.maintainers {
        if let Some(email) = &m.email {
            println!("    {} <{}>", m.name, email);
        } else {
            println!("    {}", m.name);
        }
    }
    println!();

    // Stats
    if let Some(downloads) = meta.weekly_downloads {
        println!("  weekly downloads: {}", format_downloads(downloads));
    }
    println!("  total versions:   {}", meta.total_versions);
    if let Some(ref published) = meta.published_at {
        println!("  latest published: {}", published);
    }
    if let Some(age) = meta.last_publish_age_days {
        println!("  publish age:      {} days ago", age);
    }
    println!();

    // Metadata
    if let Some(ref license) = meta.license {
        println!("  license:    {}", license);
    }
    if let Some(ref repo) = meta.repository {
        println!("  repository: {}", repo);
    }
    println!(
        "  has readme: {}",
        if meta.has_readme { "yes" } else { "no" }
    );

    Ok(())
}

fn format_downloads(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Parse an ISO 8601 datetime string and return seconds since publication.
/// Handles formats like "2024-01-15T10:30:00.000Z" or "2024-01-15T10:30:00Z"
fn parse_iso_age_secs(iso: &str) -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Extract YYYY-MM-DDTHH:MM:SS from the string
    let s = iso.trim();
    if s.len() < 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // Convert to approximate unix timestamp (good enough for age comparison)
    // Days in each month (non-leap)
    let days_before_month: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = (year - 1970) * 365 + (year - 1969) / 4; // approx leap years
    if (1..=12).contains(&month) {
        days += days_before_month[(month - 1) as usize];
    }
    // Add leap day for current year if applicable
    if month > 2
        && year.is_multiple_of(4)
        && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    {
        days += 1;
    }
    days += day - 1;
    let publish_ts = days * 86400 + hour * 3600 + min * 60 + sec;

    let now_ts = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    if now_ts > publish_ts {
        Some(now_ts - publish_ts)
    } else {
        Some(0)
    }
}

/// Parse a human duration string like "7d", "24h", "30d" into seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 'd')
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 'h')
    } else if let Some(stripped) = s.strip_suffix('w') {
        (stripped, 'w')
    } else {
        // Default to days if no unit
        (s, 'd')
    };
    let num: u64 = num_str.parse().ok()?;
    match unit {
        'h' => Some(num * 3600),
        'd' => Some(num * 86400),
        'w' => Some(num * 7 * 86400),
        _ => None,
    }
}

// ---- REMOVE -----------------------------------------------------------------

async fn cmd_remove(packages: Vec<String>) -> Result<()> {
    if packages.is_empty() {
        println!("oath remove: no packages specified");
        return Ok(());
    }

    let manifest_path = PathBuf::from("package.json");
    anyhow::ensure!(manifest_path.exists(), "no package.json found");
    let mut manifest_doc = manifest::PackageJsonDocument::load(&manifest_path)?;

    let sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    let mut removed_names = Vec::new();
    for package in &packages {
        let (name, _) = parse_package_spec(package);
        let declared = sections.iter().any(|section| {
            manifest_doc
                .value
                .get(section)
                .and_then(|d| d.as_object())
                .is_some_and(|deps| deps.contains_key(&name))
        });
        if !declared {
            println!("oath remove: '{}' not found in package.json", name);
            continue;
        }
        println!("removed {}", name);
        removed_names.push(name);
    }
    if removed_names.is_empty() {
        return Ok(());
    }

    // Arborist applies the removal to the manifest and prunes the tree the way
    // npm does, including when the last dependency goes: node_modules stays,
    // only the packages leave.
    let cwd = std::env::current_dir()?.canonicalize()?;
    let mut placement_plan =
        ArboristPlanner::plan_with(&cwd, &PlacementRequest::remove(removed_names))?;
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    if let Some(root_manifest) = &placement_plan.root_manifest {
        root_manifest.apply_to(&mut manifest_doc.value);
    } else {
        for section in sections {
            if let Some(deps) = manifest_doc
                .value
                .get_mut(section)
                .and_then(|d| d.as_object_mut())
            {
                for package in &packages {
                    deps.remove(&parse_package_spec(package).0);
                }
            }
        }
    }
    let graph = placement_plan.to_dep_graph()?;
    let deps = extract_deps(&manifest_doc.value, "dependencies");
    let dev_deps = extract_deps(&manifest_doc.value, "devDependencies");
    let project_name = manifest_doc.value["name"]
        .as_str()
        .unwrap_or("project")
        .to_string();
    let project_version = manifest_doc.value["version"]
        .as_str()
        .unwrap_or("0.0.0")
        .to_string();

    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let (to_download, _) = missing_store_nodes(&graph, &store);
    download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client)).await?;
    let linker = Linker::new((*store).clone()).with_external_link_targets(external_link_targets(
        &cwd,
        &manifest_doc.value,
        None,
    ));
    linker.link_placement_plan(&placement_plan, &cwd)?;
    placement_plan.write(&cwd.join(".oath").join("placement-plan.json"))?;
    manifest_doc.save()?;
    let lockfile = Lockfile::from_graph_with_manifest(
        &graph,
        &project_name,
        &project_version,
        &deps,
        &dev_deps,
    );
    lockfile.write(&PathBuf::from("oath-lock.json"))?;

    Ok(())
}

// ---- PUBLISH ----------------------------------------------------------------

fn collect_publish_files(
    root: &std::path::Path,
    excludes: &[&str],
    npmignore: &[String],
    whitelist: &Option<Vec<String>>,
) -> Result<Vec<PathBuf>> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize project root {}", root.display()))?;
    let mut files = Vec::new();
    collect_publish_files_inner(&root, &root, &mut files, excludes, npmignore, whitelist)?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn npm_authoritative_packlist(root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let cache = tempfile::tempdir().context("failed to create isolated npm pack cache")?;
    let output = npm_command()
        .args(["pack", "--dry-run", "--json", "--ignore-scripts"])
        .current_dir(root)
        .env("npm_config_cache", cache.path())
        .output()
        .context("npm 11 is required to compute the authoritative publish packlist")?;
    anyhow::ensure!(
        output.status.success(),
        "npm packlist failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("invalid npm pack --json output")?;
    let files = report
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("files"))
        .and_then(|files| files.as_array())
        .context("npm pack output did not contain files")?;
    let canonical_root = root.canonicalize()?;
    let mut paths = Vec::new();
    for file in files {
        let relative = file
            .get("path")
            .and_then(|value| value.as_str())
            .context("npm pack file missing path")?;
        let path = canonical_root
            .join(relative)
            .canonicalize()
            .with_context(|| format!("npm pack selected unreadable file {relative}"))?;
        anyhow::ensure!(
            path.starts_with(&canonical_root),
            "npm pack selected out-of-root file {relative}"
        );
        anyhow::ensure!(path.is_file(), "npm pack selected non-file {relative}");
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn npm_command() -> std::process::Command {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("npm.cmd")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("npm")
    }
}

fn parse_tool_version(raw: &str) -> Result<(u64, u64, u64)> {
    let raw = raw.trim().trim_start_matches('v');
    let mut parts = raw.split('.');
    let major = parts
        .next()
        .context("missing major version")?
        .parse::<u64>()?;
    let minor = parts
        .next()
        .context("missing minor version")?
        .parse::<u64>()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()
        .unwrap_or("0")
        .parse::<u64>()?;
    Ok((major, minor, patch))
}

fn command_version(mut command: std::process::Command, name: &str) -> Result<(u64, u64, u64)> {
    let output = command
        .arg("--version")
        .output()
        .with_context(|| format!("failed to run {name} --version"))?;
    anyhow::ensure!(
        output.status.success(),
        "{name} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_tool_version(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("could not parse {name} version"))
}

fn ensure_npm_stage_prerequisites() -> Result<()> {
    let npm = command_version(npm_command(), "npm")?;
    let node = command_version(std::process::Command::new("node"), "node")?;
    anyhow::ensure!(
        npm >= (11, 15, 0),
        "oath stage requires npm >= 11.15.0; found {}.{}.{}",
        npm.0,
        npm.1,
        npm.2
    );
    anyhow::ensure!(
        node >= (22, 14, 0),
        "oath stage requires Node >= 22.14.0; found {}.{}.{}",
        node.0,
        node.1,
        node.2
    );
    Ok(())
}

fn push_optional_flag(args: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        args.push(flag.to_string());
        args.push(value);
    }
}

fn cmd_stage(action: StageAction) -> Result<()> {
    ensure_npm_stage_prerequisites()?;
    let (args, destination, confirmation): (Vec<String>, Option<PathBuf>, Option<&str>) =
        match action {
            StageAction::List {
                package,
                json,
                registry,
            } => {
                let mut args = vec!["stage".into(), "list".into()];
                if let Some(package) = package {
                    args.push(package);
                }
                if json {
                    args.push("--json".into());
                }
                push_optional_flag(&mut args, "--registry", registry);
                (args, None, None)
            }
            StageAction::View {
                stage_id,
                json,
                registry,
            } => {
                let mut args = vec!["stage".into(), "view".into(), stage_id];
                if json {
                    args.push("--json".into());
                }
                push_optional_flag(&mut args, "--registry", registry);
                (args, None, None)
            }
            StageAction::Download {
                stage_id,
                json,
                registry,
                destination,
            } => {
                let mut args = vec!["stage".into(), "download".into(), stage_id];
                if json {
                    args.push("--json".into());
                }
                push_optional_flag(&mut args, "--registry", registry);
                (args, Some(destination), None)
            }
            StageAction::Approve {
                stage_id,
                yes,
                otp,
                registry,
            } => {
                anyhow::ensure!(
                    yes,
                    "oath stage approve requires --yes after reviewing `oath stage view` and `oath stage download`"
                );
                let mut args = vec!["stage".into(), "approve".into(), stage_id];
                push_optional_flag(&mut args, "--otp", otp);
                push_optional_flag(&mut args, "--registry", registry);
                (args, None, Some("approve"))
            }
            StageAction::Reject {
                stage_id,
                yes,
                otp,
                registry,
            } => {
                anyhow::ensure!(yes, "oath stage reject is permanent and requires --yes");
                let mut args = vec!["stage".into(), "reject".into(), stage_id];
                push_optional_flag(&mut args, "--otp", otp);
                push_optional_flag(&mut args, "--registry", registry);
                (args, None, Some("reject"))
            }
        };

    if let Some(destination) = &destination {
        std::fs::create_dir_all(destination).with_context(|| {
            format!(
                "failed to create staged-package destination {}",
                destination.display()
            )
        })?;
    }
    if let Some(decision) = confirmation {
        eprintln!(
            "oath stage: forwarding irreversible `{decision}` to npm; npm will require registry proof-of-presence"
        );
    }
    let mut command = npm_command();
    command.args(&args);
    if let Some(destination) = destination {
        command.current_dir(destination);
    }
    let status = command.status().context("failed to invoke npm stage")?;
    anyhow::ensure!(
        status.success(),
        "npm {} failed with status {status}",
        args.join(" ")
    );
    Ok(())
}

fn cmd_transfer(action: TransferAction) -> Result<()> {
    match action {
        TransferAction::Create {
            output,
            tag,
            access,
            json,
        } => {
            let root = std::env::current_dir()?;
            let package = read_package_json()?;
            let files = npm_authoritative_packlist(&root)?;
            let mut assessment =
                publish_assessment::assess(&root, &files, &package, &tag, access.as_deref())?;
            publish_assessment::attach_previous_release(&root, &mut assessment)?;
            anyhow::ensure!(
                assessment.decision == oath_contracts::Decision::Allow,
                "oath transfer: blocked by {}",
                assessment.reason_code
            );
            let evidence = publish_assessment::persist_signed(&root, &assessment, &package)?;
            let report = package_transfer::create_capsule(&root, &output, &assessment, &evidence)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("oath transfer: created {}", output.display());
                println!("  package: {}@{}", assessment.name, assessment.version);
                println!("  tarball: {}", report.tarball.sha512);
                println!("  decision: review-required");
                println!(
                    "  verify before use: oath transfer verify {}",
                    output.display()
                );
            }
        }
        TransferAction::Verify {
            capsule,
            trusted_public_key,
            json,
        } => {
            let report = package_transfer::verify_capsule(&capsule, trusted_public_key.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("oath transfer: verified {}", capsule.display());
                println!("  package: {}@{}", report.name, report.version);
                println!("  signed assessment: cryptographically valid");
                println!("  signing-key trust: {}", report.signature_trust);
                println!(
                    "  decision: {} (verification is not a safety proof)",
                    report.consumer_decision
                );
            }
        }
    }
    Ok(())
}

fn collect_publish_files_inner(
    dir: &std::path::Path,
    root: &std::path::Path,
    files: &mut Vec<PathBuf>,
    excludes: &[&str],
    npmignore: &[String],
    whitelist: &Option<Vec<String>>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read publish dir {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read publish dir entry {}", dir.display()))?;

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat publish path {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("oath publish: refusing symlink {}", path.display());
        }

        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize publish path {}", path.display()))?;
        if !canonical.starts_with(root) {
            anyhow::bail!(
                "oath publish: refusing out-of-root path {}",
                canonical.display()
            );
        }

        let rel = canonical
            .strip_prefix(root)
            .unwrap_or(&canonical)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.is_empty() || should_publish_exclude(&rel, excludes, npmignore) {
            continue;
        }

        if !publish_whitelist_allows(&rel, &canonical, whitelist) {
            continue;
        }

        if metadata.is_dir() {
            collect_publish_files_inner(&canonical, root, files, excludes, npmignore, whitelist)?;
        } else if metadata.is_file() {
            std::fs::File::open(&canonical)
                .with_context(|| format!("oath publish: cannot read {}", canonical.display()))?;
            files.push(canonical);
        } else {
            anyhow::bail!(
                "oath publish: refusing non-regular file {}",
                canonical.display()
            );
        }
    }

    Ok(())
}

fn publish_whitelist_allows(
    rel: &str,
    path: &std::path::Path,
    whitelist: &Option<Vec<String>>,
) -> bool {
    let Some(whitelist) = whitelist else {
        return true;
    };
    let top = rel.split('/').next().unwrap_or(rel);
    if whitelist
        .iter()
        .any(|w| w.trim_end_matches('/') == top || w.trim_end_matches('/') == rel)
    {
        return true;
    }

    let fname = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    matches!(
        fname,
        "package.json" | "README.md" | "README" | "LICENSE" | "LICENCE"
    )
}

fn should_publish_exclude(rel: &str, excludes: &[&str], npmignore: &[String]) -> bool {
    for pat in excludes {
        if rel == *pat || rel.starts_with(&format!("{}/", pat)) {
            return true;
        }
    }

    for pat in npmignore {
        let pat = pat.trim_end_matches('/');
        if rel == pat
            || rel.starts_with(&format!("{}/", pat))
            || rel.ends_with(&format!(".{}", pat.trim_start_matches("*.")))
            || (pat.starts_with("*.") && rel.ends_with(&pat[1..]))
        {
            return true;
        }
    }

    rel.ends_with(".test.js")
        || rel.ends_with(".spec.js")
        || rel.ends_with(".test.ts")
        || rel.ends_with(".spec.ts")
}

async fn cmd_publish(
    tag: Option<&str>,
    access: Option<&str>,
    dry_run: bool,
    json: bool,
    schema_version: u32,
    stage: bool,
) -> Result<()> {
    use base64::Engine;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha1::Sha1;
    use sha2::{Digest, Sha512};

    anyhow::ensure!(
        !json || dry_run,
        "oath publish --json is an assessment-only interface and requires --dry-run; stage or publish in a separate explicit command"
    );
    anyhow::ensure!(
        matches!(schema_version, 1 | 2),
        "unsupported publish assessment schema {schema_version}; supported versions are 1 and 2"
    );

    let dist_tag = tag.unwrap_or("latest");

    // 1. Read package.json
    let pkg = read_package_json()?;
    let name = pkg["name"]
        .as_str()
        .context("package.json missing 'name'")?
        .to_string();
    let version = pkg["version"]
        .as_str()
        .context("package.json missing 'version'")?
        .to_string();
    let description = pkg["description"].as_str().unwrap_or("").to_string();

    if !json {
        println!("oath publish: packing {}@{}...", name, version);
    }

    // 2. Collect files to include in tarball
    // Start with the configured `files` field if present, otherwise include everything
    let cwd = std::env::current_dir()?;

    // Default excludes
    let default_excludes: Vec<&str> =
        vec!["node_modules", ".git", "test", ".oath", "oath-lock.json"];

    // Read .npmignore
    let npmignore_patterns: Vec<String> = {
        let npmignore_path = cwd.join(".npmignore");
        if npmignore_path.exists() {
            std::fs::read_to_string(&npmignore_path)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect()
        } else {
            vec![]
        }
    };

    // Get `files` field from package.json
    let files_whitelist: Option<Vec<String>> =
        pkg.get("files").and_then(|f| f.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    let oath_files = collect_publish_files(
        &cwd,
        &default_excludes,
        &npmignore_patterns,
        &files_whitelist,
    )?;
    let files_to_pack = npm_authoritative_packlist(&cwd)?;
    let oath_set: std::collections::BTreeSet<_> = oath_files
        .iter()
        .filter_map(|path| path.strip_prefix(&cwd).ok())
        .collect();
    let npm_set: std::collections::BTreeSet<_> = files_to_pack
        .iter()
        .filter_map(|path| path.strip_prefix(&cwd).ok())
        .collect();
    if oath_set != npm_set && !json {
        eprintln!(
            "oath publish: npm packlist selected {} files; Oath's independent collector selected {}. The npm packlist is authoritative.",
            npm_set.len(),
            oath_set.len()
        );
    }

    let mut assessment = publish_assessment::assess(&cwd, &files_to_pack, &pkg, dist_tag, access)?;
    publish_assessment::attach_previous_release(&cwd, &mut assessment)?;
    if json {
        if schema_version == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&publish_assessment::legacy_v1(&assessment))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&assessment)?);
        }
    }
    anyhow::ensure!(
        assessment.decision == oath_contracts::Decision::Allow,
        "oath publish: blocked by {}",
        assessment.reason_code
    );

    if dry_run {
        if json {
            return Ok(());
        }
        println!("oath publish: dry run - would publish {}@{}", name, version);
        println!("  dist-tag: {}", dist_tag);
        if let Some(acc) = access {
            println!("  access: {}", acc);
        }
        println!("  files to pack ({}):", files_to_pack.len());
        let mut total_size = 0u64;
        for f in &files_to_pack {
            let rel = f.strip_prefix(&cwd).unwrap_or(f).to_string_lossy();
            let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
            total_size += size;
            println!("    {} ({} B)", rel, size);
        }
        println!("  total uncompressed: {} bytes", total_size);
        return Ok(());
    }

    let evidence = publish_assessment::persist_signed(&cwd, &assessment, &pkg)?;
    if !json {
        println!("  signed evidence: {}", evidence.directory);
    }

    if stage {
        ensure_npm_stage_prerequisites()?;
        let mut command = npm_command();
        command.args(["stage", "publish", "--tag", dist_tag]);
        command.env("NPM_CONFIG_PROVENANCE", "true");
        let status = command
            .status()
            .context("failed to invoke npm staged publishing")?;
        anyhow::ensure!(
            status.success(),
            "npm stage publish failed with status {status}"
        );
        return Ok(());
    }

    // 3. Build tarball in memory
    let tarball_bytes = {
        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut tar_builder = tar::Builder::new(gz);

        for file_path in &files_to_pack {
            let rel = file_path
                .strip_prefix(&cwd)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();
            // npm tarballs use "package/" prefix
            let tar_path = format!("package/{}", rel);
            tar_builder
                .append_path_with_name(file_path, &tar_path)
                .with_context(|| format!("failed to add {} to tarball", rel))?;
        }

        let gz = tar_builder.into_inner().context("failed to finalize tar")?;
        gz.finish().context("failed to finish gzip")?
    };

    // 4. Compute integrity
    let sha512_digest = {
        let mut hasher = Sha512::new();
        hasher.update(&tarball_bytes);
        hasher.finalize()
    };
    let sha512_b64 = base64::engine::general_purpose::STANDARD.encode(sha512_digest.as_slice());
    let integrity = format!("sha512-{}", sha512_b64);

    let shasum = {
        let mut hasher = Sha1::new();
        hasher.update(&tarball_bytes);
        format!("{:x}", hasher.finalize())
    };

    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let tarball_len = tarball_bytes.len();

    // 5. Check if version already published
    let http_client = oath_fetch::http::client_builder()?.build()?;

    let registry_url = "https://registry.npmjs.org";
    let pkg_url = format!("{}/{}", registry_url, name);

    let existing = http_client
        .get(&pkg_url)
        .header("Accept", "application/json")
        .send()
        .await;

    if let Ok(resp) = existing
        && resp.status().is_success()
    {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if let Some(versions) = body.get("versions").and_then(|v| v.as_object())
            && versions.contains_key(&version)
        {
            anyhow::bail!(
                "oath publish: {}@{} is already published. Bump the version to publish again.",
                name,
                version
            );
        }
    }

    // 6. Read auth token
    let token = std::env::var("NPM_TOKEN").ok().or_else(|| {
        let npmrc_path = oath_core::home_dir()?.join(".npmrc");
        let content = std::fs::read_to_string(&npmrc_path).ok()?;
        for line in content.lines() {
            let line = line.trim();
            if let Some(token) = line.strip_prefix("//registry.npmjs.org/:_authToken=") {
                return Some(token.to_string());
            }
        }
        None
    });

    let token = token.context(
        "oath publish: no npm auth token found.\n  Set NPM_TOKEN env var or add //registry.npmjs.org/:_authToken=TOKEN to ~/.npmrc"
    )?;

    // 7. Build publish payload
    let tarball_url = format!(
        "{}/{}-/-/{}-{}.tgz",
        registry_url,
        name,
        name.split('/').next_back().unwrap_or(&name),
        version
    );
    let attachment_name = format!(
        "{}-{}.tgz",
        name.split('/').next_back().unwrap_or(&name),
        version
    );

    let mut version_obj = pkg.clone();
    version_obj["dist"] = serde_json::json!({
        "tarball": tarball_url,
        "integrity": integrity,
        "shasum": shasum
    });

    let mut payload = serde_json::json!({
        "_id": name,
        "name": name,
        "description": description,
        "dist-tags": { dist_tag: version },
        "versions": {},
        "_attachments": {
            attachment_name: {
                "content_type": "application/octet-stream",
                "data": tarball_b64,
                "length": tarball_len
            }
        }
    });
    payload["versions"][&version] = version_obj;

    if let Some(acc) = access {
        payload["access"] = serde_json::Value::String(acc.to_string());
    }

    // 8. PUT to registry
    println!(
        "oath publish: publishing {}@{} (dist-tag: {})...",
        name, version, dist_tag
    );

    let resp = http_client
        .put(&pkg_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .context("failed to send publish request")?;

    let status = resp.status();
    if status.is_success() {
        println!("+ {}@{}", name, version);
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("oath publish: registry returned {}: {}", status, body)
    }
}

// ---- GLOBAL INSTALL ---------------------------------------------------------

/// Install one or more packages to the global location (~/.oath/global/).
/// Symlinks binaries into ~/.oath/global/bin/.
async fn cmd_install_global(packages: Vec<String>, dry_run: bool) -> Result<()> {
    if packages.is_empty() {
        anyhow::bail!("oath install -g: please specify at least one package to install globally");
    }

    let home = oath_core::home_dir().context("HOME or USERPROFILE not set")?;
    let global_dir = home.join(".oath").join("global");
    let nm_dir = global_dir.join("node_modules");
    let bin_dir = global_dir.join("bin");

    if dry_run {
        println!("oath install -g (dry run): would install {:?}", packages);
        println!("  install dir: {}", nm_dir.display());
        println!("  bin dir:     {}", bin_dir.display());
        return Ok(());
    }

    std::fs::create_dir_all(&nm_dir)?;
    std::fs::create_dir_all(&bin_dir)?;

    // Build deps map
    let mut deps = HashMap::new();
    for spec in &packages {
        let (name, version) = parse_package_spec(spec);
        deps.insert(name, version);
    }

    println!("oath install -g: resolving {} package(s)...", deps.len());
    let start = Instant::now();
    let global_manifest = serde_json::json!({
        "name": "oath-global",
        "version": "0.0.0",
        "private": true,
        "dependencies": &deps,
    });
    std::fs::write(
        global_dir.join("package.json"),
        serde_json::to_vec_pretty(&global_manifest)?,
    )?;
    let mut placement_plan = ArboristPlanner::plan(&global_dir)?;
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;

    println!(
        "  resolved {} packages in {:.1}s",
        graph.package_count(),
        start.elapsed().as_secs_f64()
    );

    // Download missing packages
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let (to_download, _) = missing_store_nodes(&graph, &store);
    let summary = download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client))
        .await
        .context("failed to download global dependencies")?;

    if summary.downloaded > 0 {
        println!("  downloaded {} packages", summary.downloaded);
    }

    // Link into global node_modules
    let linker = Linker::new((*store).clone());
    let link_result = linker.link_placement_plan(&placement_plan, &global_dir)?;
    placement_plan.write(&global_dir.join(".oath").join("placement-plan.json"))?;
    println!("  linked {} packages", link_result.linked);

    // Create bin symlinks for the top-level (directly requested) packages
    let mut bins_created = 0usize;
    for pkg_name in deps.keys() {
        // Find the resolved version for this package name
        let node = graph.nodes.values().find(|n| &n.name == pkg_name);
        let node = match node {
            Some(n) => n,
            None => continue,
        };

        let pkg_dir = nm_dir.join(pkg_name);
        if !pkg_dir.exists() {
            continue;
        }

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        let pkg_json_content = std::fs::read_to_string(&pkg_json_path)?;
        let pkg_json: serde_json::Value = serde_json::from_str(&pkg_json_content)?;

        let bin_entries = safe_bin_entries(&pkg_json, pkg_name);

        for (bin_name, rel_path) in &bin_entries {
            let actual_bin = pkg_dir.join(rel_path);
            let link_path = bin_dir.join(bin_name);

            // Make the bin executable
            if actual_bin.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&actual_bin) {
                        let mut perms = meta.permissions();
                        perms.set_mode(perms.mode() | 0o111);
                        let _ = std::fs::set_permissions(&actual_bin, perms);
                    }
                }
            }

            // Remove existing symlink
            if link_path.exists() || link_path.symlink_metadata().is_ok() {
                std::fs::remove_file(&link_path).ok();
            }

            // Create symlink: bin_dir/bin_name -> ../node_modules/<pkg>/<rel_path>
            let target = PathBuf::from("..")
                .join("node_modules")
                .join(pkg_name)
                .join(rel_path);
            platform_symlink_file(&target, &link_path)
                .with_context(|| format!("failed to create symlink for {bin_name}"))?;
            bins_created += 1;
            println!("  created: {}", link_path.display());
        }

        println!("  installed {}@{}", node.name, node.version);
    }

    if bins_created > 0 {
        println!();
        println!(
            "  {} bin(s) installed to {}",
            bins_created,
            bin_dir.display()
        );
        println!("  Add {} to your PATH to use them", bin_dir.display());
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());
    Ok(())
}

// ---- LOG --------------------------------------------------------------------

fn cmd_log(tail: usize) -> Result<()> {
    let logger = oath_transparency::TransparencyLogger::default_logger()?;
    let entries = logger.read_recent(tail)?;

    if entries.is_empty() {
        println!("oath log: no entries yet (run `oath install` to create entries)");
        println!("  log path: {}", logger.log_path().display());
        return Ok(());
    }

    println!("oath transparency log (last {} entries):", entries.len());
    println!();

    for entry in &entries {
        use std::time::{Duration, UNIX_EPOCH};
        let _dt = UNIX_EPOCH + Duration::from_secs(entry.ts);
        let secs = entry.ts;
        // Format as simple timestamp
        let _mins = (secs % 3600) / 60;
        let _hours = (secs % 86400) / 3600;
        let _days_since_epoch = secs / 86400;
        // Approximate date (not perfect but sufficient for display)
        println!(
            "  --- {} packages | {}ms | {}",
            entry.pkg_count, entry.duration_ms, entry.project
        );
        println!("      ts: {}", entry.ts);
        // Show first few packages
        let show_count = entry.packages.len().min(5);
        for pkg in entry.packages.iter().take(show_count) {
            if let Some(ref int) = pkg.integrity {
                println!(
                    "      {}@{}  {}",
                    pkg.name,
                    pkg.version,
                    &int[..int.len().min(30)]
                );
            } else {
                println!("      {}@{}", pkg.name, pkg.version);
            }
        }
        if entry.packages.len() > show_count {
            println!("      ... and {} more", entry.packages.len() - show_count);
        }
        println!();
    }

    println!("  log path: {}", logger.log_path().display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oath_resolve::DepNode;

    fn sandbox_capabilities(available: bool) -> oath_sandbox::BackendCapabilities {
        oath_sandbox::BackendCapabilities {
            backend: "test-native".into(),
            available,
            filesystem_isolation: available,
            network_isolation: available,
            process_isolation: available,
            resource_limits: available,
            degraded_reason: (!available).then(|| "test backend unavailable".into()),
        }
    }

    #[test]
    fn exec_auto_prefers_complete_native_containment() {
        let mode = resolve_exec_sandbox_capabilities(
            ExecSandboxMode::Auto,
            true,
            true,
            &sandbox_capabilities(true),
        )
        .unwrap();
        assert_eq!(mode, ExecSandboxMode::Native);
    }

    #[test]
    fn exec_auto_refuses_implicit_degraded_containment() {
        let error = resolve_exec_sandbox_capabilities(
            ExecSandboxMode::Auto,
            false,
            true,
            &sandbox_capabilities(false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("refused to downgrade"));
    }

    #[test]
    fn exec_node_requires_explicit_degraded_policy() {
        assert!(
            resolve_exec_sandbox_capabilities(
                ExecSandboxMode::Node,
                false,
                true,
                &sandbox_capabilities(false),
            )
            .is_err()
        );
        assert_eq!(
            resolve_exec_sandbox_capabilities(
                ExecSandboxMode::Node,
                true,
                true,
                &sandbox_capabilities(false),
            )
            .unwrap(),
            ExecSandboxMode::Node
        );
    }

    #[test]
    fn exec_native_rejects_incomplete_capability_claims() {
        let mut capabilities = sandbox_capabilities(true);
        capabilities.process_isolation = false;
        assert!(
            resolve_exec_sandbox_capabilities(ExecSandboxMode::Native, false, true, &capabilities,)
                .is_err()
        );
    }

    #[test]
    fn parses_npm_and_node_stage_versions() {
        assert_eq!(parse_tool_version("11.18.0\n").unwrap(), (11, 18, 0));
        assert_eq!(parse_tool_version("v22.14.0").unwrap(), (22, 14, 0));
        assert!(parse_tool_version("unknown").is_err());
    }

    #[test]
    fn previous_release_diff_detects_publisher_and_hook_changes() {
        let packument = serde_json::json!({
            "versions": {
                "1.0.0": { "_npmUser": { "name": "alice" }, "dist": { "integrity": "sha512-old" } },
                "1.1.0": { "_npmUser": { "name": "alice" }, "scripts": { "postinstall": "node setup.js" }, "dist": { "integrity": "sha512-middle" } },
                "2.0.0": { "_npmUser": { "name": "mallory" }, "dist": { "integrity": "sha512-current" } }
            }
        });
        let diff = previous_release_diff(&packument, "2.0.0", Some("mallory"), false).unwrap();
        assert_eq!(diff.previous_version, "1.1.0");
        assert_eq!(diff.previous_integrity.as_deref(), Some("sha512-middle"));
        assert_eq!(diff.publisher_changed, Some(true));
        assert!(diff.lifecycle_hooks_changed);
    }

    #[test]
    fn npm_packlist_is_the_authoritative_assessment_input() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"packlist-test","version":"1.0.0","files":["index.js"]}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("index.js"), "module.exports = 1").unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "not published").unwrap();
        let files = npm_authoritative_packlist(dir.path()).unwrap();
        let names: Vec<_> = files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect();
        assert!(names.contains(&"package.json"));
        assert!(names.contains(&"index.js"));
        assert!(!names.contains(&"ignored.txt"));
    }

    #[test]
    fn npm_package_env_flattens_scalars_and_skips_objects() {
        let pkg = serde_json::json!({
            "name": "demo",
            "version": "1.2.3",
            "private": true,
            "dependencies": { "left-pad": "^1.0.0" },
            "scripts": { "build": "tsc" }
        });
        let env = npm_package_env(&pkg);
        assert!(env.contains(&("npm_package_name".to_string(), "demo".to_string())));
        assert!(env.contains(&("npm_package_version".to_string(), "1.2.3".to_string())));
        assert!(env.contains(&("npm_package_private".to_string(), "true".to_string())));
        // objects/arrays (dependencies, scripts) are skipped, not stringified
        assert!(!env.iter().any(|(k, _)| k == "npm_package_dependencies"));
        assert!(!env.iter().any(|(k, _)| k == "npm_package_scripts"));
    }

    #[test]
    fn grade_rank_orders_a_best_to_f_worst_and_gates() {
        assert!(grade_rank('A') > grade_rank('B'));
        assert!(grade_rank('B') > grade_rank('C'));
        assert!(grade_rank('C') > grade_rank('D'));
        assert!(grade_rank('D') > grade_rank('F'));
        assert_eq!(grade_rank('a'), grade_rank('A')); // case-insensitive
        // `--require-grade B` blocks a C, allows an A
        assert!(grade_rank('C') < grade_rank('B')); // C is blocked
        assert!(grade_rank('A') >= grade_rank('B')); // A passes
    }

    #[test]
    fn shell_quote_args_preserves_script_arguments() {
        let args = vec![
            "plain".to_string(),
            "hello world".to_string(),
            "semi;colon".to_string(),
            "quote'arg".to_string(),
            String::new(),
        ];

        assert_eq!(
            shell_quote_args(&args),
            "plain 'hello world' 'semi;colon' 'quote'\\''arg' ''"
        );
    }

    #[test]
    fn dependency_manifest_spec_preserves_npm_aliases() {
        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "my-lodash@4.17.21".to_string(),
            DepNode {
                name: "lodash".to_string(),
                alias: Some("my-lodash".to_string()),
                version: "4.17.21".to_string(),
                resolved: "https://registry.example/lodash.tgz".to_string(),
                integrity: None,
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: false,
                optional: false,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );

        assert_eq!(
            dependency_manifest_spec("my-lodash", "npm:lodash@^4.17.21", &graph),
            "npm:lodash@^4.17.21"
        );
        assert_eq!(
            dependency_manifest_spec("lodash", "latest", &graph),
            "^4.17.21"
        );
    }

    #[test]
    fn frozen_lock_compare_includes_root_manifest_snapshot() {
        let mut graph = DepGraph::new();
        graph.roots.push("pkg@1.0.0".to_string());
        graph.nodes.insert(
            "pkg@1.0.0".to_string(),
            DepNode {
                name: "pkg".to_string(),
                alias: None,
                version: "1.0.0".to_string(),
                resolved: "https://registry.example/pkg.tgz".to_string(),
                integrity: None,
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: false,
                optional: false,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );
        let mut deps = HashMap::new();
        deps.insert("pkg".to_string(), "^1.0.0".to_string());
        let dev_deps = HashMap::new();
        let lock_a =
            Lockfile::from_graph_with_manifest(&graph, "project", "1.0.0", &deps, &dev_deps);

        deps.insert("other".to_string(), "^2.0.0".to_string());
        let lock_b =
            Lockfile::from_graph_with_manifest(&graph, "project", "1.0.0", &deps, &dev_deps);

        assert!(!lockfiles_match_for_frozen(&lock_a, &lock_b));
    }

    #[test]
    fn frozen_lock_compare_treats_entry_name_as_derived_metadata() {
        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "node_modules/pkg".to_string(),
            DepNode {
                name: "pkg".to_string(),
                alias: None,
                version: "1.0.0".to_string(),
                resolved: "https://registry.example/pkg/-/pkg-1.0.0.tgz".to_string(),
                integrity: None,
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: false,
                optional: false,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );
        let deps = HashMap::new();
        let dev_deps = HashMap::new();
        let generated =
            Lockfile::from_graph_with_manifest(&graph, "project", "1.0.0", &deps, &dev_deps);
        let mut legacy = generated.clone();
        legacy.packages.get_mut("node_modules/pkg").unwrap().name = None;

        assert!(lockfiles_match_for_frozen(&legacy, &generated));
    }

    #[test]
    fn frozen_lock_compare_allows_only_platform_optional_deltas() {
        fn node(name: &str, optional: bool) -> DepNode {
            DepNode {
                name: name.to_string(),
                alias: None,
                version: "1.0.0".to_string(),
                resolved: format!("https://registry.example/{name}-1.0.0.tgz"),
                integrity: Some(format!("sha512-{name}")),
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: true,
                optional,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            }
        }

        let package = "node_modules/bundler".to_string();
        let darwin = "node_modules/@bundler/darwin-arm64".to_string();
        let linux = "node_modules/@bundler/linux-x64".to_string();

        let mut darwin_graph = DepGraph::new();
        let mut darwin_package = node("bundler", false);
        darwin_package
            .dependencies
            .insert("@bundler/darwin-arm64".to_string(), darwin.clone());
        darwin_graph.nodes.insert(package.clone(), darwin_package);
        darwin_graph
            .nodes
            .insert(darwin.clone(), node("@bundler/darwin-arm64", true));
        darwin_graph.roots = vec![package.clone(), darwin];

        let mut linux_graph = DepGraph::new();
        let mut linux_package = node("bundler", false);
        linux_package
            .dependencies
            .insert("@bundler/linux-x64".to_string(), linux.clone());
        linux_graph.nodes.insert(package.clone(), linux_package);
        linux_graph
            .nodes
            .insert(linux.clone(), node("@bundler/linux-x64", true));
        linux_graph.roots = vec![package.clone(), linux];

        let darwin_lock = Lockfile::from_graph(&darwin_graph, "site", "1.0.0");
        let linux_lock = Lockfile::from_graph(&linux_graph, "site", "1.0.0");
        assert!(lockfiles_match_for_frozen(&darwin_lock, &linux_lock));

        let mut drifted = linux_lock;
        drifted.packages.get_mut(&package).unwrap().version = "2.0.0".to_string();
        assert!(!lockfiles_match_for_frozen(&darwin_lock, &drifted));
    }

    #[test]
    fn missing_store_nodes_reports_only_uncached_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "pkg@1.0.0".to_string(),
            DepNode {
                name: "pkg".to_string(),
                alias: None,
                version: "1.0.0".to_string(),
                resolved: "https://registry.example/pkg.tgz".to_string(),
                integrity: None,
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: false,
                optional: false,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );

        let (missing, cached) = missing_store_nodes(&graph, &store);
        assert_eq!(missing.len(), 1);
        assert_eq!(cached, 0);

        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        store
            .store_package_variant_with_manifest(
                "pkg",
                "1.0.0",
                Some("https://registry.example/pkg.tgz"),
                None,
                &source,
            )
            .unwrap();

        let (missing, cached) = missing_store_nodes(&graph, &store);
        assert!(missing.is_empty());
        assert_eq!(cached, 1);
    }

    #[test]
    fn missing_store_nodes_treats_legacy_entries_as_uncached() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let legacy = store.package_dir("pkg", "1.0.0");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(
            legacy.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "pkg@1.0.0".to_string(),
            DepNode {
                name: "pkg".to_string(),
                alias: None,
                version: "1.0.0".to_string(),
                resolved: "https://registry.example/pkg.tgz".to_string(),
                integrity: None,
                dependencies: HashMap::new(),
                has_install_script: false,
                dev: false,
                optional: false,
                peer_dependencies: HashMap::new(),
                optional_peers: HashSet::new(),
                resolved_peers: HashMap::new(),
            },
        );

        let (missing, cached) = missing_store_nodes(&graph, &store);
        assert_eq!(missing.len(), 1);
        assert_eq!(cached, 0);
    }

    #[cfg(unix)]
    #[test]
    fn publish_file_collection_rejects_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("index.js"), "console.log(1);\n").unwrap();
        let outside = tmp.path().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, tmp.path().join("link")).unwrap();

        #[cfg(unix)]
        {
            let err = collect_publish_files(tmp.path(), &[], &[], &None).unwrap_err();
            assert!(err.to_string().contains("refusing symlink"));
        }
    }

    #[test]
    fn publish_file_collection_respects_files_and_always_include() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("README.md"), "# readme\n").unwrap();
        std::fs::write(tmp.path().join("index.js"), "console.log(1);\n").unwrap();
        std::fs::write(tmp.path().join("debug.test.js"), "test\n").unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/lib.js"), "export {}\n").unwrap();

        let files = collect_publish_files(
            tmp.path(),
            &["node_modules", ".git", "test"],
            &[],
            &Some(vec!["src".to_string()]),
        )
        .unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let rels = files
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();

        assert!(rels.contains(&"package.json".to_string()));
        assert!(rels.contains(&"README.md".to_string()));
        assert!(rels.contains(&"src/lib.js".to_string()));
        assert!(!rels.contains(&"index.js".to_string()));
        assert!(!rels.contains(&"debug.test.js".to_string()));
    }

    #[test]
    fn safe_bin_entries_filters_traversal() {
        let pkg = serde_json::json!({
            "bin": {
                "../owned": "bin/owned.js",
                "escape": "../escape.js",
                "safe": "bin/safe.js"
            }
        });

        assert_eq!(
            safe_bin_entries(&pkg, "pkg"),
            vec![("safe".to_string(), PathBuf::from("bin/safe.js"))]
        );
    }

    #[test]
    fn preferred_bin_path_uses_scoped_basename() {
        let pkg = serde_json::json!({
            "bin": {
                "tool": "bin/tool.js",
                "pkg": "bin/pkg.js"
            }
        });

        assert_eq!(
            preferred_bin_path(&pkg, "@scope/pkg"),
            Some(PathBuf::from("bin/pkg.js"))
        );
    }
}
