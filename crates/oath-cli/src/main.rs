use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::io::Write;
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
use oath_resolve::placement::{
    ArboristPlanner, PlacementPlan, PlacementRequest, pinned_npm_cli_path,
};
use oath_resolve::resolver::{ResolveOptions, Resolver};
use oath_resolve::{DepGraph, Lockfile};
use oath_store::cas::{ContentStore, PackageVerification};
use oath_store::linker::Linker;
use oath_workspace::{WorkspaceRoot, detect_workspace_root};

mod approvals;
mod capabilities;
mod evidence;
mod exec_assessment;
mod install_state;
mod install_timing;
mod package_transfer;
mod prompts;
mod publish_assessment;

fn platform_symlink_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    oath_resolve::placement::link_package_binary(target, link)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(unix)]
fn platform_symlink_dir(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn platform_symlink_dir(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ExecSandboxMode {
    Off,
    Node,
    Native,
    Auto,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum LoginAuthType {
    Web,
    Legacy,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
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

#[derive(Subcommand)]
enum EvidenceAction {
    /// Validate bundle digests, commit identity, freshness, and detached signatures.
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Re-run deterministic verification and report environment differences.
    Replay {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CacheAction {
    /// Add a package tarball to Oath's verified content store.
    Add { package: String },
    /// List cached package versions.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Remove all cached package versions. npm requires --force for this action.
    Clean {
        #[arg(long)]
        force: bool,
    },
    /// Cryptographically verify every lockfile entry in the content store.
    Verify,
    /// Inspect or remove CAS-backed metadata for prior npx-style executions.
    Npx {
        #[command(subcommand)]
        action: NpxCacheAction,
    },
}

#[derive(Subcommand)]
enum NpxCacheAction {
    /// List cached execution records.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Remove one cached execution record by key.
    Rm { key: String },
    /// Show one cached execution record by key.
    Info {
        key: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PkgAction {
    /// Read one or more package.json property paths.
    Get { keys: Vec<String> },
    /// Set package.json properties from key=value assignments.
    Set {
        assignments: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Delete package.json property paths.
    Delete { keys: Vec<String> },
    /// Normalize known-correctable package.json fields.
    Fix,
}

#[derive(Subcommand)]
enum DistTagAction {
    /// Add or move a distribution tag.
    Add {
        package: String,
        #[arg(default_value = "latest")]
        tag: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a distribution tag.
    #[command(visible_alias = "remove")]
    Rm {
        package: String,
        tag: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List distribution tags.
    #[command(visible_alias = "list")]
    Ls {
        package: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// List authentication tokens visible to the current identity.
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Create a new registry authentication token.
    Create {
        #[arg(long)]
        read_only: bool,
        #[arg(long = "cidr", action = clap::ArgAction::Append)]
        cidr: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        /// Read the account password from stdin; otherwise NPM_PASSWORD is required.
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Revoke a token by key, id, or token value.
    #[command(visible_aliases = ["rm", "delete"])]
    Revoke {
        token: String,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum AccessAction {
    /// Set a package to public visibility.
    Public {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Set a package to restricted visibility.
    Restricted {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Grant read-only or read-write package access to a team.
    Grant {
        permission: String,
        team: String,
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Revoke a team's package access.
    Revoke {
        team: String,
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List packages available to a team.
    ListPackages {
        team: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List package collaborators and permissions.
    ListCollaborators {
        package: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum OrgAction {
    #[command(visible_alias = "add")]
    Set {
        org: String,
        user: String,
        #[arg(default_value = "developer")]
        role: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(visible_alias = "remove")]
    Rm {
        org: String,
        user: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(visible_alias = "list")]
    Ls {
        org: String,
        user: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum OwnerAction {
    Add {
        user: String,
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(visible_alias = "remove")]
    Rm {
        user: String,
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(visible_alias = "list")]
    Ls {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    Get {
        keys: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    Set {
        key: String,
        value: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(name = "enable-2fa", visible_alias = "enable2fa")]
    Enable2fa {
        #[arg(default_value = "auth-and-writes")]
        mode: String,
        #[arg(long)]
        registry: Option<String>,
        /// Read the account password from stdin instead of a protected terminal prompt.
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        otp: Option<String>,
    },
    #[command(name = "disable-2fa", visible_alias = "disable2fa")]
    Disable2fa {
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        otp: Option<String>,
    },
}

#[derive(Subcommand)]
enum TeamAction {
    Create {
        team: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    Destroy {
        team: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    Add {
        team: String,
        user: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    Rm {
        team: String,
        user: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    #[command(visible_alias = "list")]
    Ls {
        entity: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Trust a GitHub Actions workflow as an OIDC publisher.
    Github {
        package: Option<String>,
        #[arg(long)]
        file: String,
        #[arg(long, alias = "repo")]
        repository: String,
        #[arg(long, alias = "env")]
        environment: Option<String>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Trust a GitLab CI/CD pipeline as an OIDC publisher.
    Gitlab {
        package: Option<String>,
        #[arg(long)]
        file: String,
        #[arg(long, aliases = ["repo", "repository"])]
        project: String,
        #[arg(long, alias = "env")]
        environment: Option<String>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Trust a CircleCI pipeline as an OIDC publisher.
    Circleci {
        package: Option<String>,
        #[arg(long)]
        org_id: String,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        pipeline_definition_id: String,
        #[arg(long)]
        vcs_origin: String,
        #[arg(long, action = clap::ArgAction::Append)]
        context_id: Vec<String>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List trusted OIDC publisher relationships.
    List {
        package: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Revoke a trusted OIDC publisher relationship.
    Revoke {
        package: Option<String>,
        #[arg(long)]
        id: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
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

#[derive(Args, Clone, Debug, Default)]
struct WorkspaceArgs {
    /// Run in a workspace selected by package name, directory, or parent directory.
    #[arg(short = 'w', long = "workspace", action = clap::ArgAction::Append)]
    workspace: Vec<String>,
    /// Run in every configured workspace.
    #[arg(long)]
    workspaces: bool,
    /// Include the workspace root when a workspace filter is active.
    #[arg(long)]
    include_workspace_root: bool,
}

impl WorkspaceArgs {
    fn active(&self) -> bool {
        self.workspaces || !self.workspace.is_empty()
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Install dependencies from package.json
    #[command(visible_alias = "i")]
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
        /// Omit dependency types from physical installation while retaining lock metadata.
        #[arg(long = "omit", action = clap::ArgAction::Append)]
        omit: Vec<String>,
        /// Omit development dependencies from physical installation.
        #[arg(long)]
        production: bool,
        /// Resolve and update the lockfile without downloading or linking packages.
        #[arg(long = "package-lock-only", alias = "lockfile-only")]
        lockfile_only: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Clean install from the lockfile (like `npm ci`): fail if it is missing or would change
    Ci {
        #[arg(long = "omit", action = clap::ArgAction::Append)]
        omit: Vec<String>,
        #[arg(long)]
        production: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Add a dependency
    Add {
        packages: Vec<String>,
        #[arg(short = 'D', long, conflicts_with_all = ["optional", "peer"])]
        dev: bool,
        #[arg(short = 'O', long = "save-optional", conflicts_with_all = ["dev", "peer"])]
        optional: bool,
        #[arg(long = "save-peer", conflicts_with_all = ["dev", "optional"])]
        peer: bool,
        #[arg(short = 'E', long = "save-exact")]
        exact: bool,
        #[arg(short = 'y', long)]
        yes: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Update dependencies within package.json ranges
    Update {
        packages: Vec<String>,
        #[arg(short = 'g', long)]
        global: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Remove a dependency
    #[command(visible_aliases = ["uninstall", "rm"])]
    Remove {
        packages: Vec<String>,
        #[arg(short = 'g', long)]
        global: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run a script defined in package.json
    Run {
        script: Option<String>,
        #[arg(long)]
        if_present: bool,
        #[arg(long)]
        ignore_scripts: bool,
        args: Vec<String>,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run the package test lifecycle.
    Test {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run the package start lifecycle.
    Start {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run the package stop lifecycle if present.
    Stop {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run restart, or stop followed by start when no restart script exists.
    Restart {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Install dependencies and run the test lifecycle.
    InstallTest {
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Clean-install dependencies and run the test lifecycle.
    InstallCiTest {
        args: Vec<String>,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Execute a package binary (like npx, but scanned first)
    #[command(visible_aliases = ["x", "npx"])]
    Exec {
        /// Package to execute, or the command name when --package is present.
        package: Option<String>,
        /// Package(s) to install into the temporary execution environment.
        #[arg(short = 'p', long = "package", action = clap::ArgAction::Append)]
        packages: Vec<String>,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Run a shell command inside the temporary execution environment.
        #[arg(short = 'c', long = "call")]
        call: Option<String>,
        /// Skip the risk prompt and run without asking (like npm's --yes)
        #[arg(short = 'y', long, conflicts_with = "no")]
        yes: bool,
        /// Refuse to download a package that is not already installed locally.
        #[arg(long, conflicts_with = "yes")]
        no: bool,
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
        /// Sandbox mode to use: node, native, or auto. Off requires --allow-uncontained.
        #[arg(long, value_enum, default_value_t = ExecSandboxMode::Auto)]
        sandbox_mode: ExecSandboxMode,
        /// Compatibility opt-out: permit execution without audited containment.
        #[arg(long)]
        allow_uncontained: bool,
        /// Deny outbound network access in the selected sandbox.
        #[arg(long)]
        deny_network: bool,
        /// Permit the weaker Node permission sandbox when native containment is unavailable.
        #[arg(long)]
        allow_degraded_sandbox: bool,
        /// Persist an approval bound to this exact integrity, capability set, and sandbox policy.
        #[arg(long)]
        remember: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Scan installed packages for malicious behavior (behavioral analysis, not a CVE audit)
    Scan {
        #[arg(long)]
        production: bool,
        /// Show all findings, not just high/critical
        #[arg(long)]
        verbose: bool,
    },
    /// Check the locked dependency graph against npm-compatible CVE advisories.
    Audit {
        /// npm-compatible audit workflow, currently `signatures`.
        mode: Option<String>,
        #[arg(long)]
        production: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "low")]
        audit_level: String,
        /// Apply non-breaking dependency updates and verify the result.
        #[arg(long)]
        fix: bool,
        /// Report remediation without changing the dependency tree.
        #[arg(long, requires = "fix")]
        dry_run: bool,
    },
    /// Emit a CycloneDX or SPDX software bill of materials from oath-lock.json.
    Sbom {
        #[arg(long, default_value = "cyclonedx")]
        sbom_format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show what a package can access (permissions/capabilities)
    Perms { package: String },
    /// Initialize a project or execute a create-* initializer package.
    Init {
        initializer: Option<String>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        private: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Explain why a package is in the dependency tree
    #[command(name = "explain", visible_alias = "why")]
    Explain {
        package: String,
        #[arg(long)]
        json: bool,
    },
    /// List licenses of all installed packages
    Licenses,
    /// Verify integrity of oath-lock.json against the store
    Verify,
    /// Print an ASCII dependency graph
    #[command(visible_aliases = ["ls", "list"])]
    Graph {
        /// Maximum depth to display (default: 3)
        #[arg(long, default_value = "3")]
        depth: usize,
        /// Include the complete dependency tree.
        #[arg(long)]
        all: bool,
        /// Emit npm-compatible JSON dependency metadata.
        #[arg(long)]
        json: bool,
        /// Omit dependency types such as dev.
        #[arg(long = "omit", action = clap::ArgAction::Append)]
        omit: Vec<String>,
        /// Omit development dependencies.
        #[arg(long)]
        production: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Show safety score and metadata for a package
    Score { package: String },
    /// Show info about a package (author, downloads, publish date)
    #[command(visible_alias = "view")]
    Info {
        package: Option<String>,
        fields: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Create the npm-compatible package tarball for the current project.
    Pack {
        /// Report the tarball without writing it.
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable package and digest metadata.
        #[arg(long)]
        json: bool,
        /// Directory in which to write the tarball.
        #[arg(long, default_value = ".")]
        destination: PathBuf,
        /// Skip prepack, prepare, and postpack lifecycle hooks.
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Report direct dependencies whose installed or allowed versions are behind.
    Outdated {
        /// Emit a stable JSON report. Returns exit code 1 when updates exist.
        #[arg(long)]
        json: bool,
        /// Inspect packages installed in Oath's global prefix.
        #[arg(short = 'g', long)]
        global: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Inspect effective npm-compatible registry configuration without exposing tokens.
    Config {
        /// npm-compatible action and operands: get, set, delete, list.
        args: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, value_parser = ["user", "project", "global"])]
        location: Option<String>,
        #[arg(short = 'g', long)]
        global: bool,
    },
    /// Report the authenticated npm registry identity.
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// Store and verify a registry authentication token.
    #[command(visible_alias = "adduser")]
    Login {
        /// Registry to authenticate against.
        #[arg(long)]
        registry: Option<String>,
        /// Associate this registry with an npm scope such as @mycorp.
        #[arg(long)]
        scope: Option<String>,
        /// Read the token from standard input. Otherwise NPM_TOKEN is required.
        #[arg(long)]
        token_stdin: bool,
        /// npm-compatible interactive authentication strategy.
        #[arg(long, value_enum, default_value_t = LoginAuthType::Web)]
        auth_type: LoginAuthType,
        #[arg(long)]
        otp: Option<String>,
        /// Username for legacy authentication (otherwise prompted).
        #[arg(long)]
        username: Option<String>,
        /// Read the legacy account password from stdin.
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove locally stored registry credentials.
    Logout {
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Create or consume npm-compatible global development links.
    Link {
        packages: Vec<String>,
        /// Persist linked packages as file: dependencies.
        #[arg(long)]
        save: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Remove local development links without deleting their targets.
    Unlink {
        packages: Vec<String>,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Inspect and verify Oath's content cache.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Recompute and materialize npm's deduplicated ideal dependency tree.
    Dedupe {
        #[arg(long)]
        dry_run: bool,
        /// Prefer reusing a compatible version already present in the tree.
        #[arg(long)]
        prefer_dedupe: bool,
    },
    /// Remove packages not present in the manifest's ideal dependency tree.
    Prune {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        ignore_scripts: bool,
        #[arg(long = "omit", action = clap::ArgAction::Append)]
        omit: Vec<String>,
        #[arg(long)]
        production: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Re-run dependency lifecycle scripts inside verified native containment.
    Rebuild {
        packages: Vec<String>,
        /// Select packages but do not execute lifecycle scripts.
        #[arg(long)]
        ignore_scripts: bool,
        #[arg(short = 'g', long)]
        global: bool,
        #[arg(long = "no-bin-links")]
        no_bin_links: bool,
        #[arg(long)]
        foreground_scripts: bool,
        #[arg(long = "allow-scripts", value_delimiter = ',', action = clap::ArgAction::Append)]
        allow_scripts: Vec<String>,
        #[arg(long)]
        strict_allow_scripts: bool,
        #[arg(long)]
        dangerously_allow_all_scripts: bool,
        #[arg(long)]
        install_links: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Read and update package.json properties.
    Pkg {
        #[command(subcommand)]
        action: PkgAction,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Select installed dependencies using npm query selector forms.
    Query {
        selector: String,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Show or change package versions using npm-compatible bump names.
    Version {
        newversion: Option<String>,
        #[arg(long)]
        preid: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_same_version: bool,
        #[arg(long)]
        no_git_tag_version: bool,
        #[arg(long)]
        ignore_scripts: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Display funding information declared by installed packages.
    Fund {
        package: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        which: Option<usize>,
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        browser: Option<String>,
        #[arg(long)]
        no_browser: bool,
    },
    /// Diagnose the local toolchain, project, store, and registry connection.
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Create npm-shrinkwrap.json from the npm or Oath lockfile.
    Shrinkwrap,
    /// Compare packed package contents between local directories or registry specs.
    Diff {
        #[arg(long = "diff", action = clap::ArgAction::Append)]
        diffs: Vec<String>,
        #[arg(long)]
        diff_name_only: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Add, remove, or list registry distribution tags.
    DistTag {
        #[command(subcommand)]
        action: DistTagAction,
    },
    /// Mark a package version range as deprecated.
    Deprecate {
        package: String,
        message: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Clear deprecation metadata for a package version range.
    Undeprecate {
        package: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a published package version or package from the registry.
    Unpublish {
        package: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List, create, or revoke registry authentication tokens.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Manage registry package visibility and team permissions.
    Access {
        #[command(subcommand)]
        action: AccessAction,
    },
    /// Manage organization memberships.
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Manage package owners.
    Owner {
        #[command(subcommand)]
        action: OwnerAction,
    },
    /// Read or update the authenticated registry profile.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage organization teams and memberships.
    Team {
        #[command(subcommand)]
        action: TeamAction,
    },
    /// Mark packages as favorites.
    Star {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// List packages marked as favorites by a user.
    Stars {
        user: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove packages from the authenticated user's favorites.
    Unstar {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Manage trusted OIDC publishing relationships.
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Allow selected dependencies to run contained lifecycle scripts.
    ApproveScripts {
        packages: Vec<String>,
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Persistently deny lifecycle scripts for selected dependencies.
    DenyScripts {
        packages: Vec<String>,
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run approved dependency lifecycle scripts through verified containment.
    InstallScripts {
        packages: Vec<String>,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Print the effective node_modules directory.
    Root {
        #[arg(short = 'g', long)]
        global: bool,
    },
    /// Print the effective project or global prefix.
    Prefix {
        #[arg(short = 'g', long)]
        global: bool,
    },
    /// Test registry reachability and authentication transport.
    Ping {
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Search registry package metadata.
    Search {
        terms: Vec<String>,
        #[arg(long, default_value_t = 20)]
        searchlimit: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Open a package's issue tracker.
    Bugs {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Open a package's documentation or homepage.
    Docs {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Open a package's source repository.
    Repo {
        package: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Open an installed package in the configured editor.
    Edit { package: String },
    /// Run a command in an installed package directory.
    Explore {
        package: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Generate shell completion definitions.
    Completion {
        #[arg(value_enum)]
        shell: Option<CompletionShell>,
    },
    /// Search Oath's command help locally.
    HelpSearch { terms: Vec<String> },
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
        /// One-time password for registries that require two-factor authentication.
        #[arg(long)]
        otp: Option<String>,
        /// Generate Sigstore provenance using the CI workload's OIDC identity.
        #[arg(long, conflicts_with = "provenance_file")]
        provenance: bool,
        /// Verify and attach an existing Sigstore provenance bundle.
        #[arg(long, conflicts_with = "provenance")]
        provenance_file: Option<PathBuf>,
        #[command(flatten)]
        workspace: WorkspaceArgs,
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
    /// Verify or replay exact-commit release evidence.
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    /// Report npm compatibility, containment, signing, and evidence capabilities.
    Capabilities {
        /// Emit the stable machine-readable capability report.
        #[arg(long)]
        json: bool,
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
            mut omit,
            production,
            lockfile_only,
            workspace,
        } => {
            if production {
                omit.push("dev".to_owned());
            }
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
                false,
                lockfile_only,
                omit.to_vec(),
                workspace,
                None,
            )
            .await?;
        }
        Commands::Add {
            packages,
            dev,
            optional,
            peer,
            exact,
            yes,
            workspace,
        } => {
            cmd_add_scoped(packages, dev, optional, peer, exact, yes, workspace).await?;
        }
        Commands::Update {
            packages,
            global,
            workspace,
        } => {
            anyhow::ensure!(
                !(global && workspace.active()),
                "--global cannot be combined with workspace filters"
            );
            if global {
                cmd_update_global(packages).await?;
            } else {
                cmd_update_scoped(packages, workspace).await?;
            }
        }
        Commands::Run {
            script,
            if_present,
            ignore_scripts,
            args,
            workspace,
        } => {
            cmd_run_scoped(
                script.as_deref(),
                &args,
                if_present,
                ignore_scripts,
                &workspace,
            )?;
        }
        Commands::Test {
            args,
            ignore_scripts,
            workspace,
        } => cmd_run_scoped(Some("test"), &args, false, ignore_scripts, &workspace)?,
        Commands::Start {
            args,
            ignore_scripts,
            workspace,
        } => cmd_run_scoped(Some("start"), &args, false, ignore_scripts, &workspace)?,
        Commands::Stop {
            args,
            ignore_scripts,
            workspace,
        } => cmd_run_scoped(Some("stop"), &args, true, ignore_scripts, &workspace)?,
        Commands::Restart {
            args,
            ignore_scripts,
            workspace,
        } => cmd_restart_scoped(&args, ignore_scripts, &workspace)?,
        Commands::InstallTest {
            args,
            ignore_scripts,
            workspace,
        } => {
            cmd_install(
                args,
                false,
                false,
                true,
                false,
                false,
                ignore_scripts,
                false,
                false,
                None,
                true,
                false,
                Vec::new(),
                workspace.clone(),
                None,
            )
            .await?;
            cmd_run_scoped(Some("test"), &[], false, ignore_scripts, &workspace)?;
        }
        Commands::InstallCiTest {
            args,
            ignore_scripts,
            workspace,
        } => {
            cmd_ci_scoped(workspace.clone(), Vec::new()).await?;
            let _ = args;
            cmd_run_scoped(Some("test"), &[], false, ignore_scripts, &workspace)?;
        }
        Commands::Init {
            initializer,
            yes,
            scope,
            private,
            workspace,
        } => {
            if let Some(initializer) = initializer {
                let package = initializer_package_spec(&initializer)?;
                println!(
                    "oath: fetching initializer package {package} for assessment; \
                     execution requires approval (use --yes to skip the prompt)"
                );
                cmd_exec_scoped(
                    Some(&package),
                    &[],
                    &[],
                    None,
                    yes,
                    false,
                    None,
                    false,
                    3,
                    None,
                    false,
                    false,
                    ExecSandboxMode::Auto,
                    false,
                    false,
                    false,
                    false,
                    &workspace,
                )
                .await?;
            } else {
                cmd_init_scoped(yes, scope.as_deref(), private, &workspace)?;
            }
        }
        Commands::Scan {
            production,
            verbose,
        } => {
            cmd_scan(production, verbose).await?;
        }
        Commands::Audit {
            mode,
            production,
            json,
            audit_level,
            fix,
            dry_run,
        } => {
            if mode.as_deref() == Some("signatures") {
                anyhow::ensure!(!fix, "audit signatures cannot be combined with --fix");
                cmd_audit_signatures(json)?;
            } else {
                anyhow::ensure!(mode.is_none(), "unsupported audit workflow");
                let vulnerable = cmd_audit(production, json, &audit_level).await?;
                if fix && vulnerable && !dry_run {
                    cmd_update(Vec::new()).await?;
                    if cmd_audit(production, json, &audit_level).await? {
                        std::process::exit(1);
                    }
                } else if vulnerable {
                    std::process::exit(1);
                }
            }
        }
        Commands::Sbom {
            sbom_format,
            output,
        } => {
            cmd_sbom(&sbom_format, output.as_deref())?;
        }
        Commands::Ci {
            mut omit,
            production,
            workspace,
        } => {
            if production {
                omit.push("dev".to_owned());
            }
            cmd_ci_scoped(workspace, omit).await?;
        }
        Commands::Perms { package } => {
            cmd_perms(&package)?;
        }
        Commands::Explain { package, json } => {
            cmd_why(&package, json)?;
        }
        Commands::Licenses => {
            cmd_licenses()?;
        }
        Commands::Verify => {
            cmd_verify()?;
        }
        Commands::Graph {
            depth,
            all,
            json,
            omit,
            production,
            workspace,
        } => {
            cmd_ls_scoped(
                if all { usize::MAX } else { depth },
                json,
                production || omit.iter().any(|value| value == "dev"),
                &workspace,
            )?;
        }
        Commands::Exec {
            package,
            packages,
            args,
            call,
            yes,
            no,
            min_age,
            json,
            schema_version,
            require_grade,
            dry_run,
            sandbox,
            sandbox_mode,
            allow_uncontained,
            deny_network,
            allow_degraded_sandbox,
            remember,
            workspace,
        } => {
            cmd_exec_scoped(
                package.as_deref(),
                &packages,
                &args,
                call.as_deref(),
                yes,
                no,
                min_age.as_deref(),
                json,
                schema_version,
                require_grade.as_deref(),
                dry_run,
                sandbox,
                sandbox_mode,
                allow_uncontained,
                deny_network,
                allow_degraded_sandbox,
                remember,
                &workspace,
            )
            .await?;
        }
        Commands::Score { package } => {
            cmd_score(&package).await?;
        }
        Commands::Info {
            package,
            fields,
            json,
        } => {
            cmd_view(package.as_deref(), &fields, json).await?;
        }
        Commands::Pack {
            dry_run,
            json,
            destination,
            ignore_scripts,
            workspace,
        } => {
            cmd_pack_scoped(&destination, dry_run, json, ignore_scripts, &workspace)?;
        }
        Commands::Outdated {
            json,
            global,
            workspace,
        } => {
            if cmd_outdated_scoped(json, global, &workspace).await? {
                std::process::exit(1);
            }
        }
        Commands::Config {
            args,
            json,
            location,
            global,
        } => {
            cmd_config(&args, json, location.as_deref(), global)?;
        }
        Commands::Whoami { json } => {
            cmd_whoami(json).await?;
        }
        Commands::Login {
            registry,
            scope,
            token_stdin,
            auth_type,
            otp,
            username,
            password_stdin,
            json,
        } => {
            cmd_login(
                registry.as_deref(),
                scope.as_deref(),
                token_stdin,
                auth_type,
                otp.as_deref(),
                username.as_deref(),
                password_stdin,
                json,
            )
            .await?;
        }
        Commands::Logout {
            registry,
            scope,
            json,
        } => {
            cmd_logout(registry.as_deref(), scope.as_deref(), json).await?;
        }
        Commands::Link {
            packages,
            save,
            workspace,
        } => {
            cmd_link_scoped(packages, save, &workspace)?;
        }
        Commands::Unlink {
            packages,
            workspace,
        } => {
            cmd_unlink_scoped(packages, &workspace)?;
        }
        Commands::Cache { action } => match action {
            CacheAction::Add { package } => cmd_cache_add(&package).await?,
            CacheAction::Ls { json } => cmd_cache_ls(json)?,
            CacheAction::Clean { force } => cmd_cache_clean(force)?,
            CacheAction::Verify => cmd_verify()?,
            CacheAction::Npx { action } => cmd_cache_npx(action)?,
        },
        Commands::Dedupe {
            dry_run,
            prefer_dedupe,
        } => {
            cmd_dedupe(dry_run, prefer_dedupe).await?;
        }
        Commands::Prune {
            packages,
            dry_run,
            ignore_scripts,
            omit,
            production,
            workspace,
        } => {
            cmd_prune(
                &packages,
                dry_run,
                ignore_scripts,
                &omit,
                production,
                &workspace,
            )?;
        }
        Commands::Rebuild {
            packages,
            ignore_scripts,
            global,
            no_bin_links,
            foreground_scripts,
            allow_scripts,
            strict_allow_scripts,
            dangerously_allow_all_scripts,
            install_links,
            workspace,
        } => {
            cmd_rebuild(
                &packages,
                ignore_scripts,
                global,
                no_bin_links,
                foreground_scripts,
                &allow_scripts,
                strict_allow_scripts,
                dangerously_allow_all_scripts,
                install_links,
                &workspace,
            )?;
        }
        Commands::Pkg { action, workspace } => {
            cmd_pkg(action, &workspace)?;
        }
        Commands::Query {
            selector,
            workspace,
        } => {
            cmd_query(&selector, &workspace)?;
        }
        Commands::Version {
            newversion,
            preid,
            json,
            allow_same_version,
            no_git_tag_version,
            ignore_scripts,
            workspace,
        } => {
            cmd_version(
                newversion.as_deref(),
                preid.as_deref(),
                json,
                allow_same_version,
                no_git_tag_version,
                ignore_scripts,
                &workspace,
            )?;
        }
        Commands::Fund {
            package,
            json,
            which,
            browser,
            no_browser,
        } => {
            cmd_fund(
                package.as_deref(),
                json,
                which,
                browser.as_deref(),
                no_browser,
            )?;
        }
        Commands::Doctor { json, registry } => {
            if !cmd_doctor(json, registry.as_deref()).await? {
                std::process::exit(1);
            }
        }
        Commands::Shrinkwrap => {
            cmd_shrinkwrap()?;
        }
        Commands::Diff {
            diffs,
            diff_name_only,
            json,
            registry,
        } => {
            cmd_diff(&diffs, diff_name_only, json, registry.as_deref()).await?;
        }
        Commands::DistTag { action } => {
            cmd_dist_tag(action).await?;
        }
        Commands::Deprecate {
            package,
            message,
            registry,
        } => {
            cmd_deprecate(&package, &message, registry.as_deref()).await?;
        }
        Commands::Undeprecate { package, registry } => {
            cmd_deprecate(&package, "", registry.as_deref()).await?;
        }
        Commands::Unpublish {
            package,
            force,
            dry_run,
            registry,
        } => {
            cmd_unpublish(package.as_deref(), force, dry_run, registry.as_deref()).await?;
        }
        Commands::Root { global } => cmd_root(global)?,
        Commands::Prefix { global } => cmd_prefix(global)?,
        Commands::Ping { registry, json } => {
            cmd_ping(registry.as_deref(), json).await?;
        }
        Commands::Search {
            terms,
            searchlimit,
            json,
            registry,
        } => {
            cmd_search(&terms, searchlimit, json, registry.as_deref()).await?;
        }
        Commands::Bugs { package, registry } => {
            cmd_package_page(PackagePage::Bugs, package.as_deref(), registry.as_deref()).await?;
        }
        Commands::Docs { package, registry } => {
            cmd_package_page(PackagePage::Docs, package.as_deref(), registry.as_deref()).await?;
        }
        Commands::Repo { package, registry } => {
            cmd_package_page(PackagePage::Repo, package.as_deref(), registry.as_deref()).await?;
        }
        Commands::Edit { package } => cmd_edit(&package)?,
        Commands::Explore { package, command } => cmd_explore(&package, &command)?,
        Commands::Completion { shell } => cmd_completion(shell)?,
        Commands::HelpSearch { terms } => cmd_help_search(&terms)?,
        Commands::Publish {
            tag,
            access,
            dry_run,
            json,
            schema_version,
            stage,
            otp,
            provenance,
            provenance_file,
            workspace,
        } => {
            cmd_publish_scoped(
                tag.as_deref(),
                access.as_deref(),
                dry_run,
                json,
                schema_version,
                stage,
                otp.as_deref(),
                provenance,
                provenance_file.as_deref(),
                &workspace,
            )
            .await?;
        }
        Commands::Token { action } => {
            cmd_token(action).await?;
        }
        Commands::Access { action } => {
            cmd_access(action).await?;
        }
        Commands::Org { action } => cmd_org(action).await?,
        Commands::Owner { action } => cmd_owner(action).await?,
        Commands::Profile { action } => cmd_profile(action).await?,
        Commands::Team { action } => cmd_team(action).await?,
        Commands::Star { packages, registry } => {
            cmd_star(&packages, true, registry.as_deref()).await?;
        }
        Commands::Stars { user, registry } => {
            cmd_stars(user.as_deref(), registry.as_deref()).await?;
        }
        Commands::Unstar { packages, registry } => {
            cmd_star(&packages, false, registry.as_deref()).await?;
        }
        Commands::Trust { action } => {
            cmd_trust(action).await?;
        }
        Commands::ApproveScripts {
            packages,
            all,
            workspace,
        } => {
            cmd_script_policy(&packages, all, true, &workspace)?;
        }
        Commands::DenyScripts {
            packages,
            all,
            workspace,
        } => {
            cmd_script_policy(&packages, all, false, &workspace)?;
        }
        Commands::InstallScripts {
            packages,
            workspace,
        } => {
            cmd_install_scripts(&packages, &workspace)?;
        }
        Commands::Stage { action } => {
            cmd_stage(action).await?;
        }
        Commands::Transfer { action } => {
            cmd_transfer(action)?;
        }
        Commands::Evidence { action } => {
            let (report, json) = match action {
                EvidenceAction::Verify { bundle, json } => {
                    (evidence::verify(&bundle, false)?, json)
                }
                EvidenceAction::Replay { bundle, json } => (evidence::verify(&bundle, true)?, json),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("evidence {}: valid", report.operation);
                println!("  commit: {}", report.source_commit);
                println!("  files: {}", report.files_verified);
                println!("  signatures: {}", report.signatures_verified);
                for difference in report.environment_differences {
                    println!("  environment difference: {difference}");
                }
            }
        }
        Commands::Capabilities { json } => {
            let report = capabilities::report()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Oath {} capabilities", report.version);
                println!("  platform: {}/{}", report.platform, report.architecture);
                println!(
                    "  npm/npx commands: {} complete, {} partial, {} missing ({} tracked)",
                    report.compatibility.command_counts.complete,
                    report.compatibility.command_counts.partial,
                    report.compatibility.command_counts.missing,
                    report.compatibility.command_counts.total,
                );
                println!(
                    "  npm/npx surfaces: {} complete, {} partial, {} missing; {} qualified",
                    report.compatibility.surface_counts.complete,
                    report.compatibility.surface_counts.partial,
                    report.compatibility.surface_counts.missing,
                    report.compatibility.surface_counts.qualified,
                );
                println!(
                    "  native containment: {} ({})",
                    report.containment.available, report.containment.backend
                );
                if !report.compatibility.missing_required_commands.is_empty() {
                    println!(
                        "  missing replacement commands: {}",
                        report.compatibility.missing_required_commands.join(", ")
                    );
                }
                if !report.compatibility.partial_required_commands.is_empty() {
                    println!(
                        "  partial replacement commands: {}",
                        report.compatibility.partial_required_commands.join(", ")
                    );
                }
            }
        }
        Commands::Log { tail } => {
            cmd_log(tail)?;
        }
        Commands::Remove {
            packages,
            global,
            workspace,
        } => {
            anyhow::ensure!(
                !(global && workspace.active()),
                "--global cannot be combined with workspace filters"
            );
            if global {
                cmd_remove_global(packages).await?;
            } else {
                cmd_remove_scoped(packages, workspace).await?;
            }
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

fn run_exec_call(
    call: &str,
    exec_path: &std::path::Path,
    sandbox_mode: ExecSandboxMode,
    sandbox_plan: Option<&oath_sandbox::SandboxPlan>,
) -> Result<std::process::ExitStatus> {
    anyhow::ensure!(
        sandbox_mode != ExecSandboxMode::Node,
        "--call requires native containment; Node permissions cannot contain a shell"
    );
    let bin_dir = exec_path.join("node_modules").join(".bin");

    #[cfg(windows)]
    let (shell, shell_args) = {
        let shell = std::env::var_os("COMSPEC")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows\\System32\\cmd.exe"));
        let command = format!("set \"PATH={};%PATH%\"&& {call}", bin_dir.display());
        (shell, vec!["/D".into(), "/S".into(), "/C".into(), command])
    };
    #[cfg(not(windows))]
    let (shell, shell_args) = {
        let command = format!(
            "PATH={}:$PATH; export PATH; {call}",
            shell_quote_arg(&bin_dir.to_string_lossy())
        );
        (PathBuf::from("/bin/sh"), vec!["-c".into(), command])
    };

    if sandbox_mode == ExecSandboxMode::Off {
        return std::process::Command::new(&shell)
            .args(&shell_args)
            .current_dir(exec_path)
            .status()
            .context("failed to execute compatibility shell command");
    }
    let plan = sandbox_plan.context("native --call requires a sandbox plan")?;
    #[cfg(target_os = "linux")]
    {
        oath_sandbox::linux::run(plan, &shell, &shell_args)
    }
    #[cfg(target_os = "macos")]
    {
        let mut plan = plan.clone();
        plan.read_only_paths.push(active_node_executable()?);
        oath_sandbox::macos::run(&plan, &shell, &shell_args)
    }
    #[cfg(target_os = "windows")]
    {
        oath_sandbox::windows::run(plan, &shell, &shell_args)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("native execution containment is unsupported on this platform")
    }
}

fn run_exec_interactive_shell(
    workdir: &std::path::Path,
    sandbox_mode: ExecSandboxMode,
) -> Result<std::process::ExitStatus> {
    anyhow::ensure!(
        sandbox_mode != ExecSandboxMode::Node,
        "interactive exec requires native containment; Node permissions cannot contain a shell"
    );
    let bin_dir = workdir.join("node_modules").join(".bin");

    #[cfg(windows)]
    let (shell, args) = {
        let shell = std::env::var_os("COMSPEC")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows\\System32\\cmd.exe"));
        (
            shell,
            vec![
                "/D".into(),
                "/S".into(),
                "/K".into(),
                format!("set \"PATH={};%PATH%\"", bin_dir.display()),
            ],
        )
    };
    #[cfg(not(windows))]
    let (shell, args) = {
        let interactive_shell = std::env::var_os("SHELL")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
            .unwrap_or_else(|| PathBuf::from("/bin/sh"));
        let command = format!(
            "PATH={}:$PATH; export PATH; exec {}",
            shell_quote_arg(&bin_dir.to_string_lossy()),
            shell_quote_arg(&interactive_shell.to_string_lossy())
        );
        (PathBuf::from("/bin/sh"), vec!["-c".into(), command])
    };

    if sandbox_mode == ExecSandboxMode::Off {
        return std::process::Command::new(&shell)
            .args(&args)
            .current_dir(workdir)
            .status()
            .context("failed to start interactive compatibility shell");
    }

    let plan = oath_sandbox::SandboxPlan::strict("interactive-exec", workdir.to_path_buf());
    #[cfg(target_os = "linux")]
    {
        oath_sandbox::linux::run(&plan, &shell, &args)
    }
    #[cfg(target_os = "macos")]
    {
        let mut plan = plan;
        plan.read_only_paths.push(active_node_executable()?);
        oath_sandbox::macos::run(&plan, &shell, &args)
    }
    #[cfg(target_os = "windows")]
    {
        oath_sandbox::windows::run(&plan, &shell, &args)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("native interactive containment is unsupported on this platform")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecInvocation {
    packages: Vec<String>,
    command: String,
    args: Vec<String>,
    call: Option<String>,
    explicit_packages: bool,
}

fn normalize_exec_invocation(
    positional: Option<&str>,
    packages: &[String],
    args: &[String],
    call: Option<&str>,
) -> Result<ExecInvocation> {
    anyhow::ensure!(
        positional.is_some() || call.is_some(),
        "interactive exec is not supported in non-interactive Oath; provide a command or --call"
    );
    anyhow::ensure!(
        !(call.is_some() && positional.is_some()),
        "--call cannot be combined with a positional command"
    );

    if packages.is_empty() {
        let package = positional.context("exec requires a package when --package is absent")?;
        let (name, _) = parse_package_spec(package);
        return Ok(ExecInvocation {
            packages: vec![package.to_string()],
            command: package_bin_basename(&name).to_string(),
            args: args.to_vec(),
            call: None,
            explicit_packages: false,
        });
    }

    let command = positional
        .map(String::from)
        .unwrap_or_else(|| package_bin_basename(&parse_package_spec(&packages[0]).0).to_string());
    anyhow::ensure!(
        is_safe_bin_name(&command),
        "exec command must be a package binary name when --package is used"
    );
    Ok(ExecInvocation {
        packages: packages.to_vec(),
        command,
        args: args.to_vec(),
        call: call.map(String::from),
        explicit_packages: true,
    })
}

fn normalize_omit_types(values: &[String]) -> Result<HashSet<String>> {
    let values = values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    anyhow::ensure!(
        values
            .iter()
            .all(|value| matches!(value.as_str(), "dev" | "optional" | "peer")),
        "--omit must be dev, optional, or peer"
    );
    Ok(values)
}

fn materialization_plan(plan: &PlacementPlan, omit: &HashSet<String>) -> PlacementPlan {
    let mut filtered = plan.clone();
    let omitted = filtered
        .nodes
        .iter()
        .filter(|node| {
            (omit.contains("dev") && node.dev)
                || (omit.contains("optional") && node.optional)
                || (omit.contains("peer") && node.peer)
        })
        .map(|node| node.location.clone())
        .collect::<HashSet<_>>();
    filtered
        .nodes
        .retain(|node| !omitted.contains(&node.location));
    filtered.removed_locations.extend(omitted);
    filtered.removed_locations.sort();
    filtered.removed_locations.dedup();
    filtered
}

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
    force_replan: bool,
    lockfile_only: bool,
    omit: Vec<String>,
    workspace_args: WorkspaceArgs,
    workspace_update: Option<Vec<String>>,
) -> Result<()> {
    let start = Instant::now();
    let mut timings = install_timing::InstallTimings::new();
    let omit = normalize_omit_types(&omit)?;

    // ---- Global install shortcut --------------------------------------------
    if global {
        anyhow::ensure!(omit.is_empty(), "global installs do not yet support --omit");
        return cmd_install_global(packages, dry_run, yes_flag, run_scripts, ignore_scripts).await;
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

    if workspace_args.active() && workspace.is_none() {
        anyhow::bail!("workspace filters require a package.json workspace root");
    }
    if let Some(ref ws) = workspace {
        // Workspace mode: install all packages together with hoisted graph
        if packages.is_empty() {
            let selected = ws
                .select_packages(&workspace_args.workspace, workspace_args.workspaces)
                .map_err(anyhow::Error::msg)?;
            let selected_ws = if workspace_args.active() {
                WorkspaceRoot {
                    root: ws.root.clone(),
                    packages: selected.into_iter().cloned().collect(),
                }
            } else {
                ws.clone()
            };
            println!(
                "oath: workspace mode, {} packages",
                selected_ws.packages.len()
            );
            for pkg in &selected_ws.packages {
                println!("  - {} ({})", pkg.name, pkg.path.display());
            }
            return cmd_install_workspace(
                &selected_ws,
                dry_run,
                run_audit,
                yes_flag,
                run_scripts,
                workspace_args.active(),
                workspace_args.include_workspace_root,
                &omit,
                workspace_update,
            )
            .await;
        }
        // If specific packages are listed, fall through to normal install
    }

    // ---- Single-package install ---------------------------------------------
    let node_modules_existed_before_planning = cwd.join("node_modules").exists();

    let mut pending_manifest: Option<serde_json::Value> = None;
    let mut added_package_names: Vec<String> = Vec::new();
    let (deps, dev_deps, project_name, project_version) = if packages.is_empty() {
        let pkg = read_package_json()?;
        let name = pkg["name"].as_str().unwrap_or("unnamed").to_string();
        let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let deps = extract_deps(&pkg, "dependencies");
        let dev_deps = extract_deps(&pkg, "devDependencies");
        (deps, dev_deps, name, version)
    } else {
        let mut pkg: serde_json::Value = if PathBuf::from("package.json").exists() {
            read_package_json()?
        } else {
            serde_json::json!({"name": "project", "version": "1.0.0"})
        };
        let dep_key = if dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        if pkg.get(dep_key).is_none() {
            pkg[dep_key] = serde_json::json!({});
        }
        for spec in &packages {
            let (name, version) = parse_package_spec(spec);
            pkg[dep_key][&name] = serde_json::Value::String(npm_save_spec(&version));
            added_package_names.push(name);
        }
        let name = pkg["name"].as_str().unwrap_or("project").to_string();
        let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let deps = extract_deps(&pkg, "dependencies");
        let dev_deps = extract_deps(&pkg, "devDependencies");
        pending_manifest = Some(pkg);
        (deps, dev_deps, name, version)
    };

    let trusted_deps: HashSet<String> = {
        let pkg = pending_manifest
            .clone()
            .unwrap_or_else(|| read_package_json().unwrap_or_default());
        pkg.get("trustedDependencies")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    // Verified warm no-op: the input digests, lifecycle mode, installed
    // package identities, placement plan, policy, platform, and content store
    // must all still match before Arborist or the network is started.
    let noop_start = Instant::now();
    if packages.is_empty() && omit.is_empty() && !dry_run && !force_replan {
        match install_state::is_current(&cwd, run_audit, ignore_scripts, run_scripts, yes_flag) {
            Ok(true) => {
                let lockfile = Lockfile::read(&cwd.join("oath-lock.json"))?;
                let store = ContentStore::default_store()?;
                if lockfile.matches_manifest(&deps, &dev_deps)
                    && lockfile_all_cached(&lockfile, &store)
                {
                    timings.record("noop_validation", noop_start.elapsed());
                    println!(
                        "oath: verified no-op ({} packages unchanged)",
                        lockfile.package_count()
                    );
                    timings.finish(true)?;
                    return Ok(());
                }
            }
            Ok(false) => {}
            Err(error) => tracing::debug!("warm no-op state rejected: {error:#}"),
        }
    }
    timings.record("noop_validation", noop_start.elapsed());

    let total_direct = deps.len() + dev_deps.len();

    // npm Arborist is the authoritative placement planner for ordinary
    // package.json installs. Oath retains ownership of fetch, integrity,
    // scanning, CAS materialization, lifecycle policy, and atomic commit.
    // Keep the former resolver available only as an explicit diagnostic canary.
    let use_arborist = std::env::var("OATH_RESOLVER").as_deref() != Ok("legacy");
    let placement_plan: Option<PlacementPlan> = if use_arborist {
        println!("oath: planning npm-compatible layout with Arborist...");
        let request = if packages.is_empty() {
            PlacementRequest::default()
        } else {
            PlacementRequest::add(packages.clone(), dev)
        };
        let resolve_start = Instant::now();
        let mut plan = ArboristPlanner::plan_with(&cwd, &request)?;
        timings.record("resolve", resolve_start.elapsed());
        let metadata_start = Instant::now();
        hydrate_missing_registry_metadata(&mut plan).await?;
        timings.record("metadata", metadata_start.elapsed());
        println!(
            "  planned {} exact locations with {} (npm {})",
            plan.nodes.len(),
            plan.planner.name,
            plan.planner.npm
        );
        Some(plan)
    } else {
        None
    };

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
    if let Some(pkg_json) = pending_manifest.as_mut() {
        let dep_key = if dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        for pkg_name in &added_package_names {
            let requested_spec = pkg_json[dep_key][pkg_name].as_str().unwrap_or("latest");
            let final_spec = dependency_manifest_spec(pkg_name, requested_spec, &graph);
            pkg_json[dep_key][pkg_name] = serde_json::Value::String(final_spec.clone());
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
    let (materialization_plan, materialization_graph) = if omit.is_empty() {
        (placement_plan.clone(), graph.clone())
    } else {
        let plan = placement_plan
            .as_ref()
            .context("--omit requires the npm-compatible Arborist planner")?;
        let filtered = materialization_plan(plan, &omit);
        let graph = filtered.to_dep_graph()?;
        (Some(filtered), graph)
    };
    if frozen_lockfile {
        let existing = Lockfile::read(&lock_path)?;
        if !lockfiles_match_for_frozen(&existing, &lockfile) {
            anyhow::bail!("lockfile would be modified, refusing (--frozen-lockfile)");
        }
    }

    if lockfile_only {
        anyhow::ensure!(
            !frozen_lockfile,
            "--package-lock-only cannot be combined with --frozen-lockfile"
        );
        lockfile.write(&lock_path)?;
        if let Some(plan) = placement_plan.as_ref() {
            plan.write(&cwd.join(".oath").join("placement-plan.json"))?;
        }
        if let Some(pkg_json) = pending_manifest {
            std::fs::write("package.json", serde_json::to_string_pretty(&pkg_json)?)?;
        }
        if !node_modules_existed_before_planning && cwd.join("node_modules").exists() {
            std::fs::remove_dir_all(cwd.join("node_modules"))
                .context("remove planner side effects from lockfile-only install")?;
        }
        println!("oath: lockfile updated without materializing node_modules");
        timings.finish(false)?;
        return Ok(());
    }

    if dry_run {
        println!("  (dry run, skipping download and link)");
        return Ok(());
    }

    // Root project's own preinstall (trusted, runs like npm/bun) -- only on a
    // plain `oath install` of the project, not when adding specific packages.
    if packages.is_empty() && !ignore_scripts {
        let lifecycle_start = Instant::now();
        run_root_lifecycle("preinstall")?;
        timings.record("lifecycle", lifecycle_start.elapsed());
    }

    // Download -- parallel with JoinSet
    let download_start = Instant::now();
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);

    let (to_download, cached) = missing_store_nodes(&materialization_graph, &store);

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
    timings.record("download", download_summary.download_time);
    timings.record("extraction", download_summary.extraction_time);
    timings.record("integrity", download_summary.integrity_time);

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

    // Link
    let link_start = Instant::now();
    let store_ref = Arc::clone(&store);
    let linker = Linker::new((*store_ref).clone());
    let cwd = std::env::current_dir()?;
    let link_result = if let Some(plan) = materialization_plan.as_ref() {
        linker.link_placement_plan(plan, &cwd)?
    } else {
        linker.link_all(&materialization_graph, &cwd)?
    };
    if let Some(plan) = placement_plan.as_ref() {
        plan.write(&cwd.join(".oath").join("placement-plan.json"))?;
    }
    let link_time = link_start.elapsed();
    timings.record("link", link_time);
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    // Write lockfile
    let lockfile_start = Instant::now();
    if !frozen_lockfile {
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
    }

    // Write package.json manifest if packages were explicitly specified.
    if let Some(pkg_json) = pending_manifest {
        std::fs::write("package.json", serde_json::to_string_pretty(&pkg_json)?)?;
    }
    timings.record("lockfile", lockfile_start.elapsed());

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

    // -- Install script permission prompts ------------------------------------
    // Load policy (project-local oath-policy.toml + global ~/.oath/policy.toml)
    let policy_start = Instant::now();
    let policy = OathPolicy::load();
    timings.record("policy", policy_start.elapsed());

    let lifecycle_start = Instant::now();
    let mut scripts_blocked = 0;
    for node in materialization_graph.nodes.values() {
        if ignore_scripts || !node.has_install_script {
            continue;
        }

        // Policy hard-block
        if policy.is_package_banned(&node.name) {
            println!(
                "  oath: blocked install script for banned package {}@{}",
                node.name, node.version
            );
            continue;
        }

        // Run scripts from the linked node_modules location so that optional platform
        // packages (e.g. @esbuild/darwin-arm64) are resolvable via sibling node_modules.
        // Fall back to the store dir if the linked path doesn't exist.
        let install_name = node.alias.as_deref().unwrap_or(&node.name);
        let linked_pkg_dir = cwd.join("node_modules").join(install_name);
        let store_pkg_dir = store.package_dir_for(
            &node.name,
            &node.version,
            Some(&node.resolved),
            node.integrity.as_deref(),
        );
        let pkg_dir = if linked_pkg_dir.exists() {
            linked_pkg_dir
        } else {
            store_pkg_dir
        };

        // Analysis must complete successfully before any lifecycle execution,
        // including trusted dependencies and --yes approvals.
        PackageScanner::scan(&node.name, &node.version, &pkg_dir).with_context(|| {
            format!("analyze {} before contained lifecycle execution", node.name)
        })?;

        // Trusted: run after analysis, but always inside verified containment.
        if trusted_deps.contains(&node.name) || yes_flag {
            if pkg_dir.exists() {
                run_install_script(&node.name, &pkg_dir)?;
            }
            continue;
        }

        // --run-scripts: prompt for each (old behavior)
        if run_scripts {
            if !pkg_dir.exists() {
                continue;
            }
            let report = match PackageScanner::scan(&node.name, &node.version, &pkg_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let script_display =
                detect_install_script(&pkg_dir).unwrap_or_else(|| "node install.js".to_string());
            let decision = prompts::prompt_install_script(
                &node.name,
                &node.version,
                &script_display,
                &report.capabilities,
                false,
                &policy,
            );
            match decision {
                prompts::ScriptDecision::Allow | prompts::ScriptDecision::Always => {
                    run_install_script(&node.name, &pkg_dir)?;
                }
                prompts::ScriptDecision::Deny => {}
            }
            continue;
        }

        // Default: BLOCK (silent, just count)
        scripts_blocked += 1;
    }

    if scripts_blocked > 0 {
        println!(
            "  {} install script(s) blocked (add to trustedDependencies or use --run-scripts)",
            scripts_blocked
        );
    }
    timings.record("lifecycle", lifecycle_start.elapsed());

    // Static analysis on newly downloaded packages
    let analysis_start = Instant::now();
    if run_audit && downloaded > 0 {
        println!("  scanning {} new packages...", downloaded);
        // Scan new packages in parallel -- each scan is independent and
        // CPU-bound (oxc AST parse), so this is the cold-install hot path.
        let nodes: Vec<_> = materialization_graph.nodes.values().collect();
        let scanned: Vec<_> = nodes
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
                match PackageScanner::scan(&node.name, &node.version, &pkg_dir) {
                    Ok(r) => Some((node.name.as_str(), node.version.as_str(), r)),
                    Err(_) => None,
                }
            })
            .collect();

        let mut critical = 0usize;
        let mut high = 0usize;
        // Reporting is serial -- deterministic, ordered output.
        for (name, version, report) in &scanned {
            // Tiered behavioral verdict: capabilities are neutral; only dangerous
            // combinations escalate. Critical = Block-tier, High = Warn-tier.
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
    timings.record("analysis", analysis_start.elapsed());

    // Root project's own post-install lifecycle (trusted, runs like npm/bun) --
    // covers the common husky `prepare` and any project postinstall.
    if packages.is_empty() && !ignore_scripts {
        let lifecycle_start = Instant::now();
        run_root_lifecycle("install")?;
        run_root_lifecycle("postinstall")?;
        run_root_lifecycle("prepare")?;
        timings.record("lifecycle", lifecycle_start.elapsed());
    }

    let cleanup_start = Instant::now();
    if placement_plan.is_some() {
        install_state::write(&cwd, run_audit, ignore_scripts, run_scripts, yes_flag)?;
    }
    timings.record("cleanup", cleanup_start.elapsed());

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    // ---- Transparency log ---------------------------------------------------
    let project_path = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let pkg_entries: Vec<(String, String, Option<String>)> = materialization_graph
        .nodes
        .values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    timings.finish(false)?;

    Ok(())
}

// ---- CI ---------------------------------------------------------------------

async fn cmd_ci_scoped(workspace: WorkspaceArgs, omit: Vec<String>) -> Result<()> {
    if !workspace.active() {
        return cmd_ci(omit).await;
    }
    let cwd = std::env::current_dir()?.canonicalize()?;
    let root = detect_workspace_root(&cwd)
        .context("workspace filters require a package.json workspace root")?;
    let node_modules = root.root.join("node_modules");
    if node_modules.exists() {
        std::fs::remove_dir_all(&node_modules)
            .context("failed to clean workspace node_modules before oath ci")?;
    }
    let _guard = CurrentDirectoryGuard::enter(&root.root)?;
    cmd_install(
        Vec::new(),
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        None,
        true,
        false,
        omit,
        workspace.clone(),
        None,
    )
    .await
}

async fn cmd_ci(omit: Vec<String>) -> Result<()> {
    let start = Instant::now();
    let omit = normalize_omit_types(&omit)?;
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        if PathBuf::from("package-lock.json").exists() {
            let node_modules = PathBuf::from("node_modules");
            if node_modules.exists() {
                std::fs::remove_dir_all(&node_modules)
                    .context("failed to clean node_modules before npm lockfile import")?;
            }
            return cmd_install(
                Vec::new(),
                false,
                false,
                true,
                false,
                false,
                true,
                false,
                false,
                None,
                true,
                false,
                omit.iter().cloned().collect(),
                WorkspaceArgs::default(),
                None,
            )
            .await;
        }
        anyhow::bail!("no lockfile found, run oath install first");
    }

    let pkg = read_package_json()?;
    let deps = extract_deps(&pkg, "dependencies");
    let dev_deps = extract_deps(&pkg, "devDependencies");
    let lockfile = Lockfile::read(&lock_path)?;
    if !lockfile.matches_manifest(&deps, &dev_deps) {
        anyhow::bail!("package.json does not match oath-lock.json, run oath install first");
    }

    let cwd = std::env::current_dir()?.canonicalize()?;
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
    let materialization_plan = materialization_plan(&placement_plan, &omit);
    let materialization_graph = materialization_plan.to_dep_graph()?;
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let (to_download, cached) = missing_store_nodes(&materialization_graph, &store);
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

    let linker = Linker::new((*store).clone());
    let link_result = linker.link_placement_plan_clean(&materialization_plan, &cwd)?;
    placement_plan.write(&plan_path)?;
    println!("  linked {} packages", link_result.linked);

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    let project_path = cwd.to_string_lossy().to_string();
    let pkg_entries: Vec<(String, String, Option<String>)> = materialization_graph
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
#[allow(clippy::too_many_arguments)]
async fn cmd_install_workspace(
    ws: &WorkspaceRoot,
    dry_run: bool,
    run_audit: bool,
    _yes_flag: bool,
    _run_scripts: bool,
    filtered: bool,
    include_workspace_root: bool,
    omit: &HashSet<String>,
    update_packages: Option<Vec<String>>,
) -> Result<()> {
    let start = Instant::now();

    // Collect external deps from all workspace packages (merged, deduped)
    let (external_deps, workspace_links) =
        ws.collect_external_deps_for_packages(true, !filtered || include_workspace_root);

    println!(
        "  {} external deps, {} workspace links",
        external_deps.len(),
        workspace_links.len()
    );

    if external_deps.is_empty() && workspace_links.is_empty() {
        println!("  nothing to install");
        if dry_run {
            return Ok(());
        }
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
    let selected_names = ws
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<HashSet<_>>();
    // Arborist may create workspace symlinks while constructing its ideal tree.
    // Snapshot links that genuinely predated planning so a filtered operation
    // preserves earlier unselected installs without treating planner side effects
    // as pre-existing state.
    let preserved_unselected_links = if filtered {
        detect_workspace_root(&ws.root)
            .map(|all_workspaces| {
                all_workspaces
                    .packages
                    .iter()
                    .filter(|package| !selected_names.contains(package.name.as_str()))
                    .map(|package| format!("node_modules/{}", package.name))
                    .filter(|location| ws.root.join(location).symlink_metadata().is_ok())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default()
    } else {
        HashSet::new()
    };
    let updating = update_packages.is_some();
    let mut request =
        update_packages.map_or_else(PlacementRequest::default, PlacementRequest::update);
    request.workspaces = if filtered {
        ws.packages.iter().map(|pkg| pkg.name.clone()).collect()
    } else {
        Vec::new()
    };
    // Arborist's dry-run update path can still rewrite workspace manifests.
    // Oath owns manifest changes, so snapshot every workspace source and restore
    // it even if the planner exits with an error.
    let planner_manifest_guard = if updating {
        let all_workspaces =
            detect_workspace_root(&ws.root).context("workspace root disappeared")?;
        let mut planner_targets = all_workspaces
            .packages
            .iter()
            .map(|package| WorkspaceTarget {
                name: package.name.clone(),
                path: package.path.clone(),
            })
            .collect::<Vec<_>>();
        let root_manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ws.root.join("package.json"))?)?;
        planner_targets.push(WorkspaceTarget {
            name: root_manifest["name"]
                .as_str()
                .unwrap_or("workspace-root")
                .to_owned(),
            path: ws.root.clone(),
        });
        Some(WorkspaceManifestTransaction::snapshot(&planner_targets)?)
    } else {
        None
    };
    let mut placement_plan = ArboristPlanner::plan_with(&ws.root, &request)?;
    drop(planner_manifest_guard);
    if filtered {
        placement_plan.nodes.retain(|node| {
            !node.link
                || selected_names.contains(node.name.as_str())
                || preserved_unselected_links.contains(&node.location)
        });
        placement_plan
            .removed_locations
            .retain(|location| !preserved_unselected_links.contains(location));
    }
    hydrate_missing_registry_metadata(&mut placement_plan).await?;
    let graph = placement_plan.to_dep_graph()?;
    let materialization_plan = materialization_plan(&placement_plan, omit);
    let materialization_graph = materialization_plan.to_dep_graph()?;
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

    let (to_download, cached) = missing_store_nodes(&materialization_graph, &store);
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
    let linker = Linker::new((*store_ref).clone());
    let link_result = linker.link_placement_plan(&materialization_plan, &ws.root)?;
    placement_plan.write(&ws.root.join(".oath").join("placement-plan.json"))?;
    let link_time = link_start.elapsed();
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    let workspace_link_count = materialization_plan
        .nodes
        .iter()
        .filter(|node| node.link)
        .count();
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
    let pkg_entries: Vec<(String, String, Option<String>)> = materialization_graph
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

fn advisory_severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

async fn cmd_audit(production: bool, json_output: bool, audit_level: &str) -> Result<bool> {
    anyhow::ensure!(
        advisory_severity_rank(audit_level) > 0,
        "--audit-level must be low, moderate, high, or critical"
    );
    let lockfile = Lockfile::read(&PathBuf::from("oath-lock.json"))
        .context("oath audit requires oath-lock.json; run oath install first")?;
    let mut packages: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, entry) in &lockfile.packages {
        if production && entry.dev {
            continue;
        }
        packages
            .entry(entry.package_name_for_key(key))
            .or_default()
            .push(entry.version.clone());
    }
    for versions in packages.values_mut() {
        versions.sort();
        versions.dedup();
    }

    let config = oath_fetch::NpmrcConfig::load(&std::env::current_dir()?);
    let registry = config
        .default_registry
        .clone()
        .unwrap_or_else(|| "https://registry.npmjs.org".to_string());
    let registry = credential_registry_url(&registry)?;
    let url = format!(
        "{}/-/npm/v1/security/advisories/bulk",
        registry.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut request = client.post(&url).json(&packages);
    if let Some(host) = reqwest::Url::parse(&url)?.host_str()
        && let Some(token) = config.token_for_host(host)
    {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry audit request returned {}",
        response.status()
    );
    let advisories: serde_json::Value = response.json().await?;
    let rows = advisories
        .as_object()
        .context("registry audit response must be an object")?;
    let threshold = advisory_severity_rank(audit_level);
    let blocking = rows
        .values()
        .filter(|advisory| {
            advisory["severity"]
                .as_str()
                .is_some_and(|severity| advisory_severity_rank(severity) >= threshold)
        })
        .count();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "audit_level": audit_level,
                "production": production,
                "package_versions": packages.values().map(Vec::len).sum::<usize>(),
                "advisory_count": rows.len(),
                "blocking_count": blocking,
                "advisories": advisories,
            }))?
        );
    } else if rows.is_empty() {
        println!("found 0 vulnerabilities");
    } else {
        for (id, advisory) in rows {
            println!(
                "{}\t{}\t{}\t{}",
                advisory["severity"].as_str().unwrap_or("unknown"),
                advisory["name"]
                    .as_str()
                    .or_else(|| advisory["module_name"].as_str())
                    .unwrap_or("unknown"),
                id,
                advisory["title"].as_str().unwrap_or("untitled advisory")
            );
        }
        println!(
            "found {} vulnerabilities ({blocking} at or above {audit_level})",
            rows.len()
        );
    }
    Ok(blocking > 0)
}

fn cmd_audit_signatures(json_output: bool) -> Result<()> {
    let lock = Lockfile::read(&PathBuf::from("oath-lock.json"))
        .context("oath audit signatures requires oath-lock.json")?;
    let workspace = tempfile::tempdir().context("create signature audit workspace")?;
    let root = workspace.path();
    std::fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": lock.name,
            "version": lock.version,
            "private": true,
            "dependencies": lock.root_dependencies,
            "devDependencies": lock.root_dev_dependencies
        }))?,
    )?;
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&oath_lock_as_npm_shrinkwrap(&lock))?,
    )?;
    if let Ok(npmrc) = std::fs::read(".npmrc") {
        std::fs::write(root.join(".npmrc"), npmrc)?;
    }
    let cli = oath_resolve::placement::pinned_npm_cli_path()?;
    let mut command = std::process::Command::new("node");
    command
        .arg(cli)
        .args(["audit", "signatures", "--ignore-scripts"])
        .current_dir(root)
        .env("npm_config_cache", root.join("cache"));
    if json_output {
        command.arg("--json");
    }
    if let Ok(userconfig) = user_npmrc_path() {
        command.env("npm_config_userconfig", userconfig);
    }
    let output = command
        .output()
        .context("launch pinned signature verifier")?;
    anyhow::ensure!(
        output.status.success(),
        "package signature verification failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn current_rfc3339_utc() -> Result<String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn npm_purl(name: &str, version: &str) -> String {
    let encoded_name = if let Some(scoped) = name.strip_prefix('@') {
        format!("%40{scoped}")
    } else {
        name.to_string()
    };
    format!("pkg:npm/{encoded_name}@{version}")
}

fn cmd_sbom(format: &str, output: Option<&std::path::Path>) -> Result<()> {
    use sha2::{Digest, Sha256};

    let lock_path = PathBuf::from("oath-lock.json");
    let lock_bytes = std::fs::read(&lock_path)
        .context("oath sbom requires oath-lock.json; run oath install first")?;
    let lockfile: Lockfile = serde_json::from_slice(&lock_bytes)?;
    let digest = hex::encode(Sha256::digest(&lock_bytes));
    let document = build_sbom_document(&lockfile, &digest, format)?;
    let encoded = serde_json::to_vec_pretty(&document)?;
    if let Some(path) = output {
        std::fs::write(path, &encoded).with_context(|| format!("write SBOM {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

fn build_sbom_document(
    lockfile: &Lockfile,
    digest: &str,
    format: &str,
) -> Result<serde_json::Value> {
    let mut entries = lockfile.packages.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| *key);
    let document = match format {
        "cyclonedx" => {
            let references: BTreeMap<_, _> = entries
                .iter()
                .enumerate()
                .map(|(index, (key, _))| ((*key).clone(), format!("oath:component:{index}")))
                .collect();
            let components = entries
                .iter()
                .enumerate()
                .map(|(index, (key, entry))| {
                    let name = entry.package_name_for_key(key);
                    serde_json::json!({
                        "type": "library",
                        "bom-ref": format!("oath:component:{index}"),
                        "name": name,
                        "version": entry.version,
                        "purl": npm_purl(&name, &entry.version),
                        "properties": entry.integrity.as_ref().map(|integrity| vec![serde_json::json!({ "name": "oath:sri", "value": integrity })]).unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>();
            let root_reference = "oath:root";
            let mut dependencies = vec![serde_json::json!({
                "ref": root_reference,
                "dependsOn": lockfile.roots.iter().filter_map(|key| references.get(key)).collect::<Vec<_>>()
            })];
            dependencies.extend(entries.iter().map(|(key, entry)| {
                let depends_on = entry
                    .dependencies
                    .values()
                    .chain(entry.resolved_peers.values())
                    .filter_map(|target| references.get(target))
                    .collect::<Vec<_>>();
                serde_json::json!({ "ref": references.get(*key), "dependsOn": depends_on })
            }));
            serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": { "component": { "type": "application", "bom-ref": root_reference, "name": &lockfile.name, "version": &lockfile.version } },
                "components": components,
                "dependencies": dependencies,
            })
        }
        "spdx" => {
            let identifiers: BTreeMap<_, _> = entries
                .iter()
                .enumerate()
                .map(|(index, (key, _))| ((*key).clone(), format!("SPDXRef-Package-{index}")))
                .collect();
            let mut packages = entries
                .iter()
                .enumerate()
                .map(|(index, (key, entry))| {
                    let name = entry.package_name_for_key(key);
                    serde_json::json!({
                        "SPDXID": format!("SPDXRef-Package-{index}"),
                        "name": name,
                        "versionInfo": entry.version,
                        "downloadLocation": entry.resolved,
                        "filesAnalyzed": false,
                        "externalRefs": [{ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": npm_purl(&name, &entry.version) }]
                    })
                })
                .collect::<Vec<_>>();
            packages.insert(
                0,
                serde_json::json!({
                    "SPDXID": "SPDXRef-RootPackage",
                    "name": lockfile.name,
                    "versionInfo": lockfile.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false
                }),
            );
            let mut relationships = vec![serde_json::json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-RootPackage"
            })];
            relationships.extend(
                lockfile
                    .roots
                    .iter()
                    .filter_map(|key| identifiers.get(key))
                    .map(|target| {
                        serde_json::json!({
                            "spdxElementId": "SPDXRef-RootPackage",
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": target
                        })
                    }),
            );
            for (key, entry) in &entries {
                let Some(source) = identifiers.get(*key) else {
                    continue;
                };
                relationships.extend(
                    entry
                        .dependencies
                        .values()
                        .chain(entry.resolved_peers.values())
                        .filter_map(|target| identifiers.get(target))
                        .map(|target| {
                            serde_json::json!({
                                "spdxElementId": source,
                                "relationshipType": "DEPENDS_ON",
                                "relatedSpdxElement": target
                            })
                        }),
                );
            }
            serde_json::json!({
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": format!("{}-{}", lockfile.name, lockfile.version),
                "documentNamespace": format!("https://oath.dev/sbom/{digest}"),
                "creationInfo": { "created": current_rfc3339_utc()?, "creators": [format!("Tool: oath-{}", env!("CARGO_PKG_VERSION"))] },
                "packages": packages,
                "relationships": relationships,
            })
        }
        _ => anyhow::bail!("--sbom-format must be cyclonedx or spdx"),
    };
    Ok(document)
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

async fn cmd_add_scoped(
    packages: Vec<String>,
    dev: bool,
    optional: bool,
    peer: bool,
    exact: bool,
    yes: bool,
    workspace: WorkspaceArgs,
) -> Result<()> {
    anyhow::ensure!(!packages.is_empty(), "oath add: no packages specified");
    let targets = if workspace.active() {
        selected_workspace_targets(&workspace)?
    } else {
        let root = std::env::current_dir()?;
        let manifest_path = root.join("package.json");
        if !manifest_path.exists() {
            println!("oath add: no package.json found, creating one");
            std::fs::write(
                &manifest_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": "project",
                    "version": "1.0.0",
                }))?,
            )?;
        }
        let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        vec![WorkspaceTarget {
            name: manifest["name"].as_str().unwrap_or("package").to_owned(),
            path: root,
        }]
    };
    let dependency_group = match (dev, optional, peer) {
        (true, false, false) => "devDependencies",
        (false, true, false) => "optionalDependencies",
        (false, false, true) => "peerDependencies",
        (false, false, false) => "dependencies",
        _ => anyhow::bail!("choose only one dependency save group"),
    };
    let mut transaction = WorkspaceManifestTransaction::begin(&targets, |manifest| {
        if manifest.get(dependency_group).is_none() {
            manifest[dependency_group] = serde_json::json!({});
        }
        let dependencies = manifest[dependency_group]
            .as_object_mut()
            .context("dependency group must be an object")?;
        for package in &packages {
            let (name, version) = parse_package_spec(package);
            let saved = if exact && version.parse::<node_semver::Version>().is_ok() {
                version
            } else {
                npm_save_spec(&version)
            };
            dependencies.insert(name, serde_json::Value::String(saved));
        }
        Ok(())
    })?;
    cmd_install(
        Vec::new(),
        false,
        false,
        true,
        yes,
        false,
        false,
        false,
        false,
        None,
        true,
        false,
        Vec::new(),
        workspace.clone(),
        None,
    )
    .await?;
    if exact {
        let cwd = std::env::current_dir()?;
        let mut resolved = HashMap::new();
        for package in &packages {
            let (name, requested) = parse_package_spec(package);
            if requested.starts_with("npm:") || is_git_like_spec(&requested) {
                continue;
            }
            let path = cwd.join("node_modules").join(&name).join("package.json");
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).with_context(|| {
                    format!(
                        "cannot determine exact installed version for {name} at {}",
                        path.display()
                    )
                })?)?;
            resolved.insert(
                name,
                manifest["version"]
                    .as_str()
                    .context("installed package has no version")?
                    .to_owned(),
            );
        }
        for target in &targets {
            let path = target.path.join("package.json");
            let mut manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            let dependencies = manifest[dependency_group]
                .as_object_mut()
                .context("dependency group must be an object")?;
            for (name, version) in &resolved {
                dependencies.insert(name.clone(), serde_json::Value::String(version.clone()));
            }
            write_manifest_atomic(&path, &serde_json::to_vec_pretty(&manifest)?)?;
        }
        cmd_install(
            Vec::new(),
            false,
            false,
            true,
            yes,
            false,
            false,
            false,
            false,
            None,
            true,
            false,
            Vec::new(),
            workspace,
            None,
        )
        .await?;
    }
    transaction.commit();
    Ok(())
}

async fn cmd_update_scoped(packages: Vec<String>, workspace: WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        return cmd_update(packages).await;
    }
    let requested = packages
        .into_iter()
        .map(|spec| parse_package_spec(&spec).0)
        .collect::<HashSet<_>>();
    let mut names = HashSet::new();
    for target in selected_workspace_targets(&workspace)? {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(target.path.join("package.json"))?)?;
        for group in ["dependencies", "devDependencies", "optionalDependencies"] {
            for name in extract_deps(&manifest, group).into_keys() {
                if requested.is_empty() || requested.contains(&name) {
                    names.insert(name);
                }
            }
        }
    }
    let mut names = names.into_iter().collect::<Vec<_>>();
    names.sort();
    anyhow::ensure!(
        !names.is_empty(),
        "oath update: no matching dependencies in selected workspaces"
    );
    cmd_install(
        Vec::new(),
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        None,
        true,
        false,
        Vec::new(),
        workspace,
        Some(names),
    )
    .await
}

async fn cmd_update(packages: Vec<String>) -> Result<()> {
    let names = packages
        .into_iter()
        .map(|spec| parse_package_spec(&spec).0)
        .collect();
    cmd_reify_request(PlacementRequest::update(names), "updated").await
}

async fn cmd_dedupe(dry_run: bool, prefer_dedupe: bool) -> Result<()> {
    let request = PlacementRequest {
        prefer_dedupe,
        ..PlacementRequest::default()
    };
    if dry_run {
        let cwd = std::env::current_dir()?.canonicalize()?;
        let plan = ArboristPlanner::plan_with(&cwd, &request)?;
        println!(
            "oath dedupe: would materialize {} packages",
            plan.nodes.len()
        );
        return Ok(());
    }
    cmd_reify_request(request, "deduplicated").await
}

fn placement_location_package_name(location: &str) -> Option<String> {
    let (_, suffix) = location.rsplit_once("node_modules/")?;
    let mut parts = suffix.split('/');
    let first = parts.next()?;
    if first.starts_with('@') {
        Some(format!("{first}/{}", parts.next()?))
    } else {
        Some(first.to_owned())
    }
}

fn cmd_prune(
    packages: &[String],
    dry_run: bool,
    _ignore_scripts: bool,
    omit: &[String],
    production: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    let mut omit = omit
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if production {
        omit.insert("dev".to_owned());
    }
    anyhow::ensure!(
        omit.iter()
            .all(|value| matches!(value.as_str(), "dev" | "optional" | "peer")),
        "--omit must be dev, optional, or peer"
    );
    let cwd = std::env::current_dir()?.canonicalize()?;
    let (root, mut request) = if workspace.active() {
        let workspace_root = detect_workspace_root(&cwd)
            .context("workspace filters require a package.json workspace root")?;
        let selected = workspace_root
            .select_packages(&workspace.workspace, workspace.workspaces)
            .map_err(anyhow::Error::msg)?;
        let request = PlacementRequest {
            workspaces: selected
                .iter()
                .map(|package| package.name.clone())
                .collect(),
            ..PlacementRequest::default()
        };
        (workspace_root.root, request)
    } else {
        (cwd, PlacementRequest::default())
    };
    if workspace.include_workspace_root {
        request.workspaces.clear();
    }
    let plan = ArboristPlanner::plan_with(&root, &request)?;
    let requested = packages
        .iter()
        .map(|package| parse_package_spec(package).0)
        .collect::<HashSet<_>>();
    let mut removals = plan.removed_locations;
    removals.extend(
        plan.nodes
            .iter()
            .filter(|node| {
                (omit.contains("dev") && node.dev)
                    || (omit.contains("optional") && node.optional)
                    || (omit.contains("peer") && node.peer)
            })
            .map(|node| node.location.clone()),
    );
    removals.sort();
    removals.dedup();
    if !requested.is_empty() {
        removals.retain(|location| {
            placement_location_package_name(location).is_some_and(|name| requested.contains(&name))
        });
    }
    if dry_run {
        for location in &removals {
            println!("remove {location}");
        }
        println!(
            "oath prune: would remove {} package location(s)",
            removals.len()
        );
        return Ok(());
    }
    let removed_count = removals.len();
    let prune_plan = PlacementPlan {
        schema_version: plan.schema_version,
        planner: plan.planner,
        project: plan.project,
        nodes: Vec::new(),
        removed_locations: removals,
        invalid_edges: Vec::new(),
    };
    let linker = Linker::new(ContentStore::default_store()?);
    linker.link_placement_plan(&prune_plan, &root)?;
    println!("oath prune: removed {removed_count} package location(s)");
    Ok(())
}

async fn cmd_reify_request(request: PlacementRequest, action: &str) -> Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let pkg = read_package_json()?;
    let deps = extract_deps(&pkg, "dependencies");
    let dev_deps = extract_deps(&pkg, "devDependencies");
    let mut placement_plan = ArboristPlanner::plan_with(&cwd, &request)?;
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
    println!("oath: {action} {} packages", graph.package_count());
    Ok(())
}

async fn cmd_update_global(packages: Vec<String>) -> Result<()> {
    let root = global_prefix()?;
    let manifest_path = root.join("package.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .with_context(|| "no globally installed Oath packages to update")?,
    )?;
    let dependencies = extract_deps(&manifest, "dependencies");
    anyhow::ensure!(
        !dependencies.is_empty(),
        "no globally installed Oath packages"
    );
    let requested = packages
        .into_iter()
        .map(|value| parse_package_spec(&value).0)
        .collect::<HashSet<_>>();
    if !requested.is_empty() {
        for name in &requested {
            anyhow::ensure!(
                dependencies.contains_key(name),
                "{name} is not installed globally"
            );
        }
    }
    let mut specs = dependencies
        .into_iter()
        .map(|(name, spec)| format!("{name}@{spec}"))
        .collect::<Vec<_>>();
    specs.sort();
    cmd_install_global(specs, false, false, false, false).await
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
fn run_root_lifecycle(event: &str) -> Result<()> {
    let pkg = match read_package_json() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    let cmd = match pkg
        .get("scripts")
        .and_then(|s| s.get(event))
        .and_then(|v| v.as_str())
    {
        Some(c) => c,
        None => return Ok(()),
    };
    let mut npm_env = npm_package_env(&pkg);
    let mut paths = vec![std::path::PathBuf::from("./node_modules/.bin")];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    npm_env.push((
        "PATH".into(),
        std::env::join_paths(paths)?.to_string_lossy().into_owned(),
    ));
    println!("> {event}: {cmd}");
    run_contained_lifecycle(
        "root-project",
        &std::env::current_dir()?,
        event,
        cmd,
        &npm_env,
    )
}

struct CurrentDirectoryGuard(PathBuf);

impl CurrentDirectoryGuard {
    fn enter(path: &std::path::Path) -> Result<Self> {
        let previous = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self(previous))
    }
}

impl Drop for CurrentDirectoryGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

#[derive(Clone, Debug)]
struct WorkspaceTarget {
    name: String,
    path: PathBuf,
}

fn selected_workspace_targets(workspace: &WorkspaceArgs) -> Result<Vec<WorkspaceTarget>> {
    anyhow::ensure!(workspace.active(), "workspace selection is not active");
    let cwd = std::env::current_dir()?.canonicalize()?;
    let root = detect_workspace_root(&cwd)
        .context("workspace filters require a package.json workspace root")?;
    let selected = root
        .select_packages(&workspace.workspace, workspace.workspaces)
        .map_err(anyhow::Error::msg)?;
    let mut targets = Vec::new();
    if workspace.include_workspace_root {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.root.join("package.json"))?)?;
        targets.push(WorkspaceTarget {
            name: manifest["name"]
                .as_str()
                .unwrap_or("workspace-root")
                .to_owned(),
            path: root.root.clone(),
        });
    }
    targets.extend(selected.into_iter().map(|package| WorkspaceTarget {
        name: package.name.clone(),
        path: package.path.clone(),
    }));
    anyhow::ensure!(!targets.is_empty(), "workspace selection is empty");
    Ok(targets)
}

fn write_manifest_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().context("manifest path has no parent")?;
    let temporary = parent.join(format!(
        ".package.json.oath-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    replace_file(&temporary, path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    std::fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

struct WorkspaceManifestTransaction {
    originals: Vec<(PathBuf, Vec<u8>)>,
    committed: bool,
}

impl WorkspaceManifestTransaction {
    fn snapshot(targets: &[WorkspaceTarget]) -> Result<Self> {
        let originals = targets
            .iter()
            .map(|target| {
                let path = target.path.join("package.json");
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                Ok((path, bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            originals,
            committed: false,
        })
    }

    fn begin(
        targets: &[WorkspaceTarget],
        mut mutate: impl FnMut(&mut serde_json::Value) -> Result<()>,
    ) -> Result<Self> {
        let mut originals: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        for target in targets {
            let path = target.path.join("package.json");
            let original = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let result = (|| -> Result<()> {
                let mut manifest: serde_json::Value = serde_json::from_slice(&original)?;
                mutate(&mut manifest)?;
                let updated = format!("{}\n", serde_json::to_string_pretty(&manifest)?);
                write_manifest_atomic(&path, updated.as_bytes())
            })();
            if let Err(error) = result {
                for (changed, bytes) in originals.iter().rev() {
                    let _ = write_manifest_atomic(changed, bytes);
                }
                return Err(error);
            }
            originals.push((path, original));
        }
        Ok(Self {
            originals,
            committed: false,
        })
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for WorkspaceManifestTransaction {
    fn drop(&mut self) {
        if !self.committed {
            for (path, bytes) in self.originals.iter().rev() {
                let _ = write_manifest_atomic(path, bytes);
            }
        }
    }
}

struct FileSnapshotTransaction {
    originals: Vec<(PathBuf, Option<Vec<u8>>)>,
    committed: bool,
}

impl FileSnapshotTransaction {
    fn snapshot(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut originals = Vec::new();
        for path in paths {
            let original = match std::fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to snapshot {}", path.display()));
                }
            };
            originals.push((path, original));
        }
        Ok(Self {
            originals,
            committed: false,
        })
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for FileSnapshotTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (path, original) in self.originals.iter().rev() {
            if let Some(bytes) = original {
                let _ = write_manifest_atomic(path, bytes);
            } else if path.is_file() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn cmd_run_scoped(
    script: Option<&str>,
    args: &[String],
    if_present: bool,
    ignore_scripts: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_run(script, args, if_present, ignore_scripts);
    }
    let cwd = std::env::current_dir()?.canonicalize()?;
    let root = detect_workspace_root(&cwd)
        .context("workspace filters require a package.json workspace root")?;
    let selected = root
        .select_packages(&workspace.workspace, workspace.workspaces)
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(!selected.is_empty(), "workspace selection is empty");

    if workspace.include_workspace_root {
        let _guard = CurrentDirectoryGuard::enter(&root.root)?;
        cmd_run(script, args, if_present, ignore_scripts)?;
    }
    for package in selected {
        println!("oath: workspace {}", package.name);
        let _guard = CurrentDirectoryGuard::enter(&package.path)?;
        cmd_run(script, args, if_present, ignore_scripts)
            .with_context(|| format!("workspace {} command failed", package.name))?;
    }
    Ok(())
}

fn cmd_run(
    script: Option<&str>,
    args: &[String],
    if_present: bool,
    ignore_scripts: bool,
) -> Result<()> {
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

    let Some(scripts) = scripts_obj else {
        anyhow::ensure!(if_present, "no scripts defined in package.json");
        return Ok(());
    };

    let Some(cmd) = scripts.get(script).and_then(|v| v.as_str()) else {
        anyhow::ensure!(if_present, "script '{script}' not found");
        return Ok(());
    };

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
    if !ignore_scripts && let Some(pre_cmd) = scripts.get(&pre_name).and_then(|v| v.as_str()) {
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
    if !ignore_scripts && let Some(post_cmd) = scripts.get(&post_name).and_then(|v| v.as_str()) {
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

fn cmd_restart_one(args: &[String], ignore_scripts: bool) -> Result<()> {
    let package = read_package_json()?;
    let has_restart = package
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| scripts.contains_key("restart"));
    if has_restart {
        cmd_run(Some("restart"), args, false, ignore_scripts)
    } else {
        cmd_run(Some("stop"), &[], true, ignore_scripts)?;
        cmd_run(Some("start"), args, false, ignore_scripts)
    }
}

fn cmd_restart_scoped(
    args: &[String],
    ignore_scripts: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_restart_one(args, ignore_scripts);
    }
    for target in selected_workspace_targets(workspace)? {
        println!("oath: workspace {}", target.name);
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_restart_one(args, ignore_scripts)?;
    }
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

fn initializer_package_spec(initializer: &str) -> Result<String> {
    anyhow::ensure!(
        !initializer.is_empty() && !initializer.chars().any(char::is_control),
        "invalid initializer package"
    );
    if let Some(scoped) = initializer.strip_prefix('@') {
        let (package_and_scope, version) = scoped
            .rsplit_once('@')
            .map_or((scoped, None), |(package, version)| {
                (package, Some(version))
            });
        let (scope, package) = package_and_scope
            .split_once('/')
            .context("scoped initializer must have the form @scope/name")?;
        anyhow::ensure!(
            !scope.is_empty() && !package.is_empty(),
            "invalid initializer"
        );
        return Ok(format!(
            "@{scope}/create-{package}{}",
            version
                .map(|version| format!("@{version}"))
                .unwrap_or_default()
        ));
    }
    let (package, version) = initializer
        .rsplit_once('@')
        .map_or((initializer, None), |(package, version)| {
            (package, Some(version))
        });
    anyhow::ensure!(!package.is_empty(), "invalid initializer package");
    Ok(format!(
        "create-{package}{}",
        version
            .map(|version| format!("@{version}"))
            .unwrap_or_default()
    ))
}

fn init_prompt(label: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label}: ({default}) ");
    }
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim();
    Ok(if value.is_empty() { default } else { value }.to_owned())
}

fn cmd_init_one(yes: bool, scope: Option<&str>, private: bool) -> Result<()> {
    if PathBuf::from("package.json").exists() {
        println!("oath init: package.json already exists, overwriting");
    }
    if let Some(scope) = scope {
        validate_scope(scope)?;
    }
    let base_name = std::env::current_dir()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "project".to_owned())
        .to_ascii_lowercase()
        .replace([' ', '_'], "-");
    let default_name = scope.map_or(base_name.clone(), |scope| format!("{scope}/{base_name}"));
    let (
        project_name,
        version,
        description,
        main,
        test,
        repository,
        keywords,
        author,
        license,
        module_type,
    ) = if yes {
        (
            default_name,
            "1.0.0".to_owned(),
            String::new(),
            "index.js".to_owned(),
            "echo \"Error: no test specified\" && exit 1".to_owned(),
            String::new(),
            Vec::new(),
            String::new(),
            "UNLICENSED".to_owned(),
            "commonjs".to_owned(),
        )
    } else {
        let project_name = init_prompt("package name", &default_name)?;
        let version = init_prompt("version", "1.0.0")?;
        let description = init_prompt("description", "")?;
        let main = init_prompt("entry point", "index.js")?;
        let test = init_prompt(
            "test command",
            "echo \"Error: no test specified\" && exit 1",
        )?;
        let repository = init_prompt("git repository", "")?;
        let keywords = init_prompt("keywords", "")?
            .split_whitespace()
            .map(|keyword| keyword.trim_matches(',').to_owned())
            .filter(|keyword| !keyword.is_empty())
            .collect();
        let author = init_prompt("author", "")?;
        let license = init_prompt("license", "UNLICENSED")?;
        let module_type = init_prompt("type", "commonjs")?;
        anyhow::ensure!(
            matches!(module_type.as_str(), "commonjs" | "module"),
            "package type must be commonjs or module"
        );
        print!("Is this OK? (yes) ");
        std::io::stdout().flush()?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        anyhow::ensure!(
            matches!(
                confirmation.trim().to_ascii_lowercase().as_str(),
                "" | "y" | "yes"
            ),
            "package initialization cancelled"
        );
        (
            project_name,
            version,
            description,
            main,
            test,
            repository,
            keywords,
            author,
            license,
            module_type,
        )
    };
    validate_link_package_name(&project_name)?;
    version
        .parse::<node_semver::Version>()
        .context("package version must be valid semver")?;

    let mut pkg = serde_json::json!({
        "name": project_name,
        "version": version,
        "description": description,
        "main": main,
        "scripts": {"test": test},
        "keywords": keywords,
        "author": author,
        "license": "UNLICENSED",
        "type": module_type
    });
    if license != "UNLICENSED" {
        pkg["license"] = serde_json::Value::String(license);
    }
    if !repository.is_empty() {
        pkg["repository"] = serde_json::Value::String(repository);
    }
    if private {
        pkg["private"] = serde_json::Value::Bool(true);
    }
    write_package_manifest(&pkg)?;
    println!("{}", serde_json::to_string_pretty(&pkg)?);
    Ok(())
}

fn cmd_init_scoped(
    yes: bool,
    scope: Option<&str>,
    private: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_init_one(yes, scope, private);
    }
    for target in selected_workspace_targets(workspace)? {
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        if PathBuf::from("package.json").exists() {
            println!("{} already has package.json", target.name);
        } else {
            cmd_init_one(yes, scope, private)?;
        }
    }
    Ok(())
}

// ---- WHY --------------------------------------------------------------------

fn cmd_why(package: &str, json_output: bool) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath why: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let content = std::fs::read_to_string(&lock_path)?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let packages = match lock.get("packages").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            println!("oath why: oath-lock.json has no packages");
            return Ok(());
        }
    };

    let normalized_query = package
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_end_matches('/')
        .to_owned();
    let query_name = normalized_query
        .rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .unwrap_or(&normalized_query);

    // Find all keys that match the package name (any version)
    let mut matches: Vec<(&str, &serde_json::Value)> = packages
        .iter()
        .filter(|(key, _)| {
            let k = key.as_str();
            let node = packages.get(k).expect("entry originated from package map");
            node.get("name").and_then(|name| name.as_str()) == Some(query_name)
                || k == normalized_query
                || k.starts_with(&format!("{query_name}@"))
                || k.ends_with(&format!("node_modules/{query_name}"))
        })
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    if matches.is_empty() {
        anyhow::bail!("'{package}' not found in oath-lock.json");
    }

    // Build reverse dependency map: pkg_key -> Vec<pkg_key that depends on it>
    let mut rdeps: HashMap<String, Vec<String>> = HashMap::new();
    for (key, node) in packages.iter() {
        if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
            for (dep_name, dep_ver) in deps.iter() {
                let target = dep_ver.as_str().unwrap_or("");
                let dep_key = if packages.contains_key(target) {
                    target.to_owned()
                } else {
                    format!("{dep_name}@{target}")
                };
                rdeps.entry(dep_key).or_default().push(key.clone());
            }
        }
    }

    // Determine roots from lockfile (packages with no reverse deps or explicit roots)
    let all_keys: HashSet<&str> = packages.keys().map(|k| k.as_str()).collect();

    // Read direct deps from package.json if available
    let direct_deps: HashSet<String> = if PathBuf::from("package.json").exists() {
        let pkg = read_package_json().unwrap_or(serde_json::json!({}));
        let mut d = extract_deps(&pkg, "dependencies");
        d.extend(extract_deps(&pkg, "devDependencies"));
        d.keys().cloned().collect()
    } else {
        HashSet::new()
    };

    // For each matched package, trace path to root and record machine-readable evidence.
    let mut records = Vec::new();
    matches.sort_by_key(|(k, _)| *k);
    for (key, node) in &matches {
        let name = node
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or(query_name);
        let version = node.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let has_install = node
            .get("hasInstallScript")
            .or_else(|| node.get("has_install_script"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let direct = direct_deps.contains(name);
        let path = if direct {
            Vec::new()
        } else {
            find_dep_path(key, &rdeps, &all_keys)
        };

        // Scan from store for capabilities/risk
        let store = ContentStore::default_store()?;
        let pkg_dir = store.package_dir_for(
            name,
            version,
            node.get("resolved").and_then(|value| value.as_str()),
            node.get("integrity").and_then(|value| value.as_str()),
        );

        let scan = pkg_dir
            .exists()
            .then(|| PackageScanner::scan(name, version, &pkg_dir))
            .transpose()?;
        records.push(serde_json::json!({
            "name": name,
            "version": version,
            "location": key,
            "direct": direct,
            "dependency_path": path,
            "store_present": pkg_dir.exists(),
            "risk": scan.as_ref().map(|report| report.overall_risk.to_string()),
            "capabilities": scan.as_ref().map(|report| fmt_capabilities(&report.capabilities)),
            "has_install_script": scan
                .as_ref()
                .is_some_and(|report| report.capabilities.has_install_scripts) || has_install,
        }));
    }
    if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    for record in records {
        println!(
            "  {}@{}",
            record["name"].as_str().unwrap_or(query_name),
            record["version"].as_str().unwrap_or("?")
        );
        if record["direct"].as_bool().unwrap_or(false) {
            println!("    why: required by your package.json (direct dependency)");
        } else if let Some(path) = record["dependency_path"].as_array()
            && !path.is_empty()
        {
            let chain = path
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(" -> ");
            println!("    why: required by {chain} -> root");
        } else {
            println!("    why: required by (unknown)");
        }
        if let Some(risk) = record["risk"].as_str() {
            println!("    risk: {risk}");
        }
        if let Some(capabilities) = record["capabilities"].as_str() {
            println!("    capabilities: {capabilities}");
        }
        println!(
            "    install script: {}",
            yn(record["has_install_script"].as_bool().unwrap_or(false))
        );
        println!();
    }
    Ok(())
}

/// BFS from `start` upward through rdeps to find path to a root node.
/// Returns the chain of package keys from direct parent up to (but not including) the root.
fn find_dep_path(
    start: &str,
    rdeps: &HashMap<String, Vec<String>>,
    _all_keys: &HashSet<&str>,
) -> Vec<String> {
    // BFS
    let mut queue: std::collections::VecDeque<(String, Vec<String>)> =
        std::collections::VecDeque::new();
    queue.push_back((start.to_string(), vec![]));
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(start.to_string());

    while let Some((current, path)) = queue.pop_front() {
        if let Some(parents) = rdeps.get(&current) {
            for parent in parents {
                if visited.contains(parent) {
                    continue;
                }
                let mut new_path = vec![parent.clone()];
                new_path.extend(path.iter().cloned());
                // If parent has no rdeps it's a root
                let parent_has_parents = rdeps.get(parent).map(|v| !v.is_empty()).unwrap_or(false);
                if !parent_has_parents {
                    return new_path;
                }
                visited.insert(parent.clone());
                queue.push_back((parent.clone(), new_path));
            }
        } else {
            // current is a root, return path
            return path;
        }
    }
    vec![]
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

fn installed_ls_dependency(
    modules: &std::path::Path,
    name: &str,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
) -> serde_json::Value {
    let package_dir = modules.join(name);
    let canonical = package_dir
        .canonicalize()
        .unwrap_or_else(|_| package_dir.clone());
    if !package_dir.join("package.json").is_file() {
        return serde_json::json!({ "missing": true });
    }
    if !visited.insert(canonical.clone()) {
        return serde_json::json!({ "deduped": true });
    }
    let manifest = std::fs::read_to_string(package_dir.join("package.json"))
        .ok()
        .and_then(|bytes| serde_json::from_str::<serde_json::Value>(&bytes).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut node = serde_json::Map::new();
    node.insert(
        "version".into(),
        manifest
            .get("version")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    );
    if depth > 0 {
        let mut dependencies = serde_json::Map::new();
        let mut names: Vec<_> = ["dependencies", "optionalDependencies"]
            .into_iter()
            .flat_map(|key| {
                manifest
                    .get(key)
                    .and_then(serde_json::Value::as_object)
                    .into_iter()
                    .flatten()
                    .map(|(name, _)| name.clone())
            })
            .collect();
        names.sort();
        names.dedup();
        for dependency in names {
            let local_modules = package_dir.join("node_modules");
            let child_modules = if local_modules.join(&dependency).exists() {
                local_modules
            } else {
                modules.to_path_buf()
            };
            dependencies.insert(
                dependency.clone(),
                installed_ls_dependency(&child_modules, &dependency, depth - 1, visited),
            );
        }
        if !dependencies.is_empty() {
            node.insert(
                "dependencies".into(),
                serde_json::Value::Object(dependencies),
            );
        }
    }
    visited.remove(&canonical);
    serde_json::Value::Object(node)
}

fn ls_root_dependency_names(manifest: &serde_json::Value, omit_dev: bool) -> Vec<String> {
    let mut names: Vec<_> = ["dependencies", "optionalDependencies"]
        .into_iter()
        .chain((!omit_dev).then_some("devDependencies"))
        .flat_map(|key| {
            manifest
                .get(key)
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flatten()
                .map(|(name, _)| name.clone())
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn ls_json_current(max_depth: usize, omit_dev: bool) -> Result<serde_json::Value> {
    let manifest = read_package_json()?;
    let names = ls_root_dependency_names(&manifest, omit_dev);
    let modules = std::env::current_dir()?.join("node_modules");
    let mut dependencies = serde_json::Map::new();
    let mut visited = HashSet::new();
    for name in names {
        dependencies.insert(
            name.clone(),
            installed_ls_dependency(&modules, &name, max_depth, &mut visited),
        );
    }
    Ok(serde_json::json!({
        "name": manifest["name"].as_str().unwrap_or("project"),
        "version": manifest["version"].as_str().unwrap_or("0.0.0"),
        "dependencies": dependencies,
    }))
}

fn cmd_ls_scoped(
    max_depth: usize,
    json_output: bool,
    omit_dev: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&ls_json_current(max_depth, omit_dev)?)?
            );
            return Ok(());
        }
        return cmd_graph(max_depth);
    }
    let targets = selected_workspace_targets(workspace)?;
    if json_output {
        let mut reports = Vec::new();
        for target in targets {
            let _guard = CurrentDirectoryGuard::enter(&target.path)?;
            reports.push(ls_json_current(max_depth, omit_dev)?);
        }
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    for target in targets {
        println!("oath: workspace {}", target.name);
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_graph(max_depth)?;
    }
    Ok(())
}

fn cmd_graph(max_depth: usize) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath graph: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let content = std::fs::read_to_string(&lock_path)?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let packages = match lock.get("packages").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            println!("oath graph: oath-lock.json has no packages");
            return Ok(());
        }
    };

    // Determine root keys: packages listed under "roots" or inferred from package.json
    let roots: Vec<String> = if let Some(r) = lock.get("roots").and_then(|r| r.as_array()) {
        r.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else {
        // Fall back: use direct deps from package.json if available
        if PathBuf::from("package.json").exists() {
            let pkg = read_package_json().unwrap_or(serde_json::json!({}));
            let name = pkg["name"].as_str().unwrap_or("project").to_string();
            let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
            // Print a synthetic root
            println!("  {name}@{version}");

            let mut direct_deps: Vec<String> = {
                let mut d: Vec<String> =
                    extract_deps(&pkg, "dependencies").keys().cloned().collect();
                d.extend(extract_deps(&pkg, "devDependencies").keys().cloned());
                d.sort();
                d
            };

            // Resolve each direct dep to a versioned key in the lockfile
            let root_children: Vec<String> = direct_deps
                .drain(..)
                .filter_map(|dep_name| {
                    // Find matching key in packages
                    packages
                        .keys()
                        .find(|k| {
                            let k = k.as_str();
                            k == dep_name || k.starts_with(&format!("{dep_name}@"))
                        })
                        .cloned()
                })
                .collect();

            print_graph_children(
                &root_children,
                packages,
                1,
                max_depth,
                &mut HashSet::new(),
                "",
            );
            println!();
            return Ok(());
        } else {
            // No package.json; pick nodes with no incoming edges as roots
            let mut has_parent: HashSet<&str> = HashSet::new();
            for node in packages.values() {
                if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
                    for (dep_name, dep_ver) in deps.iter() {
                        let dep_ver_str = dep_ver.as_str().unwrap_or("");
                        let dep_key = format!("{dep_name}@{dep_ver_str}");
                        if packages.contains_key(&dep_key) {
                            has_parent.insert(
                                packages
                                    .get_key_value(&dep_key)
                                    .map(|(k, _)| k.as_str())
                                    .unwrap_or(""),
                            );
                        }
                    }
                }
            }
            packages
                .keys()
                .filter(|k| !has_parent.contains(k.as_str()))
                .cloned()
                .collect()
        }
    };

    if roots.is_empty() {
        println!("  (no root packages found)");
        return Ok(());
    }

    for root_key in &roots {
        println!("  {root_key}");
        if let Some(root_node) = packages.get(root_key)
            && let Some(deps) = root_node.get("dependencies").and_then(|d| d.as_object())
        {
            let mut dep_keys: Vec<String> = deps
                .iter()
                .map(|(dep_name, dep_ver)| {
                    let dep_ver_str = dep_ver.as_str().unwrap_or("");
                    format!("{dep_name}@{dep_ver_str}")
                })
                .collect();
            dep_keys.sort();
            print_graph_children(&dep_keys, packages, 1, max_depth, &mut HashSet::new(), "");
        }
    }
    println!();
    Ok(())
}

fn print_graph_children(
    children: &[String],
    packages: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    prefix: &str,
) {
    let count = children.len();
    for (i, child_key) in children.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = "+--";
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}|   ")
        };

        println!("  {prefix}{connector} {child_key}");

        if depth >= max_depth {
            // Check if there are deeper deps but we're truncating
            if let Some(node) = packages.get(child_key)
                && let Some(deps) = node.get("dependencies").and_then(|d| d.as_object())
                && !deps.is_empty()
            {
                println!(
                    "  {child_prefix}... ({} more deps, use --depth to show)",
                    deps.len()
                );
            }
            continue;
        }

        if visited.contains(child_key) {
            println!("  {child_prefix}(circular)");
            continue;
        }

        visited.insert(child_key.clone());

        if let Some(node) = packages.get(child_key)
            && let Some(deps) = node.get("dependencies").and_then(|d| d.as_object())
        {
            let mut dep_keys: Vec<String> = deps
                .iter()
                .map(|(dep_name, dep_ver)| {
                    let dep_ver_str = dep_ver.as_str().unwrap_or("");
                    format!("{dep_name}@{dep_ver_str}")
                })
                .collect();
            dep_keys.sort();
            print_graph_children(
                &dep_keys,
                packages,
                depth + 1,
                max_depth,
                visited,
                &child_prefix,
            );
        }

        visited.remove(child_key);
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

#[derive(Debug, Default)]
struct DownloadSummary {
    downloaded: usize,
    bytes: u64,
    download_time: std::time::Duration,
    extraction_time: std::time::Duration,
    integrity_time: std::time::Duration,
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
    let mut set: JoinSet<Result<DownloadedPackage>> = JoinSet::new();
    for node in to_download {
        let client = Arc::clone(&client);
        let limits = limits.clone();
        set.spawn(async move {
            download_tarball_to_temp(
                client,
                node.name,
                node.version,
                node.resolved,
                node.integrity,
                limits,
            )
            .await
        });
    }

    let download_start = Instant::now();
    let mut downloaded_packages = Vec::new();
    while let Some(res) = set.join_next().await {
        downloaded_packages.push(res??);
    }
    summary.download_time = download_start.elapsed();

    for downloaded in downloaded_packages {
        summary.bytes += downloaded.bytes;
        let tmp = tempfile::tempdir()?;
        let extraction_start = Instant::now();
        oath_fetch::tarball::extract_tarball_file_limited(
            &downloaded.tarball_path,
            tmp.path(),
            &limits,
        )?;
        summary.extraction_time += extraction_start.elapsed();
        let integrity_start = Instant::now();
        store.store_package_variant_with_manifest(
            &downloaded.name,
            &downloaded.version,
            Some(&downloaded.resolved),
            downloaded.integrity.as_deref(),
            tmp.path(),
        )?;
        summary.integrity_time += integrity_start.elapsed();
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
            let http = reqwest::Client::builder()
                .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
                .build()?;
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

fn npm_save_spec(requested: &str) -> String {
    if requested.parse::<node_semver::Version>().is_ok() {
        format!("^{requested}")
    } else {
        requested.to_string()
    }
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
    if bins.len() == 1 || bins.iter().all(|(_, path)| path == &bins[0].1) {
        return bins.first().map(|(_, path)| path.clone());
    }
    bins.iter()
        .find(|(name, _)| name == install_name || name == basename)
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

/// Run a package's install scripts through verified native containment.
fn run_install_script(pkg_name: &str, pkg_dir: &std::path::Path) -> Result<()> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let scripts = match value.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s.clone(),
        None => return Ok(()),
    };
    let mut npm_env = npm_package_env(&value);
    let dependency_bin = pkg_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "node_modules"))
        .map(|modules| modules.join(".bin"));
    if let Some(bin) = dependency_bin {
        let mut paths = vec![bin];
        if let Some(path) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&path));
        }
        npm_env.push((
            "PATH".into(),
            std::env::join_paths(paths)?.to_string_lossy().into_owned(),
        ));
    }

    for hook in &["preinstall", "install", "postinstall"] {
        if let Some(cmd) = scripts.get(*hook).and_then(|v| v.as_str()) {
            tracing::debug!("running {hook} for {pkg_name}: {cmd}");
            run_contained_lifecycle(pkg_name, pkg_dir, hook, cmd, &npm_env)?;
        }
    }
    Ok(())
}

fn run_contained_lifecycle(
    package: &str,
    workdir: &std::path::Path,
    hook: &str,
    command: &str,
    environment: &[(String, String)],
) -> Result<()> {
    let capabilities = oath_sandbox::verified_native_capabilities();
    anyhow::ensure!(
        capabilities.available
            && capabilities.filesystem_isolation
            && capabilities.network_isolation
            && capabilities.process_isolation
            && capabilities.resource_limits,
        "verified native lifecycle containment is unavailable ({}); use --ignore-scripts: {}",
        capabilities.backend,
        capabilities
            .degraded_reason
            .as_deref()
            .unwrap_or("required controls were not verified")
    );
    let mut plan = oath_sandbox::SandboxPlan::strict(package, workdir.to_path_buf());
    if let Some(modules) = workdir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "node_modules"))
    {
        plan.read_only_paths.push(modules.to_path_buf());
    }
    #[cfg(target_os = "macos")]
    plan.read_only_paths.push(active_node_executable()?);

    #[cfg(not(target_os = "windows"))]
    let (program, args) = {
        fn quote(value: &str) -> String {
            format!("'{}'", value.replace('\'', "'\"'\"'"))
        }
        let mut prefix = format!(
            "export npm_lifecycle_event={} npm_lifecycle_script={}; ",
            quote(hook),
            quote(command)
        );
        for (name, value) in environment {
            if name.chars().enumerate().all(|(index, character)| {
                character == '_'
                    || character.is_ascii_alphanumeric()
                        && (index > 0 || !character.is_ascii_digit())
            }) {
                prefix.push_str(&format!("export {name}={}; ", quote(value)));
            }
        }
        (
            std::path::PathBuf::from("/bin/sh"),
            vec!["-c".to_owned(), format!("{prefix}{command}")],
        )
    };
    #[cfg(target_os = "windows")]
    let (program, args) = {
        let escaped = command.replace('%', "%%");
        let mut prefix = String::new();
        for (name, value) in environment {
            if name.chars().enumerate().all(|(index, character)| {
                character == '_'
                    || character.is_ascii_alphanumeric()
                        && (index > 0 || !character.is_ascii_digit())
            }) {
                let quoted = value.replace('"', "\"\"");
                prefix.push_str(&format!("set \"{name}={quoted}\" && "));
            }
        }
        (
            std::path::PathBuf::from(
                std::env::var("ComSpec")
                    .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
            ),
            vec![
                "/D".into(),
                "/S".into(),
                "/C".into(),
                format!("{prefix}{escaped}"),
            ],
        )
    };

    #[cfg(target_os = "linux")]
    let status = oath_sandbox::linux::run(&plan, &program, &args)?;
    #[cfg(target_os = "macos")]
    let status = oath_sandbox::macos::run(&plan, &program, &args)?;
    #[cfg(target_os = "windows")]
    let status = oath_sandbox::windows::run(&plan, &program, &args)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("native lifecycle containment is unsupported on this platform");

    anyhow::ensure!(
        status.success(),
        "contained {hook} lifecycle for {package} exited with {}",
        status.code().unwrap_or(-1)
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn active_node_executable() -> Result<std::path::PathBuf> {
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .context("failed to resolve the active Node executable")?;
    anyhow::ensure!(node.status.success(), "active Node executable probe failed");
    let node = std::path::PathBuf::from(String::from_utf8(node.stdout)?.trim());
    std::fs::canonicalize(&node)
        .with_context(|| format!("failed to canonicalize Node executable {}", node.display()))
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
    allow_uncontained: bool,
) -> Result<ExecSandboxDecision> {
    let agent_mode = std::env::var("OATH_AGENT_MODE")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    let requested_mode = if allow_uncontained {
        ExecSandboxMode::Off
    } else if sandbox {
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
        anyhow::ensure!(
            allow_uncontained,
            "uncontained package execution is disabled; use --allow-uncontained only for explicit npm compatibility"
        );
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
        return oath_sandbox::linux::run(
            plan,
            std::path::Path::new("/usr/bin/node"),
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

#[allow(clippy::too_many_arguments)]
async fn cmd_exec_scoped(
    package: Option<&str>,
    packages: &[String],
    args: &[String],
    call: Option<&str>,
    yes: bool,
    no: bool,
    min_age: Option<&str>,
    json: bool,
    schema_version: u32,
    require_grade: Option<&str>,
    dry_run: bool,
    sandbox: bool,
    sandbox_mode: ExecSandboxMode,
    allow_uncontained: bool,
    deny_network: bool,
    allow_degraded_sandbox: bool,
    remember: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_exec(
            package,
            packages,
            args,
            call,
            yes,
            no,
            min_age,
            json,
            schema_version,
            require_grade,
            dry_run,
            sandbox,
            sandbox_mode,
            allow_uncontained,
            deny_network,
            allow_degraded_sandbox,
            remember,
        )
        .await;
    }
    let targets = selected_workspace_targets(workspace)?;
    anyhow::ensure!(
        !json || targets.len() == 1,
        "--json requires exactly one selected workspace"
    );
    let executable = std::env::current_exe()?;
    for target in targets {
        println!("oath: workspace {}", target.name);
        let mut command = std::process::Command::new(&executable);
        command.current_dir(&target.path).arg("exec");
        for package in packages {
            command.arg("--package").arg(package);
        }
        if let Some(package) = package {
            command.arg(package);
        }
        if let Some(call) = call {
            command.arg("--call").arg(call);
        }
        if yes {
            command.arg("--yes");
        }
        if no {
            command.arg("--no");
        }
        if let Some(min_age) = min_age {
            command.arg("--min-age").arg(min_age);
        }
        if json {
            command.arg("--json");
        }
        command
            .arg("--schema-version")
            .arg(schema_version.to_string());
        if let Some(grade) = require_grade {
            command.arg("--require-grade").arg(grade);
        }
        if dry_run {
            command.arg("--dry-run");
        }
        if sandbox {
            command.arg("--sandbox");
        }
        command.arg("--sandbox-mode").arg(sandbox_mode.as_str());
        if allow_uncontained {
            command.arg("--allow-uncontained");
        }
        if deny_network {
            command.arg("--deny-network");
        }
        if allow_degraded_sandbox {
            command.arg("--allow-degraded-sandbox");
        }
        if remember {
            command.arg("--remember");
        }
        if !args.is_empty() {
            command.arg("--").args(args);
        }
        let status = command
            .status()
            .with_context(|| format!("failed to execute in workspace {}", target.name))?;
        anyhow::ensure!(
            status.success(),
            "workspace {} exec failed with {status}",
            target.name
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_exec(
    package: Option<&str>,
    packages: &[String],
    args: &[String],
    call: Option<&str>,
    yes: bool,
    no: bool,
    min_age: Option<&str>,
    json: bool,
    schema_version: u32,
    require_grade: Option<&str>,
    dry_run: bool,
    sandbox: bool,
    sandbox_mode: ExecSandboxMode,
    allow_uncontained: bool,
    deny_network: bool,
    allow_degraded_sandbox: bool,
    remember: bool,
) -> Result<()> {
    use oath_analyze::{
        FindingKind, PackageScanner, RiskLevel, ScoreContext, compute_safety_score_contextual,
    };
    use std::io::Write;

    let start = std::time::Instant::now();
    anyhow::ensure!(
        matches!(schema_version, 2 | 3),
        "unsupported exec assessment schema {schema_version}; supported versions are 2 and 3"
    );
    if package.is_none() && packages.is_empty() && call.is_none() {
        anyhow::ensure!(
            args.is_empty(),
            "interactive exec does not accept command arguments"
        );
        anyhow::ensure!(
            !json && !dry_run && require_grade.is_none() && min_age.is_none() && !remember,
            "assessment-only flags require an exec package or --call"
        );
        let sandbox_decision = resolve_exec_sandbox(
            sandbox,
            sandbox_mode,
            allow_degraded_sandbox,
            allow_uncontained,
        )?;
        let status =
            run_exec_interactive_shell(&std::env::current_dir()?, sandbox_decision.effective_mode)?;
        std::process::exit(status.code().unwrap_or(1));
    }
    let invocation = normalize_exec_invocation(package, packages, args, call)?;
    let primary_spec = invocation
        .packages
        .first()
        .context("exec requires at least one package")?;
    let (pkg_name, pkg_version) = parse_package_spec(primary_spec);
    let sandbox_decision = resolve_exec_sandbox(
        sandbox,
        sandbox_mode,
        allow_degraded_sandbox,
        allow_uncontained,
    )?;
    let effective_deny_network = deny_network || sandbox_decision.agent_mode;

    // Local node_modules/.bin fast path: already installed by the project (trusted).
    let local_bin = PathBuf::from("node_modules/.bin").join(&invocation.command);
    if no && !local_bin.exists() {
        anyhow::bail!(
            "{} is not installed locally and --no forbids downloading it",
            invocation.command
        );
    }
    if local_bin.exists() && !dry_run && sandbox_decision.effective_mode == ExecSandboxMode::Off {
        if !json {
            eprintln!("oath exec: running {} (local)", pkg_name);
        }
        let status = std::process::Command::new(&local_bin)
            .args(&invocation.args)
            .status()
            .with_context(|| format!("failed to execute {}", pkg_name))?;
        std::process::exit(status.code().unwrap_or(1));
    }

    if !json {
        eprintln!("oath exec: inspecting {}@{}...", pkg_name, pkg_version);
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
            std::process::exit(EXEC_EXIT_AGE);
        }
    }

    // Plan the full temporary install with the same placement authority used by
    // `install`; Oath still owns download, integrity, scanning, and execution.
    let exec_dir = tempfile::tempdir()?;
    let exec_path = exec_dir.path().to_path_buf();
    let mut exec_dependencies = serde_json::Map::new();
    exec_dependencies.insert(pkg_name.clone(), serde_json::Value::String(version.clone()));
    let mut approval_packages = vec![serde_json::json!({
        "name": pkg_name.clone(),
        "version": version.clone(),
        "integrity": info.dist.integrity.clone(),
    })];
    for package in invocation.packages.iter().skip(1) {
        let (name, requested) = parse_package_spec(package);
        let packument = client
            .fetch_packument(&name)
            .await
            .with_context(|| format!("fetching {name}"))?;
        let resolved = oath_fetch::resolve_version(&packument, &requested)
            .with_context(|| format!("resolving {name}@{requested}"))?;
        approval_packages.push(serde_json::json!({
            "name": name.clone(),
            "version": resolved.version.to_string(),
            "integrity": resolved.info.dist.integrity.clone(),
        }));
        exec_dependencies.insert(
            name,
            serde_json::Value::String(resolved.version.to_string()),
        );
    }
    let approval_integrity = oath_contracts::digest_json(&approval_packages)?;
    let exec_pkg = serde_json::json!({
        "name": "oath-exec-tmp",
        "version": "0.0.0",
        "dependencies": exec_dependencies
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
    let mut report = PackageScanner::scan(&pkg_name, &version, &pkg_dir)?;
    for package in invocation.packages.iter().skip(1) {
        let package_name = parse_package_spec(package).0;
        let package_dir = exec_path.join("node_modules").join(&package_name);
        let package_version = std::fs::read_to_string(package_dir.join("package.json"))
            .ok()
            .and_then(|manifest| serde_json::from_str::<serde_json::Value>(&manifest).ok())
            .and_then(|manifest| manifest["version"].as_str().map(String::from))
            .context("temporary exec package is missing a version")?;
        let extra = PackageScanner::scan(&package_name, &package_version, &package_dir)?;
        report.overall_risk = report.overall_risk.max(extra.overall_risk);
        report.files_scanned += extra.files_scanned;
        report.lines_scanned += extra.lines_scanned;
        report.findings.extend(extra.findings);
        report.verdict_reasons.extend(
            extra
                .verdict_reasons
                .into_iter()
                .map(|reason| format!("{package_name}: {reason}")),
        );
        report.capabilities.network |= extra.capabilities.network;
        report.capabilities.filesystem |= extra.capabilities.filesystem;
        report.capabilities.env_access |= extra.capabilities.env_access;
        report.capabilities.subprocess |= extra.capabilities.subprocess;
        report.capabilities.dynamic_exec |= extra.capabilities.dynamic_exec;
        report.capabilities.has_install_scripts |= extra.capabilities.has_install_scripts;
        report.capabilities.native_addon |= extra.capabilities.native_addon;
    }
    let caps = &report.capabilities;
    // Popularity/age context so the grade (and any --require-grade gate) trusts
    // widely-used packages: a flagged-but-1M+-download package with no critical
    // finding is a false positive, not something to block on an npx-style run.
    let ctx = {
        let mut weekly = 0u64;
        let mut age = 0u32;
        if let Ok(http) = reqwest::Client::builder()
            .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
            .build()
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
    let mut preferred_binary = if pkg_json_path.exists() {
        let pkg_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pkg_json_path)?)?;
        preferred_bin_path(&pkg_json, &pkg_name)
    } else {
        None
    };
    if invocation.explicit_packages && invocation.call.is_none() {
        preferred_binary = None;
        for package in &invocation.packages {
            let package_name = parse_package_spec(package).0;
            let package_dir = exec_path.join("node_modules").join(&package_name);
            let manifest_path = package_dir.join("package.json");
            if !manifest_path.exists() {
                continue;
            }
            let manifest: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
            if let Some((_, path)) = safe_bin_entries(&manifest, &package_name)
                .into_iter()
                .find(|(name, _)| name == &invocation.command)
            {
                preferred_binary = Some(package_dir.join(path));
                break;
            }
        }
        anyhow::ensure!(
            preferred_binary.is_some(),
            "none of the requested packages exposes a '{}' binary",
            invocation.command
        );
    }

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
        integrity: approval_integrity.clone(),
        capabilities: perms.iter().map(|p| (*p).to_string()).collect(),
        sandbox_backend: assessment.sandbox.backend.clone(),
        deny_network: effective_deny_network,
    };
    let approval_store = approvals::ApprovalStore::default_store()?;
    let previously_approved =
        !approval.integrity.is_empty() && approval_store.contains(&approval)?;

    if json {
        let policy_digest = oath_contracts::digest_json(&serde_json::json!({
            "packages": approval_packages,
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
            std::process::exit(EXEC_EXIT_GRADE);
        }
        if dry_run {
            return Ok(());
        }
    } else {
        // Human pre-run card.
        eprintln!("\n  {}@{}", pkg_name, version);
        eprintln!("  grade        {} ({}/100)", score.grade, score.score);
        if let Some(d) = age_days {
            eprintln!("  published    {d} days ago");
        }
        if let Some(p) = &last_publisher {
            eprintln!("  publisher    {p}");
        }
        eprintln!(
            "  open source  {}",
            if open_source { "yes" } else { "unknown" }
        );
        eprintln!(
            "  source       {}",
            if obfuscated { "obfuscated" } else { "readable" }
        );
        eprintln!("  size         {unpacked_kb} KB");
        eprintln!(
            "  permissions  {}",
            if perms.is_empty() {
                "none".to_string()
            } else {
                perms.join(", ")
            }
        );
        if sandbox_decision.effective_mode != ExecSandboxMode::Off {
            eprintln!(
                "  sandbox      {}",
                sandbox_decision.effective_mode.as_str()
            );
        }
        if !serious.is_empty() {
            eprintln!("\n  findings:");
            for finding in serious.iter().take(5) {
                eprintln!("    {finding}");
            }
        }
        if grade_blocked {
            eprintln!(
                "\n  BLOCKED -- grade {} is below required {}",
                score.grade,
                require_grade.unwrap_or("")
            );
            std::process::exit(EXEC_EXIT_GRADE);
        }
        if dry_run {
            return Ok(());
        }
        let needs_prompt = !serious.is_empty()
            && !yes
            && !previously_approved
            && std::env::var("OATH_ALLOW_ALL").is_err();
        if needs_prompt {
            print!("\n  run anyway? [y/N] ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("  blocked.");
                std::process::exit(EXEC_EXIT_USER);
            }
        }
    }

    if remember {
        anyhow::ensure!(
            !approval.integrity.is_empty(),
            "cannot remember an approval without registry integrity"
        );
        approval_store.remember(approval)?;
    }

    // Persist only immutable identity metadata. Executable files stay in the
    // verified CAS and every invocation receives a fresh temporary tree, so a
    // prior command cannot poison a later npx-style run.
    write_npx_cache_record(&approval_integrity, &approval_packages)?;

    // Find the binary.
    let bin_path = preferred_binary
        .map(|relative| pkg_dir.join(relative))
        .with_context(|| {
            format!(
                "could not determine a unique executable for {pkg_name}; use --package with an explicit command"
            )
        })?;

    let elapsed = start.elapsed();
    if !json && elapsed.as_millis() > 100 {
        eprintln!("  fetched + scanned in {:.1}s", elapsed.as_secs_f64());
    }

    let status = if let Some(call) = &invocation.call {
        run_exec_call(
            call,
            &exec_path,
            sandbox_decision.effective_mode,
            sandbox_plan.as_ref(),
        )
        .context("failed to execute --call")?
    } else {
        run_node_binary(
            &bin_path,
            &invocation.args,
            &exec_path,
            sandbox_decision.effective_mode,
            sandbox_plan.as_ref(),
        )
        .with_context(|| format!("failed to execute node {}", bin_path.display()))?
    };
    std::process::exit(status.code().unwrap_or(1));
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
        if let Ok(http) = reqwest::Client::builder()
            .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
            .build()
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

fn view_field_values(
    selected: &serde_json::Value,
    fields: &[String],
) -> Result<Vec<(String, serde_json::Value)>> {
    fields
        .iter()
        .map(|field| {
            let path = parse_json_path(field)?;
            let value = json_path_get(selected, &path)
                .cloned()
                .with_context(|| format!("package metadata has no field {field}"))?;
            Ok((field.clone(), value))
        })
        .collect()
}

async fn print_info_report(pkg_name: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let meta = oath_fetch::fetch_package_metadata(&client, pkg_name).await?;

    println!();
    println!("  {}@{}", meta.name, meta.latest_version);
    println!();

    println!("  maintainers:");
    for m in &meta.maintainers {
        if let Some(email) = &m.email {
            println!("    {} <{}>", m.name, email);
        } else {
            println!("    {}", m.name);
        }
    }
    println!();

    if let Some(downloads) = meta.weekly_downloads {
        println!("  weekly downloads: {}", format_downloads(downloads));
    }
    println!("  total versions:   {}", meta.total_versions);
    if let Some(ref published) = meta.published_at {
        println!("  latest published: {published}");
    }
    if let Some(age) = meta.last_publish_age_days {
        println!("  publish age:      {age} days ago");
    }
    println!();

    if let Some(ref license) = meta.license {
        println!("  license:    {license}");
    }
    if let Some(ref repo) = meta.repository {
        println!("  repository: {repo}");
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

async fn cmd_view(package: Option<&str>, fields: &[String], json_output: bool) -> Result<()> {
    let package = current_or_requested_package(package.map(String::from))?;
    let (name, requested) = parse_package_spec(&package);
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &requested)
        .with_context(|| format!("resolving {package}"))?;
    let version = resolved.version.to_string();
    let full = client.fetch_packument_full(&name).await?;
    let mut selected = full
        .get("versions")
        .and_then(|versions| versions.get(&version))
        .cloned()
        .context("registry metadata does not contain the selected version")?;
    let selected_object = selected
        .as_object_mut()
        .context("selected package metadata is not an object")?;
    for key in [
        "dist-tags",
        "time",
        "maintainers",
        "versions",
        "readme",
        "readmeFilename",
    ] {
        if let Some(value) = full.get(key) {
            selected_object
                .entry(key.to_owned())
                .or_insert_with(|| value.clone());
        }
    }

    let values = view_field_values(&selected, fields)?;
    if json_output {
        let value = match values.as_slice() {
            [] => selected,
            [(_, value)] => value.clone(),
            _ => serde_json::Value::Object(values.into_iter().collect()),
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if values.is_empty() {
        print_info_report(&name).await?;
        return Ok(());
    }
    for (field, value) in values {
        let rendered = value
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| value.to_string());
        if fields.len() == 1 {
            println!("{rendered}");
        } else {
            println!("{field} = {rendered}");
        }
    }
    Ok(())
}

fn cmd_pack_scoped(
    destination: &std::path::Path,
    dry_run: bool,
    json_output: bool,
    ignore_scripts: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_pack(destination, dry_run, json_output, ignore_scripts);
    }
    let targets = selected_workspace_targets(workspace)?;
    let destination = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    if json_output {
        let mut reports = Vec::with_capacity(targets.len());
        for target in targets {
            let _guard = CurrentDirectoryGuard::enter(&target.path)?;
            reports.push(pack_report(&destination, dry_run, ignore_scripts)?);
        }
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    for target in targets {
        println!("oath: workspace {}", target.name);
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_pack(&destination, dry_run, json_output, ignore_scripts)?;
    }
    Ok(())
}

fn cmd_pack(
    destination: &std::path::Path,
    dry_run: bool,
    json_output: bool,
    ignore_scripts: bool,
) -> Result<()> {
    let report = pack_report(destination, dry_run, ignore_scripts)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if dry_run {
        println!("{}", report["filename"].as_str().unwrap_or("package.tgz"));
    } else {
        println!("{}", report["path"].as_str().unwrap_or_default());
    }
    Ok(())
}

fn run_current_package_lifecycle(hooks: &[&str], ignore_scripts: bool) -> Result<()> {
    if ignore_scripts {
        return Ok(());
    }
    let manifest = read_package_json()?;
    let Some(scripts) = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let name = manifest["name"].as_str().unwrap_or("project");
    let cwd = std::env::current_dir()?;
    let environment = npm_package_env(&manifest);
    for hook in hooks {
        if let Some(command) = scripts.get(*hook).and_then(serde_json::Value::as_str) {
            run_contained_lifecycle(name, &cwd, hook, command, &environment)?;
        }
    }
    Ok(())
}

fn pack_report(
    destination: &std::path::Path,
    dry_run: bool,
    ignore_scripts: bool,
) -> Result<serde_json::Value> {
    use sha2::{Digest, Sha256};

    run_current_package_lifecycle(&["prepack", "prepare"], ignore_scripts)?;
    let manifest = read_package_json()?;
    let name = manifest["name"]
        .as_str()
        .context("package.json name is required for pack")?;
    let version = manifest["version"]
        .as_str()
        .context("package.json version is required for pack")?;
    let safe = |value: &str| {
        value
            .trim_start_matches('@')
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>()
    };
    let filename = format!("{}-{}.tgz", safe(name), safe(version));
    let tarball = pack_local_package(&std::env::current_dir()?)?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&tarball)));
    let output = destination.join(&filename);
    if !dry_run {
        std::fs::create_dir_all(destination)
            .with_context(|| format!("create pack destination {}", destination.display()))?;
        std::fs::write(&output, &tarball)
            .with_context(|| format!("write package tarball {}", output.display()))?;
    }
    let files = native_publish_packlist(&std::env::current_dir()?)?
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(std::env::current_dir().ok()?)
                .ok()
                .map(|relative| serde_json::json!({ "path": relative.to_string_lossy() }))
        })
        .collect::<Vec<_>>();
    run_current_package_lifecycle(&["postpack"], ignore_scripts)?;
    Ok(serde_json::json!({
        "schema_version": 1,
        "name": name,
        "version": version,
        "filename": filename,
        "path": output,
        "bytes": tarball.len(),
        "sha256": digest,
        "dry_run": dry_run,
        "files": files,
    }))
}

#[derive(Debug, serde::Serialize)]
struct OutdatedDependency {
    package: String,
    dependency_type: &'static str,
    current: Option<String>,
    wanted: String,
    latest: String,
}

async fn cmd_outdated_scoped(
    json_output: bool,
    global: bool,
    workspace: &WorkspaceArgs,
) -> Result<bool> {
    anyhow::ensure!(
        !(global && workspace.active()),
        "--global cannot be combined with workspace filters"
    );
    if global {
        let root = global_prefix()?;
        anyhow::ensure!(
            root.join("package.json").is_file(),
            "no globally installed Oath packages"
        );
        let _guard = CurrentDirectoryGuard::enter(&root)?;
        return cmd_outdated(json_output).await;
    }
    if !workspace.active() {
        return cmd_outdated(json_output).await;
    }

    let targets = selected_workspace_targets(workspace)?;
    let mut any_outdated = false;
    for target in targets {
        if !json_output {
            println!("oath: workspace {}", target.name);
        }
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        any_outdated |= cmd_outdated(json_output)
            .await
            .with_context(|| format!("failed to inspect outdated packages in {}", target.name))?;
    }
    Ok(any_outdated)
}

async fn cmd_outdated(json_output: bool) -> Result<bool> {
    let manifest = read_package_json()?;
    let lockfile = Lockfile::read(&PathBuf::from("oath-lock.json")).ok();
    let mut requested = Vec::new();
    for (dependency_type, key) in [
        ("dependencies", "dependencies"),
        ("devDependencies", "devDependencies"),
    ] {
        for (name, spec) in extract_deps(&manifest, key) {
            requested.push((name, spec, dependency_type));
        }
    }
    requested.sort_by(|left, right| left.0.cmp(&right.0));

    let client = RegistryClient::default_client()?;
    let mut tasks = JoinSet::new();
    for (name, spec, dependency_type) in requested {
        let client = client.clone();
        let registry_name = alias_registry_name(&name, &spec);
        let current = lockfile
            .as_ref()
            .and_then(|lockfile| direct_lock_version(lockfile, &name))
            .or_else(|| installed_package_version(std::path::Path::new("."), &name));
        tasks.spawn(async move {
            let packument = client.fetch_packument(&registry_name).await?;
            let wanted = oath_fetch::resolve_version(&packument, &spec)?
                .version
                .to_owned();
            let latest = packument
                .latest_version()
                .context("registry packument has no latest dist-tag")?
                .to_owned();
            Ok::<_, anyhow::Error>(OutdatedDependency {
                package: name,
                dependency_type,
                current,
                wanted,
                latest,
            })
        });
    }
    let mut outdated = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let row = result??;
        if row.current.as_deref() != Some(row.wanted.as_str())
            || row.current.as_deref() != Some(row.latest.as_str())
        {
            outdated.push(row);
        }
    }
    outdated.sort_by(|left, right| left.package.cmp(&right.package));
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "outdated": outdated,
                "count": outdated.len(),
            }))?
        );
    } else if outdated.is_empty() {
        println!("All direct dependencies are current");
    } else {
        println!("Package\tCurrent\tWanted\tLatest\tType");
        for row in &outdated {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                row.package,
                row.current.as_deref().unwrap_or("MISSING"),
                row.wanted,
                row.latest,
                row.dependency_type
            );
        }
    }
    Ok(!outdated.is_empty())
}

fn installed_package_version(root: &std::path::Path, package: &str) -> Option<String> {
    let manifest = root.join("node_modules").join(package).join("package.json");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(manifest).ok()?).ok()?;
    value.get("version")?.as_str().map(str::to_owned)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NpxCacheRecord {
    schema_version: u32,
    key: String,
    created_at: u64,
    packages: Vec<serde_json::Value>,
    storage: String,
}

fn npx_cache_root() -> Result<PathBuf> {
    let oath_home = std::env::var_os("OATH_HOME")
        .map(PathBuf::from)
        .or_else(|| oath_core::home_dir().map(|home| home.join(".oath")))
        .context("could not determine Oath home directory")?;
    Ok(oath_home.join("npx-cache"))
}

fn validate_npx_cache_key(key: &str) -> Result<()> {
    anyhow::ensure!(
        key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "npx cache key must be a 64-character hexadecimal digest"
    );
    Ok(())
}

fn write_npx_cache_record(integrity: &str, packages: &[serde_json::Value]) -> Result<String> {
    let key = integrity.strip_prefix("sha256:").unwrap_or(integrity);
    validate_npx_cache_key(key)?;
    let root = npx_cache_root()?;
    std::fs::create_dir_all(&root)?;
    let record = NpxCacheRecord {
        schema_version: 1,
        key: key.to_owned(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        packages: packages.to_vec(),
        storage: "verified-cas-fresh-exec-environment".to_owned(),
    };
    write_manifest_atomic(
        &root.join(format!("{key}.json")),
        format!("{}\n", serde_json::to_string_pretty(&record)?).as_bytes(),
    )?;
    Ok(key.to_owned())
}

fn read_npx_cache_records() -> Result<Vec<NpxCacheRecord>> {
    let root = npx_cache_root()?;
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(Vec::new());
    };
    let mut records = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect::<Vec<NpxCacheRecord>>();
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(records)
}

fn cmd_cache_npx(action: NpxCacheAction) -> Result<()> {
    match action {
        NpxCacheAction::Ls { json } => {
            let records = read_npx_cache_records()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                for record in records {
                    println!("{}\t{} package(s)", record.key, record.packages.len());
                }
            }
        }
        NpxCacheAction::Info { key, json } => {
            validate_npx_cache_key(&key)?;
            let bytes = std::fs::read(npx_cache_root()?.join(format!("{key}.json")))
                .with_context(|| format!("npx cache record not found: {key}"))?;
            let record: NpxCacheRecord = serde_json::from_slice(&bytes)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!(
                    "{}\t{} package(s)\t{}",
                    record.key,
                    record.packages.len(),
                    record.storage
                );
            }
        }
        NpxCacheAction::Rm { key } => {
            validate_npx_cache_key(&key)?;
            std::fs::remove_file(npx_cache_root()?.join(format!("{key}.json")))
                .with_context(|| format!("npx cache record not found: {key}"))?;
            println!("removed {key}");
        }
    }
    Ok(())
}

fn direct_lock_version(lockfile: &Lockfile, install_name: &str) -> Option<String> {
    let direct_location = format!("node_modules/{install_name}");
    lockfile
        .packages
        .get(&direct_location)
        .or_else(|| {
            lockfile.packages.iter().find_map(|(key, entry)| {
                (lockfile.roots.contains(key)
                    && (entry.package_name_for_key(key) == install_name
                        || entry.alias.as_deref() == Some(install_name)))
                .then_some(entry)
            })
        })
        .map(|entry| entry.version.clone())
}

fn alias_registry_name(install_name: &str, spec: &str) -> String {
    let Some(alias) = spec.strip_prefix("npm:") else {
        return install_name.to_owned();
    };
    if let Some(scoped) = alias.strip_prefix('@') {
        return scoped
            .find('@')
            .map(|separator| format!("@{}", &scoped[..separator]))
            .unwrap_or_else(|| format!("@{scoped}"));
    }
    alias
        .rsplit_once('@')
        .map_or(alias, |(name, _)| name)
        .to_owned()
}

async fn cmd_cache_add(package: &str) -> Result<()> {
    let (name, requested) = parse_package_spec(package);
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &requested)?;
    let version = resolved.version.to_string();
    let info = resolved.info;
    let store = ContentStore::default_store()?;
    if !store
        .verify_package_variant(
            &name,
            &version,
            Some(&info.dist.tarball),
            info.dist.integrity.as_deref(),
        )
        .is_verified()
    {
        let limits = TarballLimits::from_env()?;
        let temp = tempfile::tempdir()?;
        let tarball = temp.path().join("package.tgz");
        client
            .fetch_tarball_to_file(
                &info.dist.tarball,
                info.dist.integrity.as_deref(),
                &tarball,
                &limits,
            )
            .await?;
        let extracted = tempfile::tempdir()?;
        oath_fetch::tarball::extract_tarball_file_limited(&tarball, extracted.path(), &limits)?;
        store.store_package_with_manifest(
            &name,
            &version,
            Some(&info.dist.tarball),
            info.dist.integrity.as_deref(),
            extracted.path(),
        )?;
    }
    println!("cached {name}@{version}");
    Ok(())
}

fn cmd_cache_ls(json_output: bool) -> Result<()> {
    let store = ContentStore::default_store()?;
    let mut packages = store.list_packages();
    packages.sort();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "packages": packages.iter().map(|(name, version)| format!("{name}@{version}")).collect::<Vec<_>>(),
                "total_size_bytes": store.total_size(),
            }))?
        );
    } else {
        for (name, version) in packages {
            println!("{name}@{version}");
        }
    }
    Ok(())
}

fn cmd_cache_clean(force: bool) -> Result<()> {
    let store = ContentStore::default_store()?;
    let removed = clean_cache_store(&store, force)?;
    println!("removed {removed} cached package versions");
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum JsonPathPart {
    Key(String),
    Index(usize),
}

fn parse_json_path(path: &str) -> Result<Vec<JsonPathPart>> {
    anyhow::ensure!(!path.is_empty(), "package property path cannot be empty");
    let mut parts = Vec::new();
    for segment in path.split('.') {
        anyhow::ensure!(!segment.is_empty(), "invalid package property path {path}");
        let mut rest = segment;
        if let Some(bracket) = rest.find('[') {
            let key = &rest[..bracket];
            if !key.is_empty() {
                parts.push(JsonPathPart::Key(key.to_string()));
            }
            rest = &rest[bracket..];
            while !rest.is_empty() {
                anyhow::ensure!(
                    rest.starts_with('['),
                    "invalid package property path {path}"
                );
                let end = rest.find(']').context("unclosed package property index")?;
                let index = rest[1..end]
                    .parse::<usize>()
                    .context("package property array index must be numeric")?;
                parts.push(JsonPathPart::Index(index));
                rest = &rest[end + 1..];
            }
        } else {
            parts.push(JsonPathPart::Key(rest.to_string()));
        }
    }
    Ok(parts)
}

fn json_path_get<'a>(
    value: &'a serde_json::Value,
    parts: &[JsonPathPart],
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in parts {
        current = match part {
            JsonPathPart::Key(key) => current.get(key)?,
            JsonPathPart::Index(index) => current.get(*index)?,
        };
    }
    Some(current)
}

fn json_path_set(
    value: &mut serde_json::Value,
    parts: &[JsonPathPart],
    replacement: serde_json::Value,
) -> Result<()> {
    anyhow::ensure!(!parts.is_empty(), "package property path cannot be empty");
    if parts.len() == 1 {
        match &parts[0] {
            JsonPathPart::Key(key) => {
                if !value.is_object() {
                    *value = serde_json::json!({});
                }
                value
                    .as_object_mut()
                    .expect("object above")
                    .insert(key.clone(), replacement);
            }
            JsonPathPart::Index(index) => {
                if !value.is_array() {
                    *value = serde_json::json!([]);
                }
                let array = value.as_array_mut().expect("array above");
                array.resize(index + 1, serde_json::Value::Null);
                array[*index] = replacement;
            }
        }
        return Ok(());
    }
    let child = match &parts[0] {
        JsonPathPart::Key(key) => {
            if !value.is_object() {
                *value = serde_json::json!({});
            }
            value
                .as_object_mut()
                .expect("object above")
                .entry(key.clone())
                .or_insert(serde_json::Value::Null)
        }
        JsonPathPart::Index(index) => {
            if !value.is_array() {
                *value = serde_json::json!([]);
            }
            let array = value.as_array_mut().expect("array above");
            array.resize(index + 1, serde_json::Value::Null);
            &mut array[*index]
        }
    };
    json_path_set(child, &parts[1..], replacement)
}

fn json_path_delete(value: &mut serde_json::Value, parts: &[JsonPathPart]) -> bool {
    if parts.is_empty() {
        return false;
    }
    if parts.len() == 1 {
        return match &parts[0] {
            JsonPathPart::Key(key) => value
                .as_object_mut()
                .and_then(|map| map.remove(key))
                .is_some(),
            JsonPathPart::Index(index) => value.as_array_mut().is_some_and(|array| {
                if *index < array.len() {
                    array.remove(*index);
                    true
                } else {
                    false
                }
            }),
        };
    }
    match &parts[0] {
        JsonPathPart::Key(key) => value
            .get_mut(key)
            .is_some_and(|child| json_path_delete(child, &parts[1..])),
        JsonPathPart::Index(index) => value
            .get_mut(*index)
            .is_some_and(|child| json_path_delete(child, &parts[1..])),
    }
}

fn write_package_manifest(manifest: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    write_manifest_atomic(&std::env::current_dir()?.join("package.json"), &bytes)
}

fn collect_installed_package_dirs(node_modules: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut packages = Vec::new();
    let Ok(entries) = std::fs::read_dir(node_modules) else {
        return Ok(packages);
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name == ".bin" {
            continue;
        }
        if file_name.starts_with('@') {
            for scoped in std::fs::read_dir(&path)? {
                let scoped = scoped?;
                let scoped_path = scoped.path();
                let scoped_metadata = std::fs::symlink_metadata(&scoped_path)?;
                if scoped_metadata.is_dir() && !scoped_metadata.file_type().is_symlink() {
                    packages.push(scoped_path.clone());
                    packages.extend(collect_installed_package_dirs(
                        &scoped_path.join("node_modules"),
                    )?);
                }
            }
        } else {
            packages.push(path.clone());
            packages.extend(collect_installed_package_dirs(&path.join("node_modules"))?);
        }
    }
    Ok(packages)
}

fn rebuild_spec_matches(spec: &str, name: &str, version: &str) -> Result<bool> {
    let (requested_name, requested) = parse_package_spec(spec);
    if requested_name != name {
        return Ok(false);
    }
    if requested == "latest" {
        return Ok(true);
    }
    let range = requested
        .parse::<node_semver::Range>()
        .with_context(|| format!("invalid rebuild package spec {spec}"))?;
    let version = version
        .parse::<node_semver::Version>()
        .with_context(|| format!("installed package {name} has invalid version {version}"))?;
    Ok(range.satisfies(&version))
}

fn run_prepare_script(pkg_name: &str, pkg_dir: &std::path::Path) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg_dir.join("package.json"))?)?;
    let Some(command) = manifest["scripts"]["prepare"].as_str() else {
        return Ok(());
    };
    let npm_env = npm_package_env(&manifest);
    run_contained_lifecycle(pkg_name, pkg_dir, "prepare", command, &npm_env)
}

fn relink_rebuilt_bins(path: &std::path::Path, name: &str, global: bool) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("package.json"))?)?;
    let modules = path
        .ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .is_some_and(|part| part == "node_modules")
        })
        .context("rebuilt package is not below node_modules")?;
    let bin_dir = if global {
        modules
            .parent()
            .context("global node_modules has no prefix")?
            .join("bin")
    } else {
        modules.join(".bin")
    };
    std::fs::create_dir_all(&bin_dir)?;
    for (bin_name, relative) in safe_bin_entries(&manifest, name) {
        let target = path.join(relative);
        if !target.is_file() {
            continue;
        }
        let link = bin_dir.join(bin_name);
        remove_link_only(&link)?;
        platform_symlink_file(&target, &link)?;
    }
    Ok(())
}

struct RebuildOptions<'a> {
    ignore_scripts: bool,
    global: bool,
    no_bin_links: bool,
    allow_scripts: &'a [String],
    strict_allow_scripts: bool,
    dangerously_allow_all_scripts: bool,
}

fn cmd_rebuild_one(packages: &[String], options: &RebuildOptions<'_>) -> Result<usize> {
    let installed = collect_installed_package_dirs(&std::env::current_dir()?.join("node_modules"))?;
    let mut rebuilt = 0;
    let mut matched = HashSet::new();
    for path in installed {
        let manifest_path = path.join("package.json");
        let Ok(bytes) = std::fs::read(&manifest_path) else {
            continue;
        };
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid {}", manifest_path.display()))?;
        let Some(name) = manifest["name"].as_str() else {
            continue;
        };
        let version = manifest["version"].as_str().unwrap_or("0.0.0");
        let mut matching_specs = Vec::new();
        for spec in packages {
            if rebuild_spec_matches(spec, name, version)? {
                matching_specs.push(spec.as_str());
            }
        }
        if !packages.is_empty() && matching_specs.is_empty() {
            continue;
        }
        matched.extend(matching_specs);
        if !options.ignore_scripts {
            let allowed = options.dangerously_allow_all_scripts
                || options.allow_scripts.is_empty()
                || options.allow_scripts.iter().any(|allowed| allowed == name);
            if !allowed {
                anyhow::ensure!(
                    !options.strict_allow_scripts,
                    "install scripts for {name} are not permitted by --allow-scripts"
                );
                continue;
            }
            PackageScanner::scan(name, version, &path)
                .with_context(|| format!("analyze {name} before contained lifecycle execution"))?;
            run_install_script(name, &path)?;
            run_prepare_script(name, &path)?;
        }
        if !options.no_bin_links {
            relink_rebuilt_bins(&path, name, options.global)?;
        }
        rebuilt += 1;
    }
    let missing: Vec<_> = packages
        .iter()
        .filter(|spec| !matched.contains(spec.as_str()))
        .map(String::as_str)
        .collect();
    anyhow::ensure!(
        missing.is_empty(),
        "packages are not installed: {}",
        missing.join(", ")
    );
    Ok(rebuilt)
}

#[allow(clippy::too_many_arguments)]
fn cmd_rebuild(
    packages: &[String],
    ignore_scripts: bool,
    global: bool,
    no_bin_links: bool,
    _foreground_scripts: bool,
    allow_scripts: &[String],
    strict_allow_scripts: bool,
    dangerously_allow_all_scripts: bool,
    _install_links: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    anyhow::ensure!(
        !(global && workspace.active()),
        "--global cannot be combined with workspace filters"
    );
    anyhow::ensure!(
        global || allow_scripts.is_empty(),
        "--allow-scripts is only valid for global rebuilds; use trustedDependencies for projects"
    );
    let options = RebuildOptions {
        ignore_scripts,
        global,
        no_bin_links,
        allow_scripts,
        strict_allow_scripts,
        dangerously_allow_all_scripts,
    };
    let mut rebuilt = 0;
    if global {
        let root = global_link_root()?;
        anyhow::ensure!(
            root.join("node_modules").is_dir(),
            "no globally installed Oath packages"
        );
        let _guard = CurrentDirectoryGuard::enter(&root)?;
        rebuilt = cmd_rebuild_one(packages, &options)?;
    } else if workspace.active() {
        for target in selected_workspace_targets(workspace)? {
            let _guard = CurrentDirectoryGuard::enter(&target.path)?;
            rebuilt += cmd_rebuild_one(packages, &options)?;
        }
    } else {
        rebuilt = cmd_rebuild_one(packages, &options)?;
    }
    if ignore_scripts {
        println!("rebuilt {rebuilt} packages (lifecycle scripts ignored)");
    } else {
        println!("rebuilt {rebuilt} packages with verified containment");
    }
    Ok(())
}

fn packages_with_install_scripts() -> Result<Vec<String>> {
    let cwd = std::env::current_dir()?;
    let lock_path = cwd
        .ancestors()
        .map(|ancestor| ancestor.join("oath-lock.json"))
        .find(|path| path.is_file())
        .unwrap_or_else(|| cwd.join("oath-lock.json"));
    let lock = Lockfile::read(&lock_path)
        .context("--all requires oath-lock.json; run oath install first")?;
    let mut packages: Vec<_> = lock
        .packages
        .iter()
        .filter(|(_, entry)| entry.has_install_script)
        .map(|(key, entry)| entry.package_name_for_key(key))
        .collect();
    packages.sort();
    packages.dedup();
    Ok(packages)
}

fn manifest_string_set(manifest: &serde_json::Value, key: &str) -> HashSet<String> {
    manifest[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn cmd_script_policy_one(packages: &[String], all: bool, approve: bool) -> Result<Vec<String>> {
    anyhow::ensure!(
        all || !packages.is_empty(),
        "specify packages or pass --all"
    );
    let selected = if all {
        packages_with_install_scripts()?
    } else {
        packages
            .iter()
            .map(|package| parse_package_spec(package).0)
            .collect()
    };
    let mut manifest = read_package_json()?;
    let mut trusted = manifest_string_set(&manifest, "trustedDependencies");
    let mut denied = manifest
        .get("oath")
        .map(|oath| manifest_string_set(oath, "deniedDependencies"))
        .unwrap_or_default();
    for package in &selected {
        if approve {
            trusted.insert(package.clone());
            denied.remove(package);
        } else {
            trusted.remove(package);
            denied.insert(package.clone());
        }
    }
    let mut trusted: Vec<_> = trusted.into_iter().collect();
    trusted.sort();
    let mut denied: Vec<_> = denied.into_iter().collect();
    denied.sort();
    manifest["trustedDependencies"] = serde_json::json!(trusted);
    if manifest.get("oath").is_none() {
        manifest["oath"] = serde_json::json!({});
    }
    manifest["oath"]["deniedDependencies"] = serde_json::json!(denied);
    write_package_manifest(&manifest)?;
    Ok(selected)
}

fn cmd_script_policy(
    packages: &[String],
    all: bool,
    approve: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    let mut changed = BTreeMap::new();
    if workspace.active() {
        for target in selected_workspace_targets(workspace)? {
            let _guard = CurrentDirectoryGuard::enter(&target.path)?;
            changed.insert(target.name, cmd_script_policy_one(packages, all, approve)?);
        }
    } else {
        changed.insert(
            read_package_json()?["name"]
                .as_str()
                .unwrap_or("package")
                .to_owned(),
            cmd_script_policy_one(packages, all, approve)?,
        );
    }
    println!("{}", serde_json::to_string_pretty(&changed)?);
    Ok(())
}

fn approved_install_script_selection(
    packages: &[String],
    trusted: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut selected: Vec<String> = if packages.is_empty() {
        trusted.iter().cloned().collect()
    } else {
        packages
            .iter()
            .map(|package| parse_package_spec(package).0)
            .collect()
    };
    selected.sort();
    selected.dedup();
    let unauthorized: Vec<_> = selected
        .iter()
        .filter(|package| !trusted.contains(*package))
        .collect();
    anyhow::ensure!(
        unauthorized.is_empty(),
        "lifecycle scripts are not approved for: {}",
        unauthorized
            .iter()
            .map(|package| package.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(selected)
}

fn cmd_install_scripts(packages: &[String], workspace: &WorkspaceArgs) -> Result<()> {
    let run_one = |packages: &[String]| -> Result<()> {
        let manifest = read_package_json()?;
        let trusted = manifest_string_set(&manifest, "trustedDependencies");
        let selected = approved_install_script_selection(packages, &trusted)?;
        if selected.is_empty() {
            println!("  no approved lifecycle scripts to run");
            return Ok(());
        }
        let options = RebuildOptions {
            ignore_scripts: false,
            global: false,
            no_bin_links: false,
            allow_scripts: &selected,
            strict_allow_scripts: true,
            dangerously_allow_all_scripts: false,
        };
        cmd_rebuild_one(&selected, &options)?;
        Ok(())
    };
    if workspace.active() {
        for target in selected_workspace_targets(workspace)? {
            let _guard = CurrentDirectoryGuard::enter(&target.path)?;
            run_one(packages)?;
        }
    } else {
        run_one(packages)?;
    }
    Ok(())
}

fn cmd_query_one(selector: &str) -> Result<Vec<serde_json::Value>> {
    let result = ArboristPlanner::query(&std::env::current_dir()?, selector)?;
    result
        .as_array()
        .cloned()
        .context("Arborist query result must be an array")
}

fn cmd_query(selector: &str, workspace: &WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        println!(
            "{}",
            serde_json::to_string_pretty(&cmd_query_one(selector)?)?
        );
        return Ok(());
    }
    let mut output = serde_json::Map::new();
    for target in selected_workspace_targets(workspace)? {
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        output.insert(
            target.name,
            serde_json::Value::Array(cmd_query_one(selector)?),
        );
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn bumped_version(current: &str, requested: &str, preid: Option<&str>) -> Result<String> {
    let current = current
        .parse::<node_semver::Version>()
        .context("package version is not valid semver")?;
    let next = match requested {
        "major" if current.is_prerelease() && current.minor == 0 && current.patch == 0 => {
            node_semver::Version::new(current.major, 0, 0)
        }
        "major" => node_semver::Version::new(current.major + 1, 0, 0),
        "minor" if current.is_prerelease() && current.patch == 0 => {
            node_semver::Version::new(current.major, current.minor, 0)
        }
        "minor" => node_semver::Version::new(current.major, current.minor + 1, 0),
        "patch" if current.is_prerelease() => {
            node_semver::Version::new(current.major, current.minor, current.patch)
        }
        "patch" => node_semver::Version::new(current.major, current.minor, current.patch + 1),
        "premajor" | "preminor" | "prepatch" | "prerelease" => {
            let (major, minor, patch) = match requested {
                "premajor" => (current.major + 1, 0, 0),
                "preminor" => (current.major, current.minor + 1, 0),
                "prepatch" => (current.major, current.minor, current.patch + 1),
                "prerelease" if current.is_prerelease() => {
                    (current.major, current.minor, current.patch)
                }
                "prerelease" => (current.major, current.minor, current.patch + 1),
                _ => unreachable!(),
            };
            let existing = current
                .pre_release
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let identifiers = if requested == "prerelease" && !existing.is_empty() {
                if let Some(preid) = preid {
                    if existing
                        .first()
                        .is_some_and(|identifier| identifier == preid)
                    {
                        let mut next = existing;
                        if let Some(last) = next.last_mut() {
                            if let Ok(number) = last.parse::<u64>() {
                                *last = (number + 1).to_string();
                            } else {
                                next.push("0".into());
                            }
                        }
                        next
                    } else {
                        vec![preid.to_owned(), "0".into()]
                    }
                } else {
                    let mut next = existing;
                    if let Some(last) = next.last_mut() {
                        if let Ok(number) = last.parse::<u64>() {
                            *last = (number + 1).to_string();
                        } else {
                            next.push("0".into());
                        }
                    }
                    next
                }
            } else if let Some(preid) = preid {
                vec![preid.to_owned(), "0".into()]
            } else {
                vec!["0".into()]
            };
            format!("{major}.{minor}.{patch}-{}", identifiers.join("."))
                .parse::<node_semver::Version>()
                .context("--preid must be a valid semver prerelease identifier")?
        }
        exact => exact
            .parse::<node_semver::Version>()
            .context("new version must be valid semver or an npm version bump name")?,
    };
    Ok(next.to_string())
}

fn update_lockfile_versions(path: &std::path::Path, version: &str) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let mut document: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    document["version"] = serde_json::Value::String(version.to_owned());
    if let Some(root) = document
        .get_mut("packages")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|packages| packages.get_mut(""))
    {
        root["version"] = serde_json::Value::String(version.to_owned());
    }
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    write_manifest_atomic(path, &bytes)
}

fn git_repository_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
}

fn cmd_version(
    requested: Option<&str>,
    preid: Option<&str>,
    json_output: bool,
    allow_same_version: bool,
    no_git_tag_version: bool,
    ignore_scripts: bool,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if requested.is_none() {
        let manifest = read_package_json()?;
        let report = serde_json::json!({
            manifest["name"].as_str().unwrap_or("package"): manifest["version"].as_str().unwrap_or("0.0.0"),
            "oath": env!("CARGO_PKG_VERSION"),
            "node": command_version("node")["version"],
            "npm": command_version("npm")["version"]
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let requested = requested.expect("checked above");
    let targets = if workspace.active() {
        selected_workspace_targets(workspace)?
    } else {
        let root = std::env::current_dir()?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("package.json"))?)?;
        vec![WorkspaceTarget {
            name: manifest["name"].as_str().unwrap_or("package").to_owned(),
            path: root,
        }]
    };

    let repository = (!no_git_tag_version && targets.len() == 1)
        .then(git_repository_root)
        .flatten();
    if let Some(repository) = repository.as_ref() {
        let output = std::process::Command::new("git")
            .current_dir(repository)
            .args(["status", "--porcelain"])
            .output()?;
        anyhow::ensure!(
            output.status.success() && output.stdout.is_empty(),
            "git working tree must be clean before versioning"
        );
    }

    let mut versions = BTreeMap::new();
    if !ignore_scripts && targets.len() == 1 {
        let _guard = CurrentDirectoryGuard::enter(&targets[0].path)?;
        run_root_lifecycle("preversion")?;
    }
    let lock_paths = targets
        .iter()
        .flat_map(|target| {
            ["oath-lock.json", "package-lock.json", "npm-shrinkwrap.json"]
                .into_iter()
                .map(move |name| target.path.join(name))
        })
        .collect::<Vec<_>>();
    let mut lock_transaction = FileSnapshotTransaction::snapshot(lock_paths.iter().cloned())?;
    let mut transaction = WorkspaceManifestTransaction::begin(&targets, |manifest| {
        let current = manifest["version"]
            .as_str()
            .context("package.json version must be a string")?;
        let next = bumped_version(current, requested, preid)?;
        anyhow::ensure!(
            allow_same_version || next != current,
            "new version is the same as the current version"
        );
        manifest["version"] = serde_json::Value::String(next);
        Ok(())
    })?;
    for target in &targets {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(target.path.join("package.json"))?)?;
        let version = manifest["version"]
            .as_str()
            .context("updated package version is missing")?
            .to_owned();
        for lock_name in ["oath-lock.json", "package-lock.json", "npm-shrinkwrap.json"] {
            update_lockfile_versions(&target.path.join(lock_name), &version)?;
        }
        versions.insert(target.name.clone(), version);
    }
    if !ignore_scripts && targets.len() == 1 {
        let _guard = CurrentDirectoryGuard::enter(&targets[0].path)?;
        run_root_lifecycle("version")?;
    }
    if let Some(repository) = repository {
        let version = versions.values().next().context("no version was updated")?;
        let mut changed_files = targets
            .iter()
            .map(|target| target.path.join("package.json"))
            .chain(lock_paths.iter().filter(|path| path.is_file()).cloned())
            .map(|path| {
                path.strip_prefix(&repository)
                    .map(PathBuf::from)
                    .with_context(|| {
                        format!(
                            "version target {} is outside git repository {}",
                            path.display(),
                            repository.display()
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        changed_files.sort();
        changed_files.dedup();
        let mut add = std::process::Command::new("git");
        add.current_dir(&repository).args(["add", "--"]);
        add.args(&changed_files);
        let status = add.status()?;
        anyhow::ensure!(status.success(), "git add failed during versioning");
        let status = std::process::Command::new("git")
            .current_dir(&repository)
            .args(["commit", "-m", &format!("v{version}")])
            .status()?;
        anyhow::ensure!(status.success(), "git commit failed during versioning");
        let status = std::process::Command::new("git")
            .current_dir(&repository)
            .args(["tag", &format!("v{version}")])
            .status()?;
        anyhow::ensure!(status.success(), "git tag failed during versioning");
    }
    transaction.commit();
    lock_transaction.commit();
    if !ignore_scripts && targets.len() == 1 {
        let _guard = CurrentDirectoryGuard::enter(&targets[0].path)?;
        run_root_lifecycle("postversion")?;
    }
    if json_output || versions.len() > 1 {
        println!("{}", serde_json::to_string_pretty(&versions)?);
    } else if let Some(version) = versions.values().next() {
        println!("v{version}");
    }
    Ok(())
}

struct DiffTree {
    temporary: tempfile::TempDir,
    label: String,
}

impl DiffTree {
    fn root(&self) -> PathBuf {
        self.temporary.path().join("content")
    }
}

async fn diff_tree(spec: &str, registry: Option<&str>) -> Result<DiffTree> {
    let temporary = tempfile::tempdir()?;
    let content = temporary.path().join("content");
    std::fs::create_dir_all(&content)?;
    let candidate = PathBuf::from(spec);
    if candidate.is_dir() {
        let tarball = pack_local_package(&candidate)?;
        oath_fetch::tarball::extract_tarball_limited(
            &tarball,
            &content,
            &TarballLimits::from_env()?,
        )?;
        return Ok(DiffTree {
            temporary,
            label: candidate.display().to_string(),
        });
    }

    let (name, requested) = parse_package_spec(spec);
    let mut config = oath_fetch::client::RegistryConfig::from_npmrc(&std::env::current_dir()?);
    if let Some(registry) = registry {
        config.registry_url = credential_registry_url(registry)?;
    }
    config.cache_dir = temporary.path().join("metadata-cache");
    let client = RegistryClient::new(config)?;
    let packument = client.fetch_packument(&name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &requested)?;
    let version = resolved.version.to_string();
    let tarball = temporary.path().join("package.tgz");
    client
        .fetch_tarball_to_file(
            &resolved.info.dist.tarball,
            resolved.info.dist.integrity.as_deref(),
            &tarball,
            &TarballLimits::from_env()?,
        )
        .await?;
    oath_fetch::tarball::extract_tarball_file_limited(
        &tarball,
        &content,
        &TarballLimits::from_env()?,
    )?;
    Ok(DiffTree {
        temporary,
        label: format!("{name}@{version}"),
    })
}

fn diff_snapshot(root: &std::path::Path) -> Result<BTreeMap<String, String>> {
    use sha2::{Digest, Sha256};

    fn visit(
        root: &std::path::Path,
        directory: &std::path::Path,
        output: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "package diff refuses symlink {}",
                path.display()
            );
            if metadata.is_dir() {
                visit(root, &path, output)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, hex::encode(Sha256::digest(std::fs::read(&path)?)));
            }
        }
        Ok(())
    }

    let mut output = BTreeMap::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

fn unified_content_diff(
    path: &str,
    before_root: &std::path::Path,
    after_root: &std::path::Path,
) -> Result<Option<String>> {
    let read = |root: &std::path::Path| -> Result<String> {
        match std::fs::read(root.join(path)) {
            Ok(bytes) => String::from_utf8(bytes).context("package diff contains binary data"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error.into()),
        }
    };
    let before = match read(before_root) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let after = match read(after_root) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    if before_lines == after_lines {
        return Ok(Some(String::new()));
    }
    let mut output = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    );
    for line in before_lines {
        output.push('-');
        output.push_str(line);
        output.push('\n');
    }
    for line in after_lines {
        output.push('+');
        output.push_str(line);
        output.push('\n');
    }
    Ok(Some(output))
}

async fn cmd_diff(
    diffs: &[String],
    name_only: bool,
    json_output: bool,
    registry: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(diffs.len() <= 2, "diff accepts at most two --diff specs");
    let local = std::env::current_dir()?.display().to_string();
    let (left_spec, right_spec) = match diffs {
        [] => {
            let manifest = read_package_json()?;
            let name = manifest["name"]
                .as_str()
                .context("package.json has no package name")?;
            let version = manifest["version"]
                .as_str()
                .context("package.json has no package version")?;
            (format!("{name}@{version}"), local)
        }
        [right] => (local, right.clone()),
        [left, right] => (left.clone(), right.clone()),
        _ => unreachable!(),
    };
    let left = diff_tree(&left_spec, registry).await?;
    let right = diff_tree(&right_spec, registry).await?;
    let left_files = diff_snapshot(&left.root())?;
    let right_files = diff_snapshot(&right.root())?;
    let names: std::collections::BTreeSet<_> = left_files
        .keys()
        .chain(right_files.keys())
        .cloned()
        .collect();
    let changes: Vec<_> = names
        .into_iter()
        .filter_map(|path| {
            let before = left_files.get(&path);
            let after = right_files.get(&path);
            (before != after).then(|| {
                serde_json::json!({
                    "path": path,
                    "status": match (before, after) {
                        (None, Some(_)) => "added",
                        (Some(_), None) => "removed",
                        _ => "modified"
                    },
                    "before_sha256": before,
                    "after_sha256": after
                })
            })
        })
        .collect();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "from": left.label,
                "to": right.label,
                "changes": changes
            }))?
        );
    } else {
        for change in &changes {
            if name_only {
                println!("{}", change["path"].as_str().unwrap_or_default());
            } else {
                let path = change["path"].as_str().unwrap_or_default();
                if let Some(diff) = unified_content_diff(path, &left.root(), &right.root())? {
                    print!("{diff}");
                } else {
                    let status = match change["status"].as_str().unwrap_or_default() {
                        "added" => "A",
                        "removed" => "D",
                        _ => "M",
                    };
                    println!("{status}\t{path} (binary)");
                }
            }
        }
    }
    Ok(())
}

fn funding_urls(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(url) => vec![url.clone()],
        serde_json::Value::Object(object) => object
            .get("url")
            .and_then(serde_json::Value::as_str)
            .map(|url| vec![url.to_owned()])
            .unwrap_or_default(),
        serde_json::Value::Array(values) => values.iter().flat_map(funding_urls).collect(),
        _ => Vec::new(),
    }
}

fn cmd_fund(
    package: Option<&str>,
    json_output: bool,
    which: Option<usize>,
    browser: Option<&str>,
    no_browser: bool,
) -> Result<()> {
    let mut records = Vec::new();
    let root = std::env::current_dir()?;
    let requested_package = package
        .map(|requested| {
            let path = PathBuf::from(requested);
            if path.join("package.json").is_file() {
                let manifest: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path.join("package.json"))?)?;
                return manifest["name"]
                    .as_str()
                    .map(String::from)
                    .context("funding package path has no package name");
            }
            Ok(requested.to_owned())
        })
        .transpose()?;
    let mut manifests = vec![root.join("package.json")];
    manifests.extend(
        collect_installed_package_dirs(&root.join("node_modules"))?
            .into_iter()
            .map(|path| path.join("package.json")),
    );
    for path in manifests {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid {}", path.display()))?;
        let Some(name) = manifest["name"].as_str() else {
            continue;
        };
        if requested_package
            .as_deref()
            .is_some_and(|wanted| wanted != name)
        {
            continue;
        }
        let urls = manifest
            .get("funding")
            .map(funding_urls)
            .unwrap_or_default();
        if urls.is_empty() {
            continue;
        }
        records.push(serde_json::json!({
            "name": name,
            "version": manifest["version"].as_str().unwrap_or("0.0.0"),
            "funding": urls
        }));
    }
    if let Some(package) = requested_package.as_deref() {
        anyhow::ensure!(
            !records.is_empty(),
            "no funding information found for {package}"
        );
    }
    let browser_enabled = !no_browser && browser != Some("false");
    if requested_package.is_some() && !json_output && browser_enabled {
        let which = which.unwrap_or(1);
        anyhow::ensure!(
            which > 0,
            "--which is one-based and must be greater than zero"
        );
        let urls: Vec<_> = records
            .iter()
            .flat_map(|record| record["funding"].as_array().into_iter().flatten())
            .filter_map(serde_json::Value::as_str)
            .collect();
        let url = urls
            .get(which - 1)
            .context("--which exceeds the available funding URLs")?;
        if let Some(browser) = browser.filter(|value| !matches!(*value, "true" | "false")) {
            let mut parts = browser.split_whitespace();
            let program = parts.next().context("--browser is empty")?;
            let status = std::process::Command::new(program)
                .args(parts)
                .arg(url)
                .status()?;
            anyhow::ensure!(status.success(), "browser command failed with {status}");
        } else {
            open_package_url(url)?;
        }
    } else if let Some(which) = which {
        anyhow::ensure!(
            which > 0,
            "--which is one-based and must be greater than zero"
        );
        let urls: Vec<_> = records
            .iter()
            .flat_map(|record| record["funding"].as_array().into_iter().flatten())
            .filter_map(serde_json::Value::as_str)
            .collect();
        let url = urls
            .get(which - 1)
            .context("--which exceeds the available funding URLs")?;
        println!("{url}");
    } else if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No funding information found");
    } else {
        for record in records {
            println!(
                "{}@{}",
                record["name"].as_str().unwrap_or_default(),
                record["version"].as_str().unwrap_or_default()
            );
            for url in record["funding"].as_array().into_iter().flatten() {
                println!("  {}", url.as_str().unwrap_or_default());
            }
        }
    }
    Ok(())
}

fn command_version(program: &str) -> serde_json::Value {
    match std::process::Command::new(program)
        .arg("--version")
        .output()
    {
        Ok(output) if output.status.success() => serde_json::json!({
            "ok": true,
            "version": String::from_utf8_lossy(&output.stdout).trim()
        }),
        Ok(output) => serde_json::json!({ "ok": false, "status": output.status.code() }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

fn registry_request_with_optional_auth(
    client: &reqwest::Client,
    url: reqwest::Url,
) -> reqwest::RequestBuilder {
    let config = oath_fetch::NpmrcConfig::load(
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    );
    let token = url
        .host_str()
        .and_then(|host| config.token_for_host(host))
        .map(str::to_owned);
    let request = client.get(url);
    if let Some(token) = token {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn registry_request_with_auth(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: reqwest::Url,
) -> Result<reqwest::RequestBuilder> {
    let config = oath_fetch::NpmrcConfig::load(&std::env::current_dir()?);
    let host = url.host_str().context("registry URL has no host")?;
    let token = config
        .token_for_host(host)
        .context("registry mutation requires an authentication token")?;
    Ok(client.request(method, url).bearer_auth(token))
}

fn publish_auth_token(
    registry_host: &str,
    npmrc: &oath_fetch::NpmrcConfig,
    environment_token: Option<String>,
) -> Result<String> {
    environment_token
        .filter(|token| !token.trim().is_empty())
        .or_else(|| npmrc.token_for_host(registry_host).map(str::to_owned))
        .with_context(|| {
            format!(
                "oath publish: no npm auth token found for {registry_host}.\n  Set NPM_TOKEN or configure //{registry_host}/:_authToken in .npmrc"
            )
        })
}

fn registry_url_with_segments(registry: &str, segments: &[&str]) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(registry)?;
    let mut path = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("registry URL cannot be a base URL"))?;
    path.pop_if_empty();
    for segment in segments {
        path.push(segment);
    }
    drop(path);
    Ok(url)
}

fn validate_dist_tag(tag: &str) -> Result<()> {
    anyhow::ensure!(
        !tag.is_empty()
            && !tag.starts_with(['.', '_'])
            && !tag.chars().any(char::is_whitespace)
            && !tag.chars().any(char::is_control)
            && tag.parse::<node_semver::Version>().is_err(),
        "invalid dist-tag {tag}"
    );
    Ok(())
}

async fn cmd_dist_tag(action: DistTagAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match action {
        DistTagAction::Add {
            package,
            tag,
            registry,
        } => {
            validate_dist_tag(&tag)?;
            let (name, version) = parse_package_spec(&package);
            anyhow::ensure!(
                version != "latest" && version.parse::<node_semver::Version>().is_ok(),
                "dist-tag add requires an exact package version"
            );
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url =
                registry_url_with_segments(&registry, &["-", "package", &name, "dist-tags", &tag])?;
            let response = registry_request_with_auth(&client, reqwest::Method::PUT, url)?
                .json(&version)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected dist-tag add with {}",
                response.status()
            );
            println!("+{tag}: {name}@{version}");
        }
        DistTagAction::Rm {
            package,
            tag,
            registry,
        } => {
            validate_dist_tag(&tag)?;
            let (name, _) = parse_package_spec(&package);
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url =
                registry_url_with_segments(&registry, &["-", "package", &name, "dist-tags", &tag])?;
            let response = registry_request_with_auth(&client, reqwest::Method::DELETE, url)?
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected dist-tag removal with {}",
                response.status()
            );
            println!("-{tag}: {name}");
        }
        DistTagAction::Ls {
            package,
            json,
            registry,
        } => {
            let package = match package {
                Some(package) => package,
                None => read_package_json()?["name"]
                    .as_str()
                    .context("package.json has no package name")?
                    .to_owned(),
            };
            let (name, _) = parse_package_spec(&package);
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "package", &name, "dist-tags"])?;
            let response = registry_request_with_optional_auth(&client, url)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected dist-tag list with {}",
                response.status()
            );
            let tags: BTreeMap<String, String> = response.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tags)?);
            } else {
                for (tag, version) in tags {
                    println!("{tag}: {version}");
                }
            }
        }
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<()> {
    let (address, prefix) = cidr
        .split_once('/')
        .context("CIDR must have the form address/prefix")?;
    let address: std::net::IpAddr = address.parse().context("invalid CIDR address")?;
    let prefix: u8 = prefix.parse().context("invalid CIDR prefix")?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    anyhow::ensure!(prefix <= maximum, "CIDR prefix exceeds {maximum}");
    Ok(())
}

async fn cmd_token(action: TokenAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match action {
        TokenAction::List { json, registry } => {
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "npm", "v1", "tokens"])?;
            let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected token list with {}",
                response.status()
            );
            let body: serde_json::Value = response.json().await?;
            let tokens = body
                .get("objects")
                .or_else(|| body.get("tokens"))
                .cloned()
                .unwrap_or(body);
            if json {
                println!("{}", serde_json::to_string_pretty(&tokens)?);
            } else {
                for token in tokens.as_array().into_iter().flatten() {
                    println!(
                        "{}\t{}\t{}",
                        token["key"].as_str().unwrap_or_default(),
                        token["token"].as_str().unwrap_or("********"),
                        if token["readonly"].as_bool().unwrap_or(false) {
                            "read-only"
                        } else {
                            "publish"
                        }
                    );
                }
            }
        }
        TokenAction::Create {
            read_only,
            cidr,
            description,
            password_stdin,
            otp,
            json,
            registry,
        } => {
            use std::io::Read;
            for item in &cidr {
                validate_cidr(item)?;
            }
            let password = if password_stdin {
                let mut value = String::new();
                std::io::stdin().read_to_string(&mut value)?;
                value.trim_end_matches(['\r', '\n']).to_owned()
            } else {
                std::env::var("NPM_PASSWORD")
                    .context("token create requires NPM_PASSWORD or --password-stdin")?
            };
            anyhow::ensure!(!password.is_empty(), "registry password is empty");
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "npm", "v1", "tokens"])?;
            let mut request = registry_request_with_auth(&client, reqwest::Method::POST, url)?
                .json(&serde_json::json!({
                    "password": password,
                    "readonly": read_only,
                    "cidr_whitelist": cidr,
                    "description": description
                }));
            if let Some(otp) = otp {
                request = request.header("npm-otp", otp);
            }
            let response = request.send().await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected token creation with {}",
                response.status()
            );
            let token: serde_json::Value = response.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&token)?);
            } else {
                println!(
                    "{}",
                    token["token"]
                        .as_str()
                        .context("registry token response has no token")?
                );
            }
        }
        TokenAction::Revoke { token, registry } => {
            anyhow::ensure!(
                !token.is_empty() && !token.chars().any(char::is_control),
                "invalid token identifier"
            );
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "npm", "v1", "tokens", &token])?;
            let response = registry_request_with_auth(&client, reqwest::Method::DELETE, url)?
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected token revocation with {}",
                response.status()
            );
            println!("revoked token {token}");
        }
    }
    Ok(())
}

fn current_or_requested_package(package: Option<String>) -> Result<String> {
    package.map_or_else(
        || {
            Ok(read_package_json()?["name"]
                .as_str()
                .context("package.json has no package name")?
                .to_owned())
        },
        Ok,
    )
}

fn parse_team(team: &str) -> Result<(String, String)> {
    let normalized = team.trim_start_matches('@');
    let (scope, name) = normalized
        .split_once(':')
        .context("team must have the form scope:team")?;
    anyhow::ensure!(
        !scope.is_empty()
            && !name.is_empty()
            && !scope.contains(['/', '\\'])
            && !name.contains(['/', '\\']),
        "invalid team identifier"
    );
    Ok((scope.to_owned(), name.to_owned()))
}

async fn access_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    registry: Option<&str>,
    segments: &[&str],
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = registry_url_with_segments(&registry, segments)?;
    let mut request = registry_request_with_auth(client, method, url)?;
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry access request returned {}",
        response.status()
    );
    Ok(response
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({ "ok": true })))
}

async fn cmd_access(action: AccessAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match action {
        AccessAction::Public { package, registry } => {
            let package = current_or_requested_package(package)?;
            access_request(
                &client,
                reqwest::Method::POST,
                registry.as_deref(),
                &["-", "package", &package, "access"],
                Some(&serde_json::json!({ "access": "public" })),
            )
            .await?;
            println!("{package}: public");
        }
        AccessAction::Restricted { package, registry } => {
            let package = current_or_requested_package(package)?;
            access_request(
                &client,
                reqwest::Method::POST,
                registry.as_deref(),
                &["-", "package", &package, "access"],
                Some(&serde_json::json!({ "access": "restricted" })),
            )
            .await?;
            println!("{package}: restricted");
        }
        AccessAction::Grant {
            permission,
            team,
            package,
            registry,
        } => {
            anyhow::ensure!(
                matches!(permission.as_str(), "read-only" | "read-write"),
                "permission must be read-only or read-write"
            );
            let (scope, team) = parse_team(&team)?;
            let package = current_or_requested_package(package)?;
            access_request(
                &client,
                reqwest::Method::PUT,
                registry.as_deref(),
                &["-", "team", &scope, &team, "package"],
                Some(&serde_json::json!({ "package": package, "permissions": permission })),
            )
            .await?;
            println!("granted {permission} on {package} to {scope}:{team}");
        }
        AccessAction::Revoke {
            team,
            package,
            registry,
        } => {
            let (scope, team) = parse_team(&team)?;
            let package = current_or_requested_package(package)?;
            access_request(
                &client,
                reqwest::Method::DELETE,
                registry.as_deref(),
                &["-", "team", &scope, &team, "package"],
                Some(&serde_json::json!({ "package": package })),
            )
            .await?;
            println!("revoked {scope}:{team} from {package}");
        }
        AccessAction::ListPackages {
            team,
            json,
            registry,
        } => {
            let team = team.context("access list-packages requires a team")?;
            let (scope, team) = parse_team(&team)?;
            let value = access_request(
                &client,
                reqwest::Method::GET,
                registry.as_deref(),
                &["-", "team", &scope, &team, "package"],
                None,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(packages) = value.as_object() {
                for (package, permission) in packages {
                    println!("{package}: {}", permission.as_str().unwrap_or_default());
                }
            }
        }
        AccessAction::ListCollaborators {
            package,
            json,
            registry,
        } => {
            let package = current_or_requested_package(package)?;
            let value = access_request(
                &client,
                reqwest::Method::GET,
                registry.as_deref(),
                &["-", "package", &package, "collaborators"],
                None,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(collaborators) = value.as_object() {
                for (collaborator, permission) in collaborators {
                    println!(
                        "{collaborator}: {}",
                        permission.as_str().unwrap_or_default()
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_trust_file(file: &str, basename_only: bool) -> Result<()> {
    anyhow::ensure!(
        file.ends_with(".yml") || file.ends_with(".yaml"),
        "trusted publisher file must end in .yml or .yaml"
    );
    if basename_only {
        anyhow::ensure!(
            std::path::Path::new(file).file_name() == Some(OsStr::new(file)),
            "GitHub workflow must be a file name, not a path"
        );
    }
    anyhow::ensure!(
        !file.chars().any(char::is_control),
        "trusted publisher file contains control characters"
    );
    Ok(())
}

fn validate_uuid(value: &str) -> bool {
    let groups: Vec<_> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.chars().all(|ch| ch.is_ascii_hexdigit())
        })
}

async fn create_trust(
    package: Option<String>,
    config: serde_json::Value,
    yes: bool,
    dry_run: bool,
    registry: Option<String>,
) -> Result<()> {
    let package = current_or_requested_package(package)?;
    anyhow::ensure!(yes || dry_run, "trust creation requires --yes or --dry-run");
    if dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "package": package, "trust": config, "mutation": false })
            )?
        );
        return Ok(());
    }
    let registry = credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
    let url = registry_url_with_segments(&registry, &["-", "package", &package, "trust"])?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_auth(&client, reqwest::Method::POST, url)?
        .json(&serde_json::json!([config]))
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry rejected trusted publisher creation with {}",
        response.status()
    );
    println!("trusted publisher created for {package}");
    Ok(())
}

fn validate_account_name(value: &str, label: &str) -> Result<String> {
    let normalized = value.trim_start_matches(['@', '~']);
    anyhow::ensure!(
        !normalized.is_empty()
            && normalized.len() <= 214
            && !normalized.chars().any(char::is_control)
            && !normalized.contains(['/', '\\']),
        "invalid {label}"
    );
    Ok(normalized.to_owned())
}

async fn cmd_org(action: OrgAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match action {
        OrgAction::Set {
            org,
            user,
            role,
            json,
            registry,
        } => {
            anyhow::ensure!(
                matches!(role.as_str(), "developer" | "admin" | "owner"),
                "org role must be developer, admin, or owner"
            );
            let org = validate_account_name(&org, "organization")?;
            let user = validate_account_name(&user, "username")?;
            let response = access_request(
                &client,
                reqwest::Method::PUT,
                registry.as_deref(),
                &["-", "org", &org, "user"],
                Some(&serde_json::json!({ "user": user, "role": role })),
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("Added {user} as {role} to {org}.");
            }
        }
        OrgAction::Rm {
            org,
            user,
            json,
            registry,
        } => {
            let org = validate_account_name(&org, "organization")?;
            let user = validate_account_name(&user, "username")?;
            access_request(
                &client,
                reqwest::Method::DELETE,
                registry.as_deref(),
                &["-", "org", &org, "user"],
                Some(&serde_json::json!({ "user": user })),
            )
            .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "user": user, "org": org, "deleted": true })
                    )?
                );
            } else {
                println!("Successfully removed {user} from {org}.");
            }
        }
        OrgAction::Ls {
            org,
            user,
            json,
            registry,
        } => {
            let org = validate_account_name(&org, "organization")?;
            let mut roster = access_request(
                &client,
                reqwest::Method::GET,
                registry.as_deref(),
                &["-", "org", &org, "user"],
                None,
            )
            .await?;
            if let Some(user) = user {
                let user = validate_account_name(&user, "username")?;
                roster = roster
                    .get(&user)
                    .map(|role| serde_json::json!({ user: role }))
                    .unwrap_or_else(|| serde_json::json!({}));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&roster)?);
            } else {
                for (user, role) in roster.as_object().into_iter().flatten() {
                    println!("{user} - {}", role.as_str().unwrap_or_default());
                }
            }
        }
    }
    Ok(())
}

async fn owner_packument(
    client: &reqwest::Client,
    package: &str,
    registry: Option<&str>,
) -> Result<serde_json::Value> {
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = registry_url_with_segments(&registry, &[package])?;
    let response = registry_request_with_optional_auth(client, url)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry owner request returned {}",
        response.status()
    );
    Ok(response.json().await?)
}

async fn cmd_owner(action: OwnerAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let (mutation, user, package, registry) = match action {
        OwnerAction::Ls { package, registry } => {
            let package = current_or_requested_package(package)?;
            let body = owner_packument(&client, &package, registry.as_deref()).await?;
            let maintainers = body["maintainers"].as_array().cloned().unwrap_or_default();
            if maintainers.is_empty() {
                println!("no admin found");
            } else {
                for maintainer in maintainers {
                    println!(
                        "{} <{}>",
                        maintainer["name"].as_str().unwrap_or_default(),
                        maintainer["email"].as_str().unwrap_or_default()
                    );
                }
            }
            return Ok(());
        }
        OwnerAction::Add {
            user,
            package,
            registry,
        } => (true, user, package, registry),
        OwnerAction::Rm {
            user,
            package,
            registry,
        } => (false, user, package, registry),
    };
    let user = validate_account_name(&user, "username")?;
    let package = current_or_requested_package(package)?;
    let registry_url = credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
    let user_url = registry_url_with_segments(
        &registry_url,
        &["-", "user", &format!("org.couchdb.user:{user}")],
    )?;
    let response = registry_request_with_auth(&client, reqwest::Method::GET, user_url)?
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry user lookup failed"
    );
    let account: serde_json::Value = response.json().await?;
    let mut packument = owner_packument(&client, &package, registry.as_deref()).await?;
    let mut maintainers = packument["maintainers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if mutation {
        if !maintainers.iter().any(|item| item["name"] == user) {
            maintainers.push(serde_json::json!({
                "name": account["name"].as_str().unwrap_or(&user),
                "email": account["email"].as_str().unwrap_or_default()
            }));
        }
    } else {
        maintainers.retain(|item| item["name"] != user);
        anyhow::ensure!(!maintainers.is_empty(), "cannot remove all package owners");
    }
    let revision = packument["_rev"]
        .as_str()
        .context("registry packument has no revision")?
        .to_owned();
    let id = packument["_id"].as_str().unwrap_or(&package).to_owned();
    let url = registry_url_with_segments(&registry_url, &[&package, "-rev", &revision])?;
    let response = registry_request_with_auth(&client, reqwest::Method::PUT, url)?
        .json(&serde_json::json!({ "_id": id, "_rev": revision, "maintainers": maintainers }))
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry owner mutation failed"
    );
    println!("{} {user} ({package})", if mutation { "+" } else { "-" });
    packument["maintainers"] = serde_json::Value::Array(maintainers);
    Ok(())
}

fn read_profile_secret(prompt: &str, from_stdin: bool) -> Result<String> {
    let secret = if from_stdin {
        let mut value = String::new();
        std::io::stdin().read_line(&mut value)?;
        value.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        rpassword::prompt_password(prompt)?
    };
    anyhow::ensure!(!secret.is_empty(), "credential cannot be empty");
    Ok(secret)
}

fn validate_otp(otp: &str) -> Result<()> {
    anyhow::ensure!(
        (6..=10).contains(&otp.len()) && otp.bytes().all(|byte| byte.is_ascii_digit()),
        "one-time password must contain 6 to 10 decimal digits"
    );
    Ok(())
}

async fn profile_mutation(
    client: &reqwest::Client,
    registry: Option<&str>,
    body: &serde_json::Value,
    supplied_otp: Option<&str>,
) -> Result<serde_json::Value> {
    if let Some(otp) = supplied_otp {
        validate_otp(otp)?;
    }
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = registry_url_with_segments(&registry, &["-", "npm", "v1", "user"])?;
    let mut otp = supplied_otp.map(str::to_owned);
    for attempt in 0..2 {
        let mut request = registry_request_with_auth(client, reqwest::Method::POST, url.clone())?;
        if let Some(value) = &otp {
            request = request.header("npm-otp", value);
        }
        let response = request.json(body).send().await?;
        if response.status().is_success() {
            return Ok(response
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({ "ok": true })));
        }
        if attempt == 0 && otp.is_none() && matches!(response.status().as_u16(), 401 | 403) {
            let prompted = read_profile_secret("One-time password: ", false)?;
            validate_otp(&prompted)?;
            otp = Some(prompted);
            continue;
        }
        anyhow::bail!("registry profile mutation returned {}", response.status());
    }
    unreachable!()
}

async fn cmd_profile_enable_2fa(
    mode: &str,
    registry: Option<&str>,
    password_stdin: bool,
    otp: Option<&str>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let current = access_request(
        &client,
        reqwest::Method::GET,
        registry,
        &["-", "npm", "v1", "user"],
        None,
    )
    .await?;
    if current["tfa"]["mode"].as_str() == Some(mode)
        && !current["tfa"]["pending"].as_bool().unwrap_or(false)
    {
        println!("Two factor authentication is already enabled and set to {mode}");
        return Ok(());
    }
    let password = read_profile_secret("Account password: ", password_stdin)?;
    let challenge = profile_mutation(
        &client,
        registry,
        &serde_json::json!({ "tfa": { "mode": mode, "password": password } }),
        otp,
    )
    .await?;
    if challenge["tfa"]["mode"].as_str() == Some(mode) {
        println!("Two factor authentication mode changed to: {mode}");
        return Ok(());
    }
    let provisioning = challenge["tfa"]
        .as_str()
        .context("registry did not return an otpauth provisioning URL")?;
    anyhow::ensure!(
        provisioning.starts_with("otpauth://"),
        "registry returned an invalid otpauth provisioning URL"
    );
    println!("Add this account to your authenticator: {provisioning}");
    let activation_otp = otp
        .map(str::to_owned)
        .map_or_else(|| read_profile_secret("Authenticator code: ", false), Ok)?;
    validate_otp(&activation_otp)?;
    let result = profile_mutation(
        &client,
        registry,
        &serde_json::json!({ "tfa": [activation_otp] }),
        None,
    )
    .await?;
    println!("2FA successfully enabled. Store these recovery codes securely:");
    for code in result["tfa"].as_array().into_iter().flatten() {
        if let Some(code) = code.as_str() {
            println!("\t{code}");
        }
    }
    Ok(())
}

async fn cmd_profile_disable_2fa(
    registry: Option<&str>,
    password_stdin: bool,
    otp: Option<&str>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let current = access_request(
        &client,
        reqwest::Method::GET,
        registry,
        &["-", "npm", "v1", "user"],
        None,
    )
    .await?;
    if current.get("tfa").is_none() || current["tfa"]["pending"].as_bool().unwrap_or(false) {
        println!("Two factor authentication not enabled.");
        return Ok(());
    }
    let password = read_profile_secret("Account password: ", password_stdin)?;
    profile_mutation(
        &client,
        registry,
        &serde_json::json!({ "tfa": { "password": password, "mode": "disable" } }),
        otp,
    )
    .await?;
    println!("Two factor authentication disabled.");
    Ok(())
}

async fn cmd_profile(action: ProfileAction) -> Result<()> {
    let (registry, json, method, body, keys) = match action {
        ProfileAction::Get {
            keys,
            json,
            registry,
        } => (registry, json, reqwest::Method::GET, None, keys),
        ProfileAction::Set {
            key,
            value,
            json,
            registry,
        } => {
            anyhow::ensure!(
                matches!(
                    key.as_str(),
                    "email" | "fullname" | "homepage" | "freenode" | "twitter" | "github"
                ),
                "profile property is not writable"
            );
            (
                registry,
                json,
                reqwest::Method::POST,
                Some(serde_json::json!({ key.clone(): value })),
                vec![key],
            )
        }
        ProfileAction::Enable2fa {
            mode,
            registry,
            password_stdin,
            otp,
        } => {
            anyhow::ensure!(
                matches!(mode.as_str(), "auth-only" | "auth-and-writes"),
                "invalid two-factor authentication mode"
            );
            return cmd_profile_enable_2fa(
                &mode,
                registry.as_deref(),
                password_stdin,
                otp.as_deref(),
            )
            .await;
        }
        ProfileAction::Disable2fa {
            registry,
            password_stdin,
            otp,
        } => {
            return cmd_profile_disable_2fa(registry.as_deref(), password_stdin, otp.as_deref())
                .await;
        }
    };
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = access_request(
        &client,
        method,
        registry.as_deref(),
        &["-", "npm", "v1", "user"],
        body.as_ref(),
    )
    .await?;
    if json {
        if keys.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({ keys[0].clone(): response.get(&keys[0]).cloned() })
                )?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
    } else if keys.is_empty() {
        for (key, value) in response.as_object().into_iter().flatten() {
            println!("{key}: {}", value.as_str().unwrap_or(&value.to_string()));
        }
    } else {
        for key in keys {
            println!(
                "{}",
                response
                    .get(&key)
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
            );
        }
    }
    Ok(())
}

async fn cmd_team(action: TeamAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let (method, entity, user, json, registry) = match action {
        TeamAction::Create {
            team,
            json,
            registry,
        } => (reqwest::Method::PUT, team, None, json, registry),
        TeamAction::Destroy {
            team,
            json,
            registry,
        } => (reqwest::Method::DELETE, team, None, json, registry),
        TeamAction::Add {
            team,
            user,
            json,
            registry,
        } => (reqwest::Method::PUT, team, Some(user), json, registry),
        TeamAction::Rm {
            team,
            user,
            json,
            registry,
        } => (reqwest::Method::DELETE, team, Some(user), json, registry),
        TeamAction::Ls {
            entity,
            json,
            registry,
        } => {
            let normalized = entity.trim_start_matches('@');
            let (segments, label) = if let Some((scope, team)) = normalized.split_once(':') {
                (vec!["-", "team", scope, team, "user"], normalized)
            } else {
                (vec!["-", "org", normalized, "team"], normalized)
            };
            let response = access_request(
                &client,
                reqwest::Method::GET,
                registry.as_deref(),
                &segments,
                None,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                for value in response.as_array().into_iter().flatten() {
                    println!("{}", value.as_str().unwrap_or_default());
                }
            }
            let _ = label;
            return Ok(());
        }
    };
    let (scope, team) = parse_team(&entity)?;
    let (segments, body) = if let Some(user) = user {
        let user = validate_account_name(&user, "username")?;
        (
            vec!["-", "team", scope.as_str(), team.as_str(), "user"],
            serde_json::json!({ "user": user }),
        )
    } else if method == reqwest::Method::PUT {
        (
            vec!["-", "org", scope.as_str(), "team"],
            serde_json::json!({ "name": team }),
        )
    } else {
        (
            vec!["-", "team", scope.as_str(), team.as_str()],
            serde_json::json!({}),
        )
    };
    access_request(&client, method, registry.as_deref(), &segments, Some(&body)).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "team": entity, "ok": true }))?
        );
    } else {
        println!("@{entity}");
    }
    Ok(())
}

async fn registry_identity(client: &reqwest::Client, registry: &str) -> Result<String> {
    let url = registry_url_with_segments(registry, &["-", "whoami"])?;
    let response = registry_request_with_auth(client, reqwest::Method::GET, url)?
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry identity lookup failed"
    );
    let body: serde_json::Value = response.json().await?;
    Ok(body["username"]
        .as_str()
        .or_else(|| body["name"].as_str())
        .context("registry identity response has no username")?
        .to_owned())
}

async fn cmd_star(packages: &[String], star: bool, registry: Option<&str>) -> Result<()> {
    anyhow::ensure!(!packages.is_empty(), "star requires at least one package");
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let username = registry_identity(&client, &registry).await?;
    for package in packages {
        let (name, _) = parse_package_spec(package);
        let mut url = registry_url_with_segments(&registry, &[&name])?;
        url.query_pairs_mut().append_pair("write", "true");
        let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "registry star lookup failed"
        );
        let mut body: serde_json::Value = response.json().await?;
        let users = body
            .as_object_mut()
            .context("registry package metadata is not an object")?
            .entry("users")
            .or_insert_with(|| serde_json::json!({}));
        let users = users
            .as_object_mut()
            .context("registry package users field is not an object")?;
        if star {
            users.insert(username.clone(), serde_json::Value::Bool(true));
        } else {
            users.remove(&username);
        }
        let url = registry_url_with_segments(&registry, &[&name])?;
        let response = registry_request_with_auth(&client, reqwest::Method::PUT, url)?
            .json(&serde_json::json!({
                "_id": body["_id"],
                "_rev": body["_rev"],
                "users": body["users"]
            }))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "registry star mutation failed"
        );
        println!("{} {name}", if star { "★" } else { "☆" });
    }
    Ok(())
}

async fn cmd_stars(user: Option<&str>, registry: Option<&str>) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let user = match user {
        Some(user) => validate_account_name(user, "username")?,
        None => registry_identity(&client, &registry).await?,
    };
    let mut url = registry_url_with_segments(&registry, &["-", "_view", "starredByUser"])?;
    url.query_pairs_mut()
        .append_pair("key", &serde_json::to_string(&user)?);
    let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry stars lookup failed"
    );
    let body: serde_json::Value = response.json().await?;
    for row in body["rows"].as_array().into_iter().flatten() {
        println!("{}", row["value"].as_str().unwrap_or_default());
    }
    Ok(())
}

async fn cmd_trust(action: TrustAction) -> Result<()> {
    match action {
        TrustAction::Github {
            package,
            file,
            repository,
            environment,
            yes,
            dry_run,
            registry,
        } => {
            validate_trust_file(&file, true)?;
            anyhow::ensure!(
                repository.split('/').count() == 2,
                "GitHub repository must have the form owner/repository"
            );
            let mut claims = serde_json::json!({
                "repository": repository,
                "workflow_ref": { "file": file }
            });
            if let Some(environment) = environment {
                claims["environment"] = serde_json::Value::String(environment);
            }
            create_trust(
                package,
                serde_json::json!({ "type": "github", "claims": claims }),
                yes,
                dry_run,
                registry,
            )
            .await?;
        }
        TrustAction::Gitlab {
            package,
            file,
            project,
            environment,
            yes,
            dry_run,
            registry,
        } => {
            validate_trust_file(&file, true)?;
            anyhow::ensure!(
                project.split('/').count() >= 2,
                "GitLab project must have the form group/project"
            );
            let mut claims = serde_json::json!({
                "project_path": project,
                "ci_config_ref_uri": { "file": file }
            });
            if let Some(environment) = environment {
                claims["environment"] = serde_json::Value::String(environment);
            }
            create_trust(
                package,
                serde_json::json!({ "type": "gitlab", "claims": claims }),
                yes,
                dry_run,
                registry,
            )
            .await?;
        }
        TrustAction::Circleci {
            package,
            org_id,
            project_id,
            pipeline_definition_id,
            vcs_origin,
            context_id,
            yes,
            dry_run,
            registry,
        } => {
            for (name, value) in [
                ("org-id", &org_id),
                ("project-id", &project_id),
                ("pipeline-definition-id", &pipeline_definition_id),
            ] {
                anyhow::ensure!(validate_uuid(value), "{name} must be a valid UUID");
            }
            for value in &context_id {
                anyhow::ensure!(validate_uuid(value), "context-id must be a valid UUID");
            }
            anyhow::ensure!(
                !vcs_origin.contains("://") && vcs_origin.split('/').count() >= 3,
                "vcs-origin must have the form provider/owner/repository without a scheme"
            );
            let mut claims = serde_json::Map::from_iter([
                ("oidc.circleci.com/org-id".into(), serde_json::json!(org_id)),
                (
                    "oidc.circleci.com/project-id".into(),
                    serde_json::json!(project_id),
                ),
                (
                    "oidc.circleci.com/pipeline-definition-id".into(),
                    serde_json::json!(pipeline_definition_id),
                ),
                (
                    "oidc.circleci.com/vcs-origin".into(),
                    serde_json::json!(vcs_origin),
                ),
            ]);
            if !context_id.is_empty() {
                claims.insert(
                    "oidc.circleci.com/context-ids".into(),
                    serde_json::json!(context_id),
                );
            }
            create_trust(
                package,
                serde_json::json!({ "type": "circleci", "claims": claims }),
                yes,
                dry_run,
                registry,
            )
            .await?;
        }
        TrustAction::List {
            package,
            json,
            registry,
        } => {
            let package = current_or_requested_package(package)?;
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "package", &package, "trust"])?;
            let client = reqwest::Client::builder()
                .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
                .build()?;
            let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected trust list with {}",
                response.status()
            );
            let body: serde_json::Value = response.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                for item in body.as_array().into_iter().flatten() {
                    println!(
                        "{}\t{}",
                        item["id"].as_str().unwrap_or_default(),
                        item["type"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        TrustAction::Revoke {
            package,
            id,
            dry_run,
            registry,
        } => {
            let package = current_or_requested_package(package)?;
            anyhow::ensure!(
                !id.is_empty() && !id.chars().any(char::is_control),
                "invalid trust id"
            );
            if dry_run {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "package": package,
                        "id": id,
                        "mutation": false
                    }))?
                );
                return Ok(());
            }
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url =
                registry_url_with_segments(&registry, &["-", "package", &package, "trust", &id])?;
            let client = reqwest::Client::builder()
                .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
                .build()?;
            let response = registry_request_with_auth(&client, reqwest::Method::DELETE, url)?
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "registry rejected trust revocation with {}",
                response.status()
            );
            println!("revoked trust {id} for {package}");
        }
    }
    Ok(())
}

async fn cmd_deprecate(package: &str, message: &str, registry: Option<&str>) -> Result<()> {
    let (name, requested) = parse_package_spec(package);
    let range = requested
        .parse::<node_semver::Range>()
        .with_context(|| format!("invalid package version range {requested}"))?;
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = registry_url_with_segments(&registry, &[&name])?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_optional_auth(&client, url.clone())
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry metadata request returned {}",
        response.status()
    );
    let mut packument: serde_json::Value = response.json().await?;
    let versions = packument["versions"]
        .as_object_mut()
        .context("registry package metadata has no versions")?;
    let mut changed = Vec::new();
    for (version, metadata) in versions {
        let Ok(parsed) = version.parse::<node_semver::Version>() else {
            continue;
        };
        if range.satisfies(&parsed) {
            if message.is_empty() {
                metadata
                    .as_object_mut()
                    .map(|object| object.remove("deprecated"));
            } else {
                metadata["deprecated"] = serde_json::Value::String(message.to_owned());
            }
            changed.push(version.clone());
        }
    }
    anyhow::ensure!(
        !changed.is_empty(),
        "no published versions of {name} match {requested}"
    );
    let response = registry_request_with_auth(&client, reqwest::Method::PUT, url)?
        .json(&packument)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry rejected deprecation update with {}",
        response.status()
    );
    println!(
        "{} {}",
        if message.is_empty() {
            "undeprecated"
        } else {
            "deprecated"
        },
        changed.join(", ")
    );
    Ok(())
}

fn package_spec_has_explicit_version(spec: &str) -> bool {
    if let Some(scoped) = spec.strip_prefix('@') {
        scoped.contains('@')
    } else {
        spec.contains('@')
    }
}

async fn cmd_unpublish(
    package: Option<&str>,
    force: bool,
    dry_run: bool,
    registry: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(force, "unpublish requires --force");
    let owned_spec;
    let spec = if let Some(package) = package {
        package
    } else {
        let manifest = read_package_json()?;
        let name = manifest["name"]
            .as_str()
            .context("package.json has no package name")?;
        let version = manifest["version"]
            .as_str()
            .context("package.json has no package version")?;
        owned_spec = format!("{name}@{version}");
        &owned_spec
    };
    let explicit_version = package.is_none() || package_spec_has_explicit_version(spec);
    let (name, version) = parse_package_spec(spec);
    if explicit_version {
        anyhow::ensure!(
            version.parse::<node_semver::Version>().is_ok(),
            "unpublish requires an exact version when a version is supplied"
        );
    }
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let package_url = registry_url_with_segments(&registry, &[&name])?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_optional_auth(&client, package_url.clone())
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry metadata request returned {}",
        response.status()
    );
    let mut packument: serde_json::Value = response.json().await?;
    if dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "package": name,
                "version": explicit_version.then_some(version),
                "registry": registry,
                "mutation": false
            }))?
        );
        return Ok(());
    }
    if !explicit_version {
        let revision = packument["_rev"]
            .as_str()
            .context("registry metadata has no revision required for full unpublish")?;
        let delete_url = registry_url_with_segments(&registry, &[&name, "-rev", revision])?;
        let response = registry_request_with_auth(&client, reqwest::Method::DELETE, delete_url)?
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "registry rejected full unpublish with {}",
            response.status()
        );
        println!("-{name}");
        return Ok(());
    }

    let removed = packument["versions"]
        .as_object_mut()
        .and_then(|versions| versions.remove(&version))
        .with_context(|| format!("{name}@{version} is not published"))?;
    let replacement = packument["versions"]
        .as_object()
        .into_iter()
        .flat_map(|versions| versions.keys())
        .filter_map(|candidate| {
            candidate
                .parse::<node_semver::Version>()
                .ok()
                .map(|parsed| (parsed, candidate.clone()))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, version)| version);
    if let Some(tags) = packument["dist-tags"].as_object_mut() {
        let affected: Vec<_> = tags
            .iter()
            .filter(|(_, tagged)| tagged.as_str() == Some(&version))
            .map(|(tag, _)| tag.clone())
            .collect();
        for tag in affected {
            if let Some(replacement) = &replacement {
                tags.insert(tag, serde_json::Value::String(replacement.clone()));
            } else {
                tags.remove(&tag);
            }
        }
    }
    if let Some(tarball) = removed
        .get("dist")
        .and_then(|dist| dist.get("tarball"))
        .and_then(serde_json::Value::as_str)
        .and_then(|url| reqwest::Url::parse(url).ok())
        .and_then(|url| url.path_segments()?.next_back().map(str::to_owned))
        && let Some(attachments) = packument["_attachments"].as_object_mut()
    {
        attachments.remove(&tarball);
    }
    let response = registry_request_with_auth(&client, reqwest::Method::PUT, package_url)?
        .json(&packument)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry rejected version unpublish with {}",
        response.status()
    );
    println!("-{name}@{version}");
    Ok(())
}

async fn cmd_doctor(json_output: bool, registry: Option<&str>) -> Result<bool> {
    let cwd = std::env::current_dir()?;
    let store = ContentStore::default_store()?;
    let mut checks = BTreeMap::new();
    checks.insert("node", command_version("node"));
    checks.insert("npm", command_version("npm"));
    checks.insert("git", command_version("git"));
    checks.insert(
        "package_json",
        serde_json::json!({ "ok": cwd.join("package.json").is_file() }),
    );
    checks.insert(
        "lockfile",
        serde_json::json!({
            "ok": cwd.join("oath-lock.json").is_file() || cwd.join("package-lock.json").is_file(),
            "oath": cwd.join("oath-lock.json").is_file(),
            "npm": cwd.join("package-lock.json").is_file()
        }),
    );
    checks.insert(
        "content_store",
        writable_directory_check(&store.store_path(), store.list_packages().len()),
    );
    checks.insert("project_permissions", writable_directory_check(&cwd, 0));
    let global = global_prefix()?;
    if global.exists() {
        checks.insert("global_permissions", writable_directory_check(&global, 0));
    }
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = reqwest::Url::parse(&format!(
        "{}/-/ping?write=true",
        registry.trim_end_matches('/')
    ))?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let registry_check = match registry_request_with_optional_auth(&client, url)
        .send()
        .await
    {
        Ok(response) => serde_json::json!({
            "ok": response.status().is_success(),
            "status": response.status().as_u16(),
            "registry": registry
        }),
        Err(error) => serde_json::json!({
            "ok": false,
            "registry": registry,
            "error": error.to_string()
        }),
    };
    checks.insert("registry", registry_check);
    let ok = checks
        .values()
        .all(|check| check["ok"].as_bool().unwrap_or(false));
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "ok": ok, "checks": checks }))?
        );
    } else {
        for (name, check) in &checks {
            println!(
                "{:16} {}",
                name,
                if check["ok"].as_bool().unwrap_or(false) {
                    "ok"
                } else {
                    "not ok"
                }
            );
        }
    }
    Ok(ok)
}

fn writable_directory_check(path: &std::path::Path, packages: usize) -> serde_json::Value {
    let probe = path.join(format!(
        ".oath-doctor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe);
    let (ok, error) = match result {
        Ok(file) => {
            drop(file);
            let removed = std::fs::remove_file(&probe).is_ok();
            (
                removed,
                (!removed).then(|| "failed to remove permission probe".to_owned()),
            )
        }
        Err(error) => (false, Some(error.to_string())),
    };
    serde_json::json!({
        "ok": ok,
        "path": path,
        "packages": packages,
        "error": error,
        "remediation": (!ok).then(|| format!(
            "restore ownership and write permission for the current user on {}",
            path.display()
        ))
    })
}

fn oath_lock_as_npm_shrinkwrap(lock: &Lockfile) -> serde_json::Value {
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        serde_json::json!({
            "name": lock.name,
            "version": lock.version,
            "dependencies": lock.root_dependencies,
            "devDependencies": lock.root_dev_dependencies
        }),
    );
    for (key, entry) in &lock.packages {
        let name = entry.package_name_for_key(key);
        packages.insert(
            format!("node_modules/{name}"),
            serde_json::json!({
                "version": entry.version,
                "resolved": entry.resolved,
                "integrity": entry.integrity,
                "dependencies": entry.dependencies,
                "dev": entry.dev,
                "optional": entry.optional,
                "hasInstallScript": entry.has_install_script
            }),
        );
    }
    serde_json::json!({
        "name": lock.name,
        "version": lock.version,
        "lockfileVersion": 3,
        "requires": true,
        "packages": packages
    })
}

fn cmd_shrinkwrap() -> Result<()> {
    let package_lock = PathBuf::from("package-lock.json");
    let shrinkwrap = PathBuf::from("npm-shrinkwrap.json");
    let document: serde_json::Value = if package_lock.is_file() {
        serde_json::from_slice(&std::fs::read(&package_lock)?)
            .context("failed to parse package-lock.json")?
    } else {
        let lock = Lockfile::read(&PathBuf::from("oath-lock.json")).context(
            "shrinkwrap requires package-lock.json or oath-lock.json; run oath install first",
        )?;
        oath_lock_as_npm_shrinkwrap(&lock)
    };
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    write_manifest_atomic(&shrinkwrap, &bytes)?;
    if package_lock.is_file() {
        std::fs::remove_file(&package_lock)?;
    }
    println!("wrote {}", shrinkwrap.display());
    Ok(())
}

fn cmd_pkg_one(action: &PkgAction) -> Result<Option<serde_json::Value>> {
    let mut manifest = read_package_json()?;
    match action {
        PkgAction::Get { keys } => {
            if keys.is_empty() {
                return Ok(Some(manifest));
            }
            let mut output = serde_json::Map::new();
            for key in keys {
                let parts = parse_json_path(key)?;
                if let Some(value) = json_path_get(&manifest, &parts) {
                    output.insert(key.clone(), value.clone());
                }
            }
            Ok(Some(if keys.len() == 1 {
                output
                    .values()
                    .next()
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Object(output)
            }))
        }
        PkgAction::Set { assignments, json } => {
            anyhow::ensure!(
                !assignments.is_empty(),
                "pkg set requires key=value assignments"
            );
            for assignment in assignments {
                let (key, raw) = assignment
                    .split_once('=')
                    .context("pkg set assignments must use key=value")?;
                let replacement = if *json {
                    serde_json::from_str(raw).context("invalid JSON package property value")?
                } else {
                    serde_json::Value::String(raw.to_string())
                };
                json_path_set(&mut manifest, &parse_json_path(key)?, replacement)?;
            }
            write_package_manifest(&manifest)?;
            Ok(None)
        }
        PkgAction::Delete { keys } => {
            anyhow::ensure!(!keys.is_empty(), "pkg delete requires at least one key");
            for key in keys {
                json_path_delete(&mut manifest, &parse_json_path(key)?);
            }
            write_package_manifest(&manifest)?;
            Ok(None)
        }
        PkgAction::Fix => {
            let npm = pinned_npm_cli_path()?;
            let status = std::process::Command::new("node")
                .arg(npm)
                .args(["pkg", "fix"])
                .status()
                .context("launch integrity-pinned npm package normalizer")?;
            anyhow::ensure!(status.success(), "package.json normalization failed");
            let mut normalized = read_package_json()?;
            for group in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                if normalized[group]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
                {
                    normalized
                        .as_object_mut()
                        .context("package.json must be an object")?
                        .remove(group);
                }
            }
            write_package_manifest(&normalized)?;
            Ok(None)
        }
    }
}

fn cmd_pkg(action: PkgAction, workspace: &WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        if let Some(output) = cmd_pkg_one(&action)? {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        return Ok(());
    }
    let mut outputs = serde_json::Map::new();
    for target in selected_workspace_targets(workspace)? {
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        if let Some(output) = cmd_pkg_one(&action)? {
            outputs.insert(target.name, output);
        }
    }
    if !outputs.is_empty() {
        println!("{}", serde_json::to_string_pretty(&outputs)?);
    }
    Ok(())
}

fn local_prefix() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    Ok(cwd
        .ancestors()
        .find(|path| path.join("package.json").is_file())
        .unwrap_or(&cwd)
        .to_path_buf())
}

fn global_prefix() -> Result<PathBuf> {
    Ok(oath_core::home_dir()
        .context("could not determine home directory")?
        .join(".oath")
        .join("global"))
}

fn cmd_root(global: bool) -> Result<()> {
    println!(
        "{}",
        if global {
            global_prefix()?.join("node_modules")
        } else {
            local_prefix()?.join("node_modules")
        }
        .display()
    );
    Ok(())
}

fn cmd_prefix(global: bool) -> Result<()> {
    println!(
        "{}",
        if global {
            global_prefix()?
        } else {
            local_prefix()?
        }
        .display()
    );
    Ok(())
}

async fn cmd_ping(registry: Option<&str>, json_output: bool) -> Result<()> {
    let registry = effective_registry(registry, None)?;
    let registry = credential_registry_url(&registry)?;
    let url = format!("{}/-/ping?write=true", registry.trim_end_matches('/'));
    let start = std::time::Instant::now();
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_optional_auth(&client, reqwest::Url::parse(&url)?)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry ping returned {}",
        response.status()
    );
    let elapsed = start.elapsed().as_millis();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "registry": registry, "time": elapsed, "details": response.json::<serde_json::Value>().await.unwrap_or_else(|_| serde_json::json!({})) })
            )?
        );
    } else {
        println!("PING {registry}");
        println!("PONG {elapsed}ms");
    }
    Ok(())
}

async fn cmd_search(
    terms: &[String],
    limit: usize,
    json_output: bool,
    registry: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(!terms.is_empty(), "search requires at least one term");
    anyhow::ensure!(
        (1..=250).contains(&limit),
        "--searchlimit must be between 1 and 250"
    );
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let mut url = reqwest::Url::parse(&format!("{}/-/v1/search", registry.trim_end_matches('/')))?;
    url.query_pairs_mut()
        .append_pair("text", &terms.join(" "))
        .append_pair("size", &limit.to_string());
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_optional_auth(&client, url)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry search returned {}",
        response.status()
    );
    let body: serde_json::Value = response.json().await?;
    let objects = body["objects"]
        .as_array()
        .context("registry search response has no objects")?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(objects)?);
    } else {
        for object in objects {
            let package = &object["package"];
            println!(
                "{}\t{}\t{}",
                package["name"].as_str().unwrap_or(""),
                package["version"].as_str().unwrap_or(""),
                package["description"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}

#[derive(Copy, Clone)]
enum PackagePage {
    Bugs,
    Docs,
    Repo,
}

fn package_page_url(packument: &serde_json::Value, page: PackagePage) -> Option<String> {
    let raw = match page {
        PackagePage::Bugs => packument
            .get("bugs")
            .and_then(|value| value.get("url").or(Some(value)))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                package_page_url(packument, PackagePage::Repo)
                    .map(|url| format!("{}/issues", url.trim_end_matches('/')))
            }),
        PackagePage::Docs => packument
            .get("homepage")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| package_page_url(packument, PackagePage::Repo)),
        PackagePage::Repo => packument
            .get("repository")
            .and_then(|value| value.get("url").or(Some(value)))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }?;
    let mut url = raw.strip_prefix("git+").unwrap_or(&raw).to_owned();
    if let Some(repository) = url.strip_prefix("git@github.com:") {
        url = format!("https://github.com/{repository}");
    } else if let Some(repository) = url.strip_prefix("git://github.com/") {
        url = format!("https://github.com/{repository}");
    }
    if url.ends_with(".git") {
        url.truncate(url.len() - 4);
    }
    reqwest::Url::parse(&url)
        .ok()
        .filter(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .map(|_| url)
}

fn open_package_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "refusing to open a non-HTTP package URL"
    );
    let status = if let Ok(browser) = std::env::var("BROWSER") {
        let mut parts = browser.split_whitespace();
        let program = parts.next().context("BROWSER is empty")?;
        std::process::Command::new(program)
            .args(parts)
            .arg(url)
            .status()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .status()
    } else {
        std::process::Command::new("xdg-open").arg(url).status()
    }
    .context("failed to launch the configured browser")?;
    anyhow::ensure!(status.success(), "browser command failed with {status}");
    Ok(())
}

async fn cmd_package_page(
    page: PackagePage,
    package: Option<&str>,
    registry: Option<&str>,
) -> Result<()> {
    let package = package.map(str::to_owned).map_or_else(
        || {
            read_package_json()?["name"]
                .as_str()
                .map(str::to_owned)
                .context("package.json has no name")
        },
        Ok,
    )?;
    let registry = credential_registry_url(&effective_registry(registry, None)?)?;
    let url = registry_url_with_segments(&registry, &[&package])?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = registry_request_with_optional_auth(&client, url)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry metadata request returned {}",
        response.status()
    );
    let packument: serde_json::Value = response.json().await?;
    let url = package_page_url(&packument, page).context("package metadata has no usable URL")?;
    open_package_url(&url)
}

fn installed_package_directory(package: &str) -> Result<PathBuf> {
    validate_link_package_name(package)?;
    for path in collect_installed_package_dirs(&std::env::current_dir()?.join("node_modules"))? {
        let Ok(bytes) = std::fs::read(path.join("package.json")) else {
            continue;
        };
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
        if manifest["name"].as_str() == Some(package) {
            return Ok(path);
        }
    }
    anyhow::bail!("package is not installed: {package}")
}

fn cmd_edit(package: &str) -> Result<()> {
    let path = installed_package_directory(package)?;
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .context("set EDITOR or VISUAL before using oath edit")?;
    let mut parts = editor.split_whitespace();
    let program = parts.next().context("EDITOR is empty")?;
    let status = std::process::Command::new(program)
        .args(parts)
        .arg(path)
        .status()?;
    anyhow::ensure!(status.success(), "editor exited with {status}");
    Ok(())
}

fn cmd_explore(package: &str, command: &[String]) -> Result<()> {
    let path = installed_package_directory(package)?;
    let status = if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| {
            if cfg!(target_os = "windows") {
                "cmd.exe".to_owned()
            } else {
                "sh".to_owned()
            }
        });
        std::process::Command::new(shell)
            .current_dir(path)
            .status()?
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("cmd.exe")
            .arg("/C")
            .arg(shell_quote_args(command))
            .current_dir(path)
            .status()?
    } else {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(shell_quote_args(command))
            .current_dir(path)
            .status()?
    };
    anyhow::ensure!(status.success(), "explore command exited with {status}");
    Ok(())
}

fn cmd_completion(shell: Option<CompletionShell>) -> Result<()> {
    let shell = shell.unwrap_or_else(|| {
        let configured = std::env::var("SHELL").unwrap_or_default();
        if configured.ends_with("zsh") {
            CompletionShell::Zsh
        } else if configured.ends_with("fish") {
            CompletionShell::Fish
        } else {
            CompletionShell::Bash
        }
    });
    let commands = Cli::command()
        .get_subcommands()
        .map(|command| command.get_name())
        .collect::<Vec<_>>()
        .join(" ");
    match shell {
        CompletionShell::Bash => println!(
            "_oath() {{ COMPREPLY=( $(compgen -W '{commands}' -- \"${{COMP_WORDS[1]}}\") ); }}\ncomplete -F _oath oath"
        ),
        CompletionShell::Zsh => {
            println!("#compdef oath\n_arguments '1:command:(({commands}))' '*::argument:->args'")
        }
        CompletionShell::Fish => {
            println!("complete -c oath -f -n '__fish_use_subcommand' -a '{commands}'")
        }
        CompletionShell::Powershell => println!(
            "Register-ArgumentCompleter -Native -CommandName oath -ScriptBlock {{ param($wordToComplete) '{commands}'.Split(' ') | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}"
        ),
    }
    Ok(())
}

fn cmd_help_search(terms: &[String]) -> Result<()> {
    anyhow::ensure!(!terms.is_empty(), "help-search requires at least one term");
    let terms = terms
        .iter()
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut matches = Vec::new();
    for command in Cli::command().get_subcommands() {
        let mut command = command.clone();
        let help = command.render_long_help().to_string();
        let searchable = help.to_ascii_lowercase();
        if terms.iter().all(|term| searchable.contains(term)) {
            matches.push((command.get_name().to_owned(), help));
        }
    }
    anyhow::ensure!(!matches.is_empty(), "no help matches found");
    for (index, (name, help)) in matches.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("Top hits for `{}`", terms.join(" "));
        println!("--- oath {name} ---");
        println!("{}", help.trim());
    }
    Ok(())
}

fn clean_cache_store(store: &ContentStore, force: bool) -> Result<usize> {
    anyhow::ensure!(force, "npm-compatible cache clean requires --force");
    let packages = store.list_packages();
    for (name, version) in &packages {
        store.remove_package(name, version)?;
    }
    Ok(packages.len())
}

fn validate_npmrc_entry(key: &str, value: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        !key.is_empty() && !key.contains('=') && !key.chars().any(char::is_control),
        "invalid npm config key"
    );
    if let Some(value) = value {
        anyhow::ensure!(
            !value
                .chars()
                .any(|character| matches!(character, '\n' | '\r' | '\0')),
            "npm config values cannot contain line breaks or NUL bytes"
        );
    }
    if let Some(value) = value.filter(|_| key == "registry" || key.ends_with(":registry")) {
        let parsed = reqwest::Url::parse(value).context("invalid registry URL")?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https"),
            "registry URL must use HTTP or HTTPS"
        );
    }
    Ok(())
}

fn config_location_path(location: Option<&str>, global: bool) -> Result<Option<PathBuf>> {
    anyhow::ensure!(
        !(global && location.is_some_and(|value| value != "global")),
        "--global conflicts with a non-global --location"
    );
    Ok(match if global { Some("global") } else { location } {
        None => None,
        Some("user") => Some(user_npmrc_path()?),
        Some("project") => Some(std::env::current_dir()?.join(".npmrc")),
        Some("global") => Some(
            std::env::var_os("NPM_CONFIG_GLOBALCONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    oath_core::home_dir()
                        .unwrap_or_else(std::env::temp_dir)
                        .join(".oath")
                        .join("global")
                        .join("etc")
                        .join("npmrc")
                }),
        ),
        Some(_) => unreachable!(),
    })
}

fn npmrc_entries(path: &std::path::Path) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(error) => return Err(error.into()),
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("invalid npmrc line in {}", path.display()))?;
        validate_npmrc_entry(key.trim(), Some(value.trim()))?;
        entries.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(entries)
}

fn cmd_config(
    args: &[String],
    json_output: bool,
    location: Option<&str>,
    global: bool,
) -> Result<()> {
    let selected_path = config_location_path(location, global)?;
    let action = args.first().map(String::as_str).unwrap_or("list");
    match action {
        "set" => {
            let (key, value) = match args.get(1..).unwrap_or_default() {
                [assignment] if assignment.contains('=') => assignment
                    .split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .context("config set requires key=value")?,
                [key, value] => (key.clone(), value.clone()),
                _ => anyhow::bail!("usage: oath config set <key> <value>"),
            };
            validate_npmrc_entry(&key, Some(&value))?;
            let path = selected_path.clone().unwrap_or(user_npmrc_path()?);
            update_npmrc_path(&path, &BTreeMap::from([(key.clone(), Some(value.clone()))]))?;
            if json_output {
                let shown = if key.to_ascii_lowercase().contains("token") {
                    "(protected)"
                } else {
                    &value
                };
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ key: shown }))?
                );
            }
            return Ok(());
        }
        "delete" | "rm" => {
            let key = args.get(1).context("usage: oath config delete <key>")?;
            anyhow::ensure!(args.len() == 2, "usage: oath config delete <key>");
            validate_npmrc_entry(key, None)?;
            let path = selected_path.clone().unwrap_or(user_npmrc_path()?);
            update_npmrc_path(&path, &BTreeMap::from([(key.clone(), None)]))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "deleted": key }))?
                );
            }
            return Ok(());
        }
        "get" => {
            anyhow::ensure!(args.len() == 2, "usage: oath config get <key>");
        }
        "list" | "ls" => {
            anyhow::ensure!(args.len() == 1, "config list does not accept operands");
        }
        "edit" => {
            anyhow::ensure!(args.len() == 1, "config edit does not accept operands");
            let path = selected_path.clone().unwrap_or(user_npmrc_path()?);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !path.exists() {
                write_manifest_atomic(&path, b"")?;
            }
            let editor = std::env::var("EDITOR")
                .or_else(|_| std::env::var("VISUAL"))
                .context("set EDITOR or VISUAL before using config edit")?;
            let mut parts = editor.split_whitespace();
            let program = parts.next().context("EDITOR is empty")?;
            let status = std::process::Command::new(program)
                .args(parts)
                .arg(&path)
                .status()?;
            anyhow::ensure!(status.success(), "editor exited with {status}");
            return Ok(());
        }
        "fix" => {
            anyhow::ensure!(args.len() == 1, "config fix does not accept operands");
            let path = selected_path.clone().unwrap_or(user_npmrc_path()?);
            let entries = npmrc_entries(&path)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "path": path,
                        "entries": entries.len(),
                        "valid": true
                    }))?
                );
            } else {
                println!("{}: configuration is valid", path.display());
            }
            return Ok(());
        }
        _ => {
            anyhow::ensure!(args.len() == 1, "usage: oath config [get] <key>");
        }
    }

    let key = match action {
        "get" => args.get(1).map(String::as_str),
        "list" | "ls" => None,
        _ if !args.is_empty() => Some(action),
        _ => None,
    };
    if let Some(path) = selected_path {
        let mut entries = npmrc_entries(&path)?;
        if let Some(key) = key {
            anyhow::ensure!(
                !key.to_ascii_lowercase().contains("token") && !key.contains("_auth"),
                "credential config values are protected and cannot be printed"
            );
            let value = entries
                .remove(key)
                .with_context(|| format!("unsupported or unset config key {key}"))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ key: value }))?
                );
            } else {
                println!("{value}");
            }
            return Ok(());
        }
        entries
            .retain(|key, _| !key.to_ascii_lowercase().contains("token") && !key.contains("_auth"));
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        } else {
            for (key, value) in entries {
                println!("{key}={value}");
            }
        }
        return Ok(());
    }
    let config = oath_fetch::NpmrcConfig::load(&std::env::current_dir()?);
    let registry = config
        .default_registry
        .clone()
        .unwrap_or_else(|| "https://registry.npmjs.org".to_owned());
    let mut token_hosts: Vec<_> = config.tokens.keys().cloned().collect();
    token_hosts.sort();
    let mut scopes: BTreeMap<_, _> = config.scoped_registries.into_iter().collect();
    if let Some(key) = key {
        anyhow::ensure!(
            !key.to_ascii_lowercase().contains("token") && !key.contains("_auth"),
            "credential config values are protected and cannot be printed"
        );
        let value = if key == "registry" {
            Some(registry)
        } else if let Some(scope) = key.strip_suffix(":registry") {
            scopes.remove(scope)
        } else {
            None
        };
        let value = value.with_context(|| format!("unsupported or unset config key {key}"))?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({ key: value }))?
            );
        } else {
            println!("{value}");
        }
        return Ok(());
    }
    let report = serde_json::json!({
        "schema_version": 1,
        "registry": registry,
        "scoped_registries": scopes.clone(),
        "authenticated_hosts": token_hosts.clone(),
        "tokens_redacted": true,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "registry={}",
            report["registry"].as_str().unwrap_or_default()
        );
        for (scope, registry) in scopes {
            println!("{scope}:registry={registry}");
        }
        for host in token_hosts {
            println!("//{host}/:_authToken=(protected)");
        }
    }
    Ok(())
}

async fn cmd_whoami(json_output: bool) -> Result<()> {
    let config = oath_fetch::NpmrcConfig::load(&std::env::current_dir()?);
    let registry = config
        .default_registry
        .clone()
        .unwrap_or_else(|| "https://registry.npmjs.org".to_owned());
    let registry = credential_registry_url(&registry)?;
    let url = reqwest::Url::parse(&format!("{}/-/whoami", registry.trim_end_matches('/')))?;
    let host = url.host_str().context("registry URL has no host")?;
    let token = config
        .token_for_host(host)
        .context("no authentication token configured for the default registry")?;
    let response = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(url)
        .bearer_auth(token)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry identity request returned {}",
        response.status()
    );
    let identity: serde_json::Value = response.json().await?;
    let username = identity["username"]
        .as_str()
        .context("registry identity response has no username")?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "username": username }))?
        );
    } else {
        println!("{username}");
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    anyhow::ensure!(
        scope.starts_with('@') && scope.len() > 1 && !scope.contains('/'),
        "scope must have the form @name"
    );
    Ok(())
}

fn effective_registry(registry: Option<&str>, scope: Option<&str>) -> Result<String> {
    if let Some(scope) = scope {
        validate_scope(scope)?;
    }
    if let Some(registry) = registry {
        return Ok(registry.trim_end_matches('/').to_owned());
    }
    let config = oath_fetch::NpmrcConfig::load(&std::env::current_dir()?);
    if let Some(scope) = scope
        && let Some(registry) = config.scoped_registries.get(scope)
    {
        return Ok(registry.trim_end_matches('/').to_owned());
    }
    Ok(config
        .default_registry
        .unwrap_or_else(|| "https://registry.npmjs.org".to_owned())
        .trim_end_matches('/')
        .to_owned())
}

fn user_npmrc_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("NPM_CONFIG_USERCONFIG") {
        return Ok(PathBuf::from(path));
    }
    Ok(oath_core::home_dir()
        .context("could not determine home directory")?
        .join(".npmrc"))
}

fn npmrc_auth_key(registry: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(registry).context("invalid registry URL")?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "https" | "http"),
        "registry URL must use HTTP or HTTPS"
    );
    let host = parsed.host_str().context("registry URL has no host")?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let path = parsed.path().trim_matches('/');
    Ok(if path.is_empty() {
        format!("//{authority}/:_authToken")
    } else {
        format!("//{authority}/{path}/:_authToken")
    })
}

fn credential_registry_url(registry: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(registry).context("invalid registry URL")?;
    let loopback = parsed.host_str().is_some_and(|host| {
        let normalized = host.trim_matches(['[', ']']);
        normalized == "localhost"
            || normalized
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    anyhow::ensure!(
        parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback),
        "credential-bearing registry requests require HTTPS except on loopback"
    );
    Ok(registry.trim_end_matches('/').to_owned())
}

fn update_user_npmrc(updates: &BTreeMap<String, Option<String>>) -> Result<()> {
    update_npmrc_path(&user_npmrc_path()?, updates)
}

fn update_npmrc_path(
    path: &std::path::Path,
    updates: &BTreeMap<String, Option<String>>,
) -> Result<()> {
    use std::io::Write;

    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut seen = HashSet::new();
    let mut lines = Vec::new();
    for line in existing.lines() {
        let key = line
            .split_once('=')
            .map(|(key, _)| key.trim())
            .unwrap_or_default();
        if let Some(value) = updates.get(key) {
            seen.insert(key.to_owned());
            if let Some(value) = value {
                lines.push(format!("{key}={value}"));
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    for (key, value) in updates {
        if !seen.contains(key)
            && let Some(value) = value
        {
            lines.push(format!("{key}={value}"));
        }
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }

    let parent = path.parent().context("npmrc path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".npmrc.oath-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    if !lines.is_empty() {
        file.write_all(lines.join("\n").as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    replace_file(&temporary, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn web_login_token(registry: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let start_url = registry_url_with_segments(registry, &["-", "v1", "login"])?;
    let response = client
        .post(start_url)
        .json(&serde_json::json!({}))
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    anyhow::ensure!(
        status.is_success(),
        "registry does not support web login ({status})"
    );
    let login_url = body["loginUrl"]
        .as_str()
        .context("web-login response has no loginUrl")?;
    let done_url = body["doneUrl"]
        .as_str()
        .context("web-login response has no doneUrl")?;
    for (label, value) in [("loginUrl", login_url), ("doneUrl", done_url)] {
        let parsed = reqwest::Url::parse(value)
            .with_context(|| format!("web-login {label} is not a URL"))?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.username().is_empty()
                && parsed.password().is_none(),
            "web-login {label} must be an HTTP(S) URL without embedded credentials"
        );
    }
    open_package_url(login_url)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "web login timed out after five minutes"
        );
        let response = client.get(done_url).send().await?;
        if response.status() == reqwest::StatusCode::OK {
            let body: serde_json::Value = response.json().await?;
            return body["token"]
                .as_str()
                .map(str::to_owned)
                .context("web-login completion response has no token");
        }
        if response.status() == reqwest::StatusCode::ACCEPTED {
            let delay = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .clamp(1, 10);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            continue;
        }
        anyhow::bail!(
            "web-login completion endpoint returned {}",
            response.status()
        );
    }
}

async fn legacy_login_token(
    registry: &str,
    username: Option<&str>,
    password_stdin: bool,
    otp: Option<&str>,
) -> Result<String> {
    let username = if let Some(username) = username {
        validate_account_name(username, "username")?
    } else {
        print!("Username: ");
        std::io::stdout().flush()?;
        let mut username = String::new();
        std::io::stdin().read_line(&mut username)?;
        validate_account_name(username.trim(), "username")?
    };
    let password = read_profile_secret("Password: ", password_stdin)?;
    if let Some(otp) = otp {
        validate_otp(otp)?;
    }
    let url = registry_url_with_segments(
        registry,
        &["-", "user", &format!("org.couchdb.user:{username}")],
    )?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut request = client.put(url);
    if let Some(otp) = otp {
        request = request.header("npm-otp", otp);
    }
    let response = request
        .json(&serde_json::json!({
            "_id": format!("org.couchdb.user:{username}"),
            "name": username,
            "password": password,
            "type": "user",
            "roles": [],
        }))
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    anyhow::ensure!(status.is_success(), "legacy login failed with {status}");
    body["token"]
        .as_str()
        .map(str::to_owned)
        .context("legacy login response has no bearer token")
}

#[allow(clippy::too_many_arguments)]
async fn cmd_login(
    registry: Option<&str>,
    scope: Option<&str>,
    token_stdin: bool,
    auth_type: LoginAuthType,
    otp: Option<&str>,
    username: Option<&str>,
    password_stdin: bool,
    json_output: bool,
) -> Result<()> {
    use std::io::Read;

    let registry = credential_registry_url(&effective_registry(registry, scope)?)?;
    let environment_token = std::env::var("NPM_TOKEN").ok();
    let web_token = if !token_stdin && environment_token.is_none() {
        match auth_type {
            LoginAuthType::Web => Some(web_login_token(&registry).await?),
            LoginAuthType::Legacy => {
                Some(legacy_login_token(&registry, username, password_stdin, otp).await?)
            }
        }
    } else {
        None
    };

    let token = if token_stdin {
        let mut token = String::new();
        std::io::stdin().read_to_string(&mut token)?;
        token.trim().to_owned()
    } else {
        environment_token
            .or(web_token)
            .context("registry login did not return a token")?
    };
    anyhow::ensure!(!token.trim().is_empty(), "registry token is empty");
    anyhow::ensure!(
        !token.contains(['\r', '\n']),
        "registry token contains a newline"
    );

    let whoami = format!("{}/-/whoami", registry.trim_end_matches('/'));
    let response = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(&whoami)
        .bearer_auth(&token)
        .send()
        .await
        .with_context(|| format!("failed to verify credentials with {registry}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry rejected credentials with {}",
        response.status()
    );
    let identity: serde_json::Value = response.json().await?;
    let username = identity["username"]
        .as_str()
        .context("registry identity response has no username")?;

    let mut updates = BTreeMap::new();
    updates.insert(npmrc_auth_key(&registry)?, Some(token));
    if let Some(scope) = scope {
        updates.insert(format!("{scope}:registry"), Some(registry.clone()));
    }
    update_user_npmrc(&updates)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "username": username,
                "registry": registry,
                "scope": scope,
                "credentials_stored": true,
            }))?
        );
    } else {
        println!("Logged in to {registry} as {username}");
    }
    Ok(())
}

fn user_npmrc_value(key: &str) -> Result<Option<String>> {
    let path = user_npmrc_path()?;
    let Ok(content) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    Ok(content.lines().rev().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key).then(|| value.trim().trim_matches(['\'', '"']).to_owned())
    }))
}

async fn cmd_logout(registry: Option<&str>, scope: Option<&str>, json_output: bool) -> Result<()> {
    let registry = credential_registry_url(&effective_registry(registry, scope)?)?;
    let auth_key = npmrc_auth_key(&registry)?;
    let token = user_npmrc_value(&auth_key)?
        .with_context(|| format!("not logged in to {registry}, so cannot log out"))?;
    let mut revoke_url = reqwest::Url::parse(&registry)?;
    revoke_url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("registry URL cannot be a base URL"))?
        .pop_if_empty()
        .push("-")
        .push("user")
        .push("token")
        .push(&token);
    let response = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?
        .delete(revoke_url)
        .bearer_auth(&token)
        .send()
        .await
        .with_context(|| format!("failed to revoke credentials with {registry}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "registry rejected logout with {}",
        response.status()
    );

    let mut updates = BTreeMap::new();
    updates.insert(auth_key, None);
    if let Some(scope) = scope {
        updates.insert(format!("{scope}:registry"), None);
    }
    update_user_npmrc(&updates)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "registry": registry,
                "scope": scope,
                "credentials_removed": true,
                "server_session_revoked": true
            }))?
        );
    } else {
        println!("Logged out of {registry}");
    }
    Ok(())
}

fn validate_link_package_name(name: &str) -> Result<()> {
    let valid_component = |part: &str| {
        !part.is_empty() && !matches!(part, "." | "..") && !part.contains(['/', '\\', '\0'])
    };
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped
            .split_once('/')
            .context("scoped package must have the form @scope/name")?;
        anyhow::ensure!(
            valid_component(scope) && valid_component(package),
            "invalid package name"
        );
    } else {
        anyhow::ensure!(valid_component(name), "invalid package name");
    }
    Ok(())
}

fn remove_link_only(path: &std::path::Path) -> Result<bool> {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Ok(false);
    };
    anyhow::ensure!(
        metadata.file_type().is_symlink(),
        "refusing to replace non-link path {}",
        path.display()
    );
    std::fs::remove_file(path)?;
    Ok(true)
}

fn create_directory_link(target: &std::path::Path, link: &std::path::Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_link_only(link)?;
    platform_symlink_dir(target, link)
        .with_context(|| format!("failed to link {} -> {}", link.display(), target.display()))?;
    Ok(())
}

fn global_link_root() -> Result<PathBuf> {
    Ok(oath_core::home_dir()
        .context("could not determine home directory")?
        .join(".oath")
        .join("global"))
}

fn cmd_link(packages: Vec<String>, save: bool) -> Result<()> {
    let global = global_link_root()?;
    let global_modules = global.join("node_modules");
    if packages.is_empty() {
        let cwd = std::env::current_dir()?.canonicalize()?;
        let package = read_package_json()?;
        let name = package["name"]
            .as_str()
            .context("package.json must declare a name before it can be linked")?;
        validate_link_package_name(name)?;
        let destination = global_modules.join(name);
        create_directory_link(&cwd, &destination)?;

        let global_bin = global.join("bin");
        std::fs::create_dir_all(&global_bin)?;
        for (bin_name, relative) in safe_bin_entries(&package, name) {
            let target = cwd.join(relative);
            anyhow::ensure!(
                target.is_file(),
                "linked binary does not exist: {}",
                target.display()
            );
            let bin_link = global_bin.join(bin_name);
            remove_link_only(&bin_link)?;
            platform_symlink_file(&target, &bin_link)?;
        }
        println!("Linked {name} globally to {}", cwd.display());
        return Ok(());
    }

    let cwd = std::env::current_dir()?.canonicalize()?;
    let local_modules = cwd.join("node_modules");
    let mut saved = Vec::new();
    for name in packages {
        validate_link_package_name(&name)?;
        let registered = global_modules.join(&name);
        let metadata = std::fs::symlink_metadata(&registered).with_context(|| {
            format!("{name} is not globally linked; run oath link in its source directory")
        })?;
        anyhow::ensure!(
            metadata.file_type().is_symlink(),
            "global registration for {name} is not a link"
        );
        let target = registered.canonicalize()?;
        let destination = local_modules.join(&name);
        create_directory_link(&target, &destination)?;
        println!("Linked {name} -> {}", target.display());
        saved.push((name, target));
    }
    if save {
        let mut package = read_package_json()?;
        if package.get("dependencies").is_none() {
            package["dependencies"] = serde_json::json!({});
        }
        let dependencies = package["dependencies"]
            .as_object_mut()
            .context("package.json dependencies must be an object")?;
        for (name, target) in saved {
            dependencies.insert(
                name,
                serde_json::Value::String(format!("file:{}", target.display())),
            );
        }
        std::fs::write(
            "package.json",
            format!("{}\n", serde_json::to_string_pretty(&package)?),
        )?;
    }
    Ok(())
}

fn cmd_link_scoped(packages: Vec<String>, save: bool, workspace: &WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        return cmd_link(packages, save);
    }
    for target in selected_workspace_targets(workspace)? {
        println!("oath: workspace {}", target.name);
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_link(packages.clone(), save)
            .with_context(|| format!("workspace {} link failed", target.name))?;
    }
    Ok(())
}

fn cmd_unlink(packages: Vec<String>) -> Result<()> {
    let global = global_link_root()?;
    if packages.is_empty() {
        let package = read_package_json()?;
        let name = package["name"]
            .as_str()
            .context("package.json must declare a name")?;
        validate_link_package_name(name)?;
        let removed = remove_link_only(&global.join("node_modules").join(name))?;
        println!(
            "{}",
            if removed {
                "Removed global link"
            } else {
                "No global link found"
            }
        );
        return Ok(());
    }
    let local_modules = std::env::current_dir()?.join("node_modules");
    for name in packages {
        validate_link_package_name(&name)?;
        let removed = remove_link_only(&local_modules.join(&name))?;
        if removed {
            println!("Unlinked {name}");
        } else {
            println!("No local link found for {name}");
        }
    }
    Ok(())
}

fn cmd_unlink_scoped(packages: Vec<String>, workspace: &WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        return cmd_unlink(packages);
    }
    for target in selected_workspace_targets(workspace)? {
        println!("oath: workspace {}", target.name);
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_unlink(packages.clone())
            .with_context(|| format!("workspace {} unlink failed", target.name))?;
    }
    Ok(())
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

    let mut pkg: serde_json::Value = if PathBuf::from("package.json").exists() {
        read_package_json()?
    } else {
        anyhow::bail!("no package.json found");
    };

    let mut removed_any = false;
    let mut removed_names = Vec::new();
    for package in &packages {
        let (name, _) = parse_package_spec(package);

        // Remove from dependencies and devDependencies
        let mut removed = false;
        for dep_key in &["dependencies", "devDependencies"] {
            if let Some(deps) = pkg.get_mut(dep_key).and_then(|d| d.as_object_mut())
                && deps.remove(&name).is_some()
            {
                removed = true;
            }
        }

        if !removed {
            println!("oath remove: '{}' not found in package.json", name);
            continue;
        }

        println!("removed {}", name);
        removed_names.push(name);
        removed_any = true;
    }

    if !removed_any {
        return Ok(());
    }

    // Rebuild lockfile from remaining deps
    let deps = extract_deps(&pkg, "dependencies");
    let dev_deps = extract_deps(&pkg, "devDependencies");
    let project_name = pkg["name"].as_str().unwrap_or("project").to_string();
    let project_version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();

    if deps.is_empty() && dev_deps.is_empty() {
        let nm_path = PathBuf::from("node_modules");
        if nm_path.exists() || nm_path.symlink_metadata().is_ok() {
            if nm_path.is_symlink() || nm_path.is_file() {
                std::fs::remove_file(&nm_path).context("failed to clean node_modules")?;
            } else {
                std::fs::remove_dir_all(&nm_path).context("failed to clean node_modules")?;
            }
        }
        std::fs::write("package.json", serde_json::to_string_pretty(&pkg)?)?;
        let empty_graph = oath_resolve::graph::DepGraph::new();
        let lockfile = Lockfile::from_graph_with_manifest(
            &empty_graph,
            &project_name,
            &project_version,
            &deps,
            &dev_deps,
        );
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
        let plan_path = PathBuf::from(".oath").join("placement-plan.json");
        if plan_path.exists() {
            std::fs::remove_file(plan_path)?;
        }
    } else {
        let cwd = std::env::current_dir()?.canonicalize()?;
        let mut placement_plan =
            ArboristPlanner::plan_with(&cwd, &PlacementRequest::remove(removed_names))?;
        hydrate_missing_registry_metadata(&mut placement_plan).await?;
        let graph = placement_plan.to_dep_graph()?;
        let store = Arc::new(ContentStore::default_store()?);
        let client = Arc::new(RegistryClient::default_client()?);
        let (to_download, _) = missing_store_nodes(&graph, &store);
        download_missing_nodes(to_download, Arc::clone(&store), Arc::clone(&client)).await?;
        let linker = Linker::new((*store).clone());
        linker.link_placement_plan(&placement_plan, &cwd)?;
        placement_plan.write(&cwd.join(".oath").join("placement-plan.json"))?;
        std::fs::write("package.json", serde_json::to_string_pretty(&pkg)?)?;
        let lockfile = Lockfile::from_graph_with_manifest(
            &graph,
            &project_name,
            &project_version,
            &deps,
            &dev_deps,
        );
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
    }

    Ok(())
}

async fn cmd_remove_scoped(packages: Vec<String>, workspace: WorkspaceArgs) -> Result<()> {
    if !workspace.active() {
        return cmd_remove(packages).await;
    }
    if packages.is_empty() {
        println!("oath remove: no packages specified");
        return Ok(());
    }
    let names: Vec<_> = packages
        .iter()
        .map(|package| parse_package_spec(package).0)
        .collect();
    let targets = selected_workspace_targets(&workspace)?;
    let mut transaction = WorkspaceManifestTransaction::begin(&targets, |manifest| {
        for group in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(dependencies) = manifest
                .get_mut(group)
                .and_then(|value| value.as_object_mut())
            {
                for name in &names {
                    dependencies.remove(name);
                }
            }
        }
        Ok(())
    })?;
    cmd_install(
        Vec::new(),
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        None,
        true,
        false,
        Vec::new(),
        workspace,
        None,
    )
    .await?;
    transaction.commit();
    Ok(())
}

async fn cmd_remove_global(packages: Vec<String>) -> Result<()> {
    anyhow::ensure!(
        !packages.is_empty(),
        "oath remove --global requires at least one package"
    );
    let root = global_prefix()?;
    let manifest_path = root.join("package.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .with_context(|| "no globally installed Oath packages to remove")?,
    )?;
    let dependencies = manifest
        .get_mut("dependencies")
        .and_then(serde_json::Value::as_object_mut)
        .context("global package manifest has no dependencies")?;
    for package in packages {
        let name = parse_package_spec(&package).0;
        anyhow::ensure!(
            dependencies.remove(&name).is_some(),
            "{name} is not installed globally"
        );
        println!("removed {name}");
    }
    let mut specs = dependencies
        .iter()
        .map(|(name, spec)| format!("{name}@{}", spec.as_str().unwrap_or("*")))
        .collect::<Vec<_>>();
    specs.sort();
    if specs.is_empty() {
        for path in [
            root.join("node_modules"),
            root.join("bin"),
            root.join(".oath"),
        ] {
            if path.is_dir() {
                std::fs::remove_dir_all(&path)
                    .with_context(|| format!("failed to remove {}", path.display()))?;
            }
        }
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
        return Ok(());
    }
    cmd_install_global(specs, false, false, false, false).await
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

fn native_publish_packlist(root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("package.json"))?)
            .context("failed to parse package.json while building publish packlist")?;
    let mut whitelist = package
        .get("files")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        });
    if let Some(entries) = whitelist.as_mut() {
        if let Some(main) = package.get("main").and_then(serde_json::Value::as_str) {
            entries.push(main.to_owned());
        }
        match package.get("bin") {
            Some(serde_json::Value::String(bin)) => entries.push(bin.to_owned()),
            Some(serde_json::Value::Object(bins)) => entries.extend(
                bins.values()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned),
            ),
            _ => {}
        }
    }
    let ignore_path = if root.join(".npmignore").is_file() {
        root.join(".npmignore")
    } else {
        root.join(".gitignore")
    };
    let ignores = std::fs::read_to_string(ignore_path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    collect_publish_files(
        root,
        &[
            "node_modules",
            ".git",
            ".hg",
            ".svn",
            ".oath",
            "oath-lock.json",
            "package-lock.json",
        ],
        &ignores,
        &whitelist,
    )
}

fn validate_stage_id(stage_id: &str) -> Result<()> {
    anyhow::ensure!(
        !stage_id.is_empty()
            && stage_id.len() <= 128
            && stage_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid staged-release identifier"
    );
    Ok(())
}

async fn stage_response_json(
    response: reqwest::Response,
    operation: &str,
) -> Result<serde_json::Value> {
    let status = response.status();
    let bytes = response.bytes().await?;
    anyhow::ensure!(
        status.is_success(),
        "oath stage {operation}: registry returned {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    if bytes.is_empty() {
        Ok(serde_json::json!({ "ok": true }))
    } else {
        serde_json::from_slice(&bytes)
            .with_context(|| format!("oath stage {operation}: registry returned invalid JSON"))
    }
}

async fn cmd_stage(action: StageAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match action {
        StageAction::List {
            package,
            json,
            registry,
        } => {
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let mut url = registry_url_with_segments(&registry, &["-", "stage"])?;
            if let Some(package) = package {
                url.query_pairs_mut().append_pair("package", &package);
            }
            let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
                .send()
                .await?;
            let report = stage_response_json(response, "list").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for item in report["items"].as_array().into_iter().flatten() {
                    println!(
                        "{}\t{}@{}\t{}",
                        item["id"].as_str().unwrap_or_default(),
                        item["packageName"].as_str().unwrap_or_default(),
                        item["version"].as_str().unwrap_or_default(),
                        item["tag"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        StageAction::View {
            stage_id,
            json,
            registry,
        } => {
            validate_stage_id(&stage_id)?;
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "stage", &stage_id])?;
            let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
                .send()
                .await?;
            let report = stage_response_json(response, "view").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{} {}@{} tag={} actor={}",
                    report["id"].as_str().unwrap_or(&stage_id),
                    report["packageName"].as_str().unwrap_or_default(),
                    report["version"].as_str().unwrap_or_default(),
                    report["tag"].as_str().unwrap_or_default(),
                    report["actor"].as_str().unwrap_or_default()
                );
            }
        }
        StageAction::Download {
            stage_id,
            json,
            registry,
            destination,
        } => {
            validate_stage_id(&stage_id)?;
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "stage", &stage_id, "tarball"])?;
            let response = registry_request_with_auth(&client, reqwest::Method::GET, url)?
                .send()
                .await?;
            let status = response.status();
            let bytes = response.bytes().await?;
            anyhow::ensure!(
                status.is_success(),
                "oath stage download: registry returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
            std::fs::create_dir_all(&destination)?;
            let output = destination.join(format!("{stage_id}.tgz"));
            write_manifest_atomic(&output, &bytes)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "stage_id": stage_id,
                        "path": output,
                        "bytes": bytes.len()
                    }))?
                );
            } else {
                println!("downloaded {}", output.display());
            }
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
            validate_stage_id(&stage_id)?;
            let otp = otp.context("oath stage approve requires --otp for proof-of-presence")?;
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "stage", &stage_id, "approve"])?;
            let response = registry_request_with_auth(&client, reqwest::Method::POST, url)?
                .header("npm-otp", otp)
                .send()
                .await?;
            let report = stage_response_json(response, "approve").await?;
            println!(
                "{}",
                report["message"]
                    .as_str()
                    .unwrap_or("staged release approved")
            );
        }
        StageAction::Reject {
            stage_id,
            yes,
            otp,
            registry,
        } => {
            anyhow::ensure!(yes, "oath stage reject is permanent and requires --yes");
            validate_stage_id(&stage_id)?;
            let otp = otp.context("oath stage reject requires --otp for proof-of-presence")?;
            let registry =
                credential_registry_url(&effective_registry(registry.as_deref(), None)?)?;
            let url = registry_url_with_segments(&registry, &["-", "stage", &stage_id])?;
            let response = registry_request_with_auth(&client, reqwest::Method::DELETE, url)?
                .header("npm-otp", otp)
                .send()
                .await?;
            let _ = stage_response_json(response, "reject").await?;
            println!("staged release {stage_id} rejected");
        }
    }
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
            let files = native_publish_packlist(&root)?;
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
    if whitelist
        .iter()
        .any(|entry| publish_pattern_matches(entry, rel))
    {
        return true;
    }

    let fname = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let uppercase = fname.to_ascii_uppercase();
    fname == "package.json"
        || uppercase == "README"
        || uppercase.starts_with("README.")
        || uppercase == "LICENSE"
        || uppercase.starts_with("LICENSE.")
        || uppercase == "LICENCE"
        || uppercase.starts_with("LICENCE.")
}

fn publish_pattern_matches(pattern: &str, rel: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches('/').trim_end_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if rel == pattern || rel.starts_with(&format!("{pattern}/")) {
        return true;
    }
    let candidate = if pattern.contains('/') {
        pattern.to_owned()
    } else {
        format!("**/{pattern}")
    };
    glob::Pattern::new(&candidate)
        .map(|compiled| compiled.matches(rel) || compiled.matches_path(std::path::Path::new(rel)))
        .unwrap_or(false)
}

fn should_publish_exclude(rel: &str, excludes: &[&str], npmignore: &[String]) -> bool {
    for pat in excludes {
        if rel == *pat || rel.starts_with(&format!("{}/", pat)) {
            return true;
        }
    }

    let mut ignored = false;
    for pattern in npmignore {
        let (negated, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |value| (true, value));
        if publish_pattern_matches(pattern, rel) {
            ignored = !negated;
        }
    }
    ignored
}

#[allow(clippy::too_many_arguments)]
async fn cmd_publish_scoped(
    tag: Option<&str>,
    access: Option<&str>,
    dry_run: bool,
    json: bool,
    schema_version: u32,
    stage: bool,
    otp: Option<&str>,
    provenance: bool,
    provenance_file: Option<&std::path::Path>,
    workspace: &WorkspaceArgs,
) -> Result<()> {
    if !workspace.active() {
        return cmd_publish(
            tag,
            access,
            dry_run,
            json,
            schema_version,
            stage,
            otp,
            provenance,
            provenance_file,
        )
        .await;
    }
    let targets = selected_workspace_targets(workspace)?;
    if json && targets.len() > 1 {
        anyhow::ensure!(
            dry_run,
            "oath publish --json is an assessment-only interface and requires --dry-run"
        );
        let executable = std::env::current_exe().context("failed to locate the Oath executable")?;
        let mut reports = Vec::with_capacity(targets.len());
        for target in targets {
            let mut command = std::process::Command::new(&executable);
            command
                .args(["publish", "--dry-run", "--json", "--schema-version"])
                .arg(schema_version.to_string())
                .current_dir(&target.path);
            if let Some(tag) = tag {
                command.args(["--tag", tag]);
            }
            if let Some(access) = access {
                command.args(["--access", access]);
            }
            if stage {
                command.arg("--stage");
            }
            if let Some(otp) = otp {
                command.args(["--otp", otp]);
            }
            if provenance {
                command.arg("--provenance");
            }
            if let Some(path) = provenance_file {
                command.arg("--provenance-file").arg(path);
            }
            let output = command
                .output()
                .with_context(|| format!("failed to assess workspace {}", target.name))?;
            anyhow::ensure!(
                output.status.success(),
                "workspace {} publish failed: {}",
                target.name,
                String::from_utf8_lossy(&output.stderr)
            );
            reports.push(
                serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .with_context(|| format!("workspace {} emitted invalid JSON", target.name))?,
            );
        }
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    for target in targets {
        if !json {
            println!("oath: workspace {}", target.name);
        }
        let _guard = CurrentDirectoryGuard::enter(&target.path)?;
        cmd_publish(
            tag,
            access,
            dry_run,
            json,
            schema_version,
            stage,
            otp,
            provenance,
            provenance_file,
        )
        .await
        .with_context(|| format!("workspace {} publish failed", target.name))?;
    }
    Ok(())
}

fn sigstore_provenance_bundle(
    name: &str,
    version: &str,
    sha512_hex: &str,
    existing: Option<&std::path::Path>,
) -> Result<serde_json::Value> {
    const SCRIPT: &str = r#"'use strict'
const { generateProvenance, verifyProvenance } = require(process.argv[2])
const npa = require(process.argv[3])
const name = process.argv[4]
const version = process.argv[5]
const subject = { name: npa.toPurl(npa(`${name}@${version}`)), digest: { sha512: process.argv[6] } }
const existing = process.argv[7] || null
Promise.resolve(existing ? verifyProvenance(subject, existing) : generateProvenance([subject], {}))
  .then(bundle => process.stdout.write(JSON.stringify(bundle)))
  .catch(error => { console.error(error.stack || error.message); process.exitCode = 1 })
"#;
    let (provenance_path, package_arg_path) = oath_resolve::pinned_npm_provenance_paths()?;
    let script = tempfile::NamedTempFile::new().context("create provenance adapter")?;
    std::fs::write(script.path(), SCRIPT)?;
    let output = std::process::Command::new("node")
        .arg(script.path())
        .arg(provenance_path)
        .arg(package_arg_path)
        .arg(name)
        .arg(version)
        .arg(sha512_hex)
        .arg(existing.unwrap_or_else(|| std::path::Path::new("")))
        .output()
        .context("launch pinned Sigstore provenance adapter")?;
    anyhow::ensure!(
        output.status.success(),
        "Sigstore provenance failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let bundle: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("decode Sigstore provenance bundle")?;
    anyhow::ensure!(
        bundle["mediaType"].as_str().is_some(),
        "Sigstore provenance bundle has no mediaType"
    );
    Ok(bundle)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_publish(
    tag: Option<&str>,
    access: Option<&str>,
    dry_run: bool,
    json: bool,
    schema_version: u32,
    stage: bool,
    otp: Option<&str>,
    provenance: bool,
    provenance_file: Option<&std::path::Path>,
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
    if provenance {
        anyhow::ensure!(
            std::env::var_os("GITHUB_ACTIONS").is_some() || std::env::var_os("GITLAB_CI").is_some(),
            "--provenance requires a supported GitHub Actions or GitLab CI OIDC workload"
        );
        anyhow::ensure!(
            access == Some("public"),
            "--provenance requires --access public so the identity is externally verifiable"
        );
    }
    if let Some(path) = provenance_file {
        anyhow::ensure!(
            path.is_file(),
            "provenance bundle does not exist: {}",
            path.display()
        );
    }
    if let Some(otp) = otp {
        anyhow::ensure!(
            (6..=10).contains(&otp.len()) && otp.bytes().all(|byte| byte.is_ascii_digit()),
            "--otp must contain 6 to 10 decimal digits"
        );
    }

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

    // 2. Collect files to include in the tarball without invoking npm.
    let cwd = std::env::current_dir()?;
    let files_to_pack = native_publish_packlist(&cwd)?;

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
    let sha512_hex = format!("{sha512_digest:x}");
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
    let http_client = reqwest::Client::builder()
        .user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let registry_url = credential_registry_url(&effective_registry(None, None)?)?;
    let pkg_url = registry_url_with_segments(&registry_url, &[&name])?;

    let existing = registry_request_with_optional_auth(&http_client, pkg_url.clone())
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
    let registry_host = pkg_url.host_str().context("registry URL has no host")?;
    let npmrc = oath_fetch::NpmrcConfig::load(&cwd);
    let token = publish_auth_token(registry_host, &npmrc, std::env::var("NPM_TOKEN").ok())?;

    // 7. Build publish payload
    let tarball_url = format!(
        "{}/{}-/-/{}-{}.tgz",
        registry_url.trim_end_matches('/'),
        name.replace('/', "%2f"),
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
        "version": version,
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

    if provenance || provenance_file.is_some() {
        let bundle = sigstore_provenance_bundle(&name, &version, &sha512_hex, provenance_file)?;
        let serialized = serde_json::to_string(&bundle)?;
        let bundle_name = format!(
            "{}-{}.sigstore",
            name.split('/').next_back().unwrap_or(&name),
            version
        );
        let serialized_len = serialized.len();
        payload["_attachments"][bundle_name] = serde_json::json!({
            "content_type": bundle["mediaType"],
            "data": serialized,
            "length": serialized_len
        });
    }

    if let Some(acc) = access {
        payload["access"] = serde_json::Value::String(acc.to_string());
    }

    if stage {
        payload["access"] = serde_json::Value::String(
            match access.unwrap_or("public") {
                "restricted" | "private" => "private",
                _ => "public",
            }
            .to_owned(),
        );
        for field in [
            "readme",
            "maintainers",
            "author",
            "license",
            "repository",
            "main",
            "scripts",
        ] {
            if let Some(value) = pkg.get(field) {
                payload[field] = value.clone();
            }
        }
        let stage_url =
            registry_url_with_segments(&registry_url, &["-", "stage", "package", &name])?;
        println!(
            "oath publish: staging {}@{} (dist-tag: {})...",
            name, version, dist_tag
        );
        let mut request = http_client.post(stage_url).bearer_auth(&token);
        if let Some(otp) = otp {
            request = request.header("npm-otp", otp);
        }
        let response = request
            .json(&payload)
            .send()
            .await
            .context("failed to send staged-publish request")?;
        let report = stage_response_json(response, "publish").await?;
        println!(
            "staged {}@{} as {}",
            name,
            version,
            report["id"].as_str().unwrap_or("pending")
        );
        return Ok(());
    }

    // 8. PUT to registry
    println!(
        "oath publish: publishing {}@{} (dist-tag: {})...",
        name, version, dist_tag
    );

    let mut request = http_client
        .put(pkg_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json");
    if let Some(otp) = otp {
        request = request.header("npm-otp", otp);
    }
    let resp = request
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
async fn cmd_install_global(
    packages: Vec<String>,
    dry_run: bool,
    yes_flag: bool,
    run_scripts: bool,
    ignore_scripts: bool,
) -> Result<()> {
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

    let policy = OathPolicy::load();
    let mut scripts_blocked = 0usize;
    for node in graph.nodes.values() {
        if ignore_scripts || !node.has_install_script {
            continue;
        }
        if policy.is_package_banned(&node.name) {
            println!(
                "  oath: blocked install script for banned package {}@{}",
                node.name, node.version
            );
            continue;
        }
        let install_name = node.alias.as_deref().unwrap_or(&node.name);
        let linked = nm_dir.join(install_name);
        let stored = store.package_dir_for(
            &node.name,
            &node.version,
            Some(&node.resolved),
            node.integrity.as_deref(),
        );
        let package_dir = if linked.exists() { linked } else { stored };
        PackageScanner::scan(&node.name, &node.version, &package_dir).with_context(|| {
            format!(
                "analyze {} before contained global lifecycle execution",
                node.name
            )
        })?;
        if yes_flag {
            run_install_script(&node.name, &package_dir)?;
        } else if run_scripts {
            let report = PackageScanner::scan(&node.name, &node.version, &package_dir)?;
            let script =
                detect_install_script(&package_dir).unwrap_or_else(|| "node install.js".to_owned());
            match prompts::prompt_install_script(
                &node.name,
                &node.version,
                &script,
                &report.capabilities,
                false,
                &policy,
            ) {
                prompts::ScriptDecision::Allow | prompts::ScriptDecision::Always => {
                    run_install_script(&node.name, &package_dir)?;
                }
                prompts::ScriptDecision::Deny => {}
            }
        } else {
            scripts_blocked += 1;
        }
    }
    if scripts_blocked > 0 {
        println!(
            "  {scripts_blocked} global install script(s) blocked (use --ignore-scripts or --run-scripts)"
        );
    }

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
    fn native_packlist_is_the_authoritative_assessment_input() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"packlist-test","version":"1.0.0","files":["index.js"]}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("index.js"), "module.exports = 1").unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "not published").unwrap();
        let files = native_publish_packlist(dir.path()).unwrap();
        let names: Vec<_> = files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect();
        assert!(names.contains(&"package.json"));
        assert!(names.contains(&"index.js"));
        assert!(!names.contains(&"ignored.txt"));
    }

    #[test]
    fn native_packlist_honors_gitignore_fallback_and_negation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"packlist-test","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(".gitignore"), "*.log\n!important.log\n").unwrap();
        std::fs::write(dir.path().join("debug.log"), "ignored").unwrap();
        std::fs::write(dir.path().join("important.log"), "included").unwrap();
        std::fs::write(dir.path().join("feature.test.js"), "included by npm").unwrap();

        let root = dir.path().canonicalize().unwrap();
        let files = native_publish_packlist(dir.path()).unwrap();
        let relative = files
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert!(!relative.contains(&"debug.log".to_owned()));
        assert!(relative.contains(&"important.log".to_owned()));
        assert!(relative.contains(&"feature.test.js".to_owned()));
    }

    #[test]
    fn empty_script_approval_set_selects_nothing() {
        let selected = approved_install_script_selection(&[], &HashSet::new()).unwrap();
        assert!(selected.is_empty());
        let error =
            approved_install_script_selection(&["unapproved@1.0.0".to_owned()], &HashSet::new())
                .unwrap_err();
        assert!(error.to_string().contains("unapproved"));
    }

    #[test]
    fn file_snapshot_transaction_restores_existing_and_created_files() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("package-lock.json");
        let created = dir.path().join("oath-lock.json");
        std::fs::write(&existing, b"before").unwrap();
        {
            let _transaction =
                FileSnapshotTransaction::snapshot([existing.clone(), created.clone()]).unwrap();
            std::fs::write(&existing, b"after").unwrap();
            std::fs::write(&created, b"created").unwrap();
        }
        assert_eq!(std::fs::read(&existing).unwrap(), b"before");
        assert!(!created.exists());
    }

    #[test]
    fn stage_identifiers_reject_path_injection() {
        assert!(validate_stage_id("1de6f3db-2ed9-4d72-b3dd-8f0e2b474a2f").is_ok());
        assert!(validate_stage_id("../../token").is_err());
        assert!(validate_stage_id("id?query=value").is_err());
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

    #[test]
    fn preferred_bin_path_rejects_ambiguous_packages_like_npm() {
        let pkg = serde_json::json!({
            "bin": {
                "alpha": "bin/alpha.js",
                "beta": "bin/beta.js"
            }
        });
        assert_eq!(preferred_bin_path(&pkg, "toolkit"), None);

        let aliases = serde_json::json!({
            "bin": {
                "alpha": "bin/cli.js",
                "beta": "bin/cli.js"
            }
        });
        assert_eq!(
            preferred_bin_path(&aliases, "toolkit"),
            Some(PathBuf::from("bin/cli.js"))
        );
    }

    #[test]
    fn outdated_resolves_registry_identity_for_npm_aliases() {
        assert_eq!(alias_registry_name("alias", "^1.0.0"), "alias");
        assert_eq!(
            alias_registry_name("alias", "npm:is-number@^7.0.0"),
            "is-number"
        );
        assert_eq!(
            alias_registry_name("alias", "npm:@scope/package@^2.0.0"),
            "@scope/package"
        );
    }

    #[test]
    fn npmrc_auth_keys_include_registry_paths_and_ports() {
        assert_eq!(
            npmrc_auth_key("https://registry.npmjs.org").unwrap(),
            "//registry.npmjs.org/:_authToken"
        );
        assert_eq!(
            npmrc_auth_key("https://registry.example.test:8443/npm/").unwrap(),
            "//registry.example.test:8443/npm/:_authToken"
        );
        assert!(npmrc_auth_key("file:///tmp/registry").is_err());
    }

    #[test]
    fn publish_auth_uses_the_selected_registry_and_prefers_environment() {
        let npmrc = oath_fetch::NpmrcConfig {
            tokens: HashMap::from([
                ("registry.npmjs.org".to_owned(), "npm-token".to_owned()),
                (
                    "packages.example.test".to_owned(),
                    "custom-token".to_owned(),
                ),
            ]),
            ..Default::default()
        };
        assert_eq!(
            publish_auth_token("packages.example.test", &npmrc, None).unwrap(),
            "custom-token"
        );
        assert_eq!(
            publish_auth_token(
                "packages.example.test",
                &npmrc,
                Some("environment-token".to_owned())
            )
            .unwrap(),
            "environment-token"
        );
        assert!(publish_auth_token("missing.example.test", &npmrc, None).is_err());
    }

    #[test]
    fn credential_registry_transport_is_encrypted_or_loopback() {
        assert!(credential_registry_url("https://registry.npmjs.org").is_ok());
        assert!(credential_registry_url("http://127.0.0.1:4873").is_ok());
        assert!(credential_registry_url("http://[::1]:4873").is_ok());
        assert!(credential_registry_url("http://registry.example.test").is_err());
        assert!(credential_registry_url("file:///tmp/registry").is_err());
    }

    #[test]
    fn config_entries_reject_npmrc_injection() {
        assert!(validate_npmrc_entry("registry", Some("https://registry.npmjs.org/")).is_ok());
        assert!(validate_npmrc_entry("bad\nkey", Some("value")).is_err());
        assert!(validate_npmrc_entry("registry", Some("javascript:alert(1)")).is_err());
        assert!(validate_npmrc_entry("key", Some("value\n//evil/:_authToken=stolen")).is_err());
    }

    #[test]
    fn config_set_and_delete_preserve_unrelated_npmrc_entries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".npmrc");
        std::fs::write(&path, "fund=false\nregistry=https://old.example/\n").unwrap();
        update_npmrc_path(
            &path,
            &BTreeMap::from([(
                "registry".to_string(),
                Some("https://registry.npmjs.org/".to_string()),
            )]),
        )
        .unwrap();
        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("fund=false"));
        assert!(updated.contains("registry=https://registry.npmjs.org/"));

        update_npmrc_path(&path, &BTreeMap::from([("registry".to_string(), None)])).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fund=false\n");
    }

    #[test]
    fn cache_clean_requires_force_and_removes_named_entries() {
        let directory = tempfile::tempdir().unwrap();
        let store = ContentStore::new(directory.path().join("store")).unwrap();
        let package = tempfile::tempdir().unwrap();
        std::fs::write(
            package.path().join("package.json"),
            r#"{"name":"cache-probe","version":"1.0.0"}"#,
        )
        .unwrap();
        store
            .store_package("cache-probe", "1.0.0", package.path())
            .unwrap();
        assert!(clean_cache_store(&store, false).is_err());
        assert_eq!(clean_cache_store(&store, true).unwrap(), 1);
        assert!(store.list_packages().is_empty());
    }

    #[test]
    fn audit_levels_and_sbom_formats_are_machine_readable() {
        assert!(advisory_severity_rank("critical") > advisory_severity_rank("high"));
        assert_eq!(advisory_severity_rank("invalid"), 0);
        let mut lockfile = Lockfile {
            lockfile_version: 2,
            name: "fixture".into(),
            version: "1.0.0".into(),
            roots: Vec::new(),
            root_dependencies: BTreeMap::new(),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::new(),
        };
        let entry = |name: &str, dependencies: BTreeMap<String, String>| {
            oath_resolve::lockfile::LockEntry {
                name: Some(name.into()),
                version: "1.0.0".into(),
                resolved: format!("https://registry.example/{name}.tgz"),
                integrity: None,
                dependencies,
                dev: false,
                optional: false,
                has_install_script: false,
                alias: None,
                peer_dependencies: BTreeMap::new(),
                resolved_peers: BTreeMap::new(),
            }
        };
        lockfile.roots.push("node_modules/parent".into());
        lockfile.packages.insert(
            "node_modules/parent".into(),
            entry(
                "parent",
                BTreeMap::from([("child".into(), "node_modules/child".into())]),
            ),
        );
        lockfile
            .packages
            .insert("node_modules/child".into(), entry("child", BTreeMap::new()));
        let cyclonedx = build_sbom_document(&lockfile, "digest", "cyclonedx").unwrap();
        assert_eq!(cyclonedx["bomFormat"], "CycloneDX");
        assert_eq!(cyclonedx["dependencies"].as_array().unwrap().len(), 3);
        assert!(
            cyclonedx["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| {
                    entry["dependsOn"]
                        .as_array()
                        .is_some_and(|dependencies| !dependencies.is_empty())
                })
        );
        let spdx = build_sbom_document(&lockfile, "digest", "spdx").unwrap();
        assert_eq!(spdx["spdxVersion"], "SPDX-2.3");
        assert!(
            spdx["relationships"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| { entry["relationshipType"] == "DEPENDS_ON" })
        );
        assert!(
            spdx["creationInfo"]["created"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        assert!(build_sbom_document(&lockfile, "digest", "xml").is_err());
        assert_eq!(
            npm_purl("@scope/pkg", "1.2.3"),
            "pkg:npm/%40scope/pkg@1.2.3"
        );
    }

    #[test]
    fn pkg_paths_support_nested_objects_and_arrays() {
        let path = parse_json_path("contributors[0].name").unwrap();
        assert_eq!(
            path,
            vec![
                JsonPathPart::Key("contributors".into()),
                JsonPathPart::Index(0),
                JsonPathPart::Key("name".into())
            ]
        );
        let mut manifest = serde_json::json!({});
        json_path_set(&mut manifest, &path, serde_json::json!("Ada")).unwrap();
        assert_eq!(
            json_path_get(&manifest, &path),
            Some(&serde_json::json!("Ada"))
        );
        assert!(json_path_delete(&mut manifest, &path));
        assert_eq!(json_path_get(&manifest, &path), None);
        assert!(parse_json_path("contributors[nope]").is_err());
    }

    #[test]
    fn version_bumps_match_stable_npm_semver_forms() {
        assert_eq!(bumped_version("1.2.3", "patch", None).unwrap(), "1.2.4");
        assert_eq!(bumped_version("1.2.3", "minor", None).unwrap(), "1.3.0");
        assert_eq!(bumped_version("1.2.3", "major", None).unwrap(), "2.0.0");
        assert_eq!(
            bumped_version("1.3.0-beta.0", "patch", None).unwrap(),
            "1.3.0"
        );
        assert_eq!(
            bumped_version("1.3.0-beta.0", "minor", None).unwrap(),
            "1.3.0"
        );
        assert_eq!(
            bumped_version("2.0.0-beta.0", "major", None).unwrap(),
            "2.0.0"
        );
        assert_eq!(bumped_version("1.2.3", "4.5.6", None).unwrap(), "4.5.6");
        assert_eq!(
            bumped_version("1.2.3", "preminor", Some("beta")).unwrap(),
            "1.3.0-beta.0"
        );
        assert_eq!(
            bumped_version("1.3.0-beta.0", "prerelease", Some("beta")).unwrap(),
            "1.3.0-beta.1"
        );
        assert!(bumped_version("not-semver", "patch", None).is_err());
        assert!(bumped_version("1.2.3", "banana", None).is_err());
    }

    #[test]
    fn rebuild_package_specs_match_names_and_semver_ranges() {
        assert!(rebuild_spec_matches("semver", "semver", "7.7.2").unwrap());
        assert!(rebuild_spec_matches("semver@^7", "semver", "7.7.2").unwrap());
        assert!(!rebuild_spec_matches("semver@^6", "semver", "7.7.2").unwrap());
        assert!(!rebuild_spec_matches("other@^7", "semver", "7.7.2").unwrap());
        assert!(rebuild_spec_matches("semver@banana", "semver", "7.7.2").is_err());
    }

    #[test]
    fn registry_mutation_paths_encode_scoped_packages_and_validate_tags() {
        let url = registry_url_with_segments(
            "https://registry.example/npm/",
            &["-", "package", "@scope/package", "dist-tags", "next"],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://registry.example/npm/-/package/@scope%2Fpackage/dist-tags/next"
        );
        assert!(validate_dist_tag("latest").is_ok());
        assert!(validate_dist_tag("next-1").is_ok());
        for invalid in ["", ".hidden", "_private", "1.2.3", "has space"] {
            assert!(validate_dist_tag(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn token_cidr_validation_accepts_only_bounded_networks() {
        for valid in ["127.0.0.1/32", "10.0.0.0/8", "2001:db8::/32"] {
            assert!(validate_cidr(valid).is_ok(), "{valid}");
        }
        for invalid in ["127.0.0.1", "10.0.0.0/33", "2001:db8::/129", "bad/8"] {
            assert!(validate_cidr(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn access_team_identifiers_are_scoped_and_path_safe() {
        assert_eq!(
            parse_team("@scope:developers").unwrap(),
            ("scope".into(), "developers".into())
        );
        assert!(parse_team("scope:developers").is_ok());
        for invalid in ["scope", ":team", "scope:", "scope:../owners"] {
            assert!(parse_team(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn account_identifiers_are_normalized_and_path_safe() {
        assert_eq!(
            validate_account_name("@fixture-org", "organization").unwrap(),
            "fixture-org"
        );
        assert_eq!(
            validate_account_name("~fixture-user", "username").unwrap(),
            "fixture-user"
        );
        for invalid in [
            "",
            "@",
            "../owner",
            "scope/user",
            "scope\\user",
            "bad\nuser",
        ] {
            assert!(
                validate_account_name(invalid, "account").is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn trusted_publisher_inputs_reject_ambiguous_files_and_ids() {
        assert!(validate_trust_file("publish.yml", true).is_ok());
        assert!(validate_trust_file(".github/workflows/publish.yml", true).is_err());
        assert!(validate_trust_file("publish.txt", true).is_err());
        assert!(validate_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!validate_uuid("123e4567-e89b-12d3-a456"));
    }

    #[test]
    fn init_maps_initializer_names_to_create_packages() {
        assert_eq!(initializer_package_spec("vite").unwrap(), "create-vite");
        assert_eq!(initializer_package_spec("vite@7").unwrap(), "create-vite@7");
        assert_eq!(
            initializer_package_spec("@scope/app").unwrap(),
            "@scope/create-app"
        );
        assert_eq!(
            initializer_package_spec("@scope/app@2").unwrap(),
            "@scope/create-app@2"
        );
        assert!(initializer_package_spec("@scope").is_err());
    }

    #[test]
    fn funding_fields_accept_npm_string_object_and_array_forms() {
        assert_eq!(
            funding_urls(&serde_json::json!("https://example.test/one")),
            ["https://example.test/one"]
        );
        assert_eq!(
            funding_urls(
                &serde_json::json!({ "type": "individual", "url": "https://example.test/two" })
            ),
            ["https://example.test/two"]
        );
        assert_eq!(
            funding_urls(&serde_json::json!([
                "https://example.test/one",
                { "url": "https://example.test/two" }
            ])),
            ["https://example.test/one", "https://example.test/two"]
        );
    }

    #[test]
    fn oath_lock_converts_to_npm_v3_shrinkwrap() {
        let mut packages = BTreeMap::new();
        packages.insert(
            "fixture@1.2.3".into(),
            oath_resolve::lockfile::LockEntry {
                name: None,
                version: "1.2.3".into(),
                resolved: "https://registry.example/fixture.tgz".into(),
                integrity: Some("sha512-fixture".into()),
                dependencies: BTreeMap::new(),
                dev: false,
                optional: false,
                has_install_script: false,
                alias: None,
                peer_dependencies: BTreeMap::new(),
                resolved_peers: BTreeMap::new(),
            },
        );
        let lock = Lockfile {
            lockfile_version: 2,
            name: "root".into(),
            version: "1.0.0".into(),
            roots: vec!["fixture@1.2.3".into()],
            root_dependencies: BTreeMap::from([("fixture".into(), "^1.2.3".into())]),
            root_dev_dependencies: BTreeMap::new(),
            packages,
        };
        let shrinkwrap = oath_lock_as_npm_shrinkwrap(&lock);
        assert_eq!(shrinkwrap["lockfileVersion"], 3);
        assert_eq!(
            shrinkwrap["packages"]["node_modules/fixture"]["version"],
            "1.2.3"
        );
    }

    #[test]
    fn rebuild_discovery_skips_symlinked_packages() {
        let directory = tempfile::tempdir().unwrap();
        let node_modules = directory.path().join("node_modules");
        let package = node_modules.join("safe-package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"safe-package","version":"1.0.0"}"#,
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&package, node_modules.join("linked-package")).unwrap();
        let packages = collect_installed_package_dirs(&node_modules).unwrap();
        assert_eq!(packages, [package]);
    }

    #[test]
    fn development_link_names_reject_path_traversal() {
        assert!(validate_link_package_name("pkg").is_ok());
        assert!(validate_link_package_name("@scope/pkg").is_ok());
        for invalid in ["../pkg", "@scope/../pkg", "@scope", "a/b", ".", ""] {
            assert!(validate_link_package_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn workspace_cli_accepts_repeated_filters() {
        let cli = Cli::try_parse_from([
            "oath",
            "run",
            "test",
            "--workspace",
            "@repo/core",
            "-w",
            "apps/web",
            "--include-workspace-root",
        ])
        .unwrap();
        let Commands::Run { workspace, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(workspace.workspace, ["@repo/core", "apps/web"]);
        assert!(workspace.include_workspace_root);
    }

    #[test]
    fn every_required_command_accepts_workspace_filters() {
        let commands: &[&[&str]] = &[
            &["oath", "add", "left-pad", "-w", "pkg"],
            &["oath", "remove", "left-pad", "-w", "pkg"],
            &["oath", "update", "left-pad", "-w", "pkg"],
            &["oath", "exec", "eslint", "-w", "pkg", "--dry-run"],
            &["oath", "pack", "-w", "pkg", "--dry-run"],
            &["oath", "publish", "-w", "pkg", "--dry-run"],
            &["oath", "ci", "-w", "pkg"],
            &["oath", "outdated", "-w", "pkg", "--json"],
            &["oath", "link", "linked-package", "-w", "pkg"],
            &["oath", "unlink", "linked-package", "-w", "pkg"],
            &["oath", "approve-scripts", "left-pad", "-w", "pkg"],
            &["oath", "deny-scripts", "left-pad", "-w", "pkg"],
            &["oath", "install-scripts", "left-pad", "-w", "pkg"],
            &[
                "oath",
                "rebuild",
                "left-pad",
                "-w",
                "pkg",
                "--ignore-scripts",
            ],
            &["oath", "query", "#left-pad", "-w", "pkg"],
            &[
                "oath",
                "version",
                "patch",
                "-w",
                "pkg",
                "--no-git-tag-version",
            ],
        ];
        for command in commands {
            Cli::try_parse_from(*command).unwrap_or_else(|error| {
                panic!("failed to parse {command:?}: {error}");
            });
        }
    }

    #[test]
    fn global_and_dedupe_compatibility_flags_parse() {
        // The Cli struct is large; Windows' 1MB default test-thread stack
        // overflows during parsing. Run with an 8MB stack (Linux default).
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                for command in [
                    &["oath", "remove", "fixture", "--global"][..],
                    &["oath", "update", "fixture", "--global"][..],
                    &["oath", "outdated", "--global", "--json"][..],
                    &["oath", "dedupe", "--prefer-dedupe", "--dry-run"][..],
                    &["oath", "install", "--package-lock-only"][..],
                    &["oath", "install", "--lockfile-only"][..],
                    &["oath", "audit", "--fix", "--dry-run", "--json"][..],
                    &["oath", "audit", "signatures", "--json"][..],
                    &[
                        "oath",
                        "profile",
                        "enable-2fa",
                        "auth-and-writes",
                        "--password-stdin",
                        "--otp",
                        "123456",
                    ][..],
                    &[
                        "oath",
                        "profile",
                        "disable-2fa",
                        "--password-stdin",
                        "--otp",
                        "123456",
                    ][..],
                    &[
                        "oath",
                        "prune",
                        "extraneous",
                        "--ignore-scripts",
                        "--omit",
                        "optional",
                        "--dry-run",
                        "-w",
                        "pkg",
                    ][..],
                    &["oath", "cache", "npx", "ls", "--json"][..],
                    &[
                        "oath",
                        "cache",
                        "npx",
                        "info",
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "--json",
                    ][..],
                    &[
                        "oath",
                        "cache",
                        "npx",
                        "rm",
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ][..],
                    &["oath", "publish", "--dry-run", "--otp", "123456"][..],
                    &["oath", "publish", "--provenance", "--access", "public"][..],
                    &["oath", "publish", "--provenance-file", "bundle.sigstore"][..],
                ] {
                    Cli::try_parse_from(command)
                        .unwrap_or_else(|error| panic!("failed to parse {command:?}: {error}"));
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn doctor_permission_probe_is_clean_and_actionable() {
        let directory = tempfile::tempdir().unwrap();
        let check = writable_directory_check(directory.path(), 3);
        assert_eq!(check["ok"], true);
        assert_eq!(check["packages"], 3);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn npx_cache_keys_are_path_safe() {
        assert!(
            validate_npx_cache_key(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_ok()
        );
        for invalid in [
            "short",
            "../record",
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(validate_npx_cache_key(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn prune_location_names_handle_scopes_and_nesting() {
        assert_eq!(
            placement_location_package_name("node_modules/@scope/pkg"),
            Some("@scope/pkg".into())
        );
        assert_eq!(
            placement_location_package_name("node_modules/parent/node_modules/child"),
            Some("child".into())
        );
        assert_eq!(placement_location_package_name("packages/pkg"), None);
    }

    #[test]
    fn exec_defaults_to_fail_closed_auto_containment() {
        // The Cli struct is large; Windows' 1MB default test-thread stack
        // overflows during parsing. Run with an 8MB stack (Linux default).
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let cli = Cli::try_parse_from(["oath", "exec", "eslint", "--dry-run"]).unwrap();
                let Commands::Exec {
                    sandbox_mode,
                    allow_uncontained,
                    ..
                } = cli.command
                else {
                    panic!("expected exec command");
                };
                assert_eq!(sandbox_mode, ExecSandboxMode::Auto);
                assert!(!allow_uncontained);

                let interactive = Cli::try_parse_from(["oath", "exec"]).unwrap();
                let Commands::Exec {
                    package,
                    packages,
                    call,
                    sandbox_mode,
                    allow_uncontained,
                    ..
                } = interactive.command
                else {
                    panic!("expected interactive exec command");
                };
                assert!(package.is_none() && packages.is_empty() && call.is_none());
                assert_eq!(sandbox_mode, ExecSandboxMode::Auto);
                assert!(!allow_uncontained);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn exec_normalizes_npx_package_and_call_forms() {
        let inferred =
            normalize_exec_invocation(Some("@scope/tool@2"), &[], &["--fix".into()], None).unwrap();
        assert_eq!(inferred.packages, ["@scope/tool@2"]);
        assert_eq!(inferred.command, "tool");
        assert_eq!(inferred.args, ["--fix"]);

        let explicit = normalize_exec_invocation(
            Some("eslint"),
            &["eslint@9".into(), "eslint-plugin-import@latest".into()],
            &[".".into()],
            None,
        )
        .unwrap();
        assert_eq!(explicit.command, "eslint");
        assert_eq!(explicit.packages.len(), 2);

        let call = normalize_exec_invocation(
            None,
            &["typescript@latest".into()],
            &[],
            Some("tsc --version"),
        )
        .unwrap();
        assert_eq!(call.call.as_deref(), Some("tsc --version"));
        assert!(normalize_exec_invocation(None, &[], &[], None).is_err());
    }

    #[test]
    fn view_fields_and_ls_omit_are_structured() {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1.2.3",
            "dist": { "tarball": "https://example.test/fixture.tgz" }
        });
        let fields = vec!["version".into(), "dist.tarball".into()];
        let selected = view_field_values(&metadata, &fields).unwrap();
        assert_eq!(selected[0], ("version".into(), serde_json::json!("1.2.3")));
        assert_eq!(
            selected[1],
            (
                "dist.tarball".into(),
                serde_json::json!("https://example.test/fixture.tgz")
            )
        );
        assert!(view_field_values(&metadata, &["missing".into()]).is_err());

        let manifest = serde_json::json!({
            "dependencies": { "prod": "1" },
            "optionalDependencies": { "optional": "1" },
            "devDependencies": { "dev": "1", "prod": "1" }
        });
        assert_eq!(
            ls_root_dependency_names(&manifest, false),
            ["dev", "optional", "prod"]
        );
        assert_eq!(
            ls_root_dependency_names(&manifest, true),
            ["optional", "prod"]
        );
    }

    #[test]
    fn exact_versions_use_npm_default_save_prefix() {
        assert_eq!(npm_save_spec("1.2.3"), "^1.2.3");
        assert_eq!(npm_save_spec("1.2.3-beta.1"), "^1.2.3-beta.1");
        assert_eq!(npm_save_spec("^1.2.3"), "^1.2.3");
        assert_eq!(npm_save_spec("latest"), "latest");
        assert_eq!(npm_save_spec("workspace:*"), "workspace:*");
    }

    #[test]
    fn workspace_manifest_transaction_rolls_back_uncommitted_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("package.json");
        let original = b"{\"name\":\"pkg\",\"version\":\"1.0.0\"}\n";
        std::fs::write(&path, original).unwrap();
        let target = WorkspaceTarget {
            name: "pkg".into(),
            path: directory.path().to_path_buf(),
        };
        {
            let _transaction =
                WorkspaceManifestTransaction::begin(std::slice::from_ref(&target), |manifest| {
                    manifest["version"] = serde_json::Value::String("2.0.0".into());
                    Ok(())
                })
                .unwrap();
            assert!(std::fs::read_to_string(&path).unwrap().contains("2.0.0"));
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let mut transaction = WorkspaceManifestTransaction::begin(&[target], |manifest| {
            manifest["version"] = serde_json::Value::String("3.0.0".into());
            Ok(())
        })
        .unwrap();
        transaction.commit();
        drop(transaction);
        assert!(std::fs::read_to_string(path).unwrap().contains("3.0.0"));
    }
}
