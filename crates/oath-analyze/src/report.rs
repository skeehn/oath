//! Risk report types

use serde::{Deserialize, Serialize};

/// Overall risk level for a package
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    /// Clean -- no suspicious patterns
    Clean,
    /// Informational -- common but worth knowing
    Info,
    /// Low risk -- expected patterns, but documented
    Low,
    /// Medium risk -- unusual patterns, review recommended
    Medium,
    /// High risk -- clearly suspicious
    High,
    /// Critical -- almost certainly malicious
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Network access: fetch, http, https, net, dns, tls
    Network,
    /// Filesystem read/write (fs, path operations)
    Filesystem,
    /// Environment variable access (process.env)
    EnvAccess,
    /// Subprocess spawning (child_process, spawn, exec)
    Subprocess,
    /// Dynamic code execution (eval, Function(), vm.runInNewContext)
    DynamicExec,
    /// Obfuscated/encoded strings (base64, hex, charCode)
    Obfuscation,
    /// Install script hook (preinstall/postinstall/install in package.json)
    InstallScript,
    /// Typosquatting suspicion (name similarity to popular packages)
    Typosquatting,
    /// Exfiltration patterns (sending data to remote hosts)
    DataExfiltration,
    /// Crypto mining patterns
    CryptoMiner,
    /// Shadow dependency (requires packages not in manifest)
    ShadowDep,
    /// Credential harvesting (SSH keys, AWS creds, browser cookies, tokens)
    CredentialHarvest,
    /// Conditional/protestware payload (locale/geo/IP-gated execution)
    ConditionalPayload,
    /// Slopsquatting: package name matches common LLM-hallucinated patterns
    Slopsquatting,
    /// Bracket notation property access to evade static string detection (process['env'])
    BracketNotation,
    /// CI environment targeting (process.env.CI, GITHUB_ACTIONS, TRAVIS, etc.)
    CiTargeting,
    /// Silent subprocess execution ({stdio: 'ignore'}) - near-definitive malware signal
    SilentSubprocess,
    /// Environment PATH or LD_PRELOAD overwrite -- redirects executables to malicious binaries
    EnvPathOverwrite,
    /// Module loader patching (Module._resolveFilename / require() hijacking)
    ModuleLoaderPatch,
    /// Native addon (.node binary / binding.gyp) -- bypasses JS sandbox entirely
    NativeAddon,
    /// An executable input could not be analyzed completely; review is required
    AnalysisIncomplete,
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::Filesystem => write!(f, "filesystem"),
            Self::EnvAccess => write!(f, "env_access"),
            Self::Subprocess => write!(f, "subprocess"),
            Self::DynamicExec => write!(f, "dynamic_exec"),
            Self::Obfuscation => write!(f, "obfuscation"),
            Self::InstallScript => write!(f, "install_script"),
            Self::Typosquatting => write!(f, "typosquatting"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::CryptoMiner => write!(f, "crypto_miner"),
            Self::ShadowDep => write!(f, "shadow_dep"),
            Self::CredentialHarvest => write!(f, "credential_harvest"),
            Self::ConditionalPayload => write!(f, "conditional_payload"),
            Self::Slopsquatting => write!(f, "slopsquatting"),
            Self::BracketNotation => write!(f, "bracket_notation"),
            Self::CiTargeting => write!(f, "ci_targeting"),
            Self::SilentSubprocess => write!(f, "silent_subprocess"),
            Self::EnvPathOverwrite => write!(f, "env_path_overwrite"),
            Self::ModuleLoaderPatch => write!(f, "module_loader_patch"),
            Self::NativeAddon => write!(f, "native_addon"),
            Self::AnalysisIncomplete => write!(f, "analysis_incomplete"),
        }
    }
}

/// A single finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub risk: RiskLevel,
    pub message: String,
    /// File where found (relative to package root)
    pub file: String,
    /// Line number (1-indexed, 0 = file-level)
    pub line: u32,
    /// Code snippet
    pub snippet: Option<String>,
}

/// Full analysis report for a single package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: String,
    pub overall_risk: RiskLevel,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub lines_scanned: usize,
    /// Detected capabilities summary (for oathx permission prompt)
    pub capabilities: Capabilities,
    /// Human-readable reasons the behavioral verdict escalated (empty if Info).
    #[serde(default)]
    pub verdict_reasons: Vec<String>,
}

/// Summary of what this package can do (for permission prompts)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub network: bool,
    pub filesystem: bool,
    pub env_access: bool,
    pub subprocess: bool,
    pub dynamic_exec: bool,
    pub has_install_scripts: bool,
    /// Package contains a native addon (.node binary or binding.gyp)
    pub native_addon: bool,
}

/// Per-package risk summary (lightweight, for lockfile/audit display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRisk {
    pub name: String,
    pub version: String,
    pub risk: RiskLevel,
    pub finding_count: usize,
    pub top_finding: Option<String>,
}
