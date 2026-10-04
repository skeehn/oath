//! OathPolicy -- loaded from oath-policy.toml (project-local or ~/.oath/policy.toml)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Risk levels, matching oath-analyze::RiskLevel ordering.
/// Duplicated here so oath-core doesn't depend on oath-analyze.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Clean,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Raw TOML-deserializable form (all fields optional so partial files work)
#[derive(Debug, Default, Deserialize)]
struct RawPolicy {
    #[serde(default)]
    banned_packages: Vec<String>,
    #[serde(default)]
    banned_licenses: Vec<String>,
    #[serde(default)]
    require_approval: Vec<String>,
    #[serde(default)]
    allow_install_scripts: Vec<String>,
    block_install_scripts: Option<bool>,
    max_risk_level: Option<String>,
    min_release_age: Option<String>,
    #[serde(default)]
    min_release_age_exclude: Vec<String>,
}

/// Policy loaded from oath-policy.toml (project or global ~/.oath/policy.toml)
#[derive(Debug, Clone)]
pub struct OathPolicy {
    /// Packages to always block regardless of version
    pub banned_packages: Vec<String>,
    /// SPDX license identifiers to block (e.g. "GPL-3.0", "AGPL-3.0")
    pub banned_licenses: Vec<String>,
    /// Packages that need explicit approval before installation
    pub require_approval: Vec<String>,
    /// Packages allowed to run install scripts without prompting
    pub allow_install_scripts: Vec<String>,
    /// If true, block ALL install scripts by default (only allow_install_scripts exceptions pass)
    pub block_install_scripts: bool,
    /// String form of the max acceptable risk level: "low"|"medium"|"high"|"critical"
    pub max_risk_level: String,
    /// Default release-age cooldown for `oath exec` (npm's `min-release-age`):
    /// a day count like "7" or a duration like "7d" / "24h". `None` means no
    /// cooldown unless the command line or `.npmrc` sets one.
    pub min_release_age: Option<String>,
    /// Packages exempt from the cooldown (`min-release-age-exclude`).
    pub min_release_age_exclude: Vec<String>,
}

impl Default for OathPolicy {
    /// Permissive defaults -- nothing banned, nothing blocked.
    fn default() -> Self {
        Self {
            banned_packages: vec![],
            banned_licenses: vec![],
            require_approval: vec![],
            allow_install_scripts: vec![],
            block_install_scripts: false,
            max_risk_level: "critical".to_string(),
            min_release_age: None,
            min_release_age_exclude: vec![],
        }
    }
}

impl OathPolicy {
    /// Load policy by merging:
    ///   1. Permissive defaults
    ///   2. Global ~/.oath/policy.toml (if it exists)
    ///   3. Local ./oath-policy.toml (if it exists, overrides global)
    ///
    /// Lists are merged (union); scalar values from local override global.
    pub fn load() -> Self {
        let mut policy = Self::default();

        // Global policy
        if let Some(home) = crate::home_dir() {
            let global_path = home.join(".oath").join("policy.toml");
            if let Ok(text) = std::fs::read_to_string(&global_path)
                && let Ok(raw) = toml::from_str::<RawPolicy>(&text)
            {
                policy.merge(raw);
            }
        }

        // Local project policy (overrides / extends global)
        let local_path = PathBuf::from("oath-policy.toml");
        if let Ok(text) = std::fs::read_to_string(&local_path)
            && let Ok(raw) = toml::from_str::<RawPolicy>(&text)
        {
            policy.merge(raw);
        }

        policy
    }

    /// Merge a raw policy layer into this one.
    /// Lists are extended (union); scalar overrides happen only when the layer sets them.
    fn merge(&mut self, raw: RawPolicy) {
        for p in raw.banned_packages {
            if !self.banned_packages.contains(&p) {
                self.banned_packages.push(p);
            }
        }
        for l in raw.banned_licenses {
            if !self.banned_licenses.contains(&l) {
                self.banned_licenses.push(l);
            }
        }
        for p in raw.require_approval {
            if !self.require_approval.contains(&p) {
                self.require_approval.push(p);
            }
        }
        for p in raw.allow_install_scripts {
            if !self.allow_install_scripts.contains(&p) {
                self.allow_install_scripts.push(p);
            }
        }
        if let Some(v) = raw.block_install_scripts {
            self.block_install_scripts = v;
        }
        if let Some(v) = raw.max_risk_level {
            self.max_risk_level = v;
        }
        if let Some(v) = raw.min_release_age {
            self.min_release_age = Some(v);
        }
        for p in raw.min_release_age_exclude {
            if !self.min_release_age_exclude.contains(&p) {
                self.min_release_age_exclude.push(p);
            }
        }
    }

    /// Returns true if the package is in the banned list (case-insensitive).
    pub fn is_package_banned(&self, name: &str) -> bool {
        self.banned_packages
            .iter()
            .any(|b| b.eq_ignore_ascii_case(name))
    }

    /// Returns true if the given SPDX license identifier is banned.
    pub fn is_license_banned(&self, license: &str) -> bool {
        self.banned_licenses
            .iter()
            .any(|b| b.eq_ignore_ascii_case(license))
    }

    /// Returns true if the package is allowed to run install scripts without prompting.
    ///
    /// When `block_install_scripts` is true, only packages in `allow_install_scripts` pass.
    /// When false, all packages are allowed (prompting happens at the CLI layer).
    pub fn allows_install_script(&self, name: &str) -> bool {
        if self
            .allow_install_scripts
            .iter()
            .any(|a| a.eq_ignore_ascii_case(name))
        {
            return true;
        }
        // If we're not blocking by default, allow (let CLI prompt handle it)
        !self.block_install_scripts
    }

    /// Parse `max_risk_level` string into a `RiskLevel`.
    /// Returns `RiskLevel::Critical` on unknown values (permissive fallback).
    pub fn max_risk(&self) -> RiskLevel {
        match self.max_risk_level.to_lowercase().as_str() {
            "clean" => RiskLevel::Clean,
            "info" => RiskLevel::Info,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => RiskLevel::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_permissive() {
        let p = OathPolicy::default();
        assert!(!p.is_package_banned("express"));
        assert!(!p.is_license_banned("MIT"));
        assert!(!p.block_install_scripts);
        assert_eq!(p.max_risk(), RiskLevel::Critical);
    }

    #[test]
    fn test_banned_package() {
        let mut p = OathPolicy::default();
        p.banned_packages.push("evil-pkg".to_string());
        assert!(p.is_package_banned("evil-pkg"));
        assert!(p.is_package_banned("Evil-Pkg")); // case-insensitive
        assert!(!p.is_package_banned("safe-pkg"));
    }

    #[test]
    fn test_banned_license() {
        let mut p = OathPolicy::default();
        p.banned_licenses.push("GPL-3.0".to_string());
        assert!(p.is_license_banned("GPL-3.0"));
        assert!(!p.is_license_banned("MIT"));
    }

    #[test]
    fn test_allows_install_script_blocked_by_default() {
        let mut p = OathPolicy {
            block_install_scripts: true,
            ..Default::default()
        };
        assert!(!p.allows_install_script("some-pkg"));
        p.allow_install_scripts.push("esbuild".to_string());
        assert!(p.allows_install_script("esbuild"));
    }

    #[test]
    fn test_max_risk_parse() {
        let mut p = OathPolicy {
            max_risk_level: "high".to_string(),
            ..Default::default()
        };
        assert_eq!(p.max_risk(), RiskLevel::High);
        p.max_risk_level = "medium".to_string();
        assert_eq!(p.max_risk(), RiskLevel::Medium);
    }

    #[test]
    fn test_toml_deserialize() {
        let toml_str = r#"
block_install_scripts = true
max_risk_level = "high"
banned_packages = ["colors", "node-ipc"]
banned_licenses = ["GPL-3.0", "AGPL-3.0"]
allow_install_scripts = ["esbuild", "sharp"]
"#;
        let raw: RawPolicy = toml::from_str(toml_str).unwrap();
        assert_eq!(raw.banned_packages, vec!["colors", "node-ipc"]);
        assert_eq!(raw.banned_licenses, vec!["GPL-3.0", "AGPL-3.0"]);
        assert_eq!(raw.allow_install_scripts, vec!["esbuild", "sharp"]);
        assert_eq!(raw.block_install_scripts, Some(true));
        assert_eq!(raw.max_risk_level, Some("high".to_string()));
    }
}
