//! Package specs for `oath exec`, following npm-package-arg's rules closely
//! enough that every spec `npx` accepts resolves to the same package here:
//! registry names with tags, exact versions, and ranges; `file:` and bare
//! paths to directories or tarballs; git URLs and hosted shorthands; and
//! remote tarball URLs. The Arborist planner performs the actual fetch for
//! git, directory, and tarball specs, so this module only has to classify a
//! spec and know which cache and revalidation rules apply to it.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// How a registry spec selects a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryKind {
    /// A dist-tag such as `latest` or `next`; `latest` is implied by a bare
    /// name.
    Tag(String),
    /// One exact version.
    Version(String),
    /// A semver range.
    Range(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecKind {
    Registry {
        name: String,
        kind: RegistryKind,
        /// `true` for a bare name (`cowsay`): npm treats that as "any version
        /// in the local tree, newest in the cache".
        name_only: bool,
    },
    /// A local package directory (absolute).
    Directory(PathBuf),
    /// A local tarball (absolute).
    File(PathBuf),
    /// A git URL or hosted shorthand, kept verbatim for the planner.
    Git(String),
    /// A remote tarball URL.
    Remote(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpec {
    /// The spec exactly as the user typed it.
    pub raw: String,
    pub kind: SpecKind,
}

impl ExecSpec {
    /// Parse one spec. Relative paths resolve against `cwd`.
    pub fn parse(raw: &str, cwd: &Path) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("empty package spec");
        }
        if let Some(rest) = raw.strip_prefix("file:") {
            let path = rest.strip_prefix("//").unwrap_or(rest);
            return local_spec(raw, path, cwd);
        }
        if is_path_like(raw) {
            return local_spec(raw, raw, cwd);
        }
        if let Some(alias) = raw.strip_prefix("npm:") {
            bail!(
                "npm: aliases are not supported by oath exec (got npm:{alias}); run the package by its real name"
            );
        }
        if raw.starts_with("http://") || raw.starts_with("https://") {
            let kind = if raw.ends_with(".git") || raw.contains(".git#") {
                SpecKind::Git(raw.to_string())
            } else {
                SpecKind::Remote(raw.to_string())
            };
            return Ok(Self {
                raw: raw.to_string(),
                kind,
            });
        }
        if is_git_url(raw) || is_hosted_shorthand(raw) {
            return Ok(Self {
                raw: raw.to_string(),
                kind: SpecKind::Git(raw.to_string()),
            });
        }
        let (name, spec) = split_name_spec(raw);
        validate_package_name(name)?;
        let name_only = spec.is_none();
        let kind = classify_registry_spec(spec.unwrap_or(""));
        Ok(Self {
            raw: raw.to_string(),
            kind: SpecKind::Registry {
                name: name.to_string(),
                kind,
                name_only,
            },
        })
    }

    /// The spec handed to the Arborist planner's `add` request. Local paths
    /// are absolute so the planner resolves them independently of its cwd.
    pub fn planner_spec(&self) -> String {
        match &self.kind {
            SpecKind::Directory(path) | SpecKind::File(path) => path.display().to_string(),
            _ => self.raw.clone(),
        }
    }

    /// The string npm hashes for the exec cache key: the resolved absolute
    /// directory for directory specs (so `npx .` and `npx ./` share an
    /// entry), the raw spec otherwise.
    pub fn cache_component(&self) -> String {
        match &self.kind {
            SpecKind::Directory(path) => path.display().to_string(),
            _ => self.raw.clone(),
        }
    }

    /// Whether a cached install of this spec can go stale: tags, ranges, and
    /// git refs can all point at something newer later. Exact versions,
    /// local paths, and remote tarballs cannot.
    pub fn revalidates(&self) -> bool {
        match &self.kind {
            SpecKind::Registry { kind, .. } => {
                matches!(kind, RegistryKind::Tag(_) | RegistryKind::Range(_))
            }
            SpecKind::Git(_) => true,
            SpecKind::Directory(_) | SpecKind::File(_) | SpecKind::Remote(_) => false,
        }
    }

    /// Whether an installed `version` satisfies this spec by npm's local-tree
    /// rules: a bare name matches anything, a version must be equal, a range
    /// must be satisfied. Tags other than a bare name need the registry and
    /// return `None`; non-registry specs also return `None`.
    pub fn satisfied_by(&self, version: &str) -> Option<bool> {
        let SpecKind::Registry {
            kind, name_only, ..
        } = &self.kind
        else {
            return None;
        };
        if *name_only {
            return Some(true);
        }
        match kind {
            RegistryKind::Version(wanted) => Some(wanted == version),
            RegistryKind::Range(range) => {
                if range == "*" {
                    return Some(true);
                }
                let range = range.parse::<node_semver::Range>().ok()?;
                let installed = version.parse::<node_semver::Version>().ok()?;
                Some(range.satisfies(&installed))
            }
            RegistryKind::Tag(_) => None,
        }
    }
}

fn local_spec(raw: &str, path: &str, cwd: &Path) -> Result<ExecSpec> {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        oath_core::home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(path))
    } else {
        PathBuf::from(path)
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    let absolute = std::fs::canonicalize(&absolute)
        .with_context(|| format!("local package {} does not exist", absolute.display()))?;
    let kind = if absolute.is_dir() {
        SpecKind::Directory(absolute)
    } else if is_tarball_name(&absolute) {
        SpecKind::File(absolute)
    } else {
        bail!(
            "local package {} is neither a directory nor a tarball",
            absolute.display()
        );
    };
    Ok(ExecSpec {
        raw: raw.to_string(),
        kind,
    })
}

fn is_tarball_name(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".tgz") || name.ends_with(".tar.gz") || name.ends_with(".tar")
}

fn is_path_like(raw: &str) -> bool {
    raw == "."
        || raw == ".."
        || raw.starts_with("./")
        || raw.starts_with("../")
        || raw.starts_with('/')
        || raw.starts_with("~/")
        || raw.starts_with(".\\")
        || raw.starts_with("..\\")
        || raw.starts_with('\\')
        || is_windows_drive_path(raw)
}

fn is_windows_drive_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn is_git_url(raw: &str) -> bool {
    const PREFIXES: [&str; 9] = [
        "git+",
        "git://",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "sourcehut:",
        "git@",
    ];
    PREFIXES.iter().any(|prefix| raw.starts_with(prefix))
}

/// npm-package-arg's GitHub shorthand: `user/repo[#committish]` with no
/// scope, no scheme, and no spaces.
fn is_hosted_shorthand(raw: &str) -> bool {
    let (base, _) = raw.split_once('#').unwrap_or((raw, ""));
    let Some((user, repo)) = base.split_once('/') else {
        return false;
    };
    let ok = |part: &str| {
        !part.is_empty()
            && !part
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '@' | '%' | '/' | ':'))
    };
    ok(user) && ok(repo)
}

/// Split `name@spec`, honoring the leading `@` of a scope.
fn split_name_spec(raw: &str) -> (&str, Option<&str>) {
    let start = usize::from(raw.starts_with('@'));
    match raw[start..].find('@') {
        Some(at) => (&raw[..start + at], Some(&raw[start + at + 1..])),
        None => (raw, None),
    }
}

/// npm's rules for names that may exist on a registry (the "old package"
/// rules npm-package-arg enforces): not empty, no leading dot or underscore,
/// no whitespace, URL-safe characters, and at most 214 characters.
pub fn validate_package_name(name: &str) -> Result<()> {
    let invalid = |why: &str| anyhow::anyhow!("invalid package name \"{name}\": {why}");
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if name.len() > 214 {
        return Err(invalid("name is longer than 214 characters"));
    }
    let bare = match name.strip_prefix('@') {
        Some(scoped) => {
            let Some((scope, bare)) = scoped.split_once('/') else {
                return Err(invalid("a scoped name needs a package after the scope"));
            };
            if scope.is_empty() || !scope.chars().all(is_name_char) {
                return Err(invalid("scope contains unsafe characters"));
            }
            bare
        }
        None => name,
    };
    if bare.is_empty() {
        return Err(invalid("name is empty"));
    }
    if bare.starts_with('.') || bare.starts_with('_') {
        return Err(invalid("name cannot start with a period or underscore"));
    }
    if !bare.chars().all(is_name_char) {
        return Err(invalid("name contains unsafe characters"));
    }
    if matches!(bare, "node_modules" | "favicon.ico") {
        return Err(invalid("name is reserved"));
    }
    Ok(())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~')
}

fn classify_registry_spec(spec: &str) -> RegistryKind {
    let spec = spec.trim();
    if spec.is_empty() {
        return RegistryKind::Tag("latest".into());
    }
    let exact = spec.trim_start_matches(['=', 'v']);
    if exact.parse::<node_semver::Version>().is_ok() {
        return RegistryKind::Version(exact.to_string());
    }
    if spec == "*" || spec.parse::<node_semver::Range>().is_ok() {
        return RegistryKind::Range(spec.to_string());
    }
    RegistryKind::Tag(spec.to_string())
}

/// libnpmexec's `getBinFromManifest`: when every bin entry points at the same
/// file, that entry is the command; otherwise the bin named like the unscoped
/// package name is; otherwise the user must say which with `--package`.
pub fn bin_from_manifest(manifest: &serde_json::Value) -> Result<String> {
    let name = manifest["name"].as_str().unwrap_or("");
    let bare = name.rsplit('/').next().unwrap_or(name);
    let entries: Vec<(String, String)> = match manifest.get("bin") {
        Some(serde_json::Value::String(path)) => vec![(bare.to_string(), path.clone())],
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .filter_map(|(bin, path)| path.as_str().map(|p| (bin.clone(), p.to_string())))
            .collect(),
        _ => Vec::new(),
    };
    let mut targets: Vec<&str> = entries.iter().map(|(_, path)| path.as_str()).collect();
    targets.sort_unstable();
    targets.dedup();
    if targets.len() == 1 {
        return Ok(entries[0].0.clone());
    }
    if entries.iter().any(|(bin, _)| bin == bare) {
        return Ok(bare.to_string());
    }
    let id = match manifest["version"].as_str() {
        Some(version) if !name.is_empty() => format!("{name}@{version}"),
        _ => name.to_string(),
    };
    if entries.is_empty() {
        bail!("could not determine executable to run: {id} declares no bin");
    }
    let mut bins: Vec<&str> = entries.iter().map(|(bin, _)| bin.as_str()).collect();
    bins.sort_unstable();
    bail!(
        "could not determine executable to run: {id} provides {}; pass --package {name} and the command to run",
        bins.join(", ")
    );
}

/// The package `npm init <initializer>` delegates to: `foo` is `create-foo`,
/// `@scope` is `@scope/create`, `@scope/foo` is `@scope/create-foo`, and a
/// hosted git `user/repo` becomes `user/create-repo`. Versions and tags carry
/// over. Local paths are refused, as npm refuses them.
pub fn initializer_package(initializer: &str) -> Result<String> {
    let initializer = initializer.trim();
    if initializer.starts_with('@') && !initializer[1..].contains('/') {
        // Only a scope, possibly with a version: `@scope` or `@scope@1.2.3`.
        let (scope, version) = split_name_spec(initializer);
        return Ok(match version {
            Some(version) if !version.is_empty() => format!("{scope}/create@{version}"),
            _ => format!("{scope}/create"),
        });
    }
    if is_path_like(initializer) || initializer.starts_with("file:") {
        bail!(
            "Unrecognized initializer: {initializer}\nFor more package binary executing power check out `oath exec`"
        );
    }
    if is_git_url(initializer) || is_hosted_shorthand(initializer) {
        let (base, committish) = match initializer.split_once('#') {
            Some((base, committish)) => (base, Some(committish)),
            None => (initializer, None),
        };
        let Some(slash) = base.rfind('/') else {
            bail!("Unrecognized initializer: {initializer}");
        };
        let project = &base[slash + 1..];
        let project = project.strip_suffix(".git").unwrap_or(project);
        let mut rewritten = format!("{}/create-{project}", &base[..slash]);
        if base.ends_with(".git") {
            rewritten.push_str(".git");
        }
        if let Some(committish) = committish {
            rewritten.push('#');
            rewritten.push_str(committish);
        }
        return Ok(rewritten);
    }
    let (name, spec) = split_name_spec(initializer);
    validate_package_name(name)?;
    let created = match name.strip_prefix('@') {
        Some(scoped) => {
            let (scope, bare) = scoped.split_once('/').unwrap_or((scoped, ""));
            format!("@{scope}/create-{bare}")
        }
        None => format!("create-{name}"),
    };
    Ok(match spec {
        Some(spec) if !spec.is_empty() => format!("{created}@{spec}"),
        _ => created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> ExecSpec {
        ExecSpec::parse(raw, Path::new("/tmp")).unwrap()
    }

    #[test]
    fn registry_specs_classify_tags_versions_and_ranges() {
        assert_eq!(
            parse("cowsay").kind,
            SpecKind::Registry {
                name: "cowsay".into(),
                kind: RegistryKind::Tag("latest".into()),
                name_only: true,
            }
        );
        assert_eq!(
            parse("cowsay@1.6.0").kind,
            SpecKind::Registry {
                name: "cowsay".into(),
                kind: RegistryKind::Version("1.6.0".into()),
                name_only: false,
            }
        );
        assert_eq!(
            parse("@scope/tool@^2").kind,
            SpecKind::Registry {
                name: "@scope/tool".into(),
                kind: RegistryKind::Range("^2".into()),
                name_only: false,
            }
        );
        assert_eq!(
            parse("vite@next").kind,
            SpecKind::Registry {
                name: "vite".into(),
                kind: RegistryKind::Tag("next".into()),
                name_only: false,
            }
        );
        assert!(parse("cowsay").revalidates());
        assert!(!parse("cowsay@1.6.0").revalidates());
        assert_eq!(parse("cowsay").satisfied_by("0.1.0"), Some(true));
        assert_eq!(parse("cowsay@1.6.0").satisfied_by("1.5.0"), Some(false));
        assert_eq!(parse("cowsay@^1.5").satisfied_by("1.6.0"), Some(true));
        assert_eq!(parse("vite@next").satisfied_by("7.0.0"), None);
    }

    #[test]
    fn git_and_remote_specs_are_recognized() {
        assert!(matches!(parse("github:user/repo").kind, SpecKind::Git(_)));
        assert!(matches!(parse("user/repo#v1").kind, SpecKind::Git(_)));
        assert!(matches!(
            parse("git+https://github.com/user/repo.git").kind,
            SpecKind::Git(_)
        ));
        assert!(matches!(
            parse("https://github.com/user/repo.git").kind,
            SpecKind::Git(_)
        ));
        assert!(matches!(
            parse("https://example.com/pkg-1.0.0.tgz").kind,
            SpecKind::Remote(_)
        ));
    }

    #[test]
    fn local_specs_resolve_directories_and_tarballs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pkg")).unwrap();
        std::fs::write(dir.path().join("pkg.tgz"), b"").unwrap();
        let spec = ExecSpec::parse("./pkg", dir.path()).unwrap();
        let canonical = std::fs::canonicalize(dir.path().join("pkg")).unwrap();
        assert_eq!(spec.kind, SpecKind::Directory(canonical.clone()));
        assert_eq!(spec.cache_component(), canonical.display().to_string());
        let spec = ExecSpec::parse("file:pkg.tgz", dir.path()).unwrap();
        assert!(matches!(spec.kind, SpecKind::File(_)));
        assert!(ExecSpec::parse("./missing", dir.path()).is_err());
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert!(ExecSpec::parse(".hidden", Path::new("/")).is_err());
        assert!(ExecSpec::parse("has space", Path::new("/")).is_err());
        assert!(ExecSpec::parse("@scope", Path::new("/")).is_err());
        assert!(ExecSpec::parse("npm:alias@1", Path::new("/")).is_err());
    }

    #[test]
    fn bin_rule_matches_libnpmexec() {
        let single = serde_json::json!({ "name": "cowsay", "bin": { "cowsay": "cli.js", "cowthink": "cli.js" } });
        assert_eq!(bin_from_manifest(&single).unwrap(), "cowsay");
        let by_name =
            serde_json::json!({ "name": "@antfu/ni", "bin": { "ni": "ni.mjs", "nr": "nr.mjs" } });
        assert_eq!(bin_from_manifest(&by_name).unwrap(), "ni");
        let string_bin = serde_json::json!({ "name": "@scope/tool", "bin": "cli.js" });
        assert_eq!(bin_from_manifest(&string_bin).unwrap(), "tool");
        let ambiguous = serde_json::json!({ "name": "typescript", "version": "5.9.3", "bin": { "tsc": "bin/tsc", "tsserver": "bin/tsserver" } });
        let error = bin_from_manifest(&ambiguous).unwrap_err().to_string();
        assert!(error.contains("could not determine executable to run"));
        assert!(error.contains("--package typescript"));
        let none = serde_json::json!({ "name": "lodash", "version": "4.17.21" });
        assert!(bin_from_manifest(&none).is_err());
    }

    #[test]
    fn initializers_map_like_npm_init() {
        assert_eq!(
            initializer_package("react-app").unwrap(),
            "create-react-app"
        );
        assert_eq!(
            initializer_package("next-app@latest").unwrap(),
            "create-next-app@latest"
        );
        assert_eq!(initializer_package("@vitejs").unwrap(), "@vitejs/create");
        assert_eq!(
            initializer_package("@vitejs@5").unwrap(),
            "@vitejs/create@5"
        );
        assert_eq!(
            initializer_package("@scope/app").unwrap(),
            "@scope/create-app"
        );
        assert_eq!(
            initializer_package("github:user/app#main").unwrap(),
            "github:user/create-app#main"
        );
        assert_eq!(initializer_package("user/app").unwrap(), "user/create-app");
        assert!(initializer_package("./local").is_err());
    }
}
