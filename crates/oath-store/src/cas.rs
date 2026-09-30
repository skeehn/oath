//! Content-Addressable Store (CAS)
//!
//! Global store at ~/.oath/store/ where each file is stored by its BLAKE3 hash.
//! A package tarball is extracted once into the store, then hardlinked everywhere.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const STORE_MANIFEST_FILE: &str = ".oath-store-manifest.json";
pub const STORE_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoreManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_integrity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
    pub package_json_name: String,
    pub package_json_version: String,
    pub file_count: u64,
    pub byte_count: u64,
    pub blake3_tree: Vec<StoreManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoreManifestFile {
    pub path: String,
    pub bytes: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageVerification {
    Verified(StoreManifest),
    Missing,
    Corrupt(String),
}

impl PackageVerification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

/// The global content-addressable store
#[derive(Clone)]
pub struct ContentStore {
    /// Root directory of the store
    root: PathBuf,
}

impl ContentStore {
    /// Create or open a store at the given path
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create store at {}", root.display()))?;
        Ok(Self { root })
    }

    /// Default store location: ~/.oath/store
    pub fn default_store() -> Result<Self> {
        let home = oath_core::home_dir().context("HOME or USERPROFILE not set")?;
        Self::new(home.join(".oath").join("store"))
    }

    /// Store a package's extracted files. Returns the package directory in the store.
    ///
    /// Layout: store/{name}/{version}/node_modules/{name}/{files...}
    /// This mirrors what node expects when resolving.
    pub fn store_package(
        &self,
        name: &str,
        version: &str,
        extracted_dir: &Path,
    ) -> Result<PathBuf> {
        self.store_package_with_manifest(name, version, None, None, extracted_dir)
    }

    /// Store a package and write a verification manifest atomically.
    pub fn store_package_with_manifest(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
        extracted_dir: &Path,
    ) -> Result<PathBuf> {
        self.store_package_at(
            name,
            version,
            resolved_url,
            lock_integrity,
            extracted_dir,
            self.package_dir(name, version),
        )
    }

    /// Store an immutable source variant. Package name and version are not a
    /// sufficient content identity: registry aliases and git dependencies can
    /// legitimately resolve the same tuple to different bytes.
    pub fn store_package_variant_with_manifest(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
        extracted_dir: &Path,
    ) -> Result<PathBuf> {
        let pkg_store_dir = self.package_dir_for(name, version, resolved_url, lock_integrity);
        self.store_package_at(
            name,
            version,
            resolved_url,
            lock_integrity,
            extracted_dir,
            pkg_store_dir,
        )
    }

    fn store_package_at(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
        extracted_dir: &Path,
        pkg_store_dir: PathBuf,
    ) -> Result<PathBuf> {
        match verify_package_at(name, version, resolved_url, lock_integrity, &pkg_store_dir) {
            PackageVerification::Verified(_) => {
                tracing::debug!("already verified in store: {name}@{version}");
                return Ok(pkg_store_dir);
            }
            PackageVerification::Missing => {}
            PackageVerification::Corrupt(reason) => {
                tracing::debug!("rebuilding corrupt store entry for {name}@{version}: {reason}");
                if pkg_store_dir.exists() {
                    std::fs::remove_dir_all(&pkg_store_dir).with_context(|| {
                        format!(
                            "failed to remove corrupt store dir: {}",
                            pkg_store_dir.display()
                        )
                    })?;
                }
            }
        }

        let parent = pkg_store_dir
            .parent()
            .with_context(|| format!("store path has no parent: {}", pkg_store_dir.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create store parent: {}", parent.display()))?;

        let temp_root = self.root.join(".tmp");
        std::fs::create_dir_all(&temp_root)
            .with_context(|| format!("failed to create store temp dir: {}", temp_root.display()))?;
        let temp_dir = temp_root.join(format!(
            "{}-{}-{}-{}",
            safe_path_component(&name.replace('/', "+")),
            safe_path_component(version),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).with_context(|| {
                format!("failed to clean stale temp dir: {}", temp_dir.display())
            })?;
        }
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create store temp dir: {}", temp_dir.display()))?;

        let result = (|| -> Result<()> {
            copy_dir_recursive(extracted_dir, &temp_dir)?;
            let manifest = build_manifest(
                name,
                version,
                resolved_url.map(str::to_string),
                lock_integrity.map(str::to_string),
                &temp_dir,
            )?;
            let manifest_json = serde_json::to_vec_pretty(&manifest)
                .context("failed to serialize store manifest")?;
            std::fs::write(temp_dir.join(STORE_MANIFEST_FILE), manifest_json)
                .context("failed to write store manifest")?;
            match validate_manifest(name, version, resolved_url, lock_integrity, &temp_dir) {
                Ok(_) => {}
                Err(StoreValidationError::Missing) => {
                    bail!("newly written store entry is missing")
                }
                Err(StoreValidationError::Corrupt(reason)) => {
                    bail!("newly written store entry is corrupt: {reason}")
                }
            }
            Ok(())
        })();

        if let Err(err) = result {
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(err);
        }

        if let Err(error) = std::fs::rename(&temp_dir, &pkg_store_dir) {
            // Another installer may have committed the same immutable variant
            // while this process was extracting it. Accept only a fully
            // verified winner; never delete or replace it behind another
            // process's back.
            if verify_package_at(name, version, resolved_url, lock_integrity, &pkg_store_dir)
                .is_verified()
            {
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Ok(pkg_store_dir);
            }
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(error).with_context(|| {
                format!(
                    "failed to atomically install store dir {} -> {}",
                    temp_dir.display(),
                    pkg_store_dir.display()
                )
            });
        }

        tracing::debug!("stored {name}@{version} at {}", pkg_store_dir.display());
        Ok(pkg_store_dir)
    }

    /// Check if a package is already in the store (and valid)
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        self.verify_package(name, version, None).is_verified()
    }

    /// Verify a package store entry against its manifest and expected integrity.
    pub fn verify_package(
        &self,
        name: &str,
        version: &str,
        lock_integrity: Option<&str>,
    ) -> PackageVerification {
        verify_package_at(
            name,
            version,
            None,
            lock_integrity,
            &self.package_dir(name, version),
        )
    }

    pub fn verify_package_variant(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
    ) -> PackageVerification {
        verify_package_at(
            name,
            version,
            resolved_url,
            lock_integrity,
            &self.package_dir_for(name, version, resolved_url, lock_integrity),
        )
    }

    /// Root path of the store (for scanning)
    pub fn store_path(&self) -> PathBuf {
        self.root.clone()
    }

    /// Get the store path for a package
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        // Scoped packages: @scope/name -> @scope+name
        self.package_name_dir(name)
            .join(safe_path_component(version))
    }

    /// Get the immutable directory for a particular resolution source. Both
    /// URL and integrity participate in identity so provenance cannot be
    /// silently swapped even when two sources claim the same package tuple.
    pub fn package_dir_for(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
    ) -> PathBuf {
        if resolved_url.is_none() && lock_integrity.is_none() {
            return self.package_dir(name, version);
        }
        let identity = format!(
            "resolved={}\nintegrity={}",
            resolved_url.unwrap_or_default(),
            lock_integrity.unwrap_or_default()
        );
        let variant = blake3::hash(identity.as_bytes()).to_hex().to_string();
        self.root
            .join(".variants")
            .join(safe_path_component(&name.replace('/', "+")))
            .join(safe_path_component(version))
            .join(variant)
    }

    /// Get the store path for all versions of a package.
    pub fn package_name_dir(&self, name: &str) -> PathBuf {
        self.root.join(safe_path_component(&name.replace('/', "+")))
    }

    /// Total size of the store (bytes)
    pub fn total_size(&self) -> u64 {
        dir_size(&self.root)
    }

    /// List all packages in the store
    pub fn list_packages(&self) -> Vec<(String, String)> {
        let mut packages = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().replace('+', "/");
                if name.starts_with('.') {
                    continue;
                }
                if let Ok(versions) = std::fs::read_dir(entry.path()) {
                    for ver in versions.flatten() {
                        let version = ver.file_name().to_string_lossy().to_string();
                        if version.starts_with('.') {
                            continue;
                        }
                        packages.push((name.clone(), version));
                    }
                }
            }
        }
        let variants = self.root.join(".variants");
        if let Ok(names) = std::fs::read_dir(variants) {
            for name in names.flatten().filter(|entry| entry.path().is_dir()) {
                let package_name = name.file_name().to_string_lossy().replace('+', "/");
                if let Ok(versions) = std::fs::read_dir(name.path()) {
                    for version in versions.flatten().filter(|entry| entry.path().is_dir()) {
                        packages.push((
                            package_name.clone(),
                            version.file_name().to_string_lossy().to_string(),
                        ));
                    }
                }
            }
        }
        packages.sort();
        packages.dedup();
        packages
    }

    /// Remove a specific package version from the store
    pub fn remove_package(&self, name: &str, version: &str) -> Result<()> {
        let dir = self.package_dir(name, version);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to remove {name}@{version}"))?;
        }
        let variants = self
            .root
            .join(".variants")
            .join(safe_path_component(&name.replace('/', "+")))
            .join(safe_path_component(version));
        if variants.exists() {
            std::fs::remove_dir_all(&variants)
                .with_context(|| format!("failed to remove variants for {name}@{version}"))?;
        }
        Ok(())
    }
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        } else {
            bail!(
                "refusing to store non-regular package entry: {}",
                src_path.display()
            );
        }
    }
    Ok(())
}

enum StoreValidationError {
    Missing,
    Corrupt(String),
}

fn verify_package_at(
    name: &str,
    version: &str,
    resolved_url: Option<&str>,
    lock_integrity: Option<&str>,
    dir: &Path,
) -> PackageVerification {
    match validate_manifest(name, version, resolved_url, lock_integrity, dir) {
        Ok(manifest) => PackageVerification::Verified(manifest),
        Err(StoreValidationError::Missing) => PackageVerification::Missing,
        Err(StoreValidationError::Corrupt(reason)) => PackageVerification::Corrupt(reason),
    }
}

fn validate_manifest(
    name: &str,
    version: &str,
    resolved_url: Option<&str>,
    lock_integrity: Option<&str>,
    dir: &Path,
) -> std::result::Result<StoreManifest, StoreValidationError> {
    if !dir.exists() {
        return Err(StoreValidationError::Missing);
    }
    let manifest_path = dir.join(STORE_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Err(StoreValidationError::Corrupt(
            "missing store manifest".to_string(),
        ));
    }

    let manifest: StoreManifest = std::fs::read(&manifest_path)
        .map_err(|err| StoreValidationError::Corrupt(format!("could not read manifest: {err}")))
        .and_then(|data| {
            serde_json::from_slice(&data).map_err(|err| {
                StoreValidationError::Corrupt(format!("malformed store manifest: {err}"))
            })
        })?;

    if manifest.schema_version != STORE_MANIFEST_SCHEMA_VERSION {
        return Err(StoreValidationError::Corrupt(format!(
            "unsupported store manifest schema {}",
            manifest.schema_version
        )));
    }
    if manifest.name != name || manifest.version != version {
        return Err(StoreValidationError::Corrupt(format!(
            "manifest package mismatch: expected {name}@{version}, got {}@{}",
            manifest.name, manifest.version
        )));
    }
    if let Some(expected) = lock_integrity
        && manifest.lock_integrity.as_deref() != Some(expected)
    {
        return Err(StoreValidationError::Corrupt(
            "manifest lock integrity mismatch".to_string(),
        ));
    }
    if let Some(expected) = resolved_url
        && manifest.resolved_url.as_deref() != Some(expected)
    {
        return Err(StoreValidationError::Corrupt(
            "manifest resolved URL mismatch".to_string(),
        ));
    }

    let rebuilt = build_manifest(
        name,
        version,
        manifest.resolved_url.clone(),
        manifest.lock_integrity.clone(),
        dir,
    )
    .map_err(|err| StoreValidationError::Corrupt(err.to_string()))?;

    if rebuilt.package_json_name != manifest.package_json_name
        || rebuilt.package_json_version != manifest.package_json_version
    {
        return Err(StoreValidationError::Corrupt(
            "package.json name/version changed".to_string(),
        ));
    }
    if rebuilt.file_count != manifest.file_count
        || rebuilt.byte_count != manifest.byte_count
        || rebuilt.blake3_tree != manifest.blake3_tree
    {
        return Err(StoreValidationError::Corrupt(
            "BLAKE3 file tree mismatch".to_string(),
        ));
    }

    Ok(manifest)
}

fn build_manifest(
    name: &str,
    version: &str,
    resolved_url: Option<String>,
    lock_integrity: Option<String>,
    dir: &Path,
) -> Result<StoreManifest> {
    let package_json_path = dir.join("package.json");
    let package_json = std::fs::read_to_string(&package_json_path).with_context(|| {
        format!(
            "package store entry missing package.json: {}",
            package_json_path.display()
        )
    })?;
    let package_json: serde_json::Value =
        serde_json::from_str(&package_json).context("package.json in store is not valid JSON")?;
    let package_json_name = package_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let package_json_version = package_json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let package_version = package_json_version
        .strip_prefix('v')
        .unwrap_or(&package_json_version);
    let version_matches = package_version == version
        || package_version
            .strip_prefix(version)
            .is_some_and(|suffix| suffix.starts_with('+') && suffix.len() > 1);
    if package_json_name != name || !version_matches {
        bail!(
            "package.json mismatch: expected {name}@{version}, got {package_json_name}@{package_json_version}"
        );
    }

    let blake3_tree = build_file_tree(dir)?;
    let byte_count = blake3_tree.iter().map(|file| file.bytes).sum();
    let file_count = blake3_tree.len() as u64;

    Ok(StoreManifest {
        schema_version: STORE_MANIFEST_SCHEMA_VERSION,
        name: name.to_string(),
        version: version.to_string(),
        lock_integrity,
        resolved_url,
        package_json_name,
        package_json_version,
        file_count,
        byte_count,
        blake3_tree,
    })
}

fn build_file_tree(root: &Path) -> Result<Vec<StoreManifestFile>> {
    let mut files = Vec::new();
    collect_file_tree(root, root, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn collect_file_tree(root: &Path, dir: &Path, files: &mut Vec<StoreManifestFile>) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read store dir: {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read store dir entry: {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat store path: {}", path.display()))?;
        if metadata.is_dir() {
            collect_file_tree(root, &path, files)?;
        } else if metadata.is_file() {
            if path.file_name().and_then(|name| name.to_str()) == Some(STORE_MANIFEST_FILE) {
                continue;
            }
            let relative = manifest_relative_path(root, &path)?;
            let data = std::fs::read(&path)
                .with_context(|| format!("failed to read store file: {}", path.display()))?;
            files.push(StoreManifestFile {
                path: relative,
                bytes: data.len() as u64,
                blake3: blake3::hash(&data).to_hex().to_string(),
            });
        } else {
            bail!("refusing special file in store: {}", path.display());
        }
    }

    Ok(())
}

fn manifest_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "store file {} is outside store entry {}",
            path.display(),
            root.display()
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .with_context(|| format!("non-UTF-8 store path: {}", path.display()))?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe store path: {}", path.display());
            }
        }
    }
    Ok(parts.join("/"))
}

fn dir_size(path: &Path) -> u64 {
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    size += dir_size(&entry.path());
                } else {
                    size += meta.len();
                }
            }
        }
    }
    size
}

fn safe_path_component(input: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manifest_accepts_npm_style_leading_v_version() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            r#"{"name":"pkg","version":"v1.2.3"}"#,
        )
        .unwrap();

        let manifest = build_manifest("pkg", "1.2.3", None, None, &source).unwrap();
        assert_eq!(manifest.package_json_version, "v1.2.3");
        assert!(build_manifest("pkg", "2.0.0", None, None, &source).is_err());
    }

    #[test]
    fn package_dir_does_not_escape_store_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();

        let path = store.package_dir("../evil", "../../outside");
        let relative = path.strip_prefix(store.store_path()).unwrap();

        assert!(!relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }));
        assert_eq!(
            path,
            store.store_path().join("..+evil").join("..%2F..%2Foutside")
        );
    }

    #[test]
    fn package_name_dir_preserves_scoped_package_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();

        assert_eq!(
            store.package_name_dir("@scope/name"),
            store.store_path().join("@scope+name")
        );
    }

    #[test]
    fn store_manifest_round_trips_and_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("lib")).unwrap();
        std::fs::write(
            source.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(source.join("lib/index.js"), "module.exports = 1;\n").unwrap();

        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        store
            .store_package_with_manifest(
                "pkg",
                "1.0.0",
                Some("https://registry.example/pkg.tgz"),
                Some("sha512-example"),
                &source,
            )
            .unwrap();

        let verified = store.verify_package("pkg", "1.0.0", Some("sha512-example"));
        let PackageVerification::Verified(manifest) = verified else {
            panic!("expected verified package, got {verified:?}");
        };
        assert_eq!(manifest.file_count, 2);
        assert_eq!(
            manifest
                .blake3_tree
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["lib/index.js", "package.json"]
        );

        std::fs::write(
            store.package_dir("pkg", "1.0.0").join("lib/index.js"),
            "tampered",
        )
        .unwrap();
        assert!(matches!(
            store.verify_package("pkg", "1.0.0", Some("sha512-example")),
            PackageVerification::Corrupt(_)
        ));
    }

    #[test]
    fn legacy_store_entry_without_manifest_is_unverified() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let dir = store.package_dir("pkg", "1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        assert!(matches!(
            store.verify_package("pkg", "1.0.0", None),
            PackageVerification::Corrupt(reason) if reason.contains("missing store manifest")
        ));
        assert!(!store.has_package("pkg", "1.0.0"));
    }

    #[test]
    fn source_variants_do_not_overwrite_the_same_name_and_version() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let source_a = tmp.path().join("source-a");
        let source_b = tmp.path().join("source-b");
        for (source, marker) in [(&source_a, "registry"), (&source_b, "git")] {
            std::fs::create_dir_all(source).unwrap();
            std::fs::write(
                source.join("package.json"),
                r#"{"name":"pkg","version":"1.0.0"}"#,
            )
            .unwrap();
            std::fs::write(source.join("source.txt"), marker).unwrap();
        }

        let registry_url = "https://registry.example/pkg.tgz";
        let git_url = "git+https://example.test/pkg.git#abc";
        let registry_dir = store
            .store_package_variant_with_manifest(
                "pkg",
                "1.0.0",
                Some(registry_url),
                Some("sha512-registry"),
                &source_a,
            )
            .unwrap();
        let git_dir = store
            .store_package_variant_with_manifest("pkg", "1.0.0", Some(git_url), None, &source_b)
            .unwrap();

        assert_ne!(registry_dir, git_dir);
        assert_eq!(
            std::fs::read_to_string(registry_dir.join("source.txt")).unwrap(),
            "registry"
        );
        assert_eq!(
            std::fs::read_to_string(git_dir.join("source.txt")).unwrap(),
            "git"
        );
        assert!(
            store
                .verify_package_variant("pkg", "1.0.0", Some(registry_url), Some("sha512-registry"))
                .is_verified()
        );
        assert!(
            store
                .verify_package_variant("pkg", "1.0.0", Some(git_url), None)
                .is_verified()
        );
        assert_eq!(store.list_packages(), vec![("pkg".into(), "1.0.0".into())]);
        store.remove_package("pkg", "1.0.0").unwrap();
        assert!(store.list_packages().is_empty());
    }

    #[test]
    fn accepts_npm_package_build_metadata_for_the_resolved_version() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            r#"{"name":"@hot-loader/react-dom","version":"17.0.2+4.13.0"}"#,
        )
        .unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let stored = store
            .store_package_variant_with_manifest(
                "@hot-loader/react-dom",
                "17.0.2",
                Some("https://registry.example/react-dom.tgz"),
                Some("sha512-example"),
                &source,
            )
            .unwrap();

        let manifest: StoreManifest =
            serde_json::from_slice(&std::fs::read(stored.join(STORE_MANIFEST_FILE)).unwrap())
                .unwrap();
        assert_eq!(manifest.version, "17.0.2");
        assert_eq!(manifest.package_json_version, "17.0.2+4.13.0");
    }
}
