//! The persistent exec cache: `~/.oath/cache/_npx/<key>/`, laid out as npm's
//! `_npx` cache is so `oath cache npx ls|rm|info` and `npm cache npx ...`
//! describe the same thing. Each entry is a small project whose
//! `package.json` records the requested specs under `_npx.packages`, with a
//! `node_modules` tree linked from Oath's content store, an `oath-lock.json`,
//! and Oath's own assessment records under `.oath/`.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};

/// One exec-cache entry as `ls` and `info` describe it.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub hash: String,
    pub path: PathBuf,
    /// The parsed `package.json`, when the entry has a readable one.
    pub manifest: Option<serde_json::Value>,
}

impl CacheEntry {
    /// The specs recorded in `_npx.packages`.
    pub fn packages(&self) -> Option<Vec<String>> {
        let packages = self.manifest.as_ref()?.get("_npx")?.get("packages")?;
        Some(
            packages
                .as_array()?
                .iter()
                .filter_map(|value| value.as_str().map(String::from))
                .collect(),
        )
    }
}

pub struct NpxCache {
    root: PathBuf,
}

impl NpxCache {
    /// `~/.oath/cache/_npx`, next to the packument and tarball caches.
    pub fn default_cache() -> Result<Self> {
        let home =
            oath_core::home_dir().context("HOME or USERPROFILE is required for the exec cache")?;
        Ok(Self {
            root: home.join(".oath").join("cache").join("_npx"),
        })
    }

    #[cfg(test)]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// npm's cache key: the first 16 hex characters of the SHA-512 of the
    /// sorted specs joined by newlines. npm sorts with `localeCompare(…,
    /// 'en')`; a case-insensitive comparison with lowercase first reproduces
    /// that order for package specs, which contain no characters the English
    /// collation would otherwise ignore.
    pub fn key(packages: &[String]) -> String {
        let mut sorted: Vec<&String> = packages.iter().collect();
        sorted.sort_by(|a, b| locale_compare(a, b));
        let joined = sorted
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let digest = Sha512::digest(joined.as_bytes());
        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn entry_dir(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    /// Every entry directory, in name order.
    pub fn entries(&self) -> Result<Vec<CacheEntry>> {
        let mut entries = Vec::new();
        let dirs = match std::fs::read_dir(&self.root) {
            Ok(dirs) => dirs,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", self.root.display()));
            }
        };
        for dir in dirs {
            let dir = dir?;
            if !dir.file_type()?.is_dir() {
                continue;
            }
            let hash = dir.file_name().to_string_lossy().into_owned();
            let path = dir.path();
            let manifest = std::fs::read_to_string(path.join("package.json"))
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok());
            entries.push(CacheEntry {
                hash,
                path,
                manifest,
            });
        }
        entries.sort_by(|a, b| a.hash.cmp(&b.hash));
        Ok(entries)
    }

    /// Resolve user-supplied keys, accepting any unambiguous prefix as npm's
    /// `abbrev` does.
    pub fn resolve_keys(&self, keys: &[String]) -> Result<Vec<CacheEntry>> {
        let entries = self.entries()?;
        let mut selected = Vec::new();
        for key in keys {
            let matches: Vec<&CacheEntry> = entries
                .iter()
                .filter(|entry| entry.hash.starts_with(key.as_str()))
                .collect();
            let entry = match matches.as_slice() {
                [entry] => *entry,
                [] => bail!("Invalid npx key {key}"),
                many => {
                    if let Some(exact) = many.iter().find(|entry| &entry.hash == key) {
                        *exact
                    } else {
                        bail!("Invalid npx key {key}: ambiguous prefix")
                    }
                }
            };
            if !selected.iter().any(|e: &CacheEntry| e.hash == entry.hash) {
                selected.push(entry.clone());
            }
        }
        Ok(selected)
    }
}

/// An approximation of `String.prototype.localeCompare(other, 'en')` for
/// ASCII package specs: letters compare case-insensitively first, then
/// lowercase sorts before uppercase.
fn locale_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let primary = a
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .cmp(b.chars().map(|c| c.to_ascii_lowercase()));
    if primary != std::cmp::Ordering::Equal {
        return primary;
    }
    // Lowercase before uppercase at the tertiary level.
    a.chars()
        .map(|c| c.is_ascii_uppercase())
        .cmp(b.chars().map(|c| c.is_ascii_uppercase()))
}

/// `oath cache npx ls`: one line per entry, like npm.
pub fn ls(cache: &NpxCache) -> Result<()> {
    let entries = cache.entries()?;
    if !cache.root().exists() {
        println!("npx cache does not exist");
        return Ok(());
    }
    for entry in entries {
        let description = match (&entry.manifest, entry.packages()) {
            (None, _) => "(empty/invalid)".to_string(),
            (Some(_), Some(packages)) => packages.join(", "),
            (Some(_), None) => "(unknown)".to_string(),
        };
        println!("{}: {description}", entry.hash);
    }
    Ok(())
}

/// `oath cache npx rm [<key>...]`: remove entries, or the whole cache with
/// `--force`.
pub fn rm(cache: &NpxCache, keys: &[String], force: bool, dry_run: bool) -> Result<()> {
    if keys.is_empty() {
        if !force {
            bail!("Please use --force to remove entire npx cache");
        }
        if !dry_run && cache.root().exists() {
            std::fs::remove_dir_all(cache.root())
                .with_context(|| format!("removing {}", cache.root().display()))?;
        }
        return Ok(());
    }
    for entry in cache.resolve_keys(keys)? {
        println!("Removing npx key at {}", entry.path.display());
        if !dry_run {
            std::fs::remove_dir_all(&entry.path)
                .with_context(|| format!("removing {}", entry.path.display()))?;
        }
    }
    Ok(())
}

/// `oath cache npx info <key>...`: validity, location, and the packages an
/// entry provides with their installed versions.
pub fn info(cache: &NpxCache, keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        bail!("usage: oath cache npx info <key>...");
    }
    for entry in cache.resolve_keys(keys)? {
        let valid = entry.manifest.is_some() && entry.path.join("node_modules").is_dir();
        println!(
            "{} npx cache entry with key {}",
            if valid { "valid" } else { "invalid" },
            entry.hash
        );
        println!("location: {}", entry.path.display());
        if valid {
            match entry.packages() {
                Some(packages) => {
                    println!("packages:");
                    for package in packages {
                        match installed_id(&entry, &package) {
                            Some(id) => println!("- {package} ({id})"),
                            None => println!("- {package}"),
                        }
                    }
                }
                None => {
                    println!("packages: (unknown)");
                    println!("dependencies:");
                    let deps = entry
                        .manifest
                        .as_ref()
                        .and_then(|m| m.get("dependencies"))
                        .and_then(|d| d.as_object());
                    for name in deps.into_iter().flat_map(|d| d.keys()) {
                        match installed_version(&entry.path, name) {
                            Some(version) => println!("- {name}@{version}"),
                            None => println!("- {name}"),
                        }
                    }
                }
            }
        }
        println!();
    }
    Ok(())
}

/// The `name@version` an entry installed for one of its recorded specs.
fn installed_id(entry: &CacheEntry, package: &str) -> Option<String> {
    let names = crate::exec::recorded_names(&entry.path);
    let name = names
        .iter()
        .find(|added| added.raw == package)
        .map(|added| added.name.clone())
        .or_else(|| {
            // Registry specs carry their own name.
            let start = usize::from(package.starts_with('@'));
            let end = package[start..]
                .find('@')
                .map(|at| start + at)
                .unwrap_or(package.len());
            let candidate = &package[..end];
            (!candidate.contains(':') && !candidate.starts_with('.') && !candidate.starts_with('/'))
                .then(|| candidate.to_string())
        })?;
    let version = installed_version(&entry.path, &name)?;
    Some(format!("{name}@{version}"))
}

fn installed_version(entry: &Path, name: &str) -> Option<String> {
    let manifest = entry.join("node_modules").join(name).join("package.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest).ok()?).ok()?;
    value["version"].as_str().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_matches_npm_hash_for_single_and_sorted_specs() {
        // `node -e "console.log(require('crypto').createHash('sha512').update('cowsay').digest('hex').slice(0,16))"`
        assert_eq!(NpxCache::key(&["cowsay".into()]), "8f497369b2d6166e");
        // Sorted before hashing, so order of -p flags does not matter.
        assert_eq!(
            NpxCache::key(&["typescript".into(), "cowsay".into()]),
            NpxCache::key(&["cowsay".into(), "typescript".into()])
        );
    }

    #[test]
    fn locale_order_is_case_insensitive_with_lowercase_first() {
        let mut specs = vec!["B".to_string(), "a".into(), "A".into(), "b".into()];
        specs.sort_by(|a, b| locale_compare(a, b));
        assert_eq!(specs, vec!["a", "A", "b", "B"]);
    }

    #[test]
    fn entries_and_prefix_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let cache = NpxCache::at(dir.path().join("_npx"));
        assert!(cache.entries().unwrap().is_empty());
        std::fs::create_dir_all(cache.entry_dir("abcdef0123456789")).unwrap();
        std::fs::write(
            cache.entry_dir("abcdef0123456789").join("package.json"),
            r#"{"dependencies":{"cowsay":"^1.6.0"},"_npx":{"packages":["cowsay"]}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(cache.entry_dir("abc0000000000000")).unwrap();
        let entries = cache.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].packages().unwrap(), vec!["cowsay"]);
        assert!(entries[0].manifest.is_none());
        assert_eq!(
            cache.resolve_keys(&["abcd".into()]).unwrap()[0].hash,
            "abcdef0123456789"
        );
        assert!(cache.resolve_keys(&["abc".into()]).is_err());
        assert!(cache.resolve_keys(&["zzz".into()]).is_err());
        rm(&cache, &["abcd".into()], false, false).unwrap();
        assert_eq!(cache.entries().unwrap().len(), 1);
        assert!(rm(&cache, &[], false, false).is_err());
        rm(&cache, &[], true, false).unwrap();
        assert!(!cache.root().exists());
    }
}
