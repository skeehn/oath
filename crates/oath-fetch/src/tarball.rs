//! Tarball download, integrity verification, and extraction
//!
//! Handles SRI (Subresource Integrity) verification using sha512/sha256/sha1.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tar::Archive;

const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_UNPACKED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 200_000;
const DEFAULT_MAX_PATH_BYTES: usize = 4096;
const DEFAULT_MAX_PATH_COMPONENTS: usize = 64;

#[derive(Debug, Clone)]
pub struct TarballLimits {
    pub max_archive_bytes: u64,
    pub max_unpacked_bytes: u64,
    pub max_entries: u64,
    pub max_path_bytes: usize,
    pub max_path_components: usize,
}

impl Default for TarballLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            max_unpacked_bytes: DEFAULT_MAX_UNPACKED_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
            max_path_components: DEFAULT_MAX_PATH_COMPONENTS,
        }
    }
}

impl TarballLimits {
    pub fn from_env() -> Result<Self> {
        let mut limits = Self::default();
        limits.max_archive_bytes = env_u64("OATH_MAX_TARBALL_BYTES", limits.max_archive_bytes)?;
        limits.max_unpacked_bytes = env_u64("OATH_MAX_UNPACKED_BYTES", limits.max_unpacked_bytes)?;
        limits.max_entries = env_u64("OATH_MAX_TARBALL_ENTRIES", limits.max_entries)?;
        Ok(limits)
    }

    pub fn check_archive_size(&self, bytes: u64) -> Result<()> {
        if bytes > self.max_archive_bytes {
            bail!(
                "tarball compressed size {bytes} exceeds limit {}",
                self.max_archive_bytes
            );
        }
        Ok(())
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("could not read {name}")),
    }
}

pub enum IntegrityVerifier {
    Sha512(Sha512, Vec<String>),
    Sha256(Sha256, Vec<String>),
    Sha1(Sha1, Vec<String>),
}

impl IntegrityVerifier {
    pub fn new(sri: &str) -> Result<Self> {
        let mut sha512 = Vec::new();
        let mut sha256 = Vec::new();
        let mut sha1 = Vec::new();
        for token in sri.split_whitespace() {
            let (algo, expected_b64) = token
                .split_once('-')
                .with_context(|| format!("invalid SRI format: {token}"))?;
            if expected_b64.is_empty() {
                bail!("invalid SRI format: {token}");
            }
            match algo {
                "sha512" => sha512.push(expected_b64.to_string()),
                "sha256" => sha256.push(expected_b64.to_string()),
                "sha1" => sha1.push(expected_b64.to_string()),
                _ => {}
            }
        }
        if !sha512.is_empty() {
            Ok(Self::Sha512(Sha512::new(), sha512))
        } else if !sha256.is_empty() {
            Ok(Self::Sha256(Sha256::new(), sha256))
        } else if !sha1.is_empty() {
            Ok(Self::Sha1(Sha1::new(), sha1))
        } else {
            bail!("SRI metadata contains no supported digest: {sri}")
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha512(hasher, _) => hasher.update(data),
            Self::Sha256(hasher, _) => hasher.update(data),
            Self::Sha1(hasher, _) => hasher.update(data),
        }
    }

    pub fn finish(self) -> Result<()> {
        let (algo, expected_b64, computed_b64) = match self {
            Self::Sha512(hasher, expected) => {
                ("sha512", expected, base64_encode(&hasher.finalize()))
            }
            Self::Sha256(hasher, expected) => {
                ("sha256", expected, base64_encode(&hasher.finalize()))
            }
            Self::Sha1(hasher, expected) => ("sha1", expected, base64_encode(&hasher.finalize())),
        };

        if !expected_b64.contains(&computed_b64) {
            let expected = expected_b64
                .iter()
                .map(|digest| format!("{algo}-{digest}"))
                .collect::<Vec<_>>()
                .join(" ");
            bail!("integrity check failed: expected one of {expected}, got {algo}-{computed_b64}");
        }

        Ok(())
    }
}

/// Verify tarball bytes against an SRI integrity string.
///
/// Supports whitespace-separated SRI digests and verifies the strongest
/// supported algorithm, matching npm's integrity semantics.
pub fn verify_integrity(data: &[u8], sri: &str) -> Result<()> {
    let mut verifier = IntegrityVerifier::new(sri)?;
    verifier.update(data);
    verifier.finish()
}

/// Extract a .tgz tarball to a destination directory.
/// npm tarballs contain a `package/` prefix which we strip.
pub fn extract_tarball(data: &[u8], dest: &Path) -> Result<()> {
    let limits = TarballLimits::from_env()?;
    extract_tarball_limited(data, dest, &limits)
}

pub fn extract_tarball_limited(data: &[u8], dest: &Path, limits: &TarballLimits) -> Result<()> {
    limits.check_archive_size(data.len() as u64)?;
    let gz = GzDecoder::new(data);
    extract_archive(gz, dest, limits)
}

pub fn extract_tarball_file(path: &Path, dest: &Path) -> Result<()> {
    let limits = TarballLimits::from_env()?;
    extract_tarball_file_limited(path, dest, &limits)
}

pub fn extract_tarball_file_limited(
    path: &Path,
    dest: &Path,
    limits: &TarballLimits,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat tarball: {}", path.display()))?;
    limits.check_archive_size(metadata.len())?;
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let gz = GzDecoder::new(std::io::BufReader::new(file));
    extract_archive(gz, dest, limits)
}

fn extract_archive<R: Read>(reader: R, dest: &Path, limits: &TarballLimits) -> Result<()> {
    let mut archive = Archive::new(reader);
    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create dir: {}", dest.display()))?;

    let mut entry_count = 0u64;
    let mut unpacked_bytes = 0u64;

    for entry in archive.entries().context("failed to read tar entries")? {
        entry_count = entry_count
            .checked_add(1)
            .context("tarball entry count overflow")?;
        if entry_count > limits.max_entries {
            bail!(
                "tarball entry count {entry_count} exceeds limit {}",
                limits.max_entries
            );
        }

        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("invalid path in tar")?;

        let Some(mut relative) = sanitize_tar_path(&path, limits)? else {
            continue;
        };
        // npm/pacote normalizes every packaged .gitignore to .npmignore,
        // including nested files. Match that observable node_modules contract
        // while preserving the containing directory.
        if relative
            .file_name()
            .is_some_and(|name| name == ".gitignore")
        {
            relative.set_file_name(".npmignore");
        }

        let full_path = dest.join(&relative);

        match entry.header().entry_type() {
            // npm/pacote does not preserve empty directory entries. Parent
            // directories are created on demand for actual package files.
            tar::EntryType::Directory => {}
            tar::EntryType::Regular => {
                let entry_size = entry.size();
                unpacked_bytes = unpacked_bytes
                    .checked_add(entry_size)
                    .context("tarball unpacked size overflow")?;
                if unpacked_bytes > limits.max_unpacked_bytes {
                    bail!(
                        "tarball unpacked size {unpacked_bytes} exceeds limit {}",
                        limits.max_unpacked_bytes
                    );
                }
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("failed to create dir: {}", parent.display()))?;
                }
                // Capture mode before consuming entry via io::copy.
                #[cfg(unix)]
                let mode = entry.header().mode().unwrap_or(0o644);
                let mut file = std::fs::File::create(&full_path)
                    .with_context(|| format!("failed to create: {}", full_path.display()))?;
                std::io::copy(&mut entry, &mut file)
                    .with_context(|| format!("failed to write: {}", full_path.display()))?;
                file.flush()
                    .with_context(|| format!("failed to flush: {}", full_path.display()))?;
                // Preserve executable bits from the tar header
                #[cfg(unix)]
                if mode & 0o111 != 0 {
                    let perms = std::fs::Permissions::from_mode(0o755);
                    std::fs::set_permissions(&full_path, perms).with_context(|| {
                        format!("failed to set permissions on: {}", full_path.display())
                    })?;
                }
            }
            // npm's extractor (pacote) drops link entries from package
            // tarballs instead of failing the install. A tarball cannot
            // legitimately point outside itself, and a link inside the package
            // is a packaging mistake, so skip the entry and keep the files.
            tar::EntryType::Symlink | tar::EntryType::Link => {
                tracing::warn!(
                    "skipping {:?} entry {} (links are not materialized from package tarballs)",
                    entry.header().entry_type(),
                    path.display()
                );
                continue;
            }
            other => {
                bail!(
                    "unsupported tar entry type {:?} for {}",
                    other,
                    path.display()
                );
            }
        }
    }

    Ok(())
}

/// List files in a tarball without extracting
pub fn list_tarball(data: &[u8]) -> Result<Vec<String>> {
    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let entry = entry?;
        if let Ok(path) = entry.path()
            && let Ok(Some(relative)) = sanitize_tar_path(&path, &TarballLimits::default())
        {
            files.push(relative.to_string_lossy().to_string());
        }
    }

    Ok(files)
}

/// Get the total unpacked size of a tarball
pub fn tarball_unpacked_size(data: &[u8]) -> Result<u64> {
    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);
    let mut total = 0u64;

    for entry in archive.entries()? {
        let entry = entry?;
        total += entry.size();
    }

    Ok(total)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn sanitize_tar_path(path: &Path, limits: &TarballLimits) -> Result<Option<PathBuf>> {
    let path_str = path
        .to_str()
        .with_context(|| format!("tar path is not valid UTF-8: {}", path.display()))?;
    if path_str.len() > limits.max_path_bytes {
        bail!(
            "tar path length {} exceeds limit {}: {path_str}",
            path_str.len(),
            limits.max_path_bytes
        );
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .with_context(|| format!("tar path has invalid UTF-8: {path_str}"))?;
                if part.is_empty() {
                    bail!("tar path contains empty component: {path_str}");
                }
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                bail!("unsafe tar path: {path_str}");
            }
        }
    }

    let relative_parts: Vec<_> = parts.into_iter().skip(1).collect();
    if relative_parts.is_empty() {
        return Ok(None);
    }
    if relative_parts.len() > limits.max_path_components {
        bail!(
            "tar path component count {} exceeds limit {}: {path_str}",
            relative_parts.len(),
            limits.max_path_components
        );
    }

    let mut relative = PathBuf::new();
    for part in relative_parts {
        relative.push(part);
    }
    Ok(Some(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    fn tar_gz_with_file(path: &str, content: &[u8]) -> Vec<u8> {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gz);
        let mut header = Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extract_tarball_rejects_parent_dir_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("extract");
        let outside = tmp.path().join("escape.txt");
        let data = tar_gz_with_file("package/../escape.txt", b"owned");

        assert!(extract_tarball(&data, &dest).is_err());

        assert!(
            !outside.exists(),
            "tarball extraction wrote outside destination"
        );
    }

    #[test]
    fn list_tarball_filters_parent_dir_entries() {
        let data = tar_gz_with_file("package/../escape.txt", b"owned");

        let files = list_tarball(&data).unwrap();

        assert!(files.is_empty(), "unsafe tar path was listed: {files:?}");
    }

    #[test]
    fn extract_tarball_enforces_unpacked_size_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tar_gz_with_file("package/big.txt", b"owned");
        let limits = TarballLimits {
            max_unpacked_bytes: 4,
            ..TarballLimits::default()
        };

        assert!(extract_tarball_limited(&data, tmp.path(), &limits).is_err());
    }

    #[test]
    fn extract_tarball_skips_symlinks_like_pacote() {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gz);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../escape").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "package/link", std::io::empty())
            .unwrap();
        let mut file = Header::new_gnu();
        file.set_size(5);
        file.set_mode(0o644);
        file.set_cksum();
        tar.append_data(&mut file, "package/index.js", &b"hello"[..])
            .unwrap();
        let data = tar.into_inner().unwrap().finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        extract_tarball(&data, tmp.path()).unwrap();
        assert!(
            tmp.path().join("link").symlink_metadata().is_err(),
            "link entry must not be materialized"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("index.js")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn extract_tarball_matches_npm_gitignore_normalization() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tar_gz_with_file("package/.gitignore", b"node_modules\n");
        extract_tarball(&data, tmp.path()).unwrap();
        assert!(!tmp.path().join(".gitignore").exists());
        assert_eq!(
            std::fs::read(tmp.path().join(".npmignore")).unwrap(),
            b"node_modules\n"
        );
    }

    #[test]
    fn extract_tarball_normalizes_nested_gitignore_files() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tar_gz_with_file("package/fixtures/example/.gitignore", b"output\n");
        extract_tarball(&data, tmp.path()).unwrap();
        assert!(!tmp.path().join("fixtures/example/.gitignore").exists());
        assert_eq!(
            std::fs::read(tmp.path().join("fixtures/example/.npmignore")).unwrap(),
            b"output\n"
        );
    }

    #[test]
    fn extract_tarball_matches_npm_by_omitting_empty_directories() {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gz);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "package/.github/", std::io::empty())
            .unwrap();
        let data = tar.into_inner().unwrap().finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        extract_tarball(&data, tmp.path()).unwrap();
        assert!(!tmp.path().join(".github").exists());
    }

    #[test]
    fn sha1_integrity_is_verified() {
        let data = b"package bytes";
        let hash = Sha1::digest(data);
        let integrity = format!("sha1-{}", base64_encode(&hash));

        verify_integrity(data, &integrity).unwrap();
        assert!(verify_integrity(b"tampered package bytes", &integrity).is_err());
    }

    #[test]
    fn multi_hash_integrity_uses_strongest_supported_algorithm() {
        let data = b"package bytes";
        let sha1 = base64_encode(&Sha1::digest(data));
        let sha512 = base64_encode(&Sha512::digest(data));
        let integrity = format!("sha1-{sha1} sha512-{sha512}");

        verify_integrity(data, &integrity).unwrap();
    }

    #[test]
    fn multi_hash_integrity_rejects_wrong_strongest_digest() {
        let data = b"package bytes";
        let sha1 = base64_encode(&Sha1::digest(data));
        let wrong_sha512 = base64_encode(&Sha512::digest(b"different package bytes"));
        let integrity = format!("sha1-{sha1} sha512-{wrong_sha512}");

        assert!(verify_integrity(data, &integrity).is_err());
    }

    #[test]
    fn multi_hash_integrity_accepts_any_digest_at_strongest_level() {
        let data = b"package bytes";
        let wrong_sha512 = base64_encode(&Sha512::digest(b"different package bytes"));
        let correct_sha512 = base64_encode(&Sha512::digest(data));
        let integrity = format!("sha512-{wrong_sha512} sha512-{correct_sha512}");

        verify_integrity(data, &integrity).unwrap();
    }
}
