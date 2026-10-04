//! Transparency log for oath installs.
//!
//! Appends a JSONL record to ~/.oath/transparency.log on every install.
//! The log is append-only and never truncated.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const GENESIS_HASH: &str = "GENESIS";

/// A single entry in the transparency log (JSONL format)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparencyEntry {
    /// Unix timestamp (seconds)
    pub ts: u64,
    /// Absolute path to the project
    pub project: String,
    /// Total number of packages installed
    pub pkg_count: usize,
    /// Individual package entries
    pub packages: Vec<PackageEntry>,
    /// Time taken for the full install (ms)
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparencyCheckpoint {
    pub version: u32,
    pub entry_count: usize,
    pub merkle_root: String,
    pub latest_entry_hash: Option<String>,
}

#[derive(Serialize)]
struct HashPayload<'a> {
    ts: u64,
    project: &'a str,
    pkg_count: usize,
    packages: &'a [PackageEntry],
    duration_ms: u64,
}

fn hash_entry(previous: &str, payload: &HashPayload<'_>) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(serde_json::to_vec(payload)?);
    Ok(hex::encode(hasher.finalize()))
}

fn merkle_root(mut hashes: Vec<String>) -> String {
    if hashes.is_empty() {
        return hex::encode(Sha256::digest([]));
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(hashes.last().unwrap().clone());
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0].as_bytes());
                hasher.update(pair[1].as_bytes());
                hex::encode(hasher.finalize())
            })
            .collect();
    }
    hashes.remove(0)
}

/// A single package in a transparency entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

/// Appends a transparency log entry to ~/.oath/transparency.log.
pub struct TransparencyLogger {
    log_path: PathBuf,
}

impl TransparencyLogger {
    /// Create a logger that writes to ~/.oath/transparency.log
    pub fn default_logger() -> Result<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("HOME or USERPROFILE not set"))?;
        let dir = PathBuf::from(home).join(".oath");
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            log_path: dir.join("transparency.log"),
        })
    }

    /// Create a logger that writes to a custom path (for testing)
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// Append a new entry. `packages` is a list of (name, version, integrity).
    pub fn log(
        &self,
        project: &str,
        packages: &[(String, String, Option<String>)],
        duration_ms: u64,
    ) -> Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let pkg_entries: Vec<PackageEntry> = packages
            .iter()
            .map(|(name, version, integrity)| PackageEntry {
                name: name.clone(),
                version: version.clone(),
                integrity: integrity.clone(),
            })
            .collect();

        let existing = self.read_all()?;
        let previous_hash = existing
            .iter()
            .rev()
            .find_map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());
        let payload = HashPayload {
            ts,
            project,
            pkg_count: pkg_entries.len(),
            packages: &pkg_entries,
            duration_ms,
        };
        let entry_hash = hash_entry(&previous_hash, &payload)?;
        let entry = TransparencyEntry {
            ts,
            project: project.to_string(),
            pkg_count: pkg_entries.len(),
            packages: pkg_entries,
            duration_ms,
            previous_hash: Some(previous_hash),
            entry_hash: Some(entry_hash),
        };

        let line = serde_json::to_string(&entry)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Read recent entries from the log. Returns up to `tail` most recent entries.
    pub fn read_recent(&self, tail: usize) -> Result<Vec<TransparencyEntry>> {
        let entries = self.read_all()?;
        let len = entries.len();
        if len <= tail {
            Ok(entries)
        } else {
            Ok(entries[len - tail..].to_vec())
        }
    }

    fn read_all(&self) -> Result<Vec<TransparencyEntry>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.log_path)?;
        let entries: Vec<TransparencyEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        Ok(entries)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let mut previous = GENESIS_HASH.to_string();
        for entry in self
            .read_all()?
            .into_iter()
            .filter(|entry| entry.entry_hash.is_some())
        {
            anyhow::ensure!(
                entry.previous_hash.as_deref() == Some(previous.as_str()),
                "transparency chain previous hash mismatch"
            );
            let payload = HashPayload {
                ts: entry.ts,
                project: &entry.project,
                pkg_count: entry.pkg_count,
                packages: &entry.packages,
                duration_ms: entry.duration_ms,
            };
            let expected = hash_entry(&previous, &payload)?;
            anyhow::ensure!(
                entry.entry_hash.as_deref() == Some(expected.as_str()),
                "transparency entry hash mismatch"
            );
            previous = expected;
        }
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<TransparencyCheckpoint> {
        self.verify_chain()?;
        let hashes: Vec<String> = self
            .read_all()?
            .into_iter()
            .filter_map(|entry| entry.entry_hash)
            .collect();
        let checkpoint = TransparencyCheckpoint {
            version: 1,
            entry_count: hashes.len(),
            merkle_root: merkle_root(hashes.clone()),
            latest_entry_hash: hashes.last().cloned(),
        };
        let path = self.log_path.with_extension("checkpoint.json");
        let temp = path.with_extension("checkpoint.tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(&checkpoint)?)?;
        std::fs::rename(temp, path)?;
        Ok(checkpoint)
    }

    /// Return the log file path
    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_and_checkpoint_detect_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transparency.log");
        let logger = TransparencyLogger::new(path.clone());
        logger
            .log(
                "/project",
                &[("a".into(), "1.0.0".into(), Some("sha512-a".into()))],
                10,
            )
            .unwrap();
        logger
            .log(
                "/project",
                &[("b".into(), "2.0.0".into(), Some("sha512-b".into()))],
                20,
            )
            .unwrap();
        logger.verify_chain().unwrap();
        let checkpoint = logger.checkpoint().unwrap();
        assert_eq!(checkpoint.entry_count, 2);
        assert_eq!(checkpoint.merkle_root.len(), 64);
        let content = std::fs::read_to_string(&path)
            .unwrap()
            .replace("sha512-a", "sha512-x");
        std::fs::write(path, content).unwrap();
        assert!(logger.verify_chain().is_err());
    }
}
