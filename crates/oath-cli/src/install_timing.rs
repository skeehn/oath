use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const PHASES: [&str; 12] = [
    "noop_validation",
    "resolve",
    "metadata",
    "download",
    "integrity",
    "extraction",
    "analysis",
    "policy",
    "link",
    "lifecycle",
    "lockfile",
    "cleanup",
];

#[derive(Debug)]
pub struct InstallTimings {
    started: Instant,
    phases_ms: BTreeMap<&'static str, f64>,
}

#[derive(Serialize)]
struct InstallTimingReport {
    schema_version: u32,
    operation: &'static str,
    outcome: &'static str,
    no_op: bool,
    total_ms: f64,
    phases_ms: BTreeMap<&'static str, f64>,
}

impl InstallTimings {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            phases_ms: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, phase: &'static str, duration: Duration) {
        debug_assert!(PHASES.contains(&phase));
        *self.phases_ms.entry(phase).or_default() += duration.as_secs_f64() * 1_000.0;
    }

    pub fn finish(mut self, no_op: bool) -> Result<()> {
        for phase in PHASES {
            self.phases_ms.entry(phase).or_default();
        }
        let Some(path) = std::env::var_os("OATH_TIMINGS_FILE").map(PathBuf::from) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create timing output directory {}", parent.display()))?;
        }
        let report = InstallTimingReport {
            schema_version: 1,
            operation: "install",
            outcome: "success",
            no_op,
            total_ms: self.started.elapsed().as_secs_f64() * 1_000.0,
            phases_ms: self.phases_ms,
        };
        std::fs::write(&path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("write install timings {}", path.display()))?;
        Ok(())
    }
}
