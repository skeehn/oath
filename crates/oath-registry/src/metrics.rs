use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

const LATENCY_BUCKETS_SECONDS: [f64; 10] =
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOperation {
    Metadata,
    Tarball,
    Assessment,
    Publish,
    Revocation,
}

impl RegistryOperation {
    const ALL: [Self; 5] = [
        Self::Metadata,
        Self::Tarball,
        Self::Assessment,
        Self::Publish,
        Self::Revocation,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Metadata => 0,
            Self::Tarball => 1,
            Self::Assessment => 2,
            Self::Publish => 3,
            Self::Revocation => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Tarball => "tarball",
            Self::Assessment => "assessment",
            Self::Publish => "publish",
            Self::Revocation => "revocation",
        }
    }
}

#[derive(Clone, Default)]
pub struct RegistryMetrics(Arc<Inner>);

#[derive(Default)]
struct Inner {
    requests: AtomicU64,
    stages: AtomicU64,
    downloads: AtomicU64,
    denied: AtomicU64,
    errors: AtomicU64,
    operations: [OperationMetrics; 5],
}

#[derive(Default)]
struct OperationMetrics {
    total: AtomicU64,
    errors: AtomicU64,
    duration_nanos: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS_SECONDS.len()],
}

impl RegistryMetrics {
    pub fn request(&self) {
        self.0.requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn stage(&self) {
        self.0.stages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn download(&self) {
        self.0.downloads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn denied(&self) {
        self.0.denied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn observe(&self, operation: RegistryOperation, duration: Duration, success: bool) {
        let metrics = &self.0.operations[operation.index()];
        metrics.total.fetch_add(1, Ordering::Relaxed);
        if !success {
            metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        metrics.duration_nanos.fetch_add(nanos, Ordering::Relaxed);
        let seconds = duration.as_secs_f64();
        for (index, upper_bound) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if seconds <= *upper_bound {
                metrics.buckets[index].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn snapshot(&self) -> serde_json::Value {
        let operations = RegistryOperation::ALL
            .into_iter()
            .map(|operation| {
                let metrics = &self.0.operations[operation.index()];
                (
                    operation.name().to_owned(),
                    serde_json::json!({
                        "total": metrics.total.load(Ordering::Relaxed),
                        "errors": metrics.errors.load(Ordering::Relaxed),
                        "duration_seconds_sum": metrics.duration_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({
            "requests":self.0.requests.load(Ordering::Relaxed),
            "stages":self.0.stages.load(Ordering::Relaxed),
            "downloads":self.0.downloads.load(Ordering::Relaxed),
            "denied":self.0.denied.load(Ordering::Relaxed),
            "errors":self.0.errors.load(Ordering::Relaxed),
            "operations": operations,
        })
    }
    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        let mut output = format!(
            "# TYPE oath_registry_requests_total counter\noath_registry_requests_total {}\n# TYPE oath_registry_stages_total counter\noath_registry_stages_total {}\n# TYPE oath_registry_downloads_total counter\noath_registry_downloads_total {}\n# TYPE oath_registry_denied_total counter\noath_registry_denied_total {}\n# TYPE oath_registry_errors_total counter\noath_registry_errors_total {}\n",
            s["requests"], s["stages"], s["downloads"], s["denied"], s["errors"]
        );
        for operation in RegistryOperation::ALL {
            let name = operation.name();
            let metrics = &self.0.operations[operation.index()];
            output.push_str(&format!(
                "# TYPE oath_registry_{name}_operations_total counter\noath_registry_{name}_operations_total {}\n# TYPE oath_registry_{name}_errors_total counter\noath_registry_{name}_errors_total {}\n# TYPE oath_registry_{name}_duration_seconds histogram\n",
                metrics.total.load(Ordering::Relaxed),
                metrics.errors.load(Ordering::Relaxed),
            ));
            for (index, upper_bound) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
                output.push_str(&format!(
                    "oath_registry_{name}_duration_seconds_bucket{{le=\"{upper_bound}\"}} {}\n",
                    metrics.buckets[index].load(Ordering::Relaxed)
                ));
            }
            let count = metrics.total.load(Ordering::Relaxed);
            output.push_str(&format!(
                "oath_registry_{name}_duration_seconds_bucket{{le=\"+Inf\"}} {count}\noath_registry_{name}_duration_seconds_sum {}\noath_registry_{name}_duration_seconds_count {count}\n",
                metrics.duration_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
            ));
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_are_machine_readable() {
        let metrics = RegistryMetrics::default();
        metrics.request();
        metrics.stage();
        metrics.observe(RegistryOperation::Metadata, Duration::from_millis(80), true);
        metrics.observe(
            RegistryOperation::Metadata,
            Duration::from_millis(300),
            false,
        );
        assert_eq!(metrics.snapshot()["requests"], 1);
        assert_eq!(metrics.snapshot()["operations"]["metadata"]["total"], 2);
        assert_eq!(metrics.snapshot()["operations"]["metadata"]["errors"], 1);
        assert!(
            metrics
                .prometheus()
                .contains("oath_registry_stages_total 1")
        );
        let prometheus = metrics.prometheus();
        assert!(
            prometheus.contains("oath_registry_metadata_duration_seconds_bucket{le=\"0.1\"} 1")
        );
        assert!(
            prometheus.contains("oath_registry_metadata_duration_seconds_bucket{le=\"+Inf\"} 2")
        );
        assert!(prometheus.contains("oath_registry_metadata_duration_seconds_count 2"));
        assert!(prometheus.contains("oath_registry_metadata_errors_total 1"));
    }

    #[test]
    fn exposes_all_slo_operation_families() {
        let output = RegistryMetrics::default().prometheus();
        for operation in RegistryOperation::ALL {
            assert!(output.contains(&format!(
                "oath_registry_{}_duration_seconds_bucket",
                operation.name()
            )));
            assert!(output.contains(&format!(
                "oath_registry_{}_operations_total",
                operation.name()
            )));
        }
    }
}
