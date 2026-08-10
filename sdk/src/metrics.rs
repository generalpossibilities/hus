use core::sync::atomic::{AtomicU64, Ordering};

/// Global metrics counters for HUS operations.
///
/// All counters use relaxed ordering (observability, not synchronization).
pub struct HusMetrics {
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub proofs_failed: AtomicU64,
    pub captures_attempted: AtomicU64,
    pub captures_failed: AtomicU64,
    pub quality_failed: AtomicU64,
    pub quality_passed: AtomicU64,
    pub last_proof_time_us: AtomicU64,
    pub last_verify_time_us: AtomicU64,
}

impl Default for HusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl HusMetrics {
    pub const fn new() -> Self {
        Self {
            proofs_generated: AtomicU64::new(0),
            proofs_verified: AtomicU64::new(0),
            proofs_failed: AtomicU64::new(0),
            captures_attempted: AtomicU64::new(0),
            captures_failed: AtomicU64::new(0),
            quality_failed: AtomicU64::new(0),
            quality_passed: AtomicU64::new(0),
            last_proof_time_us: AtomicU64::new(0),
            last_verify_time_us: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            proofs_generated: self.proofs_generated.load(Ordering::Relaxed),
            proofs_verified: self.proofs_verified.load(Ordering::Relaxed),
            proofs_failed: self.proofs_failed.load(Ordering::Relaxed),
            captures_attempted: self.captures_attempted.load(Ordering::Relaxed),
            captures_failed: self.captures_failed.load(Ordering::Relaxed),
            quality_failed: self.quality_failed.load(Ordering::Relaxed),
            quality_passed: self.quality_passed.load(Ordering::Relaxed),
            last_proof_time_us: self.last_proof_time_us.load(Ordering::Relaxed),
            last_verify_time_us: self.last_verify_time_us.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub proofs_generated: u64,
    pub proofs_verified: u64,
    pub proofs_failed: u64,
    pub captures_attempted: u64,
    pub captures_failed: u64,
    pub quality_failed: u64,
    pub quality_passed: u64,
    pub last_proof_time_us: u64,
    pub last_verify_time_us: u64,
}

/// Global singleton metrics instance.
///
/// Access via `HUS_METRICS.snapshot()`, `HUS_METRICS.proofs_generated.fetch_add(1, Ordering::Relaxed)`, etc.
pub static HUS_METRICS: HusMetrics = HusMetrics::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_snapshot_all_zeros() {
        let s = HUS_METRICS.snapshot();
        assert_eq!(s.proofs_generated, 0);
        assert_eq!(s.proofs_verified, 0);
        assert_eq!(s.proofs_failed, 0);
    }

    #[test]
    fn atomic_increment_works() {
        HUS_METRICS
            .captures_attempted
            .fetch_add(1, Ordering::Relaxed);
        let s = HUS_METRICS.snapshot();
        assert!(s.captures_attempted >= 1);
    }
}
