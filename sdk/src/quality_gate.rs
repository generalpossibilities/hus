//! Quality gate — checks how many modalities passed quality/extraction.
//!
//! HUS does NOT authenticate users or compare probe vs enrolled embeddings.
//! It only reports: did enough modalities produce valid captures?

use crate::config::{Modality, ModalityConfig};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Per-modality result
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
pub struct ModalityResult {
    pub modality: Modality,
    /// Whether this modality produced a valid capture + extraction.
    pub passed: bool,
}

// ---------------------------------------------------------------------------
// Overall quality gate result
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct QualityReport {
    pub per_modality: Vec<ModalityResult>,
    pub passed_count: usize,
    pub required_count: usize,
    /// True when enough modalities passed (passed_count >= required_count).
    pub all_passed: bool,
}

// ---------------------------------------------------------------------------
// Quality gate
// ---------------------------------------------------------------------------
pub struct QualityGate {
    pub configs: Vec<ModalityConfig>,
    pub required_pass: usize,
}

impl QualityGate {
    pub fn new(configs: Vec<ModalityConfig>) -> Self {
        let required_pass = if configs.len() <= 3 {
            configs.len()
        } else {
            (configs.len() * 3).div_ceil(4)
        };
        Self {
            configs,
            required_pass,
        }
    }

    /// Assess whether enough modalities passed quality checks.
    pub fn assess(&self, passed_flags: &[bool]) -> QualityReport {
        let mut passed_count = 0usize;
        let mut results = Vec::with_capacity(self.configs.len());

        for (i, cfg) in self.configs.iter().enumerate() {
            let ok = passed_flags.get(i).copied().unwrap_or(false);
            if ok {
                passed_count += 1;
            }
            results.push(ModalityResult {
                modality: cfg.modality,
                passed: ok,
            });
        }

        let all_passed = passed_count >= self.required_pass;
        QualityReport {
            per_modality: results,
            passed_count,
            required_count: self.required_pass,
            all_passed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ModalityConfig;

    #[test]
    fn two_modalities_both_pass() {
        let cfgs = vec![
            ModalityConfig::for_modality(Modality::Face),
            ModalityConfig::for_modality(Modality::Iris),
        ];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[true, true]);
        assert!(r.all_passed);
        assert_eq!(r.passed_count, 2);
    }

    #[test]
    fn two_modalities_one_fails() {
        let cfgs = vec![
            ModalityConfig::for_modality(Modality::Face),
            ModalityConfig::for_modality(Modality::Iris),
        ];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[true, false]);
        assert!(!r.all_passed);
        assert_eq!(r.passed_count, 1);
    }

    #[test]
    fn four_modalities_three_pass() {
        let cfgs = vec![
            ModalityConfig::for_modality(Modality::Face),
            ModalityConfig::for_modality(Modality::Iris),
            ModalityConfig::for_modality(Modality::Voice),
            ModalityConfig::for_modality(Modality::Keystroke),
        ];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[true, true, false, true]);
        assert!(r.all_passed);
        assert_eq!(r.passed_count, 3);
    }

    #[test]
    fn shorter_flags_handled_gracefully() {
        let cfgs = vec![
            ModalityConfig::for_modality(Modality::Face),
            ModalityConfig::for_modality(Modality::Iris),
        ];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[true]);
        assert!(!r.all_passed);
        assert_eq!(r.passed_count, 1);
    }

    #[test]
    fn all_fail_returns_not_passed() {
        let cfgs = vec![
            ModalityConfig::for_modality(Modality::Face),
            ModalityConfig::for_modality(Modality::Iris),
            ModalityConfig::for_modality(Modality::Voice),
        ];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[false, false, false]);
        assert!(!r.all_passed);
        assert_eq!(r.passed_count, 0);
    }

    #[test]
    fn empty_configs_all_passed_is_true() {
        let gate = QualityGate::new(vec![]);
        let r = gate.assess(&[]);
        assert!(r.all_passed);
        assert_eq!(r.passed_count, 0);
        assert_eq!(r.required_count, 0);
    }

    #[test]
    fn single_modality_requires_one() {
        let cfgs = vec![ModalityConfig::for_modality(Modality::Keystroke)];
        let gate = QualityGate::new(cfgs);
        assert_eq!(gate.required_pass, 1);
        let r = gate.assess(&[true]);
        assert!(r.all_passed);
        let r = gate.assess(&[false]);
        assert!(!r.all_passed);
    }

    #[test]
    fn flags_longer_than_configs_ignores_extra() {
        let cfgs = vec![ModalityConfig::for_modality(Modality::Face)];
        let gate = QualityGate::new(cfgs);
        let r = gate.assess(&[true, false, true]);
        assert!(r.all_passed, "extra flags beyond configs should be ignored");
        assert_eq!(r.passed_count, 1);
    }
}
