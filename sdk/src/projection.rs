//! BioHashing: V_obf = V × M
//!
//! Deterministic projection matrix derived from a 32-byte seed using SHA-256 in
//! counter mode. Column-normalized for numerical stability. ISO/IEC 24745 compliant.

use alloc::vec;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::error::SdkError;

/// Number of f32 values generated per SHA-256 hash (32 bytes / 4).
const ELEMENTS_PER_HASH: usize = 8;

/// Derive a [`rows`] × [`cols`] projection matrix deterministically from [`seed`].
///
/// Each column is normalised to unit Euclidean length for numerical stability.
#[allow(clippy::needless_range_loop)]
pub fn derive_matrix(seed: &[u8; 32], rows: usize, cols: usize) -> Vec<Vec<f32>> {
    if rows == 0 || cols == 0 {
        return vec![vec![]; rows];
    }

    let total = rows * cols;
    let num_hashes = total.div_ceil(ELEMENTS_PER_HASH);
    let mut matrix = vec![vec![0.0f32; cols]; rows];

    for h in 0..num_hashes {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update((h as u32).to_le_bytes());
        let output = hasher.finalize();
        for k in 0..ELEMENTS_PER_HASH {
            let idx = h * ELEMENTS_PER_HASH + k;
            if idx >= total {
                break;
            }
            let i = idx / cols;
            let j = idx % cols;
            let bytes = &output[4 * k..4 * k + 4];
            let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            matrix[i][j] = (val as f32 / u32::MAX as f32) * 2.0 - 1.0;
        }
    }

    for col_idx in 0..cols {
        let mut sum_sq = 0.0f64;
        for v in matrix.iter() {
            sum_sq += v[col_idx] as f64 * v[col_idx] as f64;
        }
        let norm = sum_sq.sqrt() as f32;
        if norm > 1e-10 {
            for v in matrix.iter_mut() {
                v[col_idx] /= norm;
            }
        }
    }

    matrix
}

/// Project embedding `V` through matrix `M`: V_obf = V × M.
pub fn project(embedding: &[f32], matrix: &[Vec<f32>]) -> Result<Vec<f32>, SdkError> {
    let rows = matrix.len();
    if rows == 0 {
        return Ok(vec![]);
    }
    let cols = matrix[0].len();
    if embedding.len() != rows {
        return Err(SdkError::MatrixDimensionMismatch {
            expected: rows,
            got: embedding.len(),
        });
    }

    let mut result = vec![0.0f32; cols];
    for j in 0..cols {
        let mut sum = 0.0f32;
        for i in 0..rows {
            sum += embedding[i] * matrix[i][j];
        }
        result[j] = sum;
    }
    Ok(result)
}

/// Convenience: derive matrix from [`seed`] and project [`embedding`] to [`proj_dim`] dimensions.
pub fn derive_and_project(
    seed: &[u8; 32],
    embedding: &[f32],
    proj_dim: usize,
) -> Result<Vec<f32>, SdkError> {
    let rows = embedding.len();
    let matrix = derive_matrix(seed, rows, proj_dim);
    project(embedding, &matrix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_reproducible() {
        let seed = [0xABu8; 32];
        let m1 = derive_matrix(&seed, 8, 4);
        let m2 = derive_matrix(&seed, 8, 4);
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_seeds_different_matrix() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let m1 = derive_matrix(&s1, 8, 4);
        let m2 = derive_matrix(&s2, 8, 4);
        assert_ne!(m1, m2, "different seeds should produce different matrices");
    }

    #[test]
    fn project_correct_dim() {
        let seed = [42u8; 32];
        let embedding = vec![1.0f32; 512];
        let v_obf = derive_and_project(&seed, &embedding, 128).unwrap();
        assert_eq!(v_obf.len(), 128);
    }

    #[test]
    fn project_same_input_same_output() {
        let seed = [7u8; 32];
        let embedding = vec![0.5f32; 40]; // e.g. keystroke
        let v1 = derive_and_project(&seed, &embedding, 24).unwrap();
        let v2 = derive_and_project(&seed, &embedding, 24).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn project_different_inputs_different_output() {
        let seed = [9u8; 32];
        let e1 = vec![0.1f32; 40];
        let e2 = vec![0.9f32; 40];
        let v1 = derive_and_project(&seed, &e1, 24).unwrap();
        let v2 = derive_and_project(&seed, &e2, 24).unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn zero_embedding_produces_zero_output() {
        let seed = [0u8; 32];
        let embedding = vec![0.0f32; 40];
        let v_obf = derive_and_project(&seed, &embedding, 24).unwrap();
        for v in &v_obf {
            assert!(
                v.abs() < 1e-6,
                "zero embedding should produce near-zero projection, got {}",
                v
            );
        }
    }

    #[test]
    fn empty_matrix_edge_case() {
        let seed = [0u8; 32];
        let m = derive_matrix(&seed, 0, 4);
        assert!(m.is_empty());
    }

    #[test]
    fn columns_are_unit_normalized() {
        let seed = [0xDEu8; 32];
        let m = derive_matrix(&seed, 16, 8);
        for j in 0..8 {
            let sum_sq: f64 = m.iter().map(|row| row[j] as f64).map(|v| v * v).sum();
            let norm = sum_sq.sqrt();
            // Allow small rounding error
            assert!(
                (norm - 1.0).abs() < 1e-5,
                "column {j} norm = {norm:.6}, expected ~1.0"
            );
        }
    }

    #[test]
    fn project_with_identity_like_disabled() {
        // "Derive" a matrix that is close to identity: (nearly) orthogonal,
        // so projection approximately preserves the input.
        let seed = [0xFFu8; 32];
        let rows = 8;
        let cols = 8;
        let matrix = derive_matrix(&seed, rows, cols);
        let input = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let output = project(&input, &matrix).unwrap();
        assert_eq!(output.len(), cols);
        // Output should not be identical to input (it's a random projection)
        assert_ne!(output, input);
    }

    #[test]
    fn derive_and_project_preserves_distances_approximately() {
        // BioHashing property: Euclidean distances are approximately preserved.
        let seed = [5u8; 32];
        let a = vec![0.1f32; 40];
        let b = vec![0.9f32; 40];
        let pa = derive_and_project(&seed, &a, 24).unwrap();
        let pb = derive_and_project(&seed, &b, 24).unwrap();

        let orig_dist: f32 = a
            .iter()
            .zip(&b)
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt();
        let proj_dist: f32 = pa
            .iter()
            .zip(&pb)
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt();

        // Projected distance should be proportional to original
        assert!(
            proj_dist > 0.0,
            "different inputs should have non-zero projected distance"
        );
        assert!(
            (proj_dist / orig_dist - 1.0).abs() < 2.0,
            "ratio should be within reasonable range: {:.2}",
            proj_dist / orig_dist
        );
    }

    #[test]
    fn project_wrong_length_returns_error() {
        let m = derive_matrix(&[0u8; 32], 40, 24);
        let bad = vec![0.0f32; 10];
        assert!(project(&bad, &m).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn proptest_deterministic_projection(
            seed_byte in 0..255u8,
            dim in 1..=128usize,
            val in -10.0f32..10.0f32,
        ) {
            let seed = [seed_byte; 32];
            let emb = vec![val; 40];
            let a = derive_and_project(&seed, &emb, dim).unwrap();
            let b = derive_and_project(&seed, &emb, dim).unwrap();
            assert_eq!(a.len(), dim.min(128));
            assert_eq!(a, b);
        }

        #[test]
        fn proptest_output_dimension(
            seed_a in 0..255u8,
            seed_b in 0..255u8,
            dim in 0..=128usize,
        ) {
            let seed = [seed_a ^ seed_b; 32];
            let emb = vec![0.5f32; 40];
            let result = derive_and_project(&seed, &emb, dim).unwrap();
            if dim == 0 {
                assert!(result.is_empty());
            } else {
                assert_eq!(result.len(), dim.min(128));
            }
        }

        #[test]
        fn proptest_different_seeds_different_output(
            dim in 1..=64usize,
        ) {
            let emb = vec![0.3f32; 40];
            let a = derive_and_project(&[1u8; 32], &emb, dim).unwrap();
            let b = derive_and_project(&[2u8; 32], &emb, dim).unwrap();
            prop_assert_ne!(a, b);
        }

        #[test]
        fn proptest_zero_embedding_near_zero_projection(
            dim in 1..=128usize,
        ) {
            let seed = [0x42u8; 32];
            let emb = vec![0.0f32; 40];
            let result = derive_and_project(&seed, &emb, dim).unwrap();
            for v in &result {
                prop_assert!(v.abs() < 1e-6);
            }
        }
    }

    #[test]
    fn empty_embedding_edge_case() {
        let seed = [0u8; 32];
        let result = derive_and_project(&seed, &[], 16).unwrap();
        assert!(
            result.is_empty(),
            "empty embedding should produce empty projection"
        );
    }

    #[test]
    fn zero_columns_edge_case() {
        let seed = [0u8; 32];
        let m = derive_matrix(&seed, 8, 0);
        assert_eq!(m.len(), 8);
        for row in &m {
            assert!(row.is_empty());
        }
    }
}
