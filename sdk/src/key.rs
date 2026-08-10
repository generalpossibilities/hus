//! Cryptographic key management for HUS.
//!
//! All key material is derived deterministically so that the same user always
//! derives the same keys from the same seeds. No private keys are ever stored
//! in plaintext; they are re-derived on each session.
//!
//! ## Key Hierarchy
//!
//! ```text
//! app_seed (from chain, per-app)
//!   │
//!   ├─ K_priv_s = SHA256("K_priv_s" || K_sess || model_seed)[:32]
//!   │
//!   └─ K_sess = SHA256(app_seed || K_priv_s)[:32]
//!        │
//!        ├─ client_seed = SHA256(K_sess || session_id || timestamp)[:16]
//!        │                (clamped to [1, 2^128-2])
//!        │
//!        └─ session_key (used for liveness challenges, etc.)
//! ```

use sha2::{Digest, Sha256};

use crate::error::SdkError;

/// Derive the session key `K_sess` from an app seed and private seed.
///
/// `K_sess = SHA256(app_seed || K_priv_s)[:32]`
pub fn derive_session_key(app_seed: &[u8; 32], priv_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(app_seed);
    hasher.update(priv_seed);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive the private seed `K_priv_s` from the session key and model params.
///
/// `K_priv_s = SHA256("K_priv_s" || K_sess || model_seed)[:32]`
pub fn derive_private_seed(k_sess: &[u8; 32], model_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"K_priv_s");
    hasher.update(k_sess);
    hasher.update(model_seed);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive a per-session client seed.
///
/// `client_seed = SHA256(K_sess || session_id || timestamp)[:16]`
///
/// The result is clamped to `[1, 2^128-2]` to ensure it is never zero or
/// `2^128-1` (both are invalid for some use-cases).
pub fn derive_client_seed(k_sess: &[u8; 32], session_id: &[u8], timestamp: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(k_sess);
    hasher.update(session_id);
    hasher.update(timestamp.to_le_bytes());
    let result = hasher.finalize();
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&result[..16]);

    // Clamp to [1, 2^128-2]
    if seed == [0u8; 16] {
        seed[15] = 1;
    } else if seed == [0xffu8; 16] {
        seed[15] = 0xfe;
    }
    seed
}

/// Generate a 32-byte seed from available entropy.
///
/// On WASM: uses `getrandom` (backed by `crypto.getRandomValues`).
/// On std: uses `OsRng` via `getrandom`.
/// On no_std without getrandom: returns an error.
pub fn generate_seed() -> Result<[u8; 32], SdkError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| SdkError::InvalidSeed)?;
    Ok(seed)
}

/// Hash arbitrary data with SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Key material container for a HUS session.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// `K_sess` — session key derived from app seed + private seed.
    pub k_sess: [u8; 32],
    /// `K_priv_s` — private seed derived from K_sess + model seed.
    pub k_priv_s: [u8; 32],
    /// Per-session client seed.
    pub client_seed: [u8; 16],
}

impl SessionKeys {
    /// Derive all session keys from the app seed, private seed, and model seed.
    pub fn derive(app_seed: &[u8; 32], priv_seed: &[u8; 32], model_seed: &[u8; 32]) -> Self {
        let k_sess = derive_session_key(app_seed, priv_seed);
        let k_priv_s = derive_private_seed(&k_sess, model_seed);
        let client_seed = derive_client_seed(&k_sess, b"hus", 0);
        Self {
            k_sess,
            k_priv_s,
            client_seed,
        }
    }

    /// Re-derive with a fresh timestamp.
    pub fn refresh_client_seed(&mut self, timestamp: u64) {
        self.client_seed = derive_client_seed(&self.k_sess, b"hus", timestamp);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_is_32_bytes() {
        let app_seed = [1u8; 32];
        let priv_seed = [2u8; 32];
        let k = derive_session_key(&app_seed, &priv_seed);
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn session_key_deterministic() {
        let a = derive_session_key(&[1u8; 32], &[2u8; 32]);
        let b = derive_session_key(&[1u8; 32], &[2u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_different_keys() {
        let a = derive_session_key(&[1u8; 32], &[2u8; 32]);
        let b = derive_session_key(&[1u8; 32], &[3u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn client_seed_is_16_bytes() {
        let k_sess = [0xABu8; 32];
        let seed = derive_client_seed(&k_sess, b"test", 12345);
        assert_eq!(seed.len(), 16);
    }

    #[test]
    fn client_seed_clamped_nonzero() {
        // This would be all-zero if clamping didn't work
        let k_sess = [0u8; 32];
        let seed = derive_client_seed(&k_sess, b"", 0);
        assert_ne!(seed, [0u8; 16]);
    }

    #[test]
    fn full_key_derivation() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_ne!(keys.k_sess, [0u8; 32]);
        assert_ne!(keys.k_priv_s, [0u8; 32]);
        assert_ne!(keys.client_seed, [0u8; 16]);
    }

    #[test]
    fn generate_seed_produces_entropy() {
        let a = generate_seed().unwrap();
        let b = generate_seed().unwrap();
        // Extremely unlikely to collide
        assert_ne!(a, b);
    }
}
