use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use super::poseidon::PoseidonConfig;

pub const MAX_PROJ_DIM: usize = 128;

/// Circuit that proves: Poseidon(v_obf || nonce) == commitment
///
/// Public:  commitment (Fr), v_obf[0..MAX_PROJ_DIM] (Fr)
/// Private: nonce (Fr)
///
/// Making `v_obf` public inputs binds the proof to the exact projected
/// vector the contract stores: a prover cannot submit a proof for one
/// vector while supplying a different `v_obf` — verification against the
/// submitted vector fails.
pub struct HusCircuit {
    /// Projected biometric vector (public input — revealed to the chain)
    pub v_obf: Vec<Fr>,
    /// Random nonce (witness)
    pub nonce: Fr,
    /// Poseidon commitment (public input)
    pub commitment: Fr,
}

impl ConstraintSynthesizer<Fr> for HusCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public input 0: commitment ──────────────────────────
        let commitment_var = cs.new_input_variable(|| Ok(self.commitment))?;

        // ── Public inputs 1..=N: v_obf elements ─────────────────
        let mut preimage_vars = Vec::with_capacity(self.v_obf.len() + 1);
        let mut preimage_vals = Vec::with_capacity(self.v_obf.len() + 1);
        for v in &self.v_obf {
            let var = cs.new_input_variable(|| Ok(*v))?;
            preimage_vars.push(var);
            preimage_vals.push(*v);
        }

        // ── Witness: nonce ──────────────────────────────────────
        let nonce_var = cs.new_witness_variable(|| Ok(self.nonce))?;
        preimage_vars.push(nonce_var);
        preimage_vals.push(self.nonce);

        // ── Poseidon hash ────────────────────────────────────────
        let config = PoseidonConfig::new();
        let hash_var = config.hash_r1cs(cs.clone(), &preimage_vars, &preimage_vals)?;

        // ── Constrain hash == commitment ─────────────────────────
        cs.enforce_constraint(
            LinearCombination::from(hash_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(commitment_var),
        )?;

        Ok(())
    }
}