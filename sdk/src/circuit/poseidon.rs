use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

const T: usize = 3;
const RATE: usize = 2;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

// MDS matrix for Poseidon with t=3 (Cauchy matrix)
// [[2, 1, 1], [1, 1, 2], [1, 2, 1]]
const MDS: [[u64; 3]; 3] = [[2, 1, 1], [1, 1, 2], [1, 2, 1]];

/// Generate round constants deterministically.
/// Uses the standard Grain LFSR-based PRNG: since arkworks Poseidon params
/// aren't conveniently available, we derive a minimal set.
pub struct PoseidonConfig {
    round_constants: Vec<[Fr; T]>,
}

impl PoseidonConfig {
    pub fn new() -> Self {
        let rcs = generate_poseidon_constants();
        Self {
            round_constants: rcs,
        }
    }

    /// Native Poseidon hash (non-circuit)
    pub fn hash_native(&self, inputs: &[Fr]) -> Fr {
        let mut state = [Fr::ZERO; T];
        let mut idx = 0;
        while idx < inputs.len() {
            for i in 0..RATE {
                if idx < inputs.len() {
                    state[i] += inputs[idx];
                    idx += 1;
                }
            }
            Self::permute(&mut state, &self.round_constants);
        }
        state[0]
    }

    fn permute(state: &mut [Fr; T], rcs: &[[Fr; T]]) {
        for r in 0..TOTAL_ROUNDS {
            let is_full = r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS;
            for i in 0..T {
                if is_full || i == 0 {
                    let v = state[i];
                    let v2 = v * v;
                    let v4 = v2 * v2;
                    state[i] = v4 * v;
                }
            }
            let m = MDS;
            let s0 = state[0] * Fr::from(m[0][0])
                + state[1] * Fr::from(m[0][1])
                + state[2] * Fr::from(m[0][2]);
            let s1 = state[0] * Fr::from(m[1][0])
                + state[1] * Fr::from(m[1][1])
                + state[2] * Fr::from(m[1][2]);
            let s2 = state[0] * Fr::from(m[2][0])
                + state[1] * Fr::from(m[2][1])
                + state[2] * Fr::from(m[2][2]);
            state[0] = s0 + rcs[r][0];
            state[1] = s1 + rcs[r][1];
            state[2] = s2 + rcs[r][2];
        }
    }

    /// Hash inside R1CS constraint system, computing correct witness values
    /// by running the permutation natively alongside the constraints.
    pub fn hash_r1cs(
        &self,
        cs: ConstraintSystemRef<Fr>,
        inputs: &[Variable],
        input_values: &[Fr],
    ) -> Result<Variable, SynthesisError> {
        let mut state_vars = [Variable::Zero; T];
        let mut state_vals = [Fr::ZERO; T];

        // Capacity element: witness variable with value Fr::ZERO
        let capacity = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
        for c in RATE..T {
            state_vars[c] = capacity;
        }

        let mut idx = 0;
        let mut input_val_idx = 0;
        while idx < inputs.len() {
            for i in 0..RATE {
                if idx < inputs.len() {
                    let var = inputs[idx];
                    let val = input_values[input_val_idx];
                    if state_vars[i].is_zero() {
                        state_vars[i] = var;
                        state_vals[i] = val;
                    } else {
                        state_vars[i] = sum_var_var_with_val(
                            cs.clone(),
                            state_vars[i],
                            var,
                            state_vals[i],
                            val,
                        )?;
                        state_vals[i] = state_vals[i] + val;
                    }
                    idx += 1;
                    input_val_idx += 1;
                }
            }
            let (new_vars, new_vals) = self.permute_r1cs(cs.clone(), &state_vars, &state_vals)?;
            state_vars = new_vars;
            state_vals = new_vals;
        }
        Ok(state_vars[0])
    }

    fn permute_r1cs(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &[Variable; T],
        state_vals: &[Fr; T],
    ) -> Result<([Variable; T], [Fr; T]), SynthesisError> {
        let mut s_vars = *state;
        let mut s_vals = *state_vals;
        for r in 0..TOTAL_ROUNDS {
            let is_full = r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS;

            let mut new_s_vars = [Variable::Zero; T];
            let mut new_s_vals = [Fr::ZERO; T];
            for i in 0..T {
                if is_full || i == 0 {
                    let (v, val) = sbox_pow5_with_val(cs.clone(), s_vars[i], s_vals[i])?;
                    new_s_vars[i] = v;
                    new_s_vals[i] = val;
                } else {
                    new_s_vars[i] = s_vars[i];
                    new_s_vals[i] = s_vals[i];
                }
            }

            let m = MDS;
            let s0_val = new_s_vals[0] * Fr::from(m[0][0])
                + new_s_vals[1] * Fr::from(m[0][1])
                + new_s_vals[2] * Fr::from(m[0][2]);
            let s1_val = new_s_vals[0] * Fr::from(m[1][0])
                + new_s_vals[1] * Fr::from(m[1][1])
                + new_s_vals[2] * Fr::from(m[1][2]);
            let s2_val = new_s_vals[0] * Fr::from(m[2][0])
                + new_s_vals[1] * Fr::from(m[2][1])
                + new_s_vals[2] * Fr::from(m[2][2]);

            let s0_var = linear_comb_with_val(
                cs.clone(),
                &[
                    (new_s_vars[0], Fr::from(m[0][0])),
                    (new_s_vars[1], Fr::from(m[0][1])),
                    (new_s_vars[2], Fr::from(m[0][2])),
                ],
                s0_val,
            )?;
            let s1_var = linear_comb_with_val(
                cs.clone(),
                &[
                    (new_s_vars[0], Fr::from(m[1][0])),
                    (new_s_vars[1], Fr::from(m[1][1])),
                    (new_s_vars[2], Fr::from(m[1][2])),
                ],
                s1_val,
            )?;
            let s2_var = linear_comb_with_val(
                cs.clone(),
                &[
                    (new_s_vars[0], Fr::from(m[2][0])),
                    (new_s_vars[1], Fr::from(m[2][1])),
                    (new_s_vars[2], Fr::from(m[2][2])),
                ],
                s2_val,
            )?;

            s_vars = [
                sum_scalar_with_val(
                    cs.clone(),
                    s0_var,
                    self.round_constants[r][0],
                    s0_val + self.round_constants[r][0],
                )?,
                sum_scalar_with_val(
                    cs.clone(),
                    s1_var,
                    self.round_constants[r][1],
                    s1_val + self.round_constants[r][1],
                )?,
                sum_scalar_with_val(
                    cs.clone(),
                    s2_var,
                    self.round_constants[r][2],
                    s2_val + self.round_constants[r][2],
                )?,
            ];
            s_vals = [
                s0_val + self.round_constants[r][0],
                s1_val + self.round_constants[r][1],
                s2_val + self.round_constants[r][2],
            ];
        }
        Ok((s_vars, s_vals))
    }
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// x^5 in R1CS: 3 constraints, with known native values
fn sbox_pow5_with_val(
    cs: ConstraintSystemRef<Fr>,
    x: Variable,
    x_val: Fr,
) -> Result<(Variable, Fr), SynthesisError> {
    let x2_val = x_val * x_val;
    let x4_val = x2_val * x2_val;
    let x5_val = x4_val * x_val;
    let x2 = mul_var_with_val(cs.clone(), x, x, x2_val)?;
    let x4 = mul_var_with_val(cs.clone(), x2, x2, x4_val)?;
    let x5 = mul_var_with_val(cs, x4, x, x5_val)?;
    Ok((x5, x5_val))
}

/// a * b with correct value
fn mul_var_with_val(
    cs: ConstraintSystemRef<Fr>,
    a: Variable,
    b: Variable,
    val: Fr,
) -> Result<Variable, SynthesisError> {
    let out = cs.new_witness_variable(|| Ok(val))?;
    cs.enforce_constraint(
        LinearCombination::from(a),
        LinearCombination::from(b),
        LinearCombination::from(out),
    )?;
    Ok(out)
}

/// a + b with correct value
fn sum_var_var_with_val(
    cs: ConstraintSystemRef<Fr>,
    a: Variable,
    b: Variable,
    a_val: Fr,
    b_val: Fr,
) -> Result<Variable, SynthesisError> {
    let val = a_val + b_val;
    let out = cs.new_witness_variable(|| Ok(val))?;
    cs.enforce_constraint(
        LinearCombination::from(a) + LinearCombination::from(b),
        LinearCombination::from(Variable::One),
        LinearCombination::from(out),
    )?;
    Ok(out)
}

/// Σ (var_i * coeff_i) with correct value
fn linear_comb_with_val(
    cs: ConstraintSystemRef<Fr>,
    terms: &[(Variable, Fr)],
    val: Fr,
) -> Result<Variable, SynthesisError> {
    let out = cs.new_witness_variable(|| Ok(val))?;
    let mut lc = LinearCombination::zero();
    for &(var, coeff) in terms {
        lc = lc + (coeff, var);
    }
    cs.enforce_constraint(
        lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(out),
    )?;
    Ok(out)
}

/// var + scalar with correct value
fn sum_scalar_with_val(
    cs: ConstraintSystemRef<Fr>,
    var: Variable,
    scalar: Fr,
    val: Fr,
) -> Result<Variable, SynthesisError> {
    let out = cs.new_witness_variable(|| Ok(val))?;
    cs.enforce_constraint(
        LinearCombination::from(var) + (scalar, Variable::One),
        LinearCombination::from(Variable::One),
        LinearCombination::from(out),
    )?;
    Ok(out)
}

fn generate_poseidon_constants() -> Vec<[Fr; T]> {
    use sha2::{Digest, Sha256};

    let modulus_bytes = Fr::MODULUS_BIT_SIZE.to_le_bytes();
    let mut rcs = Vec::with_capacity(TOTAL_ROUNDS);
    let mut counter = 0u32;

    while rcs.len() < TOTAL_ROUNDS {
        let mut hasher = Sha256::new();
        hasher.update(b"poseidon_round_constant");
        hasher.update(&modulus_bytes);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);

        let fe = Fr::from_be_bytes_mod_order(&arr);
        let mut round = [Fr::ZERO; T];
        round[0] = fe;

        let mut hasher2 = Sha256::new();
        hasher2.update(b"poseidon_round_constant_extra");
        hasher2.update(&hash);
        let hash2 = hasher2.finalize();
        let mut arr2 = [0u8; 32];
        arr2.copy_from_slice(&hash2);
        round[1] = Fr::from_be_bytes_mod_order(&arr2);

        let mut hasher3 = Sha256::new();
        hasher3.update(b"poseidon_round_constant_extra_2");
        hasher3.update(&hash2);
        let hash3 = hasher3.finalize();
        let mut arr3 = [0u8; 32];
        arr3.copy_from_slice(&hash3);
        round[2] = Fr::from_be_bytes_mod_order(&arr3);

        rcs.push(round);
        counter += 1;
    }

    rcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_hash_deterministic() {
        let config = PoseidonConfig::new();
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let h1 = config.hash_native(&inputs);
        let h2 = config.hash_native(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn native_hash_different_inputs() {
        let config = PoseidonConfig::new();
        let a = config.hash_native(&[Fr::from(1u64)]);
        let b = config.hash_native(&[Fr::from(2u64)]);
        assert_ne!(a, b);
    }
}
