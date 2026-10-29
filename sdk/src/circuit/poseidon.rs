use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

// Standard Poseidon over BN254's scalar field: width 3 (rate 2, capacity 1),
// x^5 S-box, 8 full and 57 partial rounds, the parameters recommended in the
// Poseidon paper for 128-bit security at this width. Round constants and the
// MDS matrix come from the paper's Grain LFSR (arkworks'
// `find_poseidon_ark_and_mds`), not from anything made up here.
//
// The sponge matches arkworks' `PoseidonSponge` exactly: capacity element at
// index 0, inputs added to indices 1..=2, one permutation per (possibly
// partial) chunk of two, output = state[1]. A test checks this against
// arkworks' own implementation.
const T: usize = 3;
const RATE: usize = 2;
const CAPACITY: usize = T - RATE;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
pub(crate) const ALPHA: u64 = 5;

pub struct PoseidonConfig {
    ark: Vec<[Fr; T]>,
    mds: [[Fr; T]; T],
}

impl PoseidonConfig {
    pub fn new() -> Self {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        let ark = ark.iter().map(|r| [r[0], r[1], r[2]]).collect();
        let mds = [
            [mds[0][0], mds[0][1], mds[0][2]],
            [mds[1][0], mds[1][1], mds[1][2]],
            [mds[2][0], mds[2][1], mds[2][2]],
        ];
        Self { ark, mds }
    }

    /// The arkworks sponge parameters these constants form; used by tests to
    /// check this implementation against arkworks' own.
    #[cfg(test)]
    pub(crate) fn arkworks_config(&self) -> ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr> {
        ark_crypto_primitives::sponge::poseidon::PoseidonConfig::new(
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            ALPHA,
            self.mds.iter().map(|r| r.to_vec()).collect(),
            self.ark.iter().map(|r| r.to_vec()).collect(),
            RATE,
            CAPACITY,
        )
    }

    fn is_full(r: usize) -> bool {
        r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS
    }

    /// Native Poseidon hash (non-circuit)
    pub fn hash_native(&self, inputs: &[Fr]) -> Fr {
        let mut state = [Fr::ZERO; T];
        for chunk in inputs.chunks(RATE) {
            for (i, x) in chunk.iter().enumerate() {
                state[CAPACITY + i] += x;
            }
            self.permute(&mut state);
        }
        if inputs.is_empty() {
            self.permute(&mut state);
        }
        state[CAPACITY]
    }

    fn permute(&self, state: &mut [Fr; T]) {
        for r in 0..TOTAL_ROUNDS {
            for i in 0..T {
                state[i] += self.ark[r][i];
            }
            for i in 0..T {
                if Self::is_full(r) || i == 0 {
                    state[i] = state[i].pow([ALPHA]);
                }
            }
            let old = *state;
            for i in 0..T {
                state[i] = (0..T).map(|j| old[j] * self.mds[i][j]).sum();
            }
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
        assert_eq!(inputs.len(), input_values.len());
        // The all-zero initial state is the constant 0: no variable needed.
        let mut state_vars = [Variable::Zero; T];
        let mut state_vals = [Fr::ZERO; T];

        let absorb = |state_vars: &mut [Variable; T], state_vals: &mut [Fr; T], i: usize, var: Variable, val: Fr| -> Result<(), SynthesisError> {
            if state_vars[i].is_zero() {
                state_vars[i] = var;
            } else {
                state_vars[i] = sum_var_var_with_val(cs.clone(), state_vars[i], var, state_vals[i], val)?;
            }
            state_vals[i] += val;
            Ok(())
        };

        for (chunk_vars, chunk_vals) in inputs.chunks(RATE).zip(input_values.chunks(RATE)) {
            for (i, (&var, &val)) in chunk_vars.iter().zip(chunk_vals).enumerate() {
                absorb(&mut state_vars, &mut state_vals, CAPACITY + i, var, val)?;
            }
            let (v, x) = self.permute_r1cs(cs.clone(), &state_vars, &state_vals)?;
            state_vars = v;
            state_vals = x;
        }
        if inputs.is_empty() {
            let (v, x) = self.permute_r1cs(cs.clone(), &state_vars, &state_vals)?;
            state_vars = v;
            state_vals = x;
        }
        Ok(state_vars[CAPACITY])
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
            // Add round constants, then the S-box.
            let mut after_sbox_vars = [Variable::Zero; T];
            let mut after_sbox_vals = [Fr::ZERO; T];
            for i in 0..T {
                let val = s_vals[i] + self.ark[r][i];
                let var = sum_scalar_with_val(cs.clone(), s_vars[i], self.ark[r][i], val)?;
                if Self::is_full(r) || i == 0 {
                    let (v, x) = sbox_pow5_with_val(cs.clone(), var, val)?;
                    after_sbox_vars[i] = v;
                    after_sbox_vals[i] = x;
                } else {
                    after_sbox_vars[i] = var;
                    after_sbox_vals[i] = val;
                }
            }
            // MDS mix.
            for i in 0..T {
                let val: Fr = (0..T).map(|j| after_sbox_vals[j] * self.mds[i][j]).sum();
                let terms: Vec<(Variable, Fr)> =
                    (0..T).map(|j| (after_sbox_vars[j], self.mds[i][j])).collect();
                s_vars[i] = linear_comb_with_val(cs.clone(), &terms, val)?;
                s_vals[i] = val;
            }
        }
        Ok((s_vars, s_vals))
    }
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Σ coeff·var, leaving out `Variable::Zero` (the constant 0). arkworks
/// accepts it when checking constraints but panics ("no symbolic LCs") when
/// building the proving matrices, and the sponge starts from an all-zero
/// state.
fn lc_of(terms: &[(Variable, Fr)]) -> LinearCombination<Fr> {
    let mut lc = LinearCombination::zero();
    for &(var, coeff) in terms {
        if !var.is_zero() {
            lc = lc + (coeff, var);
        }
    }
    lc
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
    cs.enforce_constraint(
        lc_of(terms),
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
        lc_of(&[(var, Fr::ONE)]) + (scalar, Variable::One),
        LinearCombination::from(Variable::One),
        LinearCombination::from(out),
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_relations::r1cs::ConstraintSystem;

    fn arkworks_hash(config: &PoseidonConfig, inputs: &[Fr]) -> Fr {
        let mut sponge = PoseidonSponge::<Fr>::new(&config.arkworks_config());
        sponge.absorb(&inputs.to_vec());
        sponge.squeeze_field_elements::<Fr>(1)[0]
    }

    #[test]
    fn native_hash_deterministic() {
        let config = PoseidonConfig::new();
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        assert_eq!(config.hash_native(&inputs), config.hash_native(&inputs));
    }

    #[test]
    fn native_hash_different_inputs() {
        let config = PoseidonConfig::new();
        assert_ne!(config.hash_native(&[Fr::from(1u64)]), config.hash_native(&[Fr::from(2u64)]));
    }

    /// The standard construction, checked against an independent
    /// implementation: arkworks' PoseidonSponge with the same parameters.
    #[test]
    fn native_matches_arkworks_sponge() {
        let config = PoseidonConfig::new();
        for n in [1usize, 2, 3, 4, 129, 130] {
            let inputs: Vec<Fr> = (0..n as u64).map(|i| Fr::from(i * 7 + 3)).collect();
            assert_eq!(config.hash_native(&inputs), arkworks_hash(&config, &inputs), "n = {n}");
        }
    }

    /// Building the proving matrices must work too: `is_satisfied` alone
    /// doesn't catch a constraint that refers to the constant zero.
    #[test]
    fn r1cs_matrices_build() {
        let config = PoseidonConfig::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vals = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let vars: Vec<Variable> =
            vals.iter().map(|v| cs.new_witness_variable(|| Ok(*v)).unwrap()).collect();
        config.hash_r1cs(cs.clone(), &vars, &vals).unwrap();
        cs.finalize();
        assert!(cs.to_matrices().is_some());
    }

    /// The circuit computes the same hash, and the constraints hold.
    #[test]
    fn r1cs_matches_native() {
        let config = PoseidonConfig::new();
        for n in [1usize, 2, 5] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let vals: Vec<Fr> = (0..n as u64).map(|i| Fr::from(i + 11)).collect();
            let vars: Vec<Variable> =
                vals.iter().map(|v| cs.new_witness_variable(|| Ok(*v)).unwrap()).collect();
            let out = config.hash_r1cs(cs.clone(), &vars, &vals).unwrap();
            assert!(cs.is_satisfied().unwrap(), "n = {n}");
            let got = cs.borrow().unwrap().assigned_value(out).unwrap();
            assert_eq!(got, config.hash_native(&vals), "n = {n}");
        }
    }
}
