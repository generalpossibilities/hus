//! On-chain Groth16 (BN254) verification of a HUS proof inside an AVM contract.
//! The verifier logic is a direct port of hus/verifier/src/verify.rs.
#![forbid(unsafe_code)]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use avm_contract_sdk::{Contract, MessageInput, MessageOutput, StateUpdate};

const VK_BYTES: &[u8] = include_bytes!("vk.bin");
const MAX_PROJ_DIM: usize = 128;
const V_OBF_BYTES: usize = MAX_PROJ_DIM * 8;
const STATE_BYTES: usize = 16;

// Args: [plen u32 LE][proof][commitment 32B][v_obf 128 × i64 LE][binding 32B].
// Public inputs: commitment ++ v_obf ++ binding (hus_sdk::proof_binding of the
// owner key and the verifier's challenge). A caller that registers accounts
// must compute the binding itself, not take it from the prover.
fn verify(args: &[u8]) -> bool {
    if args.len() < 4 + 32 + V_OBF_BYTES + 32 {
        return false;
    }
    let plen = u32::from_le_bytes([args[0], args[1], args[2], args[3]]) as usize;
    if args.len() != 4 + plen + 32 + V_OBF_BYTES + 32 {
        return false;
    }
    let Ok(vk) = VerifyingKey::<Bn254>::deserialize_uncompressed(VK_BYTES) else { return false };
    let pvk = prepare_verifying_key(&vk);
    let Ok(proof) = Proof::<Bn254>::deserialize_compressed(&args[4..4 + plen]) else { return false };
    let Ok(comm) = Fr::deserialize_uncompressed(&args[4 + plen..4 + plen + 32]) else { return false };
    let start = 4 + plen + 32;
    let Ok(binding) = Fr::deserialize_uncompressed(&args[start + V_OBF_BYTES..]) else { return false };
    let inputs: Vec<Fr> = core::iter::once(comm)
        .chain(args[start..start + V_OBF_BYTES].chunks_exact(8).map(|c| {
            Fr::from(i64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
        }))
        .chain(core::iter::once(binding))
        .collect();
    inputs.len() == 1 + MAX_PROJ_DIM + 1 && matches!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs), Ok(true))
}

struct HusGroth16;

impl Contract for HusGroth16 {
    fn init(_input: MessageInput<'_>) -> MessageOutput {
        MessageOutput::success(StateUpdate::FullReplace(vec![0; STATE_BYTES]))
    }

    fn process_message(input: MessageInput<'_>) -> MessageOutput {
        let Some(count) = input
            .state
            .get(..8)
            .filter(|_| input.state.len() == STATE_BYTES)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            return MessageOutput::failure(2001);
        };
        if !verify(input.message.body()) {
            return MessageOutput::failure(2000);
        }
        let mut next = vec![0; STATE_BYTES];
        next[..8].copy_from_slice(&count.saturating_add(1).to_le_bytes());
        next[8] = 1;
        MessageOutput::success(StateUpdate::FullReplace(next))
    }
}

avm_contract_sdk::export_message_contract!(HusGroth16, arena_bytes = 262_144);
