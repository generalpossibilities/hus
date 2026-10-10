//! On-chain Groth16 (BN254) verification of a HUS proof in an AVM contract,
//! using substrate-bn on raw big-endian coordinates (see rawverify.rs).
#![forbid(unsafe_code)]

mod rawverify;
use avm_contract_sdk::{Contract, MessageInput, MessageOutput, StateUpdate};

const VK_RAW: &[u8] = include_bytes!("vk_raw.bin");
const STATE_BYTES: usize = 16;

/// The ABI `bytes` argument arrives as a u32 LE length followed by the data.
fn abi_bytes(body: &[u8]) -> Option<&[u8]> {
    let n = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
    (body.len() == 4 + n).then(|| &body[4..])
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
        if !abi_bytes(input.message.body()).is_some_and(|a| rawverify::verify_raw(VK_RAW, a)) {
            return MessageOutput::failure(2000);
        }
        let mut next = vec![0; STATE_BYTES];
        next[..8].copy_from_slice(&count.saturating_add(1).to_le_bytes());
        next[8] = 1;
        MessageOutput::success(StateUpdate::FullReplace(next))
    }
}

avm_contract_sdk::export_message_contract!(HusGroth16, arena_bytes = 262_144);
