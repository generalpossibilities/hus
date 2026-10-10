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
        // Diagnostic: record what arrived instead of failing.
        let _ = count;
        let body = input.message.body();
        let mut next = vec![0; STATE_BYTES];
        next[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
        for (i, b) in body.iter().take(8).enumerate() { next[4 + i] = *b; }
        next[12] = abi_bytes(body).is_some_and(|a| {
            let (args, stage) = if a.len() == 1313 { (&a[..1312], a[1312]) } else { (a, 4) };
            rawverify::verify_stage(VK_RAW, args, stage)
        }) as u8;
        next[13] = 0xAA;
        MessageOutput::success(StateUpdate::FullReplace(next))
    }
}

avm_contract_sdk::export_message_contract!(HusGroth16, arena_bytes = 262_144);
