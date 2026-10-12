//! BN254 operations with Ethereum's EIP-196/197 encoding in an AVM contract,
//! through `hus-zk`. `bn254.call` takes an op byte (0 add, 1 mul, 2 pairing
//! check) and the operation's input, and stores the result as the state. With the
//! pure-WASM backend, add and small-scalar mul fit a message, a full-width
//! multiplication (~16M FUEL) does not, and the pairing op is only built with
//! the `native` feature (host functions).
#![forbid(unsafe_code)]

use avm_contract_sdk::{Contract, MessageInput, MessageOutput, StateUpdate};

const ADD: u8 = 0;
const MUL: u8 = 1;
#[cfg(feature = "native")]
const PAIRING: u8 = 2;

fn abi_bytes(body: &[u8]) -> Option<&[u8]> {
    let n = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
    (body.len() == 4 + n).then(|| &body[4..])
}

fn abi_wrap(data: &[u8]) -> Vec<u8> {
    let mut b = (data.len() as u32).to_le_bytes().to_vec();
    b.extend_from_slice(data);
    b
}

struct Bn254Ops;

impl Contract for Bn254Ops {
    fn init(_input: MessageInput<'_>) -> MessageOutput {
        MessageOutput::success(StateUpdate::FullReplace(abi_wrap(&[])))
    }

    fn process_message(input: MessageInput<'_>) -> MessageOutput {
        let Some((&op, a)) = abi_bytes(input.message.body()).and_then(|b| b.split_first()) else {
            return MessageOutput::failure(4000);
        };
        let result: Option<Vec<u8>> = match (op, a.len()) {
            (ADD, 128) => hus_zk::g1_add(a[..64].try_into().unwrap(), a[64..].try_into().unwrap()).ok().map(|p| p.to_vec()),
            (MUL, 96) => hus_zk::g1_mul(a[..64].try_into().unwrap(), a[64..].try_into().unwrap()).ok().map(|p| p.to_vec()),
            #[cfg(feature = "native")]
            (PAIRING, _) => hus_zk::pairing_check(a).ok().map(|ok| vec![ok as u8]),
            _ => None,
        };
        match result {
            Some(r) => MessageOutput::success(StateUpdate::FullReplace(abi_wrap(&r))),
            None => MessageOutput::failure(4000),
        }
    }
}

avm_contract_sdk::export_message_contract!(Bn254Ops, arena_bytes = 262_144);
