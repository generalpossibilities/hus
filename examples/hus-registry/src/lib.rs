//! HUS uniqueness registry for AVM: one person, one registration per app.
//!
//! Deploy one registry per app (its salt names the app). `init` takes the
//! config bytes (see `registry::Config::encode`); `hus.register` takes
//! `commitment | v_obf (dim × i64 LE, ×10⁶) | proof` and either stores it or
//! fails with the status codes listed in `avm-contract.toml`.
#![forbid(unsafe_code)]

extern crate alloc;

pub mod registry;

#[cfg(target_arch = "wasm32")]
mod contract {
    use crate::registry::{initial_state, Config, Error, Registry, VerifyMode};
    use avm_contract_sdk::{Caller, Contract, MessageInput, MessageOutput, StateOutputMode, StatePatch, StateUpdate};
    use alloc::vec::Vec;

    /// An ABI `bytes` value arrives as a u32 LE length followed by the data.
    fn abi_bytes(body: &[u8]) -> Option<&[u8]> {
        let n = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
        (body.len() == 4 + n).then(|| &body[4..])
    }

    /// The state root is an ABI `bytes` value too: the same length prefix.
    fn abi_wrap(data: Vec<u8>) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + data.len());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&data);
        b
    }

    /// The init data of a deploy. `init` receives the whole canonical deploy
    /// payload ("ACDP"), and the SDK has no accessor for the init data inside
    /// it (gosh-sh/avm-sdk#1), so this reads the layout: a length table at 264
    /// (UI-name length u16 at 264, salt length u16 at 266, init field length
    /// u32 at 268), then from 288 the UI name, the salt, and the init field, an
    /// ABI `bytes` value (u32 length, then the data) whose size must match the
    /// table. Anything that is not an ACDP payload is taken as the init data
    /// itself (an ABI `bytes` value, or raw).
    fn deploy_init_data(body: &[u8]) -> Option<&[u8]> {
        if body.get(..4) != Some(b"ACDP".as_slice()) {
            return abi_bytes(body).or(Some(body));
        }
        let u16_at = |o: usize| body.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
        let ui_name_len = u16_at(264)?;
        let salt_len = u16_at(266)?;
        let field_len = u32::from_le_bytes(body.get(268..272)?.try_into().ok()?) as usize;
        let at = 288 + ui_name_len + salt_len;
        abi_bytes(body.get(at..at.checked_add(field_len)?)?)
    }

    fn fail(e: Error) -> MessageOutput {
        MessageOutput::failure(e as u32)
    }

    struct HusRegistry;

    impl Contract for HusRegistry {
        fn init(input: MessageInput<'_>) -> MessageOutput {
            let Some(cfg) = deploy_init_data(input.message.body()).and_then(|b| Config::decode(b).ok()) else {
                return fail(Error::BadState);
            };
            MessageOutput::success(StateUpdate::FullReplace(abi_wrap(initial_state(&cfg))))
        }

        fn process_message(input: MessageInput<'_>) -> MessageOutput {
            let Some(state) = abi_bytes(input.state) else { return fail(Error::BadState) };
            let reg = match Registry::parse(state) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let Some(args) = abi_bytes(input.message.body()) else { return fail(Error::BadArgs) };
            let registration = match reg.parse_registration(args) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            match reg.config.mode {
                VerifyMode::Attestor => {
                    if !reg.config.attestors.is_empty() {
                        let Caller::External(signer) = input.caller else { return fail(Error::NotAttestor) };
                        if !reg.config.attestors.iter().any(|a| *a == signer) {
                            return fail(Error::NotAttestor);
                        }
                    }
                }
                #[cfg(feature = "groth16")]
                VerifyMode::NativeGroth16 => {
                    if let Err(e) = crate::registry::verify_proof(&registration) {
                        return fail(e);
                    }
                }
                // Built without proof verification (no AVM runtime has the BN254 host functions yet).
                #[cfg(not(feature = "groth16"))]
                VerifyMode::NativeGroth16 => return fail(Error::NoVerifier),
            }
            let (record, _) = match reg.check(&registration) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            if input.required_state_output_mode == StateOutputMode::DataPatchList {
                // Patch only what changes: the ABI length, the count, and the new record.
                let old_len = state.len();
                let new_len = (old_len + record.len()) as u32;
                let at = 4 + reg.count_offset();
                return MessageOutput::success(StateUpdate::DataPatchList(alloc::vec![
                    StatePatch { offset: 0, old_len: 4, new_bytes: new_len.to_le_bytes().to_vec() },
                    StatePatch { offset: at as u32, old_len: 4, new_bytes: (reg.count + 1).to_le_bytes().to_vec() },
                    StatePatch { offset: (4 + old_len) as u32, old_len: 0, new_bytes: record },
                ]));
            }
            let mut next = Vec::with_capacity(4 + state.len() + record.len());
            next.extend_from_slice(&((state.len() + record.len()) as u32).to_le_bytes());
            next.extend_from_slice(&state[..reg.count_offset()]);
            next.extend_from_slice(&(reg.count + 1).to_le_bytes());
            next.extend_from_slice(&state[reg.count_offset() + 4..]);
            next.extend_from_slice(&record);
            MessageOutput::success(StateUpdate::FullReplace(next))
        }
    }

    avm_contract_sdk::export_message_contract!(HusRegistry, arena_bytes = 4_194_304);
}
