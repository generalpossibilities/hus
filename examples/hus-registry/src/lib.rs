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
    use avm_contract_sdk::{Caller, Contract, MessageInput, MessageOutput, StateUpdate};
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
    /// it, so this reads the layout of release avm-dev-335a0f09fdbc: a length
    /// table at 264 (salt length u16 at 266, init length u32 at 276), then the
    /// salt at 288 followed by the init data with its own u32 length, which
    /// must match the table. Anything that is not an ACDP payload is taken as
    /// the init data itself (an ABI `bytes` value, or raw).
    fn deploy_init_data(body: &[u8]) -> Option<&[u8]> {
        if body.get(..4) != Some(b"ACDP".as_slice()) {
            return abi_bytes(body).or(Some(body));
        }
        let u32_at = |o: usize| body.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
        let salt_len = u16::from_le_bytes(body.get(266..268)?.try_into().ok()?) as usize;
        let init_len = u32_at(276)?;
        let at = 288 + salt_len;
        (u32_at(at)? == init_len).then(|| body.get(at + 4..at + 4 + init_len)).flatten()
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
                // No AVM runtime exposes BN254 host functions yet.
                VerifyMode::NativeGroth16 => return fail(Error::NoVerifier),
            }
            match reg.register(&registration) {
                Ok((next, _)) => MessageOutput::success(StateUpdate::FullReplace(abi_wrap(next))),
                Err(e) => fail(e),
            }
        }
    }

    avm_contract_sdk::export_message_contract!(HusRegistry, arena_bytes = 4_194_304);
}
