//! HUS WASM verifier component (wasm32-wasip2 / component model).

mod bindings;
pub mod verify;

#[cfg(target_arch = "wasm32")]
use bindings::exports::hus::verifier::verifier_interface::Guest;

#[cfg(target_arch = "wasm32")]
struct Component;

#[cfg(target_arch = "wasm32")]
impl Guest for Component {
    fn verify(args: Vec<u8>) -> Vec<u8> {
        let ok = verify::verify(&args);
        if ok { vec![1u8] } else { vec![0u8] }
    }
}

#[cfg(target_arch = "wasm32")]
bindings::export!(Component with_types_in bindings);