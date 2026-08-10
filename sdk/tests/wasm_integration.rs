#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn extract_invalid_data_returns_error() {
    let result = hus_sdk::wasm::extract_embedding(0, "[]");
    assert!(
        result.contains("error"),
        "bad data should return error: {}",
        result
    );
}

#[wasm_bindgen_test]
fn extract_unknown_modality_returns_error() {
    let result = hus_sdk::wasm::extract_embedding(99, "[0.1,0.2]");
    assert!(
        result.contains("error"),
        "bad modality should return error: {}",
        result
    );
}

#[wasm_bindgen_test]
fn seed_generation_returns_hex() {
    let seed = hus_sdk::wasm::generate_seed_wasm();
    assert_eq!(seed.len(), 64, "32 bytes = 64 hex chars, got '{}'", seed);
    assert!(
        seed.chars().all(|c| c.is_ascii_hexdigit()),
        "hex string only"
    );
}

#[wasm_bindgen_test]
fn seed_differs_per_call() {
    let a = hus_sdk::wasm::generate_seed_wasm();
    let b = hus_sdk::wasm::generate_seed_wasm();
    assert_ne!(a, b);
}
