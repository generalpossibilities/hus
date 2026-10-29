#![allow(clippy::not_unsafe_ptr_arg_deref)]

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use core::ffi::{c_char, c_void};
use core::mem::{align_of, size_of};
use core::ptr;

use crate::projection::derive_and_project;
use crate::prover::{prove_projected, verify_projected};
use crate::MAX_PROJ_DIM;

// ---------------------------------------------------------------------------
// Thread-local error buffer
// ---------------------------------------------------------------------------
std::thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<std::ffi::CString>> =
        const { std::cell::RefCell::new(None) };
}

fn set_error(msg: &str) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(std::ffi::CString::new(msg).unwrap_or_default()));
}

// ---------------------------------------------------------------------------
// Memory management: store a header before each allocation so any buffer
// can be freed via `hus_free_buffer` without knowing its type or length.
// ---------------------------------------------------------------------------

#[repr(C)]
struct AllocHeader {
    byte_count: usize,
}

/// Allocate a buffer, storing the total byte count in a header before the
/// returned pointer. The caller receives a pointer to `T` and must free
/// with `hus_free_buffer`.
///
/// # Safety
///
/// Assumes `data` was allocated by Rust's global allocator.
#[allow(unsafe_code)]
unsafe fn alloc_buf<T: Copy>(data: &[T]) -> *mut T {
    let elem_size = size_of::<T>();
    let byte_count = data.len().checked_mul(elem_size).expect("overflow");
    let header = size_of::<AllocHeader>();

    let layout = Layout::from_size_align(
        header + byte_count,
        align_of::<AllocHeader>().max(align_of::<T>()),
    )
    .expect("invalid layout");

    let base: *mut u8 = alloc(layout);
    if base.is_null() {
        return ptr::null_mut();
    }

    // Write header
    (base as *mut AllocHeader).write(AllocHeader { byte_count });
    // Copy data after header
    let data_ptr = base.add(header) as *mut T;
    ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());

    data_ptr
}

/// Free a buffer allocated by `alloc_buf`. Works for any `T`.
///
/// # Safety
///
/// `ptr` must have been returned by a previous `alloc_buf` call.
#[allow(unsafe_code)]
unsafe fn free_buf<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    let header = size_of::<AllocHeader>();
    let base = (ptr as *mut u8).sub(header);
    let byte_count = (base as *const AllocHeader).read().byte_count;

    let layout = Layout::from_size_align(
        header + byte_count,
        align_of::<AllocHeader>().max(align_of::<T>()),
    )
    .expect("invalid layout");
    dealloc(base, layout);
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Deprecated — kept for ABI compat. Returns a no-op sentinel.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_init(_k: u32) -> *mut c_void {
    ptr::NonNull::dangling().as_ptr() as *mut c_void
}

/// Project an embedding through BioHashing.
///
/// * `seed` — 32-byte seed
/// * `seed_len` — must be 32
/// * `embedding` — input embedding values
/// * `embedding_len` — number of f32 values
/// * `proj_dim` — output dimension (≤ 128)
/// * `out_len` — receives number of f32 values in output
///
/// Returns pointer to projected V_obf (caller must free with `hus_free_buffer`),
/// or NULL on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_project(
    seed: *const u8,
    seed_len: usize,
    embedding: *const f32,
    embedding_len: usize,
    proj_dim: u32,
    out_len: *mut usize,
) -> *mut f32 {
    if seed.is_null() || embedding.is_null() || out_len.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    if seed_len != 32 {
        set_error("seed must be exactly 32 bytes");
        return ptr::null_mut();
    }

    let seed_slice = unsafe { core::slice::from_raw_parts(seed, 32) };
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(seed_slice);

    let emb = unsafe { core::slice::from_raw_parts(embedding, embedding_len) };
    let dim = (proj_dim as usize).min(MAX_PROJ_DIM);

    let v_obf = match derive_and_project(&seed_arr, emb, dim) {
        Ok(v) => v,
        Err(e) => {
            set_error(&alloc::format!("{:?}", e));
            return ptr::null_mut();
        }
    };
    unsafe {
        *out_len = v_obf.len();
        alloc_buf(&v_obf)
    }
}

/// Prove a projected vector using Groth16 on BN254.
///
/// * `pk` — serialized Groth16 ProvingKey bytes
/// * `pk_len` — byte count of pk
/// * `v_obf` — projected embedding values
/// * `v_obf_len` — number of f32 values
/// * `binding` — 32 bytes from `hus_proof_binding` (owner key + verifier challenge)
/// * `out_proof` — receives pointer to proof bytes
/// * `out_proof_len` — receives proof byte count
/// * `out_commitment` — receives pointer to 32-byte commitment
/// * `out_commitment_len` — receives 32
/// * `out_v_obf_scaled` — receives pointer to fixed-point i64 V_obf (×10⁶)
/// * `out_v_obf_scaled_len` — receives number of i64 values
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_prove(
    pk: *const u8,
    pk_len: usize,
    v_obf: *const f32,
    v_obf_len: usize,
    binding: *const u8,
    out_proof: *mut *mut u8,
    out_proof_len: *mut usize,
    out_commitment: *mut *mut u8,
    out_commitment_len: *mut usize,
    out_v_obf_scaled: *mut *mut i64,
    out_v_obf_scaled_len: *mut usize,
) -> i32 {
    if pk.is_null()
        || v_obf.is_null()
        || binding.is_null()
        || out_proof.is_null()
        || out_proof_len.is_null()
        || out_commitment.is_null()
        || out_commitment_len.is_null()
        || out_v_obf_scaled.is_null()
        || out_v_obf_scaled_len.is_null()
    {
        set_error("null pointer argument");
        return -1;
    }

    let pk_slice = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let v = unsafe { core::slice::from_raw_parts(v_obf, v_obf_len) };
    let mut b = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(binding, b.as_mut_ptr(), 32);
    }

    match prove_projected(pk_slice, v, &b) {
        Ok((proof, commitment)) => {
            unsafe {
                *out_proof = alloc_buf(&proof);
                *out_proof_len = proof.len();
                *out_commitment = alloc_buf(&commitment);
                *out_commitment_len = commitment.len();

                // Build scaled V_obf as i64[] ×10⁶ fixed-point (canonical encoding)
                let scaled = crate::v_obf_to_contract(v);
                *out_v_obf_scaled = alloc_buf(&scaled);
                *out_v_obf_scaled_len = scaled.len();
            }
            0
        }
        Err(e) => {
            set_error(&alloc::format!("prove failed: {:?}", e));
            -1
        }
    }
}

/// Verify a Groth16 proof using the serialized VerifyingKey.
///
/// * `vk` — serialized Groth16 VerifyingKey bytes
/// * `vk_len` — byte count of vk
/// * `proof` — proof bytes
/// * `proof_len` — byte count
/// * `commitment` — 32-byte commitment
/// * `commitment_len` — must be 32
/// * `v_obf` — projected embedding
/// * `v_obf_len` — number of f32 values
/// * `binding` — 32 bytes the verifier computed with `hus_proof_binding`
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_verify(
    vk: *const u8,
    vk_len: usize,
    proof: *const u8,
    proof_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    v_obf: *const f32,
    v_obf_len: usize,
    binding: *const u8,
) -> i32 {
    if vk.is_null() || proof.is_null() || commitment.is_null() || v_obf.is_null() || binding.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    if commitment_len != 32 {
        set_error("commitment must be exactly 32 bytes");
        return -1;
    }

    let vk_slice = unsafe { core::slice::from_raw_parts(vk, vk_len) };
    let p = unsafe { core::slice::from_raw_parts(proof, proof_len) };
    let mut c = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(commitment, c.as_mut_ptr(), 32);
    }
    let v = unsafe { core::slice::from_raw_parts(v_obf, v_obf_len) };
    let mut b = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(binding, b.as_mut_ptr(), 32);
    }

    // Verify against the canonical fixed-point encoding (v_obf is bound by
    // the proof as a public input).
    let v_contract = crate::v_obf_to_contract(v);
    match verify_projected(vk_slice, p, &c, &v_contract, &b) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_error(&alloc::format!("verify failed: {:?}", e));
            -1
        }
    }
}

/// Compute the 32-byte proof binding for an owner key and a verifier
/// challenge (see `prover::proof_binding`). Writes into `out` (32 bytes).
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_proof_binding(
    owner_pubkey: *const u8,
    owner_pubkey_len: usize,
    challenge: *const u8,
    challenge_len: usize,
    out: *mut u8,
) -> i32 {
    if owner_pubkey.is_null() || challenge.is_null() || out.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    let k = unsafe { core::slice::from_raw_parts(owner_pubkey, owner_pubkey_len) };
    let c = unsafe { core::slice::from_raw_parts(challenge, challenge_len) };
    let b = crate::prover::proof_binding(k, c);
    unsafe {
        ptr::copy_nonoverlapping(b.as_ptr(), out, 32);
    }
    0
}

/// Free a buffer allocated by any `hus_*` function.
///
/// # Safety
///
/// `ptr` must have been returned by a prior `hus_project`, `hus_prove`, or
/// similar call. Double-free is undefined behaviour.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_free_buffer(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            free_buf(ptr);
        }
    }
}

/// Return the last error message. Returns empty string if no error.
/// The returned string is valid until the next `hus_*` call on this thread.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn hus_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let err = e.borrow();
        match err.as_ref() {
            Some(s) => s.as_ptr() as *const c_char,
            None => {
                static EMPTY: [u8; 1] = [0u8];
                EMPTY.as_ptr() as *const c_char
            }
        }
    })
}
