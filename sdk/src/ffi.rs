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

/// Compute the 32-byte challenge the device's hardware attestation must
/// carry for one submission (see `prover::attestation_challenge`).
/// `app_address` is UTF-8; `commitment`, `binding` and `out` are 32 bytes;
/// `v_obf` is the canonical fixed-point vector.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_attestation_challenge(
    app_address: *const u8,
    app_address_len: usize,
    modality_id: u8,
    commitment: *const u8,
    v_obf: *const i64,
    v_obf_len: usize,
    proof: *const u8,
    proof_len: usize,
    binding: *const u8,
    out: *mut u8,
) -> i32 {
    if app_address.is_null()
        || commitment.is_null()
        || v_obf.is_null()
        || proof.is_null()
        || binding.is_null()
        || out.is_null()
    {
        set_error("null pointer argument");
        return -1;
    }
    let app = unsafe { core::slice::from_raw_parts(app_address, app_address_len) };
    let app = match core::str::from_utf8(app) {
        Ok(a) => a,
        Err(_) => {
            set_error("app_address is not UTF-8");
            return -1;
        }
    };
    let mut c = [0u8; 32];
    let mut b = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(commitment, c.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(binding, b.as_mut_ptr(), 32);
    }
    let v = unsafe { core::slice::from_raw_parts(v_obf, v_obf_len) };
    let p = unsafe { core::slice::from_raw_parts(proof, proof_len) };
    let h = crate::prover::attestation_challenge(app, modality_id, &c, v, p, &b);
    unsafe {
        ptr::copy_nonoverlapping(h.as_ptr(), out, 32);
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

// ---------------------------------------------------------------------------
// Face enrolment session (see `enroll`). The app passes camera frames and
// face-detector signals in and gets back a finished request; it never
// chooses the vector, the proof inputs or the attestation challenge.
// ---------------------------------------------------------------------------

/// Face-detector output for one frame. Coordinates in upright pixels.
/// `landmarks`: left eye, right eye, nose tip, left mouth corner, right
/// mouth corner, as x,y pairs ("left" = smaller x).
#[repr(C)]
pub struct HusFaceSignals {
    pub t_ms: u64,
    pub track_id: i64,
    pub has_track_id: u32,
    pub faces: u32,
    pub image_w: f32,
    pub image_h: f32,
    pub bbox: [f32; 4],
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub left_eye_open: f32,
    pub right_eye_open: f32,
    pub smile: f32,
    pub has_landmarks: u32,
    pub landmarks: [f32; 10],
}

/// One camera buffer. `format`: 0 RGBA, 1 BGRA, 2 NV21. `rotation`:
/// clockwise degrees that make it upright.
#[repr(C)]
pub struct HusFrame {
    pub format: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub rotation: u32,
    pub data: *const u8,
    pub len: usize,
}

/// Session state. `phase`: 0 settle, 1 act, 2 return to rest, 3 done,
/// 4 failed. `action`: 0 none, 1 blink, 2 smile, 3 turn left, 4 turn
/// right. `hint` and `failure` codes: see `face_liveness::Hint::id` and
/// `Failure::id` (0 = none).
#[repr(C)]
#[derive(Default)]
pub struct HusFaceStatus {
    pub phase: u32,
    pub action: u32,
    pub completed: u32,
    pub total: u32,
    pub hint: u32,
    pub failure: u32,
}

fn status_to_c(s: crate::face_liveness::Status) -> HusFaceStatus {
    use crate::face_liveness::Phase;
    let (phase, failure) = match s.phase {
        Phase::Settle => (0, 0),
        Phase::Act(_) => (1, 0),
        Phase::Return(_) => (2, 0),
        Phase::Done => (3, 0),
        Phase::Failed(f) => (4, f.id()),
    };
    HusFaceStatus {
        phase,
        action: s.action.map(|a| a.id()).unwrap_or(0),
        completed: s.completed as u32,
        total: s.total as u32,
        hint: s.hint.id(),
        failure,
    }
}

/// Load the proving key (must be the key HUS pins, by SHA-256; see
/// `prover::ProverKey`). Returns an opaque handle to free with
/// `hus_prover_key_free`, or NULL on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_prover_key_load(bytes: *const u8, len: usize) -> *mut c_void {
    if bytes.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    let b = unsafe { core::slice::from_raw_parts(bytes, len) };
    match crate::prover::ProverKey::load(b) {
        Ok(k) => alloc::boxed::Box::into_raw(alloc::boxed::Box::new(k)) as *mut c_void,
        Err(e) => {
            set_error(&alloc::format!("{e}"));
            ptr::null_mut()
        }
    }
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_prover_key_free(key: *mut c_void) {
    if !key.is_null() {
        drop(unsafe { alloc::boxed::Box::from_raw(key as *mut crate::prover::ProverKey) });
    }
}

fn read_path(path: *const c_char) -> Option<std::vec::Vec<u8>> {
    if path.is_null() {
        set_error("null pointer argument");
        return None;
    }
    #[allow(unsafe_code)]
    let p = match unsafe { std::ffi::CStr::from_ptr(path) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_error("path is not UTF-8");
            return None;
        }
    };
    match std::fs::read(p) {
        Ok(b) => Some(b),
        Err(e) => {
            set_error(&alloc::format!("read {p}: {e}"));
            None
        }
    }
}

/// `hus_prover_key_load` from a file (NUL-terminated UTF-8 path), so the
/// app never holds the 17 MB key itself.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_prover_key_load_file(path: *const c_char) -> *mut c_void {
    match read_path(path) {
        Some(b) => hus_prover_key_load(b.as_ptr(), b.len()),
        None => ptr::null_mut(),
    }
}

/// `hus_face_model_load` from a file (NUL-terminated UTF-8 path).
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_model_load_file(path: *const c_char) -> *mut c_void {
    match read_path(path) {
        Some(b) => hus_face_model_load(b.as_ptr(), b.len()),
        None => ptr::null_mut(),
    }
}

/// Load the face model (must be the model HUS pins, by SHA-256). Returns an
/// opaque handle to free with `hus_face_model_free`, or NULL on error.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_model_load(bytes: *const u8, len: usize) -> *mut c_void {
    if bytes.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    #[cfg(feature = "ml")]
    {
        let b = unsafe { core::slice::from_raw_parts(bytes, len) };
        match crate::enroll::FaceModel::load(b) {
            Ok(m) => alloc::boxed::Box::into_raw(alloc::boxed::Box::new(m)) as *mut c_void,
            Err(e) => {
                set_error(&alloc::format!("{e}"));
                ptr::null_mut()
            }
        }
    }
    #[cfg(not(feature = "ml"))]
    {
        let _ = len;
        set_error("built without the `ml` feature");
        ptr::null_mut()
    }
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_model_free(model: *mut c_void) {
    if !model.is_null() {
        drop(unsafe { alloc::boxed::Box::from_raw(model as *mut crate::enroll::FaceModel) });
    }
}

/// Start a session for the verifier's single-use `challenge` (≥ 16 bytes).
/// Returns an opaque handle to free with `hus_face_session_free`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_session_new(challenge: *const u8, challenge_len: usize) -> *mut c_void {
    if challenge.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    let c = unsafe { core::slice::from_raw_parts(challenge, challenge_len) };
    match crate::enroll::FaceEnrollment::new(c, crate::enroll::EnrollConfig::default()) {
        Ok(s) => alloc::boxed::Box::into_raw(alloc::boxed::Box::new(s)) as *mut c_void,
        Err(e) => {
            set_error(&alloc::format!("{e}"));
            ptr::null_mut()
        }
    }
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_session_free(session: *mut c_void) {
    if !session.is_null() {
        drop(unsafe { alloc::boxed::Box::from_raw(session as *mut crate::enroll::FaceEnrollment) });
    }
}

/// The session's actions in order (codes as in `HusFaceStatus.action`).
/// Writes up to `cap` codes into `out` and returns how many there are.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_session_actions(session: *const c_void, out: *mut u32, cap: usize) -> i32 {
    if session.is_null() || out.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    let s = unsafe { &*(session as *const crate::enroll::FaceEnrollment) };
    let a = s.actions();
    for (i, x) in a.iter().take(cap).enumerate() {
        unsafe { *out.add(i) = x.id() };
    }
    a.len() as i32
}

/// Feed one analysed frame. `frame` may be NULL (no pixels this time).
/// Writes the new state to `out`. Returns 0, or -1 on a bad argument.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_session_push(
    session: *mut c_void,
    signals: *const HusFaceSignals,
    frame: *const HusFrame,
    out: *mut HusFaceStatus,
) -> i32 {
    use crate::face::{Frame, PixelFormat};
    use crate::face_liveness::FaceSignals;
    if session.is_null() || signals.is_null() || out.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    let s = unsafe { &mut *(session as *mut crate::enroll::FaceEnrollment) };
    let g = unsafe { &*signals };
    let mut lm = [[0.0f32; 2]; 5];
    for (i, p) in lm.iter_mut().enumerate() {
        *p = [g.landmarks[2 * i], g.landmarks[2 * i + 1]];
    }
    let sig = FaceSignals {
        t_ms: g.t_ms,
        faces: g.faces,
        track_id: (g.has_track_id != 0).then_some(g.track_id),
        image_w: g.image_w,
        image_h: g.image_h,
        bbox: g.bbox,
        yaw: g.yaw,
        pitch: g.pitch,
        roll: g.roll,
        left_eye_open: g.left_eye_open,
        right_eye_open: g.right_eye_open,
        smile: g.smile,
        landmarks: (g.has_landmarks != 0).then_some(lm),
    };
    let status = if frame.is_null() {
        s.push(&sig, None)
    } else {
        let f = unsafe { &*frame };
        if f.data.is_null() {
            set_error("null frame data");
            return -1;
        }
        let Some(format) = PixelFormat::from_id(f.format) else {
            set_error("unknown pixel format");
            return -1;
        };
        let data = unsafe { core::slice::from_raw_parts(f.data, f.len) };
        let rotation = match u16::try_from(f.rotation) {
            Ok(r) => r,
            Err(_) => {
                set_error("bad rotation");
                return -1;
            }
        };
        match Frame::new(format, f.width as usize, f.height as usize, f.stride as usize, rotation, data) {
            Ok(fr) => s.push(&sig, Some(&fr)),
            Err(e) => {
                set_error(&alloc::format!("bad frame: {e:?}"));
                return -1;
            }
        }
    };
    unsafe { *out = status_to_c(status) };
    0
}

/// Finish a passed session with a key from `hus_prover_key_load`: embed,
/// check one face, project with the app's
/// 32-byte `projection_seed`, prove for `owner_pubkey`, and compute the
/// attestation challenge for `app_address` (NUL-terminated UTF-8).
///
/// Returns a NUL-terminated JSON string to free with `hus_free_string`:
/// `{"modality_id", "commitment", "v_obf", "proof", "binding",
/// "attestation_challenge", "min_similarity"}` (byte fields hex), or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_face_session_finish(
    session: *const c_void,
    model: *const c_void,
    prover_key: *const c_void,
    projection_seed: *const u8,
    owner_pubkey: *const u8,
    owner_pubkey_len: usize,
    app_address: *const c_char,
) -> *mut c_char {
    if session.is_null()
        || model.is_null()
        || prover_key.is_null()
        || projection_seed.is_null()
        || owner_pubkey.is_null()
        || app_address.is_null()
    {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    let s = unsafe { &*(session as *const crate::enroll::FaceEnrollment) };
    let m = unsafe { &*(model as *const crate::enroll::FaceModel) };
    let pk = unsafe { &*(prover_key as *const crate::prover::ProverKey) };
    let mut seed = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(projection_seed, seed.as_mut_ptr(), 32) };
    let owner = unsafe { core::slice::from_raw_parts(owner_pubkey, owner_pubkey_len) };
    let app = match unsafe { std::ffi::CStr::from_ptr(app_address) }.to_str() {
        Ok(a) => a,
        Err(_) => {
            set_error("app_address is not UTF-8");
            return ptr::null_mut();
        }
    };
    enrollment_json(s.finish(m, pk, &seed, owner, app))
}

fn enrollment_json(r: Result<crate::enroll::Enrollment, crate::enroll::EnrollError>) -> *mut c_char {
    match r {
        Ok(r) => {
            let json = serde_json::json!({
                "modality_id": r.modality_id,
                "commitment": hex::encode(r.commitment),
                "v_obf": r.v_obf,
                "proof": hex::encode(&r.proof),
                "binding": hex::encode(r.binding),
                "attestation_challenge": hex::encode(r.attestation_challenge),
                "min_similarity": r.min_similarity,
            });
            match std::ffi::CString::new(json.to_string()) {
                Ok(c) => c.into_raw(),
                Err(_) => {
                    set_error("result encoding failed");
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            set_error(&alloc::format!("{e}"));
            ptr::null_mut()
        }
    }
}

/// Free a string returned by `hus_face_session_finish`.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(s) });
    }
}

// ---------------------------------------------------------------------------
// Typing enrolment session (see `typing`). The app draws its own keypad and
// reports each key's press and release.
// ---------------------------------------------------------------------------

/// `phase`: 0 typing, 3 done, 4 failed. `failure`: see
/// `typing::TypingFailure::id` (0 = none). `restarted` is 1 when the last
/// key was wrong and the code starts again.
#[repr(C)]
#[derive(Default)]
pub struct HusTypingStatus {
    pub phase: u32,
    pub typed: u32,
    pub total: u32,
    pub restarted: u32,
    pub failure: u32,
}

fn typing_status_to_c(s: crate::typing::TypingStatus) -> HusTypingStatus {
    use crate::typing::TypingPhase;
    let (phase, failure) = match s.phase {
        TypingPhase::Typing => (0, 0),
        TypingPhase::Done => (3, 0),
        TypingPhase::Failed(f) => (4, f.id()),
    };
    HusTypingStatus {
        phase,
        typed: s.typed as u32,
        total: s.total as u32,
        restarted: s.restarted as u32,
        failure,
    }
}

/// Start a typing session for the verifier's single-use `challenge`.
/// Returns an opaque handle to free with `hus_typing_session_free`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_typing_session_new(challenge: *const u8, challenge_len: usize) -> *mut c_void {
    if challenge.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    let c = unsafe { core::slice::from_raw_parts(challenge, challenge_len) };
    match crate::typing::TypingEnrollment::new(c, crate::typing::TypingConfig::default()) {
        Ok(s) => alloc::boxed::Box::into_raw(alloc::boxed::Box::new(s)) as *mut c_void,
        Err(e) => {
            set_error(&alloc::format!("{e}"));
            ptr::null_mut()
        }
    }
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_typing_session_free(session: *mut c_void) {
    if !session.is_null() {
        drop(unsafe { alloc::boxed::Box::from_raw(session as *mut crate::typing::TypingEnrollment) });
    }
}

/// The digits to type (ASCII). Writes up to `cap` bytes into `out` and
/// returns the code's length.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_typing_session_code(session: *const c_void, out: *mut u8, cap: usize) -> i32 {
    if session.is_null() || out.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    let s = unsafe { &*(session as *const crate::typing::TypingEnrollment) };
    let code = s.code();
    let n = code.len().min(cap);
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), out, n) };
    code.len() as i32
}

/// One key from the app's keypad: ASCII `key`, press and release times in
/// milliseconds. Writes the new state to `out`. Returns 0, or -1.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_typing_session_push(
    session: *mut c_void,
    key: u32,
    press_ms: u64,
    release_ms: u64,
    out: *mut HusTypingStatus,
) -> i32 {
    if session.is_null() || out.is_null() {
        set_error("null pointer argument");
        return -1;
    }
    let Ok(key) = u8::try_from(key) else {
        set_error("key must be ASCII");
        return -1;
    };
    let s = unsafe { &mut *(session as *mut crate::typing::TypingEnrollment) };
    unsafe { *out = typing_status_to_c(s.push(key, press_ms, release_ms)) };
    0
}

/// Finish a typed session; arguments and result as `hus_face_session_finish`.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn hus_typing_session_finish(
    session: *const c_void,
    prover_key: *const c_void,
    projection_seed: *const u8,
    owner_pubkey: *const u8,
    owner_pubkey_len: usize,
    app_address: *const c_char,
) -> *mut c_char {
    if session.is_null() || prover_key.is_null() || projection_seed.is_null() || owner_pubkey.is_null() || app_address.is_null() {
        set_error("null pointer argument");
        return ptr::null_mut();
    }
    let s = unsafe { &*(session as *const crate::typing::TypingEnrollment) };
    let pk = unsafe { &*(prover_key as *const crate::prover::ProverKey) };
    let mut seed = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(projection_seed, seed.as_mut_ptr(), 32) };
    let owner = unsafe { core::slice::from_raw_parts(owner_pubkey, owner_pubkey_len) };
    let app = match unsafe { std::ffi::CStr::from_ptr(app_address) }.to_str() {
        Ok(a) => a,
        Err(_) => {
            set_error("app_address is not UTF-8");
            return ptr::null_mut();
        }
    };
    enrollment_json(s.finish(pk, &seed, owner, app))
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    fn pk_handle() -> *mut c_void {
        let b = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keep/pk.bin")).unwrap();
        let k = hus_prover_key_load(b.as_ptr(), b.len());
        assert!(!k.is_null());
        k
    }

    #[test]
    fn the_prover_key_must_be_the_pinned_one() {
        let junk = [0u8; 64];
        assert!(hus_prover_key_load(junk.as_ptr(), junk.len()).is_null());
    }

    #[test]
    fn a_typing_session_through_the_c_api() {
        let challenge = [0x42u8; 16];
        let s = hus_typing_session_new(challenge.as_ptr(), challenge.len());
        assert!(!s.is_null());
        let mut code = [0u8; 32];
        let n = hus_typing_session_code(s, code.as_mut_ptr(), code.len()) as usize;
        assert_eq!(n, 12);
        let mut st = HusTypingStatus::default();
        let mut now = 10_000u64;
        for (i, c) in code[..n].iter().enumerate() {
            now += 170 + (i as u64 * 41 % 150);
            assert_eq!(hus_typing_session_push(s, *c as u32, now, now + 60 + (i as u64 * 17 % 60), &mut st), 0);
        }
        assert_eq!((st.phase, st.typed, st.total), (3, 12, 12));

        let k = pk_handle();
        let seed = [3u8; 32];
        let owner = [9u8; 32];
        let app = std::ffi::CString::new("njd-registrar").unwrap();
        let out = hus_typing_session_finish(s, k, seed.as_ptr(), owner.as_ptr(), owner.len(), app.as_ptr());
        assert!(!out.is_null());
        let json: serde_json::Value =
            serde_json::from_str(unsafe { std::ffi::CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        hus_free_string(out);
        assert_eq!(json["modality_id"], 4);
        assert_eq!(json["v_obf"].as_array().unwrap().len(), crate::MAX_PROJ_DIM);
        let v_obf: Vec<i64> = json["v_obf"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        let commitment: [u8; 32] = hex::decode(json["commitment"].as_str().unwrap()).unwrap().try_into().unwrap();
        let proof = hex::decode(json["proof"].as_str().unwrap()).unwrap();
        let binding = crate::proof_binding(&owner, &challenge);
        let vk = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keep/vk.bin")).unwrap();
        assert!(crate::verify_projected(&vk, &proof, &commitment, &v_obf, &binding).unwrap());
        assert_eq!(
            json["attestation_challenge"].as_str().unwrap(),
            hex::encode(crate::attestation_challenge("njd-registrar", 4, &commitment, &v_obf, &proof, &binding))
        );
        hus_typing_session_free(s);
        hus_prover_key_free(k);
    }

    #[test]
    fn a_face_session_reports_progress_through_the_c_api() {
        use crate::face_liveness::tests::{image, passing_trace, CHALLENGE};
        let s = hus_face_session_new(CHALLENGE.as_ptr(), CHALLENGE.len());
        assert!(!s.is_null());
        let mut actions = [0u32; 4];
        assert_eq!(hus_face_session_actions(s, actions.as_mut_ptr(), 4), 3);
        let img = image();
        let frame = HusFrame { format: 0, width: 320, height: 240, stride: 1280, rotation: 0, data: img.as_ptr(), len: img.len() };
        let mut st = HusFaceStatus::default();
        for g in passing_trace() {
            let mut lm = [0f32; 10];
            for (i, p) in g.landmarks.unwrap().iter().enumerate() {
                lm[2 * i] = p[0];
                lm[2 * i + 1] = p[1];
            }
            let c = HusFaceSignals {
                t_ms: g.t_ms,
                track_id: g.track_id.unwrap(),
                has_track_id: 1,
                faces: g.faces,
                image_w: g.image_w,
                image_h: g.image_h,
                bbox: g.bbox,
                yaw: g.yaw,
                pitch: g.pitch,
                roll: g.roll,
                left_eye_open: g.left_eye_open,
                right_eye_open: g.right_eye_open,
                smile: g.smile,
                has_landmarks: 1,
                landmarks: lm,
            };
            assert_eq!(hus_face_session_push(s, &c, &frame, &mut st), 0);
        }
        assert_eq!((st.phase, st.completed, st.total, st.failure), (3, 3, 3, 0));
        // A bad frame is an argument error, not a session failure.
        let bad = HusFrame { format: 9, ..frame };
        let c = HusFaceSignals { t_ms: 1, track_id: 0, has_track_id: 0, faces: 0, image_w: 0.0, image_h: 0.0, bbox: [0.0; 4], yaw: 0.0, pitch: 0.0, roll: 0.0, left_eye_open: 0.0, right_eye_open: 0.0, smile: 0.0, has_landmarks: 0, landmarks: [0.0; 10] };
        assert_eq!(hus_face_session_push(s, &c, &bad, &mut st), -1);
        hus_face_session_free(s);
    }
}
