"""
HUS C FFI — Python ctypes example.

Demonstrates:
  1. Loading the shared library
  2. Initializing Halo2 IPA keys (hus_init)
  3. Projecting an embedding through BioHashing (hus_project)
  4. Generating a ZK proof (hus_prove)
  5. Verifying the proof (hus_verify)
  6. Cleaning up (hus_free_handle, hus_free_buffer)

Usage:
  python sdk/examples/ffi_python_example.py
"""

import ctypes
import json
import os
import random
import sys

# Locate the shared library
LIB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "target", "release", "libhus_sdk.so",
)
lib = ctypes.CDLL(LIB_PATH)

# ---------------------------------------------------------------------------
# Type signatures
# ---------------------------------------------------------------------------

lib.hus_init.argtypes = [ctypes.c_uint32]
lib.hus_init.restype = ctypes.c_void_p

lib.hus_project.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # seed
    ctypes.c_size_t,                  # seed_len
    ctypes.POINTER(ctypes.c_float),   # embedding
    ctypes.c_size_t,                  # embedding_len
    ctypes.c_uint32,                  # proj_dim
    ctypes.POINTER(ctypes.c_size_t),  # out_len
]
lib.hus_project.restype = ctypes.POINTER(ctypes.c_float)

lib.hus_prove.argtypes = [
    ctypes.c_void_p,                  # handle
    ctypes.POINTER(ctypes.c_float),   # v_obf
    ctypes.c_size_t,                  # v_obf_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),  # out_proof
    ctypes.POINTER(ctypes.c_size_t),  # out_proof_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),  # out_commitment
    ctypes.POINTER(ctypes.c_size_t),  # out_commitment_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_longlong)),  # out_scaled
    ctypes.POINTER(ctypes.c_size_t),  # out_scaled_len
]
lib.hus_prove.restype = ctypes.c_int

lib.hus_verify.argtypes = [
    ctypes.c_void_p,                  # handle
    ctypes.POINTER(ctypes.c_ubyte),   # proof
    ctypes.c_size_t,                  # proof_len
    ctypes.POINTER(ctypes.c_ubyte),   # commitment
    ctypes.c_size_t,                  # commitment_len
    ctypes.POINTER(ctypes.c_float),   # v_obf
    ctypes.c_size_t,                  # v_obf_len
]
lib.hus_verify.restype = ctypes.c_int

lib.hus_free_handle.argtypes = [ctypes.c_void_p]
lib.hus_free_handle.restype = None

lib.hus_free_buffer.argtypes = [ctypes.c_void_p]
lib.hus_free_buffer.restype = None

lib.hus_last_error.restype = ctypes.c_char_p


def check_ptr(ptr, label="ptr"):
    if not ptr:
        err = lib.hus_last_error()
        raise RuntimeError(f"{label} returned NULL: {err.decode() if err else 'unknown'}")
    return ptr


def main():
    print("=== HUS C FFI — Python Example ===")
    print(f"Library: {LIB_PATH}")
    print()

    # 1. Init (keygen ~30s)
    print("Initializing (k=12)...")
    handle = lib.hus_init(12)
    check_ptr(handle, "hus_init")
    print("  OK")
    print()

    # 2. Project
    dim = 40
    emb = [random.uniform(-1, 1) for _ in range(dim)]
    seed = bytes([0xAB] * 32)
    proj_dim = 24

    print(f"Projecting {dim}-dim embedding to {proj_dim} dims...")
    out_len = ctypes.c_size_t()
    v_obf_ptr = lib.hus_project(
        (ctypes.c_ubyte * 32)(*seed),
        32,
        (ctypes.c_float * dim)(*emb),
        dim,
        proj_dim,
        ctypes.byref(out_len),
    )
    check_ptr(v_obf_ptr, "hus_project")
    v_obf = [v_obf_ptr[i] for i in range(out_len.value)]
    lib.hus_free_buffer(v_obf_ptr)
    print(f"  V_obf ({out_len.value} dims): [{', '.join(f'{v:.4f}' for v in v_obf[:4])}, ...]")
    print()

    # 3. Prove
    print("Proving...")
    out_proof = ctypes.POINTER(ctypes.c_ubyte)()
    out_proof_len = ctypes.c_size_t()
    out_commitment = ctypes.POINTER(ctypes.c_ubyte)()
    out_commitment_len = ctypes.c_size_t()
    out_scaled = ctypes.POINTER(ctypes.c_longlong)()
    out_scaled_len = ctypes.c_size_t()

    rc = lib.hus_prove(
        handle,
        (ctypes.c_float * len(v_obf))(*v_obf),
        len(v_obf),
        ctypes.byref(out_proof),
        ctypes.byref(out_proof_len),
        ctypes.byref(out_commitment),
        ctypes.byref(out_commitment_len),
        ctypes.byref(out_scaled),
        ctypes.byref(out_scaled_len),
    )
    if rc != 0:
        err = lib.hus_last_error()
        raise RuntimeError(f"hus_prove failed: {err.decode() if err else f'code {rc}'}")

    proof = bytes(out_proof[:out_proof_len.value])
    commitment = bytes(out_commitment[:out_commitment_len.value])
    scaled = [out_scaled[i] for i in range(out_scaled_len.value)]

    lib.hus_free_buffer(out_proof)
    lib.hus_free_buffer(out_commitment)
    lib.hus_free_buffer(out_scaled)

    print(f"  Proof:       {len(proof)} bytes")
    print(f"  Commitment:  {commitment.hex()}")
    print(f"  V_obf scaled: {scaled[:4]}...")
    print()

    # 4. Verify
    print("Verifying...")
    valid = lib.hus_verify(
        handle,
        (ctypes.c_ubyte * len(proof))(*proof),
        len(proof),
        (ctypes.c_ubyte * len(commitment))(*commitment),
        len(commitment),
        (ctypes.c_float * len(v_obf))(*v_obf),
        len(v_obf),
    )
    if valid == 1:
        print("  ✅ Proof is VALID")
    elif valid == 0:
        print("  ❌ Proof is INVALID")
    else:
        err = lib.hus_last_error()
        print(f"  ❌ Verification failed: {err.decode() if err else f'code {valid}'}")
    print()

    # 5. Cleanup
    lib.hus_free_handle(handle)
    print("Done. Handle freed.")


if __name__ == "__main__":
    main()
