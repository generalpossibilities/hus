/**
 * HUS C FFI — Example
 *
 * Build:
 *   gcc -o ffi_c_example ffi_c_example.c -L../target/release -lhus_sdk
 *   LD_LIBRARY_PATH=../target/release ./ffi_c_example
 *
 * Or with rpath:
 *   gcc -o ffi_c_example ffi_c_example.c -L../target/release -lhus_sdk \
 *       -Wl,-rpath,../target/release
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Opaque handle */
typedef void hus_handle_t;

/* FFI declarations */
hus_handle_t* hus_init(uint32_t k);
float*        hus_project(const uint8_t* seed, size_t seed_len,
                          const float* embedding, size_t embedding_len,
                          uint32_t proj_dim, size_t* out_len);
int           hus_prove(hus_handle_t* handle,
                        const float* v_obf, size_t v_obf_len,
                        uint8_t** out_proof, size_t* out_proof_len,
                        uint8_t** out_commitment, size_t* out_commitment_len,
                        int64_t** out_v_obf_scaled, size_t* out_v_obf_scaled_len);
int           hus_verify(hus_handle_t* handle,
                         const uint8_t* proof, size_t proof_len,
                         const uint8_t* commitment, size_t commitment_len,
                         const float* v_obf, size_t v_obf_len);
void          hus_free_handle(hus_handle_t* handle);
void          hus_free_buffer(void* ptr);
const char*   hus_last_error(void);

static void check_error(const char* label) {
    const char* err = hus_last_error();
    if (err && err[0]) {
        fprintf(stderr, "%s failed: %s\n", label, err);
        exit(1);
    }
}

int main(void) {
    printf("=== HUS C FFI Example ===\n");

    /* 1. Init */
    printf("\nInitializing (k=12)...\n");
    hus_handle_t* h = hus_init(12);
    check_error("hus_init");
    printf("  OK\n");

    /* 2. Project */
    const int dim = 40;
    float emb[40];
    srand(time(NULL));
    for (int i = 0; i < dim; i++)
        emb[i] = (float)rand() / RAND_MAX * 2.0f - 1.0f;

    uint8_t seed[32];
    memset(seed, 0xAB, 32);
    size_t proj_len = 0;

    printf("\nProjecting 40-dim embedding to 24 dims...\n");
    float* v_obf = hus_project(seed, 32, emb, dim, 24, &proj_len);
    check_error("hus_project");
    printf("  V_obf (%zu dims): [%.4f, %.4f, %.4f, %.4f, ...]\n",
           proj_len, v_obf[0], v_obf[1], v_obf[2], v_obf[3]);

    /* 3. Prove */
    printf("\nProving...\n");
    uint8_t* proof = NULL;
    size_t proof_len = 0;
    uint8_t* commitment = NULL;
    size_t commitment_len = 0;
    int64_t* scaled = NULL;
    size_t scaled_len = 0;

    int rc = hus_prove(h, v_obf, proj_len,
                       &proof, &proof_len,
                       &commitment, &commitment_len,
                       &scaled, &scaled_len);
    if (rc != 0) {
        check_error("hus_prove");
        return 1;
    }
    printf("  Proof:       %zu bytes\n", proof_len);
    printf("  Commitment:  ");
    for (size_t i = 0; i < commitment_len; i++)
        printf("%02x", commitment[i]);
    printf("\n");
    printf("  V_obf scaled: [%ld, %ld, %ld, %ld, ...]\n",
           scaled[0], scaled[1], scaled[2], scaled[3]);

    /* 4. Verify */
    printf("\nVerifying...\n");
    int valid = hus_verify(h, proof, proof_len, commitment, commitment_len,
                           v_obf, proj_len);
    if (valid == 1)
        printf("  ✅ Proof is VALID\n");
    else if (valid == 0)
        printf("  ❌ Proof is INVALID\n");
    else
        check_error("hus_verify");

    /* 5. Cleanup */
    hus_free_buffer(v_obf);
    hus_free_buffer(proof);
    hus_free_buffer(commitment);
    hus_free_buffer(scaled);
    hus_free_handle(h);

    printf("\nDone.\n");
    return 0;
}
