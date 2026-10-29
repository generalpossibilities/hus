# Hardware attestation

A HUS proof shows that a vector matches its commitment and is bound to an
owner key and a challenge. It does not show that the vector came from a real
capture: a script can make up a vector and prove it. Hardware attestation
closes most of that gap. Every verification and registration must come with
an attestation showing it was produced:

- by the integrator's own app, unmodified and signed with the integrator's
  key;
- on a genuine device whose keystore is in secure hardware (TEE or
  StrongBox), with a locked bootloader and verified boot;
- for exactly this request: this vector, proof, owner, challenge, modality
  and app.

Checks run off-chain in the verifier (the gateway, or `hus-attest` in your
own verifier). TVM and AVM can't check certificate chains, so the contract
stores the attestation's hash (`attestationHash`) and the verifier publishes
the attestation (`GET /api/v1/attestation/{hash}`) so anyone can re-check
it. No route accepts a proof without an attestation.

**What it does not stop:** a face shown to a real phone's camera. Face
liveness ([liveness.md](liveness.md)) stops photos and recordings; a face on a
screen puppeted live is still open. Nor a device whose TEE itself is broken
(revocation covers known cases).

On-chain proof verification (the AVM `hus-groth16` contract) covers the
proof only. An integrator that verifies on chain must still get the
attestation checked by its verifier before it accepts anyone.

## Rules for the integrating app

An attestation proves the genuine app made the request, nothing more. If
anything outside the app can choose what gets attested, a script can still
register a made-up vector through the genuine app. So:

- Compute `attestation_challenge` only over a vector the app captured and
  proved itself, in the same session.
- Never expose attestation, the challenge computation, or the proving step
  to mini-apps, web views, JavaScript bridges, intents or other apps.
- Release builds only: the policy names the release signing certificate,
  never a debug one.

## Supported formats

| Format | Platform | Status |
|---|---|---|
| `android-key` | Android Key Attestation, chain to a Google root | Supported |
| Play Integrity | Android, via Google's servers | Possible add-on |
| App Attest | iOS | Planned |

## The challenge

```
attestation_challenge = SHA-256(
    "hus.attest.v1"
    ‖ u32 LE len(app) ‖ app            -- app address, trimmed, lowercase
    ‖ modality_id (1 byte)
    ‖ commitment (32 bytes)
    ‖ binding (32 bytes)                -- proof_binding(owner_pubkey, challenge)
    ‖ u32 LE len(v_obf) ‖ v_obf[i] as i64 LE ...   -- v_obf_to_contract
    ‖ u32 LE len(proof) ‖ proof
)
```

It's available as `hus_sdk::attestation_challenge`, the C function
`hus_attestation_challenge` and the WASM function `attestation_challenge_wasm`.
The app computes it after proving and before attesting.

The integrator's single-use `challenge` (inside `binding`) is what makes an
attestation fresh. Never accept the same challenge twice.

## Android: producing the attestation

Generate a **new** key for each request, with the challenge set at
generation time, then send its certificate chain (leaf first). The key itself
is never used and can be deleted afterwards.

```kotlin
val alias = "hus-attest-" + UUID.randomUUID()
val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(attestationChallenge) // 32 bytes from HUS
    // .setIsStrongBoxBacked(true) if your policy requires StrongBox
    .build()
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    .apply { initialize(spec) }
    .generateKeyPair()
val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val chain = ks.getCertificateChain(alias).map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
ks.deleteEntry(alias)
// attestation = {"format": "android-key", "chain": chain}
```

## What the verifier checks (`hus-attest`)

- The chain is 2–10 certificates, each signed by the next, names chained,
  every issuer a CA, ending in one of Google's attestation roots (matched by
  key; roots as published at `https://android.googleapis.com/attestation/root`).
- No certificate is on Google's status list
  (`https://android.googleapis.com/attestation/status`; the gateway refreshes
  it every 6 hours and refuses everything once its copy is over 48 hours old).
- Intermediates are in date, except in factory-provisioned chains, as in
  Google's own verifier. The leaf's dates are ignored.
- Only the leaf has a key attestation. A chain extended below an attested key
  is refused.
- The attestation challenge equals the request's `attestation_challenge`.
- Attestation and KeyMint security levels are at least the policy's
  (TEE by default; never software). Attestation version at least 3.
- The key was generated on the device (not imported).
- Hardware-enforced root of trust: bootloader locked, boot state Verified.
- Every package in `attestationApplicationId` is in the policy, and every
  signing-certificate digest is in the policy.
- Patch levels meet the policy's minimums, when it sets any.

Tests: synthetic chains for every failure above, plus real device chains
from Google's verifier test data (Pixel 3 to a 2026 device, factory and RKP).

## Policy

The integrator names its own app. HUS has no built-in app identity.

```json
{
  "android": {
    "package_names": ["com.example.app"],
    "signing_cert_sha256": ["<sha-256 of the release signing certificate, hex>"],
    "min_security_level": "trusted-environment",
    "min_os_patch_level": 202501
  },
  "revocation_max_age_secs": 172800
}
```

Unknown fields are refused, so a typo can't silently weaken the policy.
A starting point is in `attest/policy.example.json`.

## Re-checking a registration

- Fetch the attestation from the verifier (`GET /api/v1/attestation/{hash}`)
  and check that `Attestation::hash` equals the registration's
  `attestationHash`. That value is the raw SHA-256 read as a big-endian
  uint256, with no byte reversal (unlike `binding`).
- Check the chain as of the registration's on-chain `timestamp`, not now:
  remotely provisioned intermediates expire within months.
- Recompute `attestation_challenge` from the stored registration and the
  binding.

The attestation route is public. A chain shows the device's model or batch
and its patch level, and two registrations from one device within an RKP
key's lifetime can be linked. An operator who doesn't want that can put the
route behind the API key.
