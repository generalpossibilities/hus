# Liveness and enrolment sessions

A HUS proof shows a vector matches its commitment; hardware attestation
shows the integrator's genuine app made it on a genuine device. Neither
shows a live person was in front of the camera. The enrolment sessions do:
the app feeds camera frames and touches in, and HUS decides whether a live
person produced them before it projects, proves and computes the
attestation challenge.

## The rule that makes it count

Liveness, the biometric and the proof come from **one session**. The app
never chooses the vector, the embedding or the challenge it attests:

```text
FaceEnrollment::new(challenge)          the verifier's single-use challenge
  .push(signals, frame) ...             every analysed camera frame
  .finish(model, prover_key, seed, owner, app)
      → Enrollment { commitment, v_obf, proof, binding, attestation_challenge }
```

`finish` refuses until the session passed. The `attestation_challenge` it
returns is the only thing the app hands to the hardware attestation. An app
that also exposes separate project/prove/challenge calls to anything else
(a mini-app, a web view) undoes this; see [attestation.md](attestation.md).

## Face (`face_liveness`, `enroll`)

The platform's face detector (ML Kit on Android, ML Kit or Vision on iOS)
supplies, per frame: face count, tracking id, box, head yaw/pitch/roll,
eye-open and smile probabilities, and five landmarks (eyes, nose, mouth
corners). HUS:

1. **Orders the actions from the challenge.** Three of blink, smile, turn
   left, turn right, shuffled by `SHA-256("hus.face-liveness.v1" ‖ challenge)`.
   Nobody knows the order before the verifier issues the challenge.
2. **Requires a rest pose before and after each action** (looking straight,
   eyes open, not smiling, held 400 ms) and crops the face there: four
   aligned 112×112 crops (ArcFace 5-point alignment) from the camera frame.
3. **Fails the session** on two faces, a lost face (over 0.7 s), a changed
   tracking id, a face that jumps between frames, frames that stop or go
   backwards, an action not done within 7 s, or **a different action than
   the one asked for** (a recording that runs through every action can't
   wait for its cue). A blink never counts as wrong.
4. **Checks identity on `finish`**: every pair of crops must embed to cosine
   similarity ≥ 0.5, so the face that did the actions is the face that is
   proved. The proved embedding is the mean of the four.

Unknown detector values (NaN, negative probabilities) never count as at
rest or as an action. The thresholds are in `LivenessConfig`.

Yaw is positive when the person turns to **their own left**. ML Kit's Euler Y
("positive = looking to the right of the camera") has the same sign.

**What it does not stop:** a face on a screen that an attacker controls
live (a puppeted deepfake). Attestation forces it onto a real phone's
camera; detecting screens and prints needs presentation-attack detection,
not done yet.

## Typing (`typing`)

The person types a 12-digit code, `SHA-256("hus.typing.v1" ‖ challenge)`
one digit per byte, on **the app's own keypad** (a system keyboard reports
no press/release times and allows paste). HUS refuses a wrong key more than
three times, holds under 20 ms or over 800 ms, presses under 50 ms apart or
over 5 s apart, and uniform timing (press-gap variation under 12 %, or hold
times all the same). The timing features (`KeystrokeExtractor`) are the
biometric. Typing rhythm tells people apart only weakly; it adds to the
face, it doesn't replace it.

## Files the session needs

- **Face model**: `arcface.onnx`, pinned by SHA-256 in `model_registry`
  (`FaceModel::load` refuses any other file). 131 MB; download once.
- **Proving key**: pinned by SHA-256 in `prover::PROVING_KEY_SHA256`.
  `ProverKey::load` checks the hash, then skips the per-point curve checks
  (48 s on a laptop, minutes on a phone; 50 ms without). The key changes
  when the multi-party setup replaces the dev setup.

## C API (`sdk/src/ffi.rs`)

```text
hus_prover_key_load[_file] / hus_prover_key_free
hus_face_model_load[_file] / hus_face_model_free
hus_face_session_new(challenge) / _actions / _push(signals, frame, &status) / _finish → JSON / _free
hus_typing_session_new(challenge) / _code / _push(key, press_ms, release_ms, &status) / _finish → JSON / _free
hus_free_string, hus_last_error
```

`HusFaceSignals`, `HusFrame` (RGBA, BGRA or NV21, with the rotation that
makes it upright), `HusFaceStatus` and `HusTypingStatus` are `#[repr(C)]`.
`finish` returns `{modality_id, commitment, v_obf, proof, binding,
attestation_challenge, min_similarity}` with byte fields in hex and `v_obf`
in the contract's fixed point, exactly what `/api/v1/verify` and
`/api/v1/submit` take.

## Building

- Android: `scripts/build-android.sh` (cargo-ndk on the build server) →
  `target/android-libs/<abi>/libhus_sdk.so`, with the `ml` feature.
- iOS: `scripts/build-ios.sh` on a Mac → `target/HusSdk.xcframework`
  (static library), linked into the app; `DynamicLibrary.process()` in Dart.
- Web and desktop can't attest a genuine app, so they don't enrol
  themselves: the integrator hands the test off to the person's phone.
