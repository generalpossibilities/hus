use axum::{
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser, Debug)]
#[command(name = "hus-gateway", version = "0.2.0")]
struct Args {
    #[arg(long, env = "HUS_LISTEN", default_value = "0.0.0.0:3000")]
    listen: String,

    #[arg(long, env = "HUS_NETWORK", default_value = "https://shellnet.ackinacki.org/graphql")]
    network: String,

    #[arg(long, env = "HUS_REGISTRY")]
    registry: String,

    #[arg(long, env = "HUS_PROVING_KEY_FILE")]
    proving_key_file: String,

    #[arg(long, env = "HUS_VERIFYING_KEY_FILE")]
    verifying_key_file: String,

    /// Protocol wallet public key (hex, with or without 0x prefix).
    #[arg(long, env = "HUS_PUBLIC_KEY")]
    public_key: String,

    /// Protocol wallet secret key (hex, with or without 0x prefix).
    #[arg(long, env = "HUS_SECRET_KEY")]
    secret_key: String,

    /// Optional API key for bearer-token auth. If omitted, all endpoints are public.
    #[arg(long, env = "HUS_API_KEY")]
    api_key: Option<String>,

    /// The integrator's attestation policy (JSON, see hus_attest::Policy):
    /// which app, signed by which key, may submit. Required: every
    /// verification and submission needs a hardware attestation.
    #[arg(long, env = "HUS_ATTEST_POLICY")]
    attest_policy: String,

    /// Where checked attestations are kept and served from
    /// (`GET /api/v1/attestation/{hash}`), so anyone can re-check the hash
    /// stored with a registration.
    #[arg(long, env = "HUS_ATTESTATION_DIR", default_value = "attestations")]
    attestation_dir: String,
}

struct AppState {
    pk: Vec<u8>,
    vk: Vec<u8>,
    registry: hus_onchain::HusRegistry,
    client_context: Arc<tvm_client::ClientContext>,
    protocol_signer: tvm_client::abi::Signer,
    network: String,
    api_key: Option<String>,
    attest_policy: hus_attest::Policy,
    trust_anchors: hus_attest::TrustAnchors,
    /// Google's revocation list, refreshed in the background. Until it has
    /// loaded (or once it is too old), every attestation is refused.
    revocations: RwLock<Option<hus_attest::RevocationList>>,
    attestation_dir: std::path::PathBuf,
}

/// Maximum projection dimension accepted from clients (matches the in-circuit
/// `MAX_PROJ_DIM` constraint). Larger values would allow unbounded
/// matrix allocation (`embedding.len() × proj_dim`), i.e. an OOM DoS.
const MAX_PROJ_DIM: usize = 128;
/// Cap on raw embedding length (SDK raw dims are ≤ 512 across modalities).
const MAX_EMBEDDING_LEN: usize = 4096;

// ── Request/Response types ─────────────────────────────────

#[derive(Deserialize)]
struct ProjectRequest {
    seed: String,
    embedding: Vec<f32>,
    proj_dim: usize,
}

#[derive(Serialize)]
struct ProjectResponse {
    v_obf: Vec<f32>,
}

/// Who a proof is for (HUS S3): the key that will control the account and
/// the challenge the integrating app issued for this attempt, both hex. The
/// proof is bound to `hus_sdk::proof_binding(owner_pubkey, challenge)`, so
/// it can't be replayed with another challenge or used for another key.
#[derive(Deserialize)]
struct ProofFor {
    owner_pubkey: String,
    challenge: String,
}

impl ProofFor {
    fn binding(&self) -> Result<[u8; 32], AppError> {
        let key = hex::decode(self.owner_pubkey.trim_start_matches("0x"))
            .map_err(|e| AppError(format!("owner_pubkey hex: {e}")))?;
        let challenge = hex::decode(self.challenge.trim_start_matches("0x"))
            .map_err(|e| AppError(format!("challenge hex: {e}")))?;
        if key.is_empty() || key.len() > 128 {
            return Err(AppError("owner_pubkey must be 1..=128 bytes".into()));
        }
        if challenge.len() < 16 || challenge.len() > 64 {
            return Err(AppError("challenge must be 16..=64 bytes".into()));
        }
        Ok(hus_sdk::proof_binding(&key, &challenge))
    }
}

#[derive(Deserialize)]
struct ProveRequest {
    v_obf: Vec<f32>,
    #[serde(flatten)]
    proof_for: ProofFor,
}

#[derive(Serialize)]
struct ProveResponse {
    proof: String,
    commitment: String,
}

/// The device side of a request: who it is for (the app, so one app's
/// attestations can't be used at another) and the hardware attestation over
/// `hus_sdk::attestation_challenge` of the request.
#[derive(Deserialize)]
struct Attested {
    /// The HusApp address, or for an integrator that keeps its own registry,
    /// the identifier its app puts into the attestation challenge.
    app_address: String,
    modality_id: u8,
    attestation: hus_attest::Attestation,
}

#[derive(Deserialize)]
struct VerifyRequest {
    proof: String,
    commitment: String,
    v_obf: Vec<f32>,
    #[serde(flatten)]
    proof_for: ProofFor,
    #[serde(flatten)]
    attested: Attested,
}

#[derive(Serialize)]
struct VerifyResponse {
    /// The proof verifies and the attestation passed.
    valid: bool,
    /// SHA-256 of the attestation (hex); keep it with the registration.
    attestation_hash: Option<String>,
}

#[derive(Deserialize)]
struct RegisterAppRequest {
    app_name: String,
    modality_ids: Vec<u8>,
}

#[derive(Serialize)]
struct RegisterAppResponse {
    message_hash: String,
    app_address: String,
}

#[derive(Serialize)]
struct MessageResponse {
    /// Accepted message hash (submit-with-proof path).
    message_hash: Option<String>,
    /// Deduplication outcome (submit path): was the registration unique?
    is_unique: Option<bool>,
}

#[derive(Deserialize)]
struct SubmitRequest {
    app_address: String,
    /// Poseidon commitment, 32 bytes hex.
    commitment: String,
    /// Canonical fixed-point vector (`hus_sdk::v_obf_to_contract`), 128 values.
    v_obf: Vec<i64>,
    /// Groth16 proof, hex.
    proof: String,
    modality_id: u8,
    #[serde(flatten)]
    proof_for: ProofFor,
    attestation: hus_attest::Attestation,
}

/// The binding as a big-endian 256-bit number (the contract's uint256), from
/// the field element's little-endian encoding.
fn binding_be(binding: &[u8; 32]) -> [u8; 32] {
    let mut be = *binding;
    be.reverse();
    be
}

#[derive(Deserialize)]
struct CheckRequest {
    app_address: String,
    commitment_hash: String,
}

#[derive(Serialize)]
struct CheckResponse {
    duplicate: bool,
}

#[derive(Deserialize)]
struct DepositRequest {
    app_address: String,
    payment_id: String,
    wallet_keys: WalletKeys,
}

#[derive(Deserialize)]
struct AppInfoRequest {
    app_address: String,
}

#[derive(Deserialize)]
struct WalletKeys {
    public: String,
    secret: String,
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    network: String,
    registry: String,
}

// ── Error type ─────────────────────────────────────────────

struct AppError(String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("{}", self.0);
        (StatusCode::BAD_REQUEST, self.0).into_response()
    }
}

// ── Helpers ────────────────────────────────────────────────

fn parse_hex_32(s: &str) -> Result<[u8; 32], AppError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| AppError(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(AppError(format!("expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Check a device attestation for one request, then keep it so it can be
/// served next to the hash that goes on chain.
#[allow(clippy::too_many_arguments)]
fn check_attestation(
    state: &AppState,
    attestation: &hus_attest::Attestation,
    app_address: &str,
    modality_id: u8,
    commitment: &[u8; 32],
    v_obf: &[i64],
    proof: &[u8],
    binding: &[u8; 32],
) -> Result<[u8; 32], AppError> {
    let challenge =
        hus_sdk::attestation_challenge(app_address, modality_id, commitment, v_obf, proof, binding);
    let verdict = {
        let guard = state.revocations.read().map_err(|_| AppError("revocation list lock".into()))?;
        let list = guard
            .as_ref()
            .ok_or_else(|| AppError("attestation revocation list not loaded yet".into()))?;
        hus_attest::verify(
            attestation,
            &challenge,
            &state.attest_policy,
            &state.trust_anchors,
            list,
            now_unix(),
        )
        .map_err(|e| AppError(format!("attestation: {e}")))?
    };
    let hash = verdict.attestation_hash;
    let path = state.attestation_dir.join(format!("{}.json", hex::encode(hash)));
    let body = serde_json::to_vec(attestation).map_err(|e| AppError(e.to_string()))?;
    std::fs::write(&path, body).map_err(|e| AppError(format!("store attestation: {e}")))?;
    Ok(hash)
}

/// Fetch Google's attestation status list now and then. A failed fetch keeps
/// the old list; `hus_attest::verify` refuses it once it is too old.
async fn refresh_revocations(state: Arc<AppState>) {
    let client = reqwest::Client::new();
    loop {
        let fetched = async {
            let r = client
                .get(hus_attest::RevocationList::URL)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?;
            let body = r.bytes().await.map_err(|e| e.to_string())?;
            hus_attest::RevocationList::from_json(&body, now_unix()).map_err(|e| e.to_string())
        }
        .await;
        let wait = match fetched {
            Ok(list) => {
                tracing::info!("attestation revocation list: {} entries", list.len());
                if let Ok(mut g) = state.revocations.write() {
                    *g = Some(list);
                }
                6 * 3600
            }
            Err(e) => {
                tracing::warn!("attestation revocation list fetch failed: {e}");
                600
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    }
}

fn make_signer(keys: WalletKeys) -> tvm_client::abi::Signer {
    tvm_client::abi::Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: keys.public,
            secret: keys.secret,
        },
    }
}

// ── Handlers ───────────────────────────────────────────────

fn validate_embedding(embedding: &[f32]) -> Result<(), AppError> {
    if embedding.is_empty() {
        return Err(AppError("embedding must not be empty".into()));
    }
    if embedding.len() > MAX_EMBEDDING_LEN {
        return Err(AppError(format!(
            "embedding length {} exceeds MAX_EMBEDDING_LEN ({MAX_EMBEDDING_LEN})",
            embedding.len()
        )));
    }
    Ok(())
}

fn validate_proj_dim(proj_dim: usize) -> Result<(), AppError> {
    if proj_dim == 0 || proj_dim > MAX_PROJ_DIM {
        return Err(AppError(format!(
            "proj_dim must be in 1..={MAX_PROJ_DIM}, got {proj_dim}"
        )));
    }
    Ok(())
}

/// Constant-time string equality (token comparison must not leak length or
/// byte equality through timing).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    if let Some(ref expected) = state.api_key {
        let header = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = header.strip_prefix("Bearer ").unwrap_or("");
        if !constant_time_eq(token, expected.as_str()) {
            return Err(AppError("unauthorized".into()));
        }
    }
    Ok(next.run(request).await)
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: "0.2.0",
        network: state.network.clone(),
        registry: state.registry.address().to_string(),
    })
}

async fn project_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<ProjectRequest>,
) -> Result<Json<ProjectResponse>, AppError> {
    validate_embedding(&req.embedding)?;
    validate_proj_dim(req.proj_dim)?;
    let seed = parse_hex_32(&req.seed)?;
    let v_obf = hus_sdk::projection::derive_and_project(&seed, &req.embedding, req.proj_dim)
        .map_err(|e| AppError(e.to_string()))?;
    Ok(Json(ProjectResponse { v_obf }))
}

async fn prove_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, AppError> {
    if req.v_obf.is_empty() || req.v_obf.len() > MAX_PROJ_DIM {
        return Err(AppError(format!(
            "v_obf must have 1..={MAX_PROJ_DIM} elements, got {}",
            req.v_obf.len()
        )));
    }
    let (proof_bytes, commitment) =
        hus_sdk::prover::prove_projected(&state.pk, &req.v_obf, &req.proof_for.binding()?)
            .map_err(|e| AppError(e.to_string()))?;
    Ok(Json(ProveResponse {
        proof: hex::encode(&proof_bytes),
        commitment: hex::encode(commitment),
    }))
}

async fn verify_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let commitment = parse_hex_32(&req.commitment)?;
    let proof_bytes = hex::decode(&req.proof)
        .map_err(|e| AppError(format!("hex decode: {e}")))?;
    let v_obf = hus_sdk::v_obf_to_contract(&req.v_obf);
    let binding = req.proof_for.binding()?;
    let valid = hus_sdk::prover::verify_projected(&state.vk, &proof_bytes, &commitment, &v_obf, &binding)
        .map_err(|e| AppError(e.to_string()))?;
    if !valid {
        return Ok(Json(VerifyResponse { valid: false, attestation_hash: None }));
    }
    let a = &req.attested;
    let hash = check_attestation(
        &state,
        &a.attestation,
        &a.app_address,
        a.modality_id,
        &commitment,
        &v_obf,
        &proof_bytes,
        &binding,
    )?;
    Ok(Json(VerifyResponse { valid: true, attestation_hash: Some(hex::encode(hash)) }))
}

async fn register_app_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterAppRequest>,
) -> Result<Json<RegisterAppResponse>, AppError> {
    let result = state
        .registry
        .register_app(&req.app_name, &req.modality_ids, state.protocol_signer.clone())
        .await
        .map_err(|e| AppError(e))?;

    Ok(Json(RegisterAppResponse {
        message_hash: result.message_hash.unwrap_or_default(),
        app_address: String::new(),
    }))
}

/// Off-chain verification, then registration. The proof must verify against
/// the commitment and every v_obf element (the circuit's public inputs);
/// only then does the gateway sign `submitVerified` with its own key, which
/// the app operator has named as the app's verifier. Callers never send keys.
async fn submit_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    if req.v_obf.len() != MAX_PROJ_DIM {
        return Err(AppError(format!("v_obf must have {MAX_PROJ_DIM} elements")));
    }
    let commitment = parse_hex_32(&req.commitment)?;
    let binding = req.proof_for.binding()?;
    let proof_bytes = hex::decode(&req.proof)
        .map_err(|e| AppError(format!("hex decode: {e}")))?;
    let valid = hus_sdk::prover::verify_projected(
        &state.vk,
        &proof_bytes,
        &commitment,
        &req.v_obf,
        &binding,
    )
    .map_err(|e| AppError(e.to_string()))?;
    if !valid {
        return Err(AppError("proof does not match the submitted v_obf".into()));
    }
    let attestation_hash = check_attestation(
        &state,
        &req.attestation,
        &req.app_address,
        req.modality_id,
        &commitment,
        &req.v_obf,
        &proof_bytes,
        &binding,
    )?;

    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let output = app
        .submit_verified(
            &format!("0x{}", hex::encode(commitment)),
            &req.v_obf,
            &hex::encode(&proof_bytes),
            &format!("0x{}", hex::encode(binding_be(&binding))),
            &format!("0x{}", hex::encode(attestation_hash)),
            req.modality_id,
            state.protocol_signer.clone(),
        )
        .await
        .map_err(|e| AppError(e))?;
    Ok(Json(MessageResponse {
        message_hash: None,
        is_unique: output["isUnique"].as_bool(),
    }))
}

/// A checked attestation, by the hash stored with its registration.
async fn attestation_handler(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Response, AppError> {
    let hash = parse_hex_32(&hash)?;
    let path = state.attestation_dir.join(format!("{}.json", hex::encode(hash)));
    match std::fs::read(&path) {
        Ok(body) => Ok(([(axum::http::header::CONTENT_TYPE, "application/json")], body).into_response()),
        Err(_) => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn check_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, AppError> {
    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let duplicate = app
        .check_duplicate(&req.commitment_hash)
        .await
        .map_err(|e| AppError(e))?;
    Ok(Json(CheckResponse { duplicate }))
}

async fn deposit_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let signer = make_signer(req.wallet_keys);
    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let result = app
        .deposit(&req.payment_id, signer)
        .await
        .map_err(|e| AppError(e))?;
    Ok(Json(MessageResponse {
        message_hash: result.message_hash,
        is_unique: None,
    }))
}

async fn app_info_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AppInfoRequest>,
) -> Result<Json<hus_onchain::HusAppInfo>, AppError> {
    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let info = app.get_app_info().await.map_err(|e| AppError(e))?;
    Ok(Json(info))
}

// ── Main ───────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let pubkey = args
        .public_key
        .strip_prefix("0x")
        .unwrap_or(&args.public_key)
        .to_string();
    let seckey = args
        .secret_key
        .strip_prefix("0x")
        .unwrap_or(&args.secret_key)
        .to_string();
    let protocol_signer = tvm_client::abi::Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: pubkey,
            secret: seckey,
        },
    };

    tracing::info!("connecting to network: {}", args.network);

    let client_config = tvm_client::ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec![args.network.clone()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let client_context = Arc::new(
        tvm_client::ClientContext::new(client_config).expect("create TVM client"),
    );

    // Load Groth16 proving key and verifying key from binary files
    tracing::info!("loading proving key from: {}", args.proving_key_file);
    let pk_bytes = std::fs::read(&args.proving_key_file)
        .expect("read proving key file");
    tracing::info!("proving key loaded: {} bytes", pk_bytes.len());

    tracing::info!("loading verifying key from: {}", args.verifying_key_file);
    let vk_bytes = std::fs::read(&args.verifying_key_file)
        .expect("read verifying key file");
    tracing::info!("verifying key loaded: {} bytes", vk_bytes.len());

    let registry =
        hus_onchain::HusRegistry::new(Arc::clone(&client_context), &args.registry);

    let policy_json = std::fs::read_to_string(&args.attest_policy).expect("read attestation policy");
    let attest_policy = hus_attest::Policy::from_json(&policy_json).expect("attestation policy");
    let attestation_dir = std::path::PathBuf::from(&args.attestation_dir);
    std::fs::create_dir_all(&attestation_dir).expect("create attestation dir");

    let state = Arc::new(AppState {
        pk: pk_bytes,
        vk: vk_bytes,
        registry,
        client_context,
        protocol_signer,
        network: args.network.clone(),
        api_key: args.api_key.clone(),
        attest_policy,
        trust_anchors: hus_attest::TrustAnchors::google(),
        revocations: RwLock::new(None),
        attestation_dir,
    });
    tokio::spawn(refresh_revocations(state.clone()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let secured_routes = Router::new()
        .route("/api/v1/project", post(project_handler))
        .route("/api/v1/prove", post(prove_handler))
        .route("/api/v1/verify", post(verify_handler))
        .route("/api/v1/register-app", post(register_app_handler))
        .route("/api/v1/submit", post(submit_handler))
        .route("/api/v1/check", post(check_handler))
        .route("/api/v1/deposit", post(deposit_handler))
        .route("/api/v1/app-info", post(app_info_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/attestation/:hash", get(attestation_handler))
        .merge(secured_routes)
        .layer(cors)
        .with_state(state);

    tracing::info!("HUS Gateway listening on {}", args.listen);
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
