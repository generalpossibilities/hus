use axum::{
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
}

struct AppState {
    pk: Vec<u8>,
    vk: Vec<u8>,
    registry: hus_onchain::HusRegistry,
    client_context: Arc<tvm_client::ClientContext>,
    protocol_signer: tvm_client::abi::Signer,
    network: String,
    api_key: Option<String>,
}

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

#[derive(Deserialize)]
struct ProveRequest {
    v_obf: Vec<f32>,
}

#[derive(Serialize)]
struct ProveResponse {
    proof: String,
    commitment: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    proof: String,
    commitment: String,
    v_obf: Vec<f32>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
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
    message_hash: String,
}

#[derive(Deserialize)]
struct SubmitRequest {
    app_address: String,
    commitment_hash: String,
    v_obf: Vec<i64>,
    modality_id: u8,
    wallet_keys: WalletKeys,
}

#[derive(Deserialize)]
struct SubmitWithProofRequest {
    app_address: String,
    v_obf: Vec<i64>,
    proof: String,
    commitment: String,
    modality_id: u8,
    wallet_keys: WalletKeys,
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

fn make_signer(keys: WalletKeys) -> tvm_client::abi::Signer {
    tvm_client::abi::Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: keys.public,
            secret: keys.secret,
        },
    }
}

// ── Handlers ───────────────────────────────────────────────

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
        if token != *expected {
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
    let seed = parse_hex_32(&req.seed)?;
    let v_obf = hus_sdk::projection::derive_and_project(&seed, &req.embedding, req.proj_dim)
        .map_err(|e| AppError(e.to_string()))?;
    Ok(Json(ProjectResponse { v_obf }))
}

async fn prove_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, AppError> {
    let (proof_bytes, commitment) =
        hus_sdk::prover::prove_projected(&state.pk, &req.v_obf)
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
    let valid = hus_sdk::prover::verify_projected(
        &state.vk,
        &proof_bytes,
        &commitment,
        &req.v_obf,
    )
    .map_err(|e| AppError(e.to_string()))?;
    Ok(Json(VerifyResponse { valid }))
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

async fn submit_with_proof_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitWithProofRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let signer = make_signer(req.wallet_keys);
    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let result = app
        .submit_with_proof(&req.v_obf, &req.proof, &req.commitment, req.modality_id, signer)
        .await
        .map_err(|e| AppError(e))?;
    Ok(Json(MessageResponse {
        message_hash: result.message_hash.unwrap_or_default(),
    }))
}

async fn submit_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let signer = make_signer(req.wallet_keys);
    let app = hus_onchain::HusApp::new(Arc::clone(&state.client_context), &req.app_address);
    let output = app
        .submit_commitment(&req.commitment_hash, &req.v_obf, req.modality_id, signer)
        .await
        .map_err(|e| AppError(e))?;
    Ok(Json(MessageResponse {
        message_hash: output["isUnique"].to_string(),
    }))
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
        message_hash: result.message_hash.unwrap_or_default(),
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

    let state = Arc::new(AppState {
        pk: pk_bytes,
        vk: vk_bytes,
        registry,
        client_context,
        protocol_signer,
        network: args.network.clone(),
        api_key: args.api_key.clone(),
    });

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
        .route("/api/v1/submit-with-proof", post(submit_with_proof_handler))
        .route("/api/v1/check", post(check_handler))
        .route("/api/v1/deposit", post(deposit_handler))
        .route("/api/v1/app-info", post(app_info_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .merge(secured_routes)
        .layer(cors)
        .with_state(state);

    tracing::info!("HUS Gateway listening on {}", args.listen);
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
