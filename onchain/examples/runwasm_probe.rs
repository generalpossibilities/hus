//! Live RUNWASM availability probe for Shellnet.
//!
//! Deploys a fresh `runWasmSmoke_pubkey`, funds it via GiverV3, then calls
//! `runWasm5(binary="", module="docs:adder/add@0.1.0", function="add",
//! args=[0x01,0x02], hash=66fddc0a…)` and reports the compute exit code:
//!
//!   0  -> RUNWASM live: file placed AND hash whitelisted (result [3])
//!  33  -> WasmWhitelistMissingBinary: operator has NOT placed the file
//!  32  -> WasmWhitelistForbiddenHash: file present, whitelist missing
//!
//! Usage: cargo run --release -p hus-onchain --example runwasm_probe \
//!            [-- keys.json]

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use tvm_client::abi::{
    encode_message, Abi, CallSet, FunctionHeader, ParamsOfEncodeMessage, Signer,
};
use tvm_client::crypto::KeyPair;
use tvm_client::{ClientConfig, ClientContext};

const WASM_HASH: &str = "66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e";
const WASM_MODULE: &str = "docs:adder/add@0.1.0";
const WASM_FUNCTION: &str = "add";
const WASM_ARGS_HEX: &str = "0102";

const ENDPOINT: &str = "http://shellnet.ackinacki.org/graphql";
const REST_BASE: &str = "http://shellnet.ackinacki.org";
const GIVER_ADDRESS: &str = "0:1111111111111111111111111111111111111111111111111111111111111111";

fn rest_post(path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let resp = ureq::post(&format!("{REST_BASE}{path}"))
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .send_json(body)
        .map_err(|e| format!("POST {path}: {e}"))?;
    resp.into_json().map_err(|e| format!("json decode: {e}"))
}

fn gql(query: &str) -> Result<serde_json::Value, String> {
    let resp = ureq::post(ENDPOINT)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .send_json(json!({ "query": query }))
        .map_err(|e| format!("POST graphql: {e}"))?;
    let v: serde_json::Value = resp.into_json().map_err(|e| format!("json: {e}"))?;
    if let Some(errs) = v["errors"].as_array() {
        if !errs.is_empty() {
            return Err(format!("graphql: {errs:?}"));
        }
    }
    Ok(v)
}

fn send_msg(
    message_id: &str,
    message_boc: &str,
    account_id: &str,
) -> Result<(), String> {
    let body = json!([{
        "id": message_id,
        "body": message_boc,
        "dapp_id": account_id,
        "account_id": account_id,
    }]);
    let res = rest_post("/v2/messages", &body)?;
    let aborted = res["result"]["aborted"].as_bool().unwrap_or(true);
    let short = if message_id.len() > 16 { &message_id[..16] } else { message_id };
    println!("  send {short}.. aborted={aborted}");
    if aborted {
        return Err(format!("message rejected: {res}"));
    }
    Ok(())
}

fn wait_txs(account_id: &str, want: usize, timeout: Duration) -> Result<Vec<i64>, String> {
    let start = Instant::now();
    loop {
        let q = format!(
            r#"{{ blockchain {{ account(account_id:"{account_id}", dapp_id:"{account_id}") \
            {{ transactions(last: 10) {{ edges {{ node {{ id status compute {{ exit_code }} }} }} }} }} }} }}"#
        );
        let v = gql(&q).unwrap_or(json!(null));
        let edges = v["data"]["blockchain"]["account"]["transactions"]["edges"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if edges.len() >= want {
            let mut codes: Vec<i64> = edges
                .iter()
                .map(|e| e["node"]["compute"]["exit_code"].as_i64().unwrap_or(-1))
                .collect();
            codes.reverse();
            if codes.len() >= want {
                return Ok(codes);
            }
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for {want} tx(s); got {}",
                edges.len()
            ));
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let keys_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "keep/hus-testnet/wallet/wallet.keys.json".to_string());
    let k: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&keys_path).map_err(|e| format!("read {keys_path}: {e}"))?,
    )
    .map_err(|e| format!("parse keys: {e}"))?;
    let signer = Signer::Keys {
        keys: KeyPair {
            public: k["public"].as_str().unwrap_or("").to_string(),
            secret: k["secret"].as_str().unwrap_or("").to_string(),
        },
    };
    println!("signer pubkey: {}", k["public"].as_str().unwrap_or("?"));

    let ctx = Arc::new(
        ClientContext::new(ClientConfig {
            network: tvm_client::net::NetworkConfig {
                endpoints: Some(vec![ENDPOINT.to_string()]),
                ..Default::default()
            },
            ..Default::default()
        })
        .map_err(|e| format!("client: {e}"))?,
    );

    let smoke_abi = Abi::Json(
        include_str!("../abi/smoke_pubkey.abi.json").to_string(),
    );
    let giver_abi = Abi::Json(
        include_str!("../abi/GiverV3.abi.json").to_string(),
    );
    let tvc_b64 = general_purpose::STANDARD.encode(
        std::fs::read("avm/runwasm-smoke/runWasmSmoke_pubkey_v2_deploy.tvc")
            .map_err(|e| format!("read tvc: {e}"))?,
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // ── 1. Encode deploy message ──
    println!("encoding deploy message...");
    let deploy_enc = encode_message(
        Arc::clone(&ctx),
        ParamsOfEncodeMessage {
            abi: smoke_abi.clone(),
            address: None,
            deploy_set: tvm_client::abi::DeploySet::some_with_tvc(Some(tvc_b64)),
            call_set: Some(CallSet {
                function_name: "constructor".into(),
                input: Some(json!({ "value": 1000000u64 })),
                header: Some(FunctionHeader {
                    time: Some(now),
                    expire: Some((now / 1000) as u32 + 300),
                    ..Default::default()
                }),
            }),
            signer: signer.clone(),
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await
    .map_err(|e| format!("encode deploy: {e}"))?;

    let addr = deploy_enc.address.clone();
    let account_id = addr.trim_start_matches("0:").to_string();
    println!("smoke contract addr: {addr}");
    println!("account_id: {account_id}");

    // ── 2. Fund via GiverV3 ──
    println!("funding via GiverV3...");
    let fund_enc = encode_message(
        Arc::clone(&ctx),
        ParamsOfEncodeMessage {
            abi: giver_abi,
            address: Some(GIVER_ADDRESS.to_string()),
            deploy_set: None,
            call_set: Some(CallSet {
                function_name: "sendCurrencyWithFlag".into(),
                input: Some(json!({
                    "dest": addr,
                    "value": 100_000_000_000u64,
                    "ecc": {},
                    "flag": 16,
                })),
                header: Some(FunctionHeader {
                    time: Some(now + 1),
                    expire: Some((now / 1000) as u32 + 120),
                    ..Default::default()
                }),
            }),
            signer: Signer::None,
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await
    .map_err(|e| format!("encode fund: {e}"))?;

    // Giver has no dapp_id restriction (self-rooted root)
    let giver_account = "1111111111111111111111111111111111111111111111111111111111111111";
    send_msg(&fund_enc.message_id, &fund_enc.message, giver_account)?;

    // ── 2b. Wait for funding to land ──
    println!("waiting for funding to land...");
    let fund_q = format!(
        r#"{{ blockchain {{ account(account_id:"{account_id}", dapp_id:"{account_id}") {{ info {{ last_paid }} }} }} }}"#
    );
    let fund_start = Instant::now();
    loop {
        let v = gql(&fund_q).unwrap_or(json!(null));
        let info = &v["data"]["blockchain"]["account"]["info"];
        if !info.is_null() && info != &json!(null) {
            println!("  account alive (last_paid={})", info["last_paid"]);
            break;
        }
        if fund_start.elapsed() > Duration::from_secs(60) {
            println!("  WARNING: account still not alive after 60s, trying deploy anyway...");
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }

    // ── 3. Deploy ──
    println!("deploying smoke contract...");
    send_msg(&deploy_enc.message_id, &deploy_enc.message, &account_id)?;

    println!("waiting for constructor tx...");
    let codes = wait_txs(&account_id, 1, Duration::from_secs(90))?;
    println!("constructor exit_code={}", codes[0]);
    if codes[0] != 0 {
        return Err(format!("deploy failed (exit {}), cannot probe runwasm", codes[0]));
    }

    // ── 4. runWasm5 probe ──
    let now2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let call_enc = encode_message(
        Arc::clone(&ctx),
        ParamsOfEncodeMessage {
            abi: smoke_abi.clone(),
            address: Some(addr.clone()),
            deploy_set: None,
            call_set: Some(CallSet {
                function_name: "runWasm5".into(),
                input: Some(json!({
                    "wasmBinary": "",
                    "wasmModule": WASM_MODULE,
                    "wasmFunction": WASM_FUNCTION,
                    "wasmArgs": WASM_ARGS_HEX,
                    "wasmHash": WASM_HASH,
                })),
                header: Some(FunctionHeader {
                    time: Some(now2),
                    expire: Some((now2 / 1000) as u32 + 300),
                    ..Default::default()
                }),
            }),
            signer: signer.clone(),
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await
    .map_err(|e| format!("encode call: {e}"))?;

    println!("calling runWasm5(hash-mode, add([1,2]))...");
    send_msg(&call_enc.message_id, &call_enc.message, &account_id)?;

    println!("waiting for runWasm5 tx...");
    let codes = wait_txs(&account_id, 2, Duration::from_secs(90))?;
    let exit = codes[1];
    println!("runWasm5 exit_code={exit}");
    match exit {
        0 => println!("RESULT: RUNWASM IS LIVE (file placed + whitelisted, result [3])"),
        33 => println!("RESULT: NOT AVAILABLE — node missing config/wasm/{WASM_HASH}"),
        32 => println!("RESULT: PARTIAL — file present but hash not whitelisted"),
        other => println!("RESULT: unexpected exit code {other}"),
    }

    Ok(())
}
