//! HusRegistry deploy example.
//! Usage (preferred): `tvm-cli deployx` — see AGENTS.md for instructions.
//!
//! This example shows how to use the SDK's encoding + REST API
//! bypassing `process_message` (the SDK's GraphQL account query is
//! broken for v3 servers).

use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use tvm_client::abi::{Abi, CallSet, DeploySet, FunctionHeader, ParamsOfEncodeMessage, Signer};
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

const GIVER_DAPP: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const GIVER_ACCOUNT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const GIVER_ADDRESS: &str = "0000000000000000000000000000000000000000000000000000000000000000::\
      1111111111111111111111111111111111111111111111111111111111111111";
const API_BASE: &str = "http://shellnet.ackinacki.org";

fn rest_post(
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let url = format!("{API_BASE}{path}");
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(body)?;
    Ok(resp.into_json()?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(ClientContext::new(ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec!["http://shellnet.ackinacki.org/graphql".to_string()]),
            ..Default::default()
        },
        ..Default::default()
    })?);

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let giver_abi = Abi::Json(include_str!("../abi/GiverV3.abi.json").to_string());
    let registry_abi = Abi::Json(include_str!("../abi/HusRegistry.abi.json").to_string());
    let registry_tvc =
        general_purpose::STANDARD.encode(&std::fs::read("contracts/onchain/HusRegistry.tvc")?);

    let keys_content = std::fs::read_to_string("/tmp/hus-testnet/wallet/wallet.keys.json")?;
    let k: serde_json::Value = serde_json::from_str(&keys_content)?;
    let signer = Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: k["public"].as_str().unwrap_or("").to_string(),
            secret: k["secret"].as_str().unwrap_or("").to_string(),
        },
    };

    // Compute target address
    let target_enc = tvm_client::abi::encode_message(
        Arc::clone(&ctx),
        ParamsOfEncodeMessage {
            abi: registry_abi.clone(),
            address: None,
            deploy_set: DeploySet::some_with_tvc(Some(registry_tvc.clone())),
            call_set: Some(CallSet {
                function_name: "constructor".to_string(),
                input: Some(json!({})),
                header: Some(FunctionHeader {
                    time: Some(time),
                    expire: Some((time / 1000) as u32 + 120),
                    ..Default::default()
                }),
            }),
            signer: signer.clone(),
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await?;
    let target = &target_enc.address;
    let target_account_id = target.strip_prefix("0:").unwrap_or(target);
    println!("Target: {target} (account_id: {target_account_id})");
    println!("NOTE: target is self-rooted (dapp_id == account_id)");

    // Fund via GiverV3
    println!("Funding via GiverV3.sendCurrencyWithFlag...");
    let fund_enc = tvm_client::abi::encode_message(
        Arc::clone(&ctx),
        ParamsOfEncodeMessage {
            abi: giver_abi.clone(),
            address: Some(GIVER_ADDRESS.to_string()),
            call_set: Some(CallSet {
                function_name: "sendCurrencyWithFlag".to_string(),
                header: Some(FunctionHeader {
                    time: Some(time + 1),
                    expire: Some((time / 1000) as u32 + 60),
                    ..Default::default()
                }),
                input: Some(json!({
                    "dest": target,
                    "value": 1000000000u64,
                    "ecc": {"2": 100000000000u64},
                    "flag": 16,
                })),
            }),
            signer: Signer::None,
            deploy_set: None,
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await?;

    let send_body = json!([{
        "id": fund_enc.message_id,
        "body": fund_enc.message,
        "dapp_id": GIVER_DAPP,
        "account_id": GIVER_ACCOUNT,
    }]);
    let result = rest_post("/v2/messages", &send_body)?;
    println!("  aborted={}", result["result"]["aborted"]);

    Ok(())
}
