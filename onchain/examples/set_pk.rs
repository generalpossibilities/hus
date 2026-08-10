//! Upload a proving key to a deployed HusRegistry using chunked storage.
//!
//! The proving key (17MB binary, 34MB hex) is too large for a single TVM message,
//! so this tool splits it into 32KB chunks and uploads them one by one.
//!
//! Usage:
//!   cargo run --example set_pk -p hus-onchain -- <endpoint> <pk_hex_file> <keys_json> <registry_addr>
//!
//! Example:
//!   cargo run --example set_pk -p hus-onchain -- \
//!     https://shellnet.ackinacki.org/graphql \
//!     keep/pk.hex \
//!     /tmp/hus-testnet/wallet/wallet.keys.json \
//!     "<registry_addr>"

use std::sync::Arc;

use hus_onchain::HusRegistry;
use tvm_client::abi::Signer;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let endpoint = args.get(1).map(|s| s.as_str())
        .unwrap_or("https://shellnet.ackinacki.org/graphql");
    let pk_path = args.get(2).map(|s| s.as_str())
        .unwrap_or("keep/pk.hex");
    let keys_path = args.get(3).map(|s| s.as_str())
        .unwrap_or("/tmp/hus-testnet/wallet/wallet.keys.json");
    let reg_addr = args.get(4).map(|s| s.as_str())
        .unwrap_or("");

    let ctx = Arc::new(ClientContext::new(ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec![endpoint.to_string()]),
            ..Default::default()
        },
        ..Default::default()
    })?);

    let keys_content = std::fs::read_to_string(keys_path)?;
    let k: serde_json::Value = serde_json::from_str(&keys_content)?;
    let signer = Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: k["public"].as_str().unwrap_or("").to_string(),
            secret: k["secret"].as_str().unwrap_or("").to_string(),
        },
    };

    let registry = HusRegistry::new(ctx.clone(), reg_addr);

    println!("=== Proving Key Upload ===");
    println!("Endpoint:     {}", endpoint);
    println!("PK hex file:  {}", pk_path);
    println!("Registry:     {}", reg_addr);
    println!("");

    match registry.upload_proving_key_from_hex_file(pk_path, signer).await {
        Ok(()) => {
            println!("");
            println!("✅ Proving key uploaded successfully.");
            println!("You can verify by running:");
            println!("  cargo run --example check_pk -p hus-onchain -- {} {}",
                endpoint, reg_addr);
        }
        Err(e) => {
            eprintln!("❌ Upload failed: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
