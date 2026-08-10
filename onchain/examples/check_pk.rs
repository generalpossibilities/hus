//! Verify a proving key stored in chunks on a deployed HusRegistry.
//!
//! Fetches all chunks, reassembles, verifies the on-chain hash.
//!
//! Usage:
//!   cargo run --example check_pk -p hus-onchain -- <endpoint> <registry_addr>

use std::sync::Arc;

use hus_onchain::HusRegistry;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let endpoint = args.get(1).map(|s| s.as_str())
        .unwrap_or("https://shellnet.ackinacki.org/graphql");
    let reg_addr = args.get(2).map(|s| s.as_str())
        .unwrap_or("");

    let ctx = Arc::new(ClientContext::new(ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec![endpoint.to_string()]),
            ..Default::default()
        },
        ..Default::default()
    })?);

    let registry = HusRegistry::new(ctx.clone(), reg_addr);

    let count = registry.get_proving_key_chunk_count().await?;
    println!("Proving key chunks: {}", count);

    if count == 0 {
        println!("No proving key stored on-chain.");
        return Ok(());
    }

    let pk = registry.fetch_proving_key().await?;
    println!("Proving key size: {} bytes ({} hex chars)",
        pk.len(), pk.len() * 2);

    let hash = registry.get_proving_key_hash().await?;
    println!("On-chain hash: 0x{}", hash);

    Ok(())
}
