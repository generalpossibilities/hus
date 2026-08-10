use std::sync::Arc;
use tvm_client::abi::{Abi, CallSet, FunctionHeader, ParamsOfEncodeMessage, Signer};
use tvm_client::processing::ParamsOfProcessMessage;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(
        ClientContext::new(ClientConfig {
            network: tvm_client::net::NetworkConfig {
                endpoints: Some(vec!["http://shellnet.ackinacki.org/graphql".to_string()]),
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("create client"),
    );

    let wallet_id = "0e66139ba2d172e3ff9c2d7a1ed19cfb90402805fbe980841e402674f13bd990";
    let wallet_addr = format!("{wallet_id}::{wallet_id}");
    let wallet_abi = Abi::Json(std::fs::read_to_string(
        "hus-testnet/wallet/UpdateCustodianMultisigWallet.abi.json",
    )?);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    async fn call(
        abi: Abi,
        addr: &str,
        fn_name: &str,
        input: Option<serde_json::Value>,
        time: u64,
        ctx: &Arc<ClientContext>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dapp_id = addr.split("::").next().unwrap_or(addr).to_string();
        let r = tvm_client::processing::process_message(
            Arc::clone(ctx),
            ParamsOfProcessMessage {
                message_encode_params: ParamsOfEncodeMessage {
                    abi,
                    address: Some(addr.to_string()),
                    call_set: Some(CallSet {
                        function_name: fn_name.to_string(),
                        header: Some(FunctionHeader {
                            time: Some(time),
                            expire: Some((time / 1000) as u32 + 60),
                            ..Default::default()
                        }),
                        input,
                    }),
                    signer: Signer::None,
                    ..Default::default()
                },
                send_events: false,
                dapp_id,
            },
            |_| async {},
        )
        .await?;
        println!("{fn_name}: decoded={:?}", r.decoded.and_then(|d| d.output));
        println!("  aborted={:?}", r.transaction["aborted"]);
        Ok(())
    }

    call(
        wallet_abi.clone(),
        &wallet_addr,
        "getParameters",
        None,
        time,
        &ctx,
    )
    .await?;
    call(
        wallet_abi.clone(),
        &wallet_addr,
        "getCustodians",
        None,
        time + 1,
        &ctx,
    )
    .await?;
    call(
        wallet_abi.clone(),
        &wallet_addr,
        "getTransactions",
        None,
        time + 2,
        &ctx,
    )
    .await?;
    call(
        wallet_abi.clone(),
        &wallet_addr,
        "getUpdateCodeIds",
        None,
        time + 3,
        &ctx,
    )
    .await?;

    Ok(())
}
