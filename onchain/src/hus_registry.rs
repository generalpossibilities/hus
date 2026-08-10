use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tvm_client::abi::{Abi, CallSet, Signer};
use tvm_client::processing::{self, ParamsOfSendMessage, ResultOfSendMessage};
use tvm_client::tvm::{self, ParamsOfRunTvm};
use tvm_client::ClientContext;

const ABI: &str = include_str!("../abi/HusRegistry.abi.json");

const CHUNK_SIZE: usize = 32768;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpgradeInfo {
    #[serde(rename = "newCode")]
    pub new_code: String,
    #[serde(rename = "newVk")]
    pub new_vk: String,
    #[serde(rename = "proposedAt")]
    pub proposed_at: u32,
}

#[derive(Debug)]
pub struct HusRegistry {
    context: Arc<ClientContext>,
    address: String,
    abi: Abi,
}

impl HusRegistry {
    pub fn new(context: Arc<ClientContext>, address: impl Into<String>) -> Self {
        Self {
            context,
            address: address.into(),
            abi: Abi::Json(ABI.to_string()),
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    fn dapp_id(&self) -> String {
        if self.address.contains("::") {
            self.address.split("::").next().unwrap_or("").to_string()
        } else {
            self.address.trim_start_matches("0:").to_string()
        }
    }

    async fn send_message(
        &self,
        call_set: CallSet,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let encode_params = tvm_client::abi::ParamsOfEncodeMessage {
            abi: self.abi.clone(),
            address: Some(self.address.clone()),
            call_set: Some(call_set),
            signer,
            deploy_set: None,
            processing_try_index: None,
            signature_id: None,
        };
        let encoded = tvm_client::abi::encode_message(Arc::clone(&self.context), encode_params)
            .await
            .map_err(|e| format!("encode: {e}"))?;

        let params = ParamsOfSendMessage {
            message: encoded.message,
            abi: Some(self.abi.clone()),
            thread_id: None,
            send_events: false,
            dapp_id: self.dapp_id(),
        };
        processing::send_message(Arc::clone(&self.context), params, |_| async {})
            .await
            .map_err(|e| format!("send: {e}"))
    }

    async fn run_tvm(&self, call_set: CallSet) -> Result<serde_json::Value, String> {
        let encode_params = tvm_client::abi::ParamsOfEncodeMessage {
            abi: self.abi.clone(),
            address: Some(self.address.clone()),
            call_set: Some(call_set),
            signer: Signer::None,
            deploy_set: None,
            processing_try_index: None,
            signature_id: None,
        };
        let encoded = tvm_client::abi::encode_message(Arc::clone(&self.context), encode_params)
            .await
            .map_err(|e| format!("encode: {e}"))?;

        let params = ParamsOfRunTvm {
            message: encoded.message,
            account: String::new(),
            abi: Some(self.abi.clone()),
            execution_options: None,
            boc_cache: None,
            return_updated_account: None,
        };
        let result = tvm::run_tvm(Arc::clone(&self.context), params)
            .await
            .map_err(|e| format!("run_tvm: {e}"))?;

        let decoded = result.decoded.ok_or("no decoded output")?;
        let output = decoded.output.ok_or("no output in decoded")?;
        Ok(output)
    }

    // ── Admin methods ───────────────────────────────────────────

    pub async fn set_proving_key(
        &self,
        pk: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "setProvingKey".to_string(),
            header: None,
            input: Some(json!({
                "pk": pk,
            })),
        };
        self.send_message(call_set, signer).await
    }

    pub async fn set_vk(&self, vk: &str, signer: Signer) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "setVk".to_string(),
            header: None,
            input: Some(json!({
                "vk": vk,
            })),
        };
        self.send_message(call_set, signer).await
    }

    // ── Chunked proving key storage ────────────────────────────

    pub async fn set_proving_key_chunk(
        &self,
        index: u16,
        chunk: &[u8],
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let chunk_hex = hex::encode(chunk);
        let call_set = CallSet {
            function_name: "setProvingKeyChunk".to_string(),
            header: None,
            input: Some(json!({
                "index": index,
                "chunk": chunk_hex,
            })),
        };
        self.send_message(call_set, signer).await
    }

    pub async fn clear_proving_key_chunks(
        &self,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "clearProvingKeyChunks".to_string(),
            header: None,
            input: None,
        };
        self.send_message(call_set, signer).await
    }

    pub async fn set_proving_key_hash(
        &self,
        hash: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "setProvingKeyHash".to_string(),
            header: None,
            input: Some(json!({
                "hash": hash,
            })),
        };
        self.send_message(call_set, signer).await
    }

    /// Upload a full proving key in chunks.
    /// Splits `pk_bytes` into CHUNK_SIZE pieces and sends them one by one,
    /// then sets the SHA-256 hash for integrity verification.
    pub async fn upload_proving_key(
        &self,
        pk_bytes: &[u8],
        signer: Signer,
    ) -> Result<(), String> {
        let hash = Self::sha256(pk_bytes);
        let chunks: Vec<&[u8]> = pk_bytes.chunks(CHUNK_SIZE).collect();
        let total = chunks.len();

        println!("Splitting PK ({} bytes) into {} chunks of {} bytes each",
            pk_bytes.len(), total, CHUNK_SIZE);
        println!("PK hash: 0x{}", hex::encode(&hash));

        // Clear any existing chunks first
        self.clear_proving_key_chunks(signer.clone()).await?;

        for (i, chunk) in chunks.iter().enumerate() {
            println!("  Uploading chunk {}/{} ({} bytes)...", i + 1, total, chunk.len());
            self.set_proving_key_chunk(i as u16, chunk, signer.clone()).await?;
        }

        // Set the integrity hash
        self.set_proving_key_hash(&format!("0x{}", hex::encode(&hash)), signer).await?;
        println!("All chunks uploaded. Hash set for integrity verification.");

        Ok(())
    }

    /// Fetch the full proving key from on-chain chunks.
    /// Returns the reassembled binary PK and verifies the hash if one is set.
    pub async fn fetch_proving_key(&self) -> Result<Vec<u8>, String> {
        let count = self.get_proving_key_chunk_count().await?;
        if count == 0 {
            return Err("no proving key chunks on chain".to_string());
        }

        let mut pk = Vec::new();
        for i in 0..count {
            let chunk = self.get_proving_key_chunk(i).await?;
            let chunk_bytes = hex::decode(&chunk).map_err(|e| format!("hex decode chunk {i}: {e}"))?;
            pk.extend_from_slice(&chunk_bytes);
        }

        // Verify hash
        let onchain_hash = self.get_proving_key_hash().await?;
        if !onchain_hash.is_empty() && onchain_hash != "0" {
            let computed = Self::sha256(&pk);
            let expected = hex::decode(&onchain_hash).map_err(|e| format!("hex decode hash: {e}"))?;
            if computed != expected.as_slice() {
                return Err("proving key hash mismatch — data may be corrupt".to_string());
            }
            println!("Proving key integrity verified (SHA-256 match).");
        }

        Ok(pk)
    }

    /// Upload a proving key from a hex file: reads, decodes, chunks, uploads.
    pub async fn upload_proving_key_from_hex_file(
        &self,
        hex_path: &str,
        signer: Signer,
    ) -> Result<(), String> {
        let hex_str = std::fs::read_to_string(hex_path)
            .map_err(|e| format!("read {}: {e}", hex_path))?;
        let hex_str = hex_str.trim();
        let pk = hex::decode(hex_str).map_err(|e| format!("hex decode: {e}"))?;
        self.upload_proving_key(&pk, signer).await
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }

    // ── App management ─────────────────────────────────────────

    pub async fn register_app(
        &self,
        app_name: &str,
        modality_ids: &[u8],
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "registerApp".to_string(),
            header: None,
            input: Some(json!({
                "appName": app_name,
                "modalityIds": modality_ids,
            })),
        };
        self.send_message(call_set, signer).await
    }

    // ── Timelocked upgrade ─────────────────────────────────────

    pub async fn propose_app_upgrade(
        &self,
        app_id: &str,
        new_code_base64: &str,
        new_vk: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "proposeAppUpgrade".to_string(),
            header: None,
            input: Some(json!({
                "appId": app_id,
                "newCode": new_code_base64,
                "newVk": new_vk,
            })),
        };
        self.send_message(call_set, signer).await
    }

    pub async fn cancel_app_upgrade(
        &self,
        app_id: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "cancelAppUpgrade".to_string(),
            header: None,
            input: Some(json!({
                "appId": app_id,
            })),
        };
        self.send_message(call_set, signer).await
    }

    pub async fn execute_app_upgrade(
        &self,
        app_id: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "executeAppUpgrade".to_string(),
            header: None,
            input: Some(json!({
                "appId": app_id,
            })),
        };
        self.send_message(call_set, signer).await
    }

    // ── View methods ────────────────────────────────────────────

    pub async fn get_app_address(&self, app_id: &str) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getAppAddress".to_string(),
            header: None,
            input: Some(json!({ "appId": app_id })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn is_app_registered(&self, app_id: &str) -> Result<bool, String> {
        let call_set = CallSet {
            function_name: "isAppRegistered".to_string(),
            header: None,
            input: Some(json!({ "appId": app_id })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_bool().ok_or("no value0")?)
    }

    pub async fn get_proving_key(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getProvingKey".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn get_vk(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getVk".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn get_upgrade_delay(&self) -> Result<u32, String> {
        let call_set = CallSet {
            function_name: "getUpgradeDelay".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"]
            .as_str()
            .ok_or("missing value0")?
            .parse()
            .map_err(|_| "invalid value0")?)
    }

    pub async fn get_pending_upgrade(&self, app_id: &str) -> Result<PendingUpgradeInfo, String> {
        let call_set = CallSet {
            function_name: "getPendingUpgrade".to_string(),
            header: None,
            input: Some(json!({ "appId": app_id })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(        PendingUpgradeInfo {
            new_code: output["newCode"].as_str().ok_or("missing newCode")?.to_string(),
            new_vk: output["newVk"].as_str().ok_or("missing newVk")?.to_string(),
            proposed_at: output["proposedAt"]
                .as_str()
                .ok_or("missing proposedAt")?
                .parse()
                .map_err(|_| "invalid proposedAt")?,
        })
    }

    pub async fn is_upgrade_ready(&self, app_id: &str) -> Result<bool, String> {
        let call_set = CallSet {
            function_name: "isUpgradeReady".to_string(),
            header: None,
            input: Some(json!({ "appId": app_id })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_bool().ok_or("no value0")?)
    }

    pub async fn get_proving_key_chunk_count(&self) -> Result<u16, String> {
        let call_set = CallSet {
            function_name: "getProvingKeyChunkCount".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(serde_json::from_value(output["value0"].clone())
            .map_err(|e| format!("parse chunk count: {e}"))?)
    }

    pub async fn get_proving_key_chunk(&self, index: u16) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getProvingKeyChunk".to_string(),
            header: None,
            input: Some(json!({ "index": index })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn get_proving_key_hash(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getProvingKeyHash".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn get_version(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getVersion".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }
}
