use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tvm_client::abi::{Abi, CallSet, Signer};
use tvm_client::processing::{self, ParamsOfSendMessage, ResultOfSendMessage};
use tvm_client::tvm::{self, ParamsOfRunTvm};
use tvm_client::ClientContext;

const ABI: &str = include_str!("../abi/HusApp.abi.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainModalityConfig {
    #[serde(rename = "modalityId")]
    pub modality_id: String,
    #[serde(rename = "projDim")]
    pub proj_dim: String,
    #[serde(rename = "minScore")]
    pub min_score: String,
}

#[derive(Debug)]
pub struct HusApp {
    context: Arc<ClientContext>,
    address: String,
    abi: Abi,
}

impl HusApp {
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

    /// Return just the account_id in `0:hex64` format for the SDK.
    fn account_id_0x(&self) -> String {
        if self.address.contains("::") {
            let hex = self.address.split("::").nth(1).unwrap_or("");
            format!("0:{hex}")
        } else if self.address.starts_with("0:") {
            self.address.clone()
        } else {
            format!("0:{}", self.address)
        }
    }

    async fn send_message(
        &self,
        call_set: CallSet,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let encode_params = tvm_client::abi::ParamsOfEncodeMessage {
            abi: self.abi.clone(),
            address: Some(self.account_id_0x()),
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
            .map_err(|e| format!("send: {:?}", e))
    }

    async fn send_process_message(
        &self,
        call_set: CallSet,
        signer: Signer,
    ) -> Result<Value, String> {
        let encode_params = tvm_client::abi::ParamsOfEncodeMessage {
            abi: self.abi.clone(),
            address: Some(self.account_id_0x()),
            call_set: Some(call_set),
            signer,
            deploy_set: None,
            processing_try_index: None,
            signature_id: None,
        };
        let params = tvm_client::processing::ParamsOfProcessMessage {
            message_encode_params: encode_params,
            send_events: false,
            dapp_id: self.dapp_id(),
        };
        let result = processing::process_message(Arc::clone(&self.context), params, |_| async {})
            .await
            .map_err(|e| format!("process: {:?}", e))?;
        let output = result
            .decoded
            .and_then(|d| d.output)
            .ok_or("no decoded output".to_string())?;
        Ok(output)
    }

    async fn run_tvm(&self, call_set: CallSet) -> Result<serde_json::Value, String> {
        let encode_params = tvm_client::abi::ParamsOfEncodeMessage {
            abi: self.abi.clone(),
            address: Some(self.account_id_0x()),
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

    // ── Registry-controlled methods ────────────────────────────

    /// Sets a new verifying key on this HusApp.
    /// Only callable by the HusRegistry contract (not directly from an external key).
    pub async fn set_vk(
        &self,
        new_vk: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "setVk".to_string(),
            header: None,
            input: Some(json!({
                "newVk": new_vk,
            })),
        };
        self.send_message(call_set, signer).await
    }

    // ── Write methods ──────────────────────────────────────────

    /// Register a vector whose proof the verifier has already checked
    /// off-chain. Only the key set with `set_verifier` may sign this; the
    /// proof is stored so anyone can re-check it.
    pub async fn submit_verified(
        &self,
        commitment_hash: &str,
        v_obf: &[i64],
        proof: &str,
        binding: &str,
        modality_id: u8,
        signer: Signer,
    ) -> Result<Value, String> {
        let v_obf_json: Vec<serde_json::Value> = v_obf.iter().map(|v| json!(v)).collect();
        let call_set = CallSet {
            function_name: "submitVerified".to_string(),
            header: None,
            input: Some(json!({
                "commitmentHash": commitment_hash,
                "vObf": v_obf_json,
                "proof": proof,
                "binding": binding,
                "modalityId": modality_id,
            })),
        };
        self.send_process_message(call_set, signer).await
    }

    /// Name the verifier key (signed by the app operator's key).
    pub async fn set_verifier(
        &self,
        verifier_pubkey: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "setVerifier".to_string(),
            header: None,
            input: Some(json!({
                "verifierPubkey": verifier_pubkey,
            })),
        };
        self.send_message(call_set, signer).await
    }

    pub async fn deposit(
        &self,
        payment_id: &str,
        signer: Signer,
    ) -> Result<ResultOfSendMessage, String> {
        let call_set = CallSet {
            function_name: "deposit".to_string(),
            header: None,
            input: Some(json!({
                "paymentId": payment_id,
            })),
        };
        self.send_message(call_set, signer).await
    }

    // ── View methods ──────────────────────────────────────────

    pub async fn check_duplicate(&self, commitment_hash: &str) -> Result<bool, String> {
        let call_set = CallSet {
            function_name: "checkDuplicate".to_string(),
            header: None,
            input: Some(json!({
                "commitmentHash": commitment_hash,
            })),
        };
        let output = self.run_tvm(call_set).await?;
        let val = output["value0"].as_bool().ok_or("no value0 in output")?;
        Ok(val)
    }

    pub async fn get_registration(&self, index: u32) -> Result<RegistrationInfo, String> {
        let call_set = CallSet {
            function_name: "getRegistration".to_string(),
            header: None,
            input: Some(json!({
                "index": index,
            })),
        };
        let output = self.run_tvm(call_set).await?;
        Ok(RegistrationInfo {
            commitment_hash: output["commitmentHash"]
                .as_str()
                .ok_or("missing commitmentHash")?
                .to_string(),
            v_obf: output["vObf"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str()?.parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
            modality_id: output["modalityId"]
                .as_str()
                .ok_or("missing modalityId")?
                .parse()
                .map_err(|_| "invalid modalityId")?,
            timestamp: output["timestamp"]
                .as_str()
                .ok_or("missing timestamp")?
                .parse()
                .map_err(|_| "invalid timestamp")?,
            proof: output["proof"].as_str().unwrap_or("").to_string(),
            binding: output["binding"].as_str().unwrap_or("").to_string(),
        })
    }

    pub async fn get_registration_count(&self) -> Result<u32, String> {
        let call_set = CallSet {
            function_name: "getRegistrationCount".to_string(),
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

    pub async fn get_app_info(&self) -> Result<AppInfo, String> {
        let call_set = CallSet {
            function_name: "getAppInfo".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(AppInfo {
            vk: output["vk"].as_str().ok_or("missing vk")?.to_string(),
            app_version: output["appVersion"]
                .as_str()
                .ok_or("missing appVersion")?
                .parse()
                .map_err(|_| "invalid appVersion")?,
            seed_hash: output["seedHash"]
                .as_str()
                .ok_or("missing seedHash")?
                .to_string(),
            registration_count: output["registrationCount"]
                .as_str()
                .ok_or("missing registrationCount")?
                .parse()
                .map_err(|_| "invalid registrationCount")?,
        })
    }

    pub async fn get_balance(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getBalance".to_string(),
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

    pub async fn get_verification_fee(&self) -> Result<String, String> {
        let call_set = CallSet {
            function_name: "getVerificationFee".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        Ok(output["value0"].as_str().ok_or("no value0")?.to_string())
    }

    pub async fn get_modality_configs(&self) -> Result<Vec<ChainModalityConfig>, String> {
        let call_set = CallSet {
            function_name: "getModalityConfigs".to_string(),
            header: None,
            input: None,
        };
        let output = self.run_tvm(call_set).await?;
        let arr = output["value0"]
            .as_array()
            .ok_or("getModalityConfigs: expected array")?;
        let mut configs = Vec::with_capacity(arr.len());
        for val in arr {
            configs.push(serde_json::from_value(val.clone()).map_err(|e| {
                format!("getModalityConfigs: deser {e}")
            })?);
        }
        Ok(configs)
    }

    pub async fn get_modality_config(&self, modality_id: u8) -> Result<ChainModalityConfig, String> {
        let call_set = CallSet {
            function_name: "getModalityConfig".to_string(),
            header: None,
            input: Some(json!({ "modalityId": modality_id })),
        };
        let output = self.run_tvm(call_set).await?;
        serde_json::from_value(output["value0"].clone())
            .map_err(|e| format!("getModalityConfig: deser {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub vk: String,
    pub app_version: u32,
    pub seed_hash: String,
    pub registration_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInfo {
    pub commitment_hash: String,
    pub v_obf: Vec<i64>,
    pub modality_id: u8,
    pub timestamp: u32,
    pub proof: String,
    /// proof_binding(owner key, challenge) as a uint256 string.
    pub binding: String,
}
