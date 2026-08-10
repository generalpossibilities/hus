use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use serde_json::Value;
use tvm_block::{Account, CurrencyCollection, Deserializable, InRefValue, Message, MsgAddressInt, Serializable, StateInit, TrComputePhase};
use tvm_client::abi::{
    encode_message, decode_message_body, Abi, AbiContract, CallSet, FunctionHeader,
    ParamsOfDecodeMessageBody, ParamsOfEncodeMessage, Signer,
};
use tvm_client::crypto::KeyPair;
use tvm_client::{ClientConfig, ClientContext};
use tvm_executor::ordinary_transaction::OrdinaryTransactionExecutor;
use tvm_executor::transaction_executor::{ExecuteParams, TransactionExecutor};
use tvm_executor::BlockchainConfig;
use tvm_types::write_boc;
use tvm_vm::executor::Engine;

const WASM_HASH: &str = "66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e";
const WASM_MODULE: &str = "docs:adder/add@0.1.0";
const WASM_FUNCTION: &str = "add";
const WASM_ARGS_HEX: &str = "0102";

const KEEP_ROOT: &str = "/workspaces/hus/keep";
const TVC_PATH: &str = "/workspaces/hus/keep/runwasm-smoke/runWasmSmoke_pubkey_v2_deploy.tvc";
const ABI_PATH: &str = "/workspaces/hus/keep/runwasm-smoke/runWasmSmoke_pubkey.abi.json";
const KEYS_PATH: &str = "/workspaces/hus/keep/hus-testnet/wallet/wallet.keys.json";

const CONFIG_WASM_DIR: &str = "/workspaces/hus/keep/tools/wasm-smoke-harness/config/wasm";
const CONFIG_EMPTY_DIR: &str = "/workspaces/hus/keep/tools/wasm-smoke-harness/config/empty";

struct ExecOutcome {
    exit_code: i32,
    success: bool,
    aborted: bool,
    gas_used: u64,
    minted_shell: i128,
    out_msgs: Vec<String>,
}

async fn run_tx(
    ton: Arc<ClientContext>,
    abi: AbiContract,
    executor: &Box<dyn TransactionExecutor>,
    account_root: &mut tvm_types::Cell,
    params: ExecuteParams,
    message: Message,
) -> Result<ExecOutcome> {
    let (tr, minted_shell) = executor
        .execute_with_libs_and_params(Some(&message), account_root, params)
        .map_err(|e| anyhow!("execute failed: {e}"))?;
    let desc = tr.read_description()?;
    let (exit_code, success, gas_used) = match desc.compute_phase_ref() {
        Some(TrComputePhase::Vm(vm)) => (vm.exit_code, vm.success, vm.gas_used.as_u64()),
        _ => (0, false, 0),
    };
    let mut out_msgs = Vec::new();
    for m in tr.out_msgs.export_vector()? {
        let msg = match m {
            InRefValue(m) => m,
        };
        let cell = msg.serialize()?;
        let boc = write_boc(&cell)?;
        let base64 = base64::engine::general_purpose::STANDARD.encode(&boc);
        let decoded = if let Ok(res) = decode_message_body(
            ton.clone(),
            ParamsOfDecodeMessageBody {
                abi: Abi::Contract(abi.clone()),
                body: base64.clone(),
                is_internal: false,
                ..Default::default()
            },
        ) {
            format!("decoded: {}", serde_json::to_string(&res.value).unwrap_or_default())
        } else if let Ok(res) = decode_message_body(
            ton.clone(),
            ParamsOfDecodeMessageBody {
                abi: Abi::Contract(abi.clone()),
                body: base64.clone(),
                is_internal: true,
                ..Default::default()
            },
        ) {
            format!("decoded(internal): {}", serde_json::to_string(&res.value).unwrap_or_default())
        } else {
            let mut s = String::new();
            dump_msg_tree(&cell, 1, &mut s)?;
            format!("raw msg cell tree:\n{s}")
        };
        out_msgs.push(decoded);
    }
    Ok(ExecOutcome { exit_code, success, aborted: false, gas_used, minted_shell, out_msgs })
}

fn build_params(
    wasm_root: &str,
    whitelist: HashSet<[u8; 32]>,
    engine: wasmtime::Engine,
    cache: HashMap<[u8; 32], wasmtime::component::Component>,
    now_secs: u32,
) -> ExecuteParams {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tvm_vm::executor::EngineTraceInfoType;
    let last = Mutex::new(VecDeque::new());
    let trace_callback = Arc::new(move |_: &Engine, info: &tvm_vm::executor::EngineTraceInfo| {
        last.lock().unwrap().push_back((info.step, info.cmd_str.clone()));
        while last.lock().unwrap().len() > 100 {
            last.lock().unwrap().pop_front();
        }
        if info.cmd_str.contains("RUNWASM") || (info.step >= 100 && info.step <= 130 && info.step != 0) {
            eprintln!("STEP {} {:?} {}: {:?}", info.step, info.info_type, info.cmd_str, info.stack);
        }
        if matches!(info.info_type, EngineTraceInfoType::Exception) {
            eprintln!("TRACE last steps before exception: {:?}", last.lock().unwrap());
        }
    });
    ExecuteParams {
        block_unixtime: now_secs,
        debug: true,
        trace_callback: Some(trace_callback),
        wasm_binary_root_path: wasm_root.to_string(),
        wasm_hash_whitelist: whitelist,
        wasm_engine: Some(engine),
        wasm_component_cache: cache,
        ..Default::default()
    }
}

async fn encode_call(
    ton: Arc<ClientContext>,
    abi: AbiContract,
    addr: &str,
    function_name: &str,
    input: Value,
) -> Result<Message> {
    let keys: KeyPair = serde_json::from_str(&std::fs::read_to_string(KEYS_PATH)?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let msg_params = ParamsOfEncodeMessage {
        abi: Abi::Contract(abi),
        address: Some(addr.to_string()),
        call_set: Some(CallSet {
            function_name: function_name.to_string(),
            input: Some(input),
            header: Some(FunctionHeader {
                expire: Some((now / 1000) as u32 + 600),
                time: Some(now),
                ..Default::default()
            }),
            ..Default::default()
        }),
        signer: Signer::Keys { keys },
        ..Default::default()
    };
    let result = encode_message(ton.clone(), msg_params).await?;
    Ok(Message::construct_from_base64(&result.message)?)
}

fn hash_set(hash_strs: &[&str]) -> HashSet<[u8; 32]> {
    hash_strs
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).unwrap();
            bytes.try_into().unwrap()
        })
        .collect()
}

fn dump_msg_tree(cell: &tvm_types::Cell, depth: usize, out: &mut String) -> Result<()> {
    let slice = tvm_types::SliceData::load_cell(cell.clone())?;
    let nbits = slice.remaining_bits();
    let data_hex = hex::encode(slice.get_bytestring(0));
    out.push_str(&format!("{}bits={} data={}\n", "  ".repeat(depth), nbits, data_hex));
    for i in 0..slice.remaining_references() {
        dump_msg_tree(&slice.reference(i)?, depth + 1, out)?;
    }
    Ok(())
}

fn print_outcome(label: &str, o: &ExecOutcome) {
    println!("[{label}] exit_code={} success={} aborted={} gas_used={} minted_shell={}",
        o.exit_code, o.success, o.aborted, o.gas_used, o.minted_shell);
    for m in &o.out_msgs {
        println!("[{label}] out msg: {m}");
    }
}

fn rebuild_deploy_tvc() -> Result<()> {
    use tvm_types::Cell;
    let mut state_init = StateInit::construct_from_file(
        "/workspaces/hus/keep/runwasm-smoke/runWasmSmoke_pubkey_deploy.tvc",
    )?;
    let new_code = Cell::construct_from_file(
        "/tmp/opencode/build-runwasm/runWasmSmoke_pubkey.tvc",
    )?;
    state_init.set_code(new_code);
    let old_data = state_init.data().ok_or(anyhow!("no data in old tvc"))?.clone();
    let mut s = tvm_types::SliceData::load_cell(old_data)?;
    let pubkey = s.get_next_bits(256)?;
    let mut b = tvm_types::BuilderData::new();
    b.append_raw(&pubkey, 256)?;
    b.append_raw(&0u64.to_be_bytes(), 64)?;
    b.append_raw(&[0u8], 1)?;
    b.append_raw(&0u32.to_be_bytes(), 32)?;
    b.checked_append_reference(Cell::default())?;
    state_init.set_data(b.into_cell()?);
    let cell = state_init.serialize()?;
    std::fs::write(TVC_PATH, write_boc(&cell)?)?;
    println!("v2 deploy tvc written: {TVC_PATH}");
    println!("v2 addr: 0:{}", cell.repr_hash().as_hex_string());
    Ok(())
}

fn dump_cell_rec(cell: &tvm_types::Cell, depth: usize, label: &str) -> Result<()> {
    use tvm_types::Cell;
    let slice = tvm_types::SliceData::load_cell(cell.clone())?;
    let nbits = slice.remaining_bits();
    let data_hex = hex::encode(slice.get_bytestring(0));
    println!("{}{label} bits={nbits} data={data_hex}", "  ".repeat(depth));
    for i in 0..slice.remaining_references() {
        dump_cell_rec(&slice.reference(i)?, depth + 1, &format!("ref[{i}] "))?;
    }
    Ok(())
}

fn dump_c4(label: &str, account_root: &tvm_types::Cell) -> Result<()> {
    let account = Account::construct_from_cell(account_root.clone())?;
    if let Some(tvm_block::accounts::AccountState::AccountActive { state_init }) = account.state() {
        if let Some(data) = state_init.data() {
            println!("[{label}] c4 tree:");
            dump_cell_rec(data, 1, "c4 ")?;
        }
    }
    Ok(())
}

fn dump_tvc_data(path: &str) -> Result<()> {
    use tvm_types::Cell;
    let si = StateInit::construct_from_file(path)?;
    println!("tvc: {path}");
    println!("code hash: 0:{}", si.code().map(|c| c.repr_hash().as_hex_string()).unwrap_or_default());
    println!("data hash: 0:{}", si.data().map(|c| c.repr_hash().as_hex_string()).unwrap_or_default());
    if let Some(data) = si.data() {
        let mut s = tvm_types::SliceData::load_cell(data.clone())?;
        let bits = s.get_bytestring(0);
        println!("data bits: {} ({} bits)", hex::encode(&bits), bits.len() * 8);
        println!("data refs: {}", s.remaining_references());
        for i in 0..s.remaining_references() {
            let r = tvm_types::SliceData::load_cell(s.reference(i)?)?;
            println!("  ref[{i}]: bits: {}", hex::encode(r.get_bytestring(0)));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("rebuild-tvc") => return rebuild_deploy_tvc(),
        Some("dump-tvc") => {
            return dump_tvc_data(
                std::env::args().nth(2).as_deref().unwrap_or(TVC_PATH),
            )
        }
        _ => {}
    }
    simplelog::SimpleLogger::init(
        simplelog::LevelFilter::Debug,
        simplelog::ConfigBuilder::new().add_filter_ignore("tvm_client".to_string()).build(),
    )?;

    let ton = Arc::new(ClientContext::new(ClientConfig::default())?);
    let abi: AbiContract = serde_json::from_str(&std::fs::read_to_string(ABI_PATH)?)?;

    let state_init = StateInit::construct_from_file(TVC_PATH)?;
    let state_cell = state_init.serialize()?;
    let addr_str = format!("0:{}", state_cell.repr_hash().as_hex_string());
    let mut account = Account::active_by_init_code_hash(
        MsgAddressInt::from_str(&addr_str)?,
        CurrencyCollection::with_grams(u64::MAX),
        0,
        state_init,
        true,
    )?;
    
    println!("account addr: {addr_str}");
    let mut account_root = account.serialize()?;

    let wasm_engine = Engine::extern_wasm_engine_init()?;
    let now_secs = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() / 1000) as u32;
    let our_hash = hash_set(&[WASM_HASH]);
    let our_cache = Engine::extern_precompile_all_wasm_from_hash_list(
        CONFIG_WASM_DIR.to_string(),
        wasm_engine.clone(),
        our_hash.clone(),
    );
    println!("precompiled components in cache: {}", our_cache.len());

    let bc_config = BlockchainConfig::default();
    let executor: Box<dyn TransactionExecutor> = Box::new(OrdinaryTransactionExecutor::new(bc_config));

    let deploy_msg = encode_call(ton.clone(), abi.clone(), &addr_str, "constructor", serde_json::json!({"value": 1000000})).await?;
    let deploy_params = build_params(CONFIG_WASM_DIR, our_hash.clone(), wasm_engine.clone(), our_cache.clone(), now_secs);
    let outcome = run_tx(ton.clone(), abi.clone(), &executor, &mut account_root, deploy_params, deploy_msg).await?;
    print_outcome("deploy", &outcome);
    if outcome.exit_code != 0 || !outcome.success {
        bail!("deploy failed");
    }

    let account_after = Account::construct_from_cell(account_root.clone())?;
    let state = match account_after.state() {
        Some(tvm_block::accounts::AccountState::AccountActive { .. }) => "active",
        Some(tvm_block::accounts::AccountState::AccountUninit { .. }) => "uninit",
        Some(tvm_block::accounts::AccountState::AccountFrozen { .. }) => "frozen",
        None => "none",
    };
    println!("post-deploy account state: {state}");
    write_boc(&account_root)?;
    std::fs::write("/tmp/opencode/acc.boc", write_boc(&account_root)?)?;
    let call_msg = encode_call(
        ton.clone(),
        abi.clone(),
        &addr_str,
        "runWasm5",
        serde_json::json!({
            "wasmBinary": "",
            "wasmModule": WASM_MODULE,
            "wasmFunction": WASM_FUNCTION,
            "wasmArgs": WASM_ARGS_HEX,
            "wasmHash": WASM_HASH,
        }),
    )
    .await?;
    let call_cell = call_msg.serialize()?;
    std::fs::write("/tmp/opencode/call.boc", write_boc(&call_cell)?)?;
    println!("dumped acc.boc and call.boc");

    let inline_wasm_hex = hex::encode(std::fs::read(format!("{CONFIG_WASM_DIR}/{WASM_HASH}"))?);
    let scenarios: Vec<(&str, Value, &str, bool)> = vec![
        (
            "run-hash",
            serde_json::json!({
                "wasmBinary": "",
                "wasmModule": WASM_MODULE,
                "wasmFunction": WASM_FUNCTION,
                "wasmArgs": WASM_ARGS_HEX,
                "wasmHash": WASM_HASH,
            }),
            CONFIG_WASM_DIR,
            true,
        ),
        (
            "run-inline",
            serde_json::json!({
                "wasmBinary": inline_wasm_hex,
                "wasmModule": WASM_MODULE,
                "wasmFunction": WASM_FUNCTION,
                "wasmArgs": WASM_ARGS_HEX,
                "wasmHash": WASM_HASH,
            }),
            CONFIG_EMPTY_DIR,
            false,
        ),
        (
            "run-missing",
            serde_json::json!({
                "wasmBinary": "",
                "wasmModule": WASM_MODULE,
                "wasmFunction": WASM_FUNCTION,
                "wasmArgs": WASM_ARGS_HEX,
                "wasmHash": WASM_HASH,
            }),
            CONFIG_EMPTY_DIR,
            false,
        ),
        (
            "run-forbidden",
            serde_json::json!({
                "wasmBinary": "",
                "wasmModule": WASM_MODULE,
                "wasmFunction": WASM_FUNCTION,
                "wasmArgs": WASM_ARGS_HEX,
                "wasmHash": WASM_HASH,
            }),
            CONFIG_WASM_DIR,
            false,
        ),
    ];

    for (label, input, root, whitelist_on) in scenarios {
        let whitelist = if whitelist_on { our_hash.clone() } else { HashSet::new() };
        let cache = Engine::extern_precompile_all_wasm_from_hash_list(
            root.to_string(),
            wasm_engine.clone(),
            whitelist.clone(),
        );
        let call_msg = encode_call(ton.clone(), abi.clone(), &addr_str, "runWasm5", input).await?;
        let params = build_params(root, whitelist, wasm_engine.clone(), cache, now_secs);
        let outcome = run_tx(ton.clone(), abi.clone(), &executor, &mut account_root, params, call_msg).await?;
        print_outcome(label, &outcome);
        dump_c4(label, &account_root)?;
    }

    Ok(())
}
