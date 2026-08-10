pragma tvm-solidity >=0.76.1;
pragma AbiHeader pubkey;
pragma AbiHeader expire;

// Smoke test for RUNWASM on Shellnet v0.18.0.
//
// RUNWASM is hash-mode on the node: sold pushes args left-to-right
// (arg0 at stack bottom), while tvm_vm's execute_run_wasm reads
// var(0)=wasmBinary (top) .. var(4)=wasmHash (bottom). The call must
// therefore list the arguments in REVERSE order: (hash, args, func,
// module, binary) — exactly like acki-nacki's own Miner.sol.
// wasmHash must be `bytes` (not bytes32): the executor reads it via
// TokenValue::read_bytes, which requires the ref-chain cell format
// (abi.encode of `bytes`), while abi.encode(bytes32) is stored inline
// as 256 raw bits (0 refs) and triggers CellUnderflow.
// The wasm binary argument is only used by nodes compiled with the
// `wasm_external` feature; otherwise the node loads the binary from its
// local whitelist by sha256.
contract runWasmSmoke {
    uint32 public timestamp;
    bytes public lastResult;

    constructor(uint64 value) {
        gosh.cnvrtshellq(value);
        require(tvm.pubkey() != 0, 101);
        tvm.accept();
        timestamp = block.timestamp;
    }

    function getTokens() private pure {
        if (address(this).balance > 100000000000) {
            return;
        }
        gosh.mintshell(100000000000);
    }

    // Call the official `docs:adder/add@0.1.0` example.
    //   - wasmBinary: pass real bytes. If the node ignores it (default flags)
    //     it must be empty in order to activate hash-mode.
    //   - wasmHash: sha256 of the add.wasm binary (32 bytes).
    //   - wasmArgs: raw bytes [a, b] — the docs:adder add() sums the first two
    //     bytes of the arg payload (byte0 + byte1), not JSON. [0x01,0x02] → [3].
    function runWasm5 (
        bytes wasmBinary,
        string wasmModule,
        string wasmFunction,
        bytes wasmArgs,
        bytes wasmHash
    ) public returns (bytes) {
        tvm.accept();
        getTokens();
        TvmCell wasmResultCell = gosh.runwasm(
            abi.encode(wasmHash),
            abi.encode(wasmArgs),
            abi.encode(wasmFunction),
            abi.encode(wasmModule),
            abi.encode(wasmBinary));
        tvm.commit();
        bytes wasmResult = abi.decode(wasmResultCell, bytes);
        lastResult = wasmResult;
        return wasmResult;
    }

    // Touch to keep contract usable.
    function touch() external {
        tvm.accept();
        getTokens();
        timestamp = block.timestamp;
    }
}