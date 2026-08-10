pragma tvm-solidity >=0.76.1;
pragma AbiHeader expire;

// Smoke test for RUNWASM on Shellnet v0.18.0.
//
// Difference from the outdated WASM.md example: sold >= 0.78.1 builds
// hash-mode RUNWASM, i.e. 5 cells: (emptyBinary, instance, func, args, hash).
// The wasm binary argument is only used by nodes compiled with the
// `wasm_external` feature; otherwise the node loads the binary from its
// local whitelist by sha256.
contract runWasmSmoke {
    uint32 public timestamp;

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
    //   - expected: returns [3] for args [1,2].
    function runWasm5 (
        bytes wasmBinary,
        string wasmModule,
        string wasmFunction,
        bytes wasmArgs,
        bytes32 wasmHash
    ) public returns (bytes) {
        tvm.accept();
        getTokens();
        TvmCell wasmResultCell = gosh.runwasm(
            abi.encode(wasmBinary),
            abi.encode(wasmModule),
            abi.encode(wasmFunction),
            abi.encode(wasmArgs),
            abi.encode(wasmHash));
        tvm.commit();
        bytes wasmResult = abi.decode(wasmResultCell, bytes);
        return wasmResult;
    }

    // Touch to keep contract usable.
    function touch() external {
        tvm.accept();
        getTokens();
        timestamp = block.timestamp;
    }
}