use wasmtime::*;
fn main() -> Result<()> {
    let mut cfg = Config::new();
    cfg.consume_fuel(true).wasm_simd(false).wasm_relaxed_simd(false);
    let engine = Engine::new(&cfg)?;
    let module = Module::from_file(&engine, std::env::args().nth(1).unwrap())?;
    // Stages to run: from the command line (`label=stage` or `stage`), else the original sweep.
    let args: Vec<(String, u32)> = std::env::args().skip(2).map(|a| match a.split_once('=') {
        Some((l, s)) => (l.to_string(), s.parse().unwrap()),
        None => (format!("stage {a}"), a.parse().unwrap()),
    }).collect();
    let default = [("loop 256k (passes AVM)", 0x18u32), ("loop 512k", 0x19), ("loop 1024k (fails AVM)", 0x1a),
                   ("stage 5: G1 points only", 5), ("stage 6: one G2 point", 6), ("stage 1: parse all", 1),
                   ("stage 2: parse + MSM", 2), ("stage 3: parse + pairing", 3), ("stage 4: full verify", 4)]
        .map(|(l, s)| (l.to_string(), s));
    for (label, stage) in if args.is_empty() { default.to_vec() } else { args } {
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX)?;
        let inst = Instance::new(&mut store, &module, &[])?;
        let f = inst.get_typed_func::<u32, u32>(&mut store, "run")?;
        let r = f.call(&mut store, stage)?;
        let used = u64::MAX - store.get_fuel()?;
        println!("{label:<28} result {r}  fuel {used:>14}");
    }
    Ok(())
}
