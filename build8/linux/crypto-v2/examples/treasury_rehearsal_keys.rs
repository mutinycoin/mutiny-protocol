//! TEST-VALUE Treasury rehearsal key tool (SIMULATED, not production). See
//! docs/TREASURY-REHEARSAL-TOOLING-V1.md. Build: --features wallet-custody. Never part of a node.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = mutiny_crypto_v2::rehearsal_keys_v1::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
