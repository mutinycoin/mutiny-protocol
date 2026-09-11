# Build 7.0 Candidate 2

Visible identity: **Mutiny Protocol V1.0 Build 7.0 Candidate 2**.

Candidate 1 (`575ff7e6de0b149354a93eccfd9c0334acafa3cd`) is failed historical evidence. Its release CLI staged Block 1, then called ordinary full replay, which intentionally rejects Mainnet Genesis -> Block 1. The ordinary rejection guard remains intact.

Candidate 2 changes the explicit `bootstrap-mainnet` command to use the existing authenticated runtime-aware full replay before the atomic storage commit. Replay calls the existing runtime block-application boundary; no second consensus implementation or unauthenticated exception is introduced. The command authenticates the canonical witness, reads the committed input snapshot without recovery/migration, requires clean Mainnet height 0 and verifies the complete Genesis prestate through runtime replay, stages and checks the locked identities, verifies replay, commits once, reloads and byte-compares the result. Pending journals require separate recovery; bootstrap itself never performs recovery or migration during preflight.

Build 6.9 remains the production authority. This candidate does not authorize deployment, production Block 1, services, listeners, custody changes or mining.

## Real CLI regression gate

Set `CARGO_TARGET_DIR` outside the source tree and `MUTINY_MAINNET_BOOTSTRAP_WITNESS` to the canonical witness (161323 bytes, SHA-256 `b115c11cc8a4085a5d950be608c0e6448d9d3823d3ab15fb439d1fd231aa6126`). Preserve Git LF bytes in the checkout.

```text
cargo fmt --all -- --check
cargo test --release --locked -p mutiny-node --test bootstrap_mainnet_cli
cargo test --locked -p mutiny-node mainnet_bootstrap::
cargo test --locked --workspace build70
cargo test --locked --workspace
cargo build --release --locked -p mutiny-node --bin mutinyd
```

The integration tests spawn the real executable: init, bootstrap-mainnet, status, check, storage-verify and repeat invocation. They compare directory membership and exact file bytes on every negative case. They cover missing/invalid witnesses, malformed framing, wrong hash/network/Genesis, truncated/trailing bytes, wrong/implicit runtime network, wrong stored network, repeat invocation at height 1, absent storage, legacy input, a pending journal and all four dirty Genesis anchor fields. All fixture output is outside the source tree and is retained after success or failure.

`MUTINY_BUILD70_CLI_EVIDENCE_DIR` selects the evidence parent. `MUTINY_BUILD70_RELEASE_EXE` may select an independently built release executable; otherwise Cargo's actual `mutinyd` executable for the selected profile is used. Run the focused gate with `--release`, and point the later workspace run at the verified release executable. Neither setting replaces the CLI with internal helper calls. The canonical witness is mandatory; missing test input is an error, not a skipped passing test.

To demonstrate the regression, select the preserved Candidate 1 executable with `MUTINY_BUILD70_RELEASE_EXE` and run only `build70_candidate2_cli_activation_and_repeat`. It must fail at the real bootstrap command with the ordinary height-0 guard error. Preserve that expected Candidate 1 failure separately; it is not a Candidate 2 validation pass.

After the listed gates, run a separately scripted release-executable activation in another fresh isolated directory and preserve its executable identity, commands, outputs, exit statuses and directory manifests. Push only after all Candidate 2 gates pass. A passing candidate is not a formal lock or deployment authorization.
