# Build 8 Windows wallet native test runner: operator guide

This runner executes the **software-only, offline, TEST-VALUE** test campaign for the Windows components of Build 8 on
**Windows 10/11 x86_64 (MSVC)**: the offline release signer (`release-signer/`), the Windows wallet (`desktop/`, package
`mutiny-desktop-v8`) and the UI-free wallet library `wallet-core/` of phase 1 (which the Linux package
`package/linux-native-test` also tests). A pass is at most **Windows-native NATIVE PASS (offline, TEST-VALUE)**
(`docs/EVIDENCE-CLASSES-V1.md`). It is **not** Linux evidence, **not** physical clock or TPM qualification, **not** a real wallet or
key, **not** production readiness and **not** release lock. No real wallet is created or touched, no network is used and no TPM
is opened.

## Current state (read this before interpreting a result)
Observed at commit 9520c2f (integration branch `integ/p0b`, phases 0B, 0C and 1 merged) on the Windows 11 test host, as a complete
campaign (Windows evidence only; not Linux evidence):
* **release-signer**: builds and passes its 13 tests (3 library tests, two of which use the imported public fixture, and 10 binary
  tests) in debug and in release.
* **desktop**: the shipping build (`cargo build --release`) compiles, and the resulting exe contains no wallet code because the
  production gates (`App::new`, `wallet_v2::ready()`) are closed. Phase 0C removed `desktop/src/admission.rs` and its private
  NODE-A include, so the tests compile: 33 pass in debug and in release and 1 is ignored (`non_test_binary_refuses_to_start`, which
  needs `MUTINY_DESKTOP_RELEASE_EXE`; the runner does not run it). The KNOWN BLOCKER branch of the runner no longer triggers.
* **wallet-core**: present (phase 1). 134 tests pass in `d-wallet-core`, in the NON-SHIPPING `d-wallet-core-test-value` (the same
  134: the crate's own tests always enable `test-value-signing` through a dev-dependency on itself) and in `r-wallet-core`.
* `x-exclusion-checks` (the full `build/check-shipping-config.sh` over both release binaries and their pdbs): 164 passed, 0 failed.
* Result: 16 steps NATIVE PASS (offline, TEST-VALUE), 0 failed, 0 not run, `complete_campaign: true`, exit status 0.
  `--skip-desktop` remains available for a focused run (reported as `complete_campaign: false`).

## What the run will and will not do
* Runs in an **ordinary (non-elevated) Git Bash** (it refuses an Administrator shell), on Windows x86_64 only, in a **separate
  workspace** (`%USERPROFILE%\build8-windows-wallet-test-<UTC stamp>` by default; it must not exist). Nothing is written into the
  source tree by the runner itself; cargo writes only to the target directory. (The TESTS of consensus, node and transport-v2 do create
  SQLite databases under `qualification/continuity-custody-tests/` and `qualification/transport-object-tests/` of the checkout: compile-time
  paths, gitignored; the exclusion step tolerates the `.sqlite` suffix only there and counts the files.)
* `CARGO_NET_OFFLINE=true` and `--locked --offline` on every cargo call; it never fetches. Unlike the Linux runner it uses the
  host's own Cargo cache (there is no vendored Windows package), so every locked crate must already be in the cache: the runner
  checks `cargo metadata --locked --offline` for each component first and aborts with an explanation otherwise.
* Redirects `LOCALAPPDATA`, `TEMP` and `TMP` into the workspace, so tests that use the local profile or temp directory cannot
  touch yours.
* **Blocks and records** any attempt to run `sudo`, `ssh`, `scp`, `sftp`, `pkexec`, `su` or any `tpm2_*` tool from bash (shims first on
  `PATH`; one hit fails the run). Native Windows programs started by tests resolve names themselves and are not covered by the shims;
  the only external program a test spawns is `powershell.exe` (release-signer `storage_io`, an ACL check) plus the test executable
  itself. The tests do not open a TPM, call a host-specific TPM helper or touch custody.
* **Ignores** an inherited `BUILD8_ONLY` (recorded). A focused rerun needs `--only "step names"` and is reported as
  `complete_campaign: false`.
* The first recorded step, `g0-source-paths`, runs `build/check-source-paths.pl`: the Linux (POSIX) path semantics of the source
  tree, the same static check the Linux runner runs first (`docs/BUILD-CONFIGURATIONS-V1.md` 6.1). It needs `perl` (Git Bash has it).

## Prerequisites (install once; the campaign itself needs no privileges)
* Windows 10/11 x86_64 and **Git for Windows** (Git Bash: `bash`, `sha256sum`, `grep`, `sed`, `awk`, `tr`, `find`, `tee`, `perl`).
* Rust **1.98.1** for `x86_64-pc-windows-msvc` (pinned by `rust-toolchain.toml`): `rustup toolchain install 1.98.1 --profile minimal`
  (online, once), then `rustc -V` in the source tree must print `rustc 1.98.1`. On a host whose toolchain is named `stable` (which is
  1.98.1) set `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`.
* **Visual Studio Build Tools** with "Desktop development with C++" and a Windows SDK (the crypto and SQLite build scripts compile
  C; the `cc` crate finds MSVC itself).
* The **offline cache**, populated once while online: run `cargo fetch --locked` in `release-signer/`, `desktop/` and (when present)
  `wallet-core/`. Afterwards the runner needs no network.
* Disk: at least 15 GB free for the target directory (the desktop's GUI dependency tree is large). Time: roughly 30 to 90 minutes,
  most of it the first compile of the desktop tree and the `-D unexpected_cfgs` compile checks of the exclusion step.

## Invocation
```bash
cd /d/path/to/the/source          # a checkout of the commit being tested (or an extracted package)
export RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc   # only if your 1.98.1 toolchain is named stable
# Optional dry run: checks every precondition, the offline cache and the environment record; runs no test.
bash package/windows-wallet-test/run-windows-wallet-tests.sh --dry-run
# The campaign (use the real archive hash if you were given one, so that it is recorded):
env -u BUILD8_ONLY BUILD8_ARCHIVE_SHA256=<archive sha256 or omit> \
  bash package/windows-wallet-test/run-windows-wallet-tests.sh 2>&1 | tee "$HOME/build8-windows-wallet-test.console.log"
```
Useful options: `--skip-desktop` (focused run, incomplete campaign), `--debug-only`, `--release-only`, `--only "g-release-signer d-release-signer"`.
`BUILD8_TARGET_DIR` points every cargo step at an existing target directory (for example to reuse earlier builds); by default it is
`<workspace>\target`.

## Steps
For each component `c` in `release-signer`, `desktop` and (when present) `wallet-core`: `g-c` compile gate (`cargo test --no-run`),
`d-c` debug suite, `r-c` release suite, `p-c-build` shipping build (`cargo build --release`; wallet-core: `--lib`). For wallet-core
only, additionally the **NON-SHIPPING** rehearsal steps `g-wallet-core-test-value` and `d-wallet-core-test-value`
(`--features test-value-signing`), labelled `[NON-SHIPPING feature test-value-signing]` in `results.tsv`. Before them `p0-import-provenance`
(`build/check-import-provenance.sh`: the imported wallet and signer sources equal their identity-verified imports or carry an
explicit record), and at the end `x-exclusion-checks` (`build/check-shipping-config.sh`: graph, manifest, guard, lockfile and
provenance checks, the `-D unexpected_cfgs` compile checks of every configuration that compiles here, and the per-binary string
rules over the built release binaries, scanning each `.pdb` as well because a Windows exe holds no Rust symbol names). Test steps
of a component whose compile gate failed are recorded as `NOT RUN (compile gate ... failed)`.

## What to send back
The runner prints the evidence directory (`<workspace>\evidence`). It contains `summary.json` (per-component status:
`release_signer`, `desktop`, `wallet_core`; `known_blockers`; `complete_campaign`), `results.tsv`, `environment.txt`, `run.log`,
`tripwire.log` (must be empty), one log per step, the built exe and pdb copies and `evidence.sha256`. Return it with its hash:
```bash
cd "$HOME/build8-windows-wallet-test-<stamp>" && tar -czf evidence.tar.gz evidence && sha256sum evidence.tar.gz
```
Exit status 0 means: every declared step passed, nothing was NOT RUN, every expected step ran, no tripwire fired and (for a
package) the sources were unchanged. A non-zero status with `summary.json` is still evidence; do not delete a failed run.

## Known limits
No Linux, physical TPM, hardware-clock, live NTS or production-custody evidence is produced, and no real wallet or key is involved.
The GUI is not driven (no window is opened by the tests). The runner does not run the desktop's ignored release-refusal test
(see Current state). The runner depends on the host's offline Cargo cache and on the host MSVC installation,
both recorded in `environment.txt`.
