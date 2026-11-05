# Native absolute path spelling follow-up

Codex (GPT-6), source parent06b280d. The public checked path accepts ordinary
absolute drive paths containing either separator, while native extended paths
disable ordinary slash normalization. Convert only separator UTF16 code units
before adding the extended prefix; preserve every other code unit exactly.
No ACL, owner, lock, provider, calibration or consensus policy change.

Actual ordinary full Node-root command:
`cargo test --manifest-path node/Cargo.toml --offline --locked c8_windows_safe_creation_handle_identity_and_native_store_bytes -- --nocapture --test-threads=2`
**1/1 meaningful native positive PASS**, zero ignored, 8.66s compile/0.07s runtime.
Two required child invocations confirm the original backslash spelling and an
ordinary absolute slash spelling encounter the same already-held native lock.
Child invocations are not extra qualification counts. Full Node library, binary
and integration targets compiled; other tests were filtered, not executed.

Immutable source copy, source SHA256/start record, exact output and exit record:
`D:/Mutiny/build8-targets/codex-clock-windows-evidence-20261004/c8-slash-positive-1-*`.
No earlier native evidence changed. Protected TEST fixture retained. Broader final
combined/native regression remains queued; the prior14/14 storage result is
historical06source, not silently transferred to changed bytes. Windows HostClock
launch and physical/provider/power-loss qualification remain open.

Primary namespace basis:
[Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
# Complete current-source follow-up

After the narrow positive, parent requested the complete native state_dir suite on the same clean `18ee78a9e3d9b82b8dc5291b21c94fbe7861a158` source. `c8-slash-state-whole-2.log` records 14/14 passed, zero ignored, 0.20 seconds runtime. This consists of 13 meaningful parent tests plus one env-absent child helper; helper executions are evidence for their parent process tests and are not extra qualifications. The first filter attempt (`whole-1`) selected only three outer tests, all passed, and is retained explicitly as partial suite evidence. Corrected whole-2 used `host_clock::state_dir`, including the native child module. Exact source bytes and hashes were captured before execution; all ordinary Node targets compiled. No behavior or authorization limitation changed, and Windows launch/provider and physical clock qualification remain open.
