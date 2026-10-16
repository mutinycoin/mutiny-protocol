# Build 8 successor Linux execution guide V3

Status: **PROPOSED â€” successor integrated campaign pending**. Applies to the new candidate-3 runner/source identity, never retroactively to frozen candidate-2 package `54517334b88a`. All ordinary-user software evidence is at most NATIVE PASS, offline, TEST-VALUE. Physical clock/TPM qualification, production custody and release lock require separate evidence.

The runner declares the existing 35 steps when wallet-core is present; its three fixture steps also include `treasury_rehearsal_rotation_v1` with `dividend-test-fixtures`. Desktop and release-signer files are source-only on Linux: neither component is built, tested or vendored by this campaign. A focused `--only`, profile selection, missing wallet-core or missing declared step is incomplete and exits nonzero.

The successor uses `umask 077`, a newly created mode-0700 workspace and private `TMPDIR=$BUILD8_WORKSPACE/tmp`. Linux preflight checks workspace ancestors are directories, not symbolic links, owned by root/effective user and have no group/other write bits. It names an offending path, owner and mode before running any step. Existing ancestors are never repaired or chmodded. Package ancestor findings are recorded as diagnostics; generated tests use the workspace. Safe ancestors must be explicitly created; setting umask does not alter existing permissions. Unix owner/mode enforcement is not established by a Windows package-form run.

Tests create atomically owned temporary directories with collision retry and Unix 0700 permissions; only the creating test removes them. Shipped fixture inputs stay under qualification. Deliberate public-vector generators require explicit export environment variables; do not enable those in a package campaign. The successor records complete pre/post package-tree listings with file SHA-256, directories and symlinks. The manifest check rejects every unlisted regular file anywhere, missing/changed files, symlinks and special objects. A successful successor run requires byte-identical listings, including additions/removals. This is the mechanism to verify a write-free package; the claim remains unqualified until the identified integrated campaign passes.

Candidate-2 baseline run 1 remains FAILED historical evidence: its test databases were generated under the extracted package, and its final run.log was changed after evidence hashes. Do not rewrite that evidence, permit its SQLite allowances in the successor or claim successor verification covers the baseline. Keep the separately observed run-2 permission modes and statuses in its ledger; the original extraction's umask 0002 and group-write are different from the corrected extraction's umask 022/0755 ancestors.

For the authorized candidate-3 campaign on `mutiny-mainnet-02`, the verified volume is `/var/lib/mutiny/qualification-c3.tX6KzBh4`. Use it as the qualification root below and run as `mutinyadmin` without sudo. Recheck its owner/mode, all ancestors and available space immediately before extraction. The package and fresh `BUILD8_WORKSPACE` both stay on that volume; the runner places target, empty Cargo home, temporary files and evidence beneath the workspace. Preserve every baseline build/archive and existing failed or partial workspace. The home volume is not the selected storage for this campaign.

The runner enforces empty CARGO_HOME, vendored source replacement, Cargo `--locked --offline`/`CARGO_NET_OFFLINE`, tripwire shims, declared steps, manifest/tree identity and shipping graph/exclusion checks. PATH tripwires are regression diagnostics, not a sandbox; absolute executable paths can bypass them. Cargo offline is not a network firewall. Review source/build scripts and isolate the authorized software host as required by its operating procedure. No production signing, TPM provisioning/flashing, services, Genesis initialization/sealing or publication is performed. Source/build/home prefixes are remapped for rustc, and GNU C source/build/home prefixes on Linux; shipping forbidden-string checks remain strict. Remapping is not removal of actual forbidden dependencies.

Verify host identity/toolchain/compiler/Perl/space and competing workloads before the campaign. Serialize heavy work per host. Install missing administrator prerequisites separately, never inside the campaign. Use the supplied source/tree/runner/archive identities from the integrated freeze record; no identity is invented here.

Run this block in Bash with the actual recorded ID and expected hash. Set the variables from the authorized freeze record; the placeholders deliberately fail if not replaced. Every existing extraction/workspace is refused.

```bash
set -euo pipefail
umask 077
id='<recorded-source-commit12>'
expected='<recorded-archive-sha256>'
archive="build8-linux-native-test-$id.tar.gz"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --strict -
# Select a verified writable qualification volume with enough free space for
# package, vendored source, workspace, targets, empty Cargo home and evidence.
# Verify safe root/current-user-owned ancestors before using this path; do not repair them.
qualification_root='<verified-writable-qualification-root>'
[[ "$qualification_root" = /* && "$qualification_root" != *'<'* ]]
root="$qualification_root/b8-successor-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 0700 "$root"
mkdir -m 0700 "$root/extract"
tar -xzf "$archive" -C "$root/extract"
package="$root/extract/build8-linux-native-test-$id"
cd "$package"
cat PACKAGE-IDENTITY.json
perl build/package-tree.pl manifest "$package"
# Compare the displayed source/tree/runner against the trusted freeze record.
# Dry run and full campaign require different fresh workspaces.
BUILD8_WORKSPACE="$root/dry" bash package/linux-native-test/run-linux-native-tests.sh --dry-run
# Capture BOTH statuses immediately; tee failure cannot conceal runner failure.
set +e
env -u BUILD8_ONLY BUILD8_WORKSPACE="$root/run" BUILD8_ARCHIVE_SHA256="$expected" BUILD8_TEST_THREADS=2 \
  bash package/linux-native-test/run-linux-native-tests.sh 2>&1 | tee "$root/console.log"
status=("${PIPESTATUS[@]}")
set -e
printf 'runner_exit=%s tee_exit=%s\n' "${status[0]}" "${status[1]}" > "$root/pipeline-status.txt"
# Preserve/archive evidence even when the runner failed.
(cd "$root/run/evidence" && sha256sum --check --quiet evidence.sha256)
tar -czf "$root/evidence.tar.gz" -C "$root/run" evidence
sha256sum "$root/evidence.tar.gz" > "$root/evidence.tar.gz.sha256"
[ "${status[0]}" = 0 ] && [ "${status[1]}" = 0 ]
```

The last line returns both failures after preserving evidence. If preflight aborts before finalization, `evidence.sha256` may be absent: retain/archive the partial directory with a new exterior archive hash and report PRECONDITION-FAILED, never fabricate a complete summary. The runner finalizes run.log before generating evidence.sha256, includes every evidence regular file including tripwire shims, immediately verifies the checksums, and writes `finished.txt` outside the finalized set. Console/pipeline-status are exterior records; hash them only after their writers finish. No append-after-hash is permitted.

Return results.tsv, summary.json, environment/ancestor diagnostics, final run/step/tripwire logs, pre/post tree listings and any diff, copied binaries, evidence.sha256, console/pipeline-status, archive hash, exact freeze identities, all ignored/failing/partial classifications and the commands actually executed. Exit zero requires a complete campaign with every declared step passed, empty tripwire and unchanged package. Physical ignored tests are SKIPPED-PHYSICAL; wallet golden printers/generators are IGNORED. A changed executable after freeze creates a new identity and requires affected qualification to be repeated honestly.
