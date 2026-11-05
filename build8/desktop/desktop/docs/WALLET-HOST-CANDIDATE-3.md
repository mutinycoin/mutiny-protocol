# Desktop wallet host, candidate 3, Stage A (Order W7, W8, W10, W11, W16)

Evidence label: Windows 11 host, software, TEST-VALUE: at most **NATIVE-PASS-offline-TEST-VALUE**
(`docs/EVIDENCE-CLASSES-V1.md`). Implemented is not Qualified; offline is not physical; simulated is
not physical. Nothing here was run on Linux (the desktop does not build there by design,
`docs/BUILD-CONFIGURATIONS-V1.md` 4.2). Production signing and Genesis stay closed: the shipping
window still refuses to start outside tests (`App::new`), `wallet_v2::ready()` still refuses while
`mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is false, and no gate, chain class or economic
rule is changed by anything below.

Branch `cand3/desktop` (worktree `build8-dk3`) from `integration/candidate-3` at 8ecb3c7. The Order
is `Build8-Architect-Continuation-Order-20261004.txt`, section 6 (W1-W23, Q1-Q17). The design of the
mounted TEST-VALUE executable (W15) is `qualification/candidate-3/W15-MOUNTED-TESTVALUE-DESIGN.md`.
Every claim of the form "X refuses Y" names the test that shows it; the tests are in the module they
name (`desktop/src/<module>.rs`, `#[cfg(test)]`).

## W8: the wallet executable is `mutiny-wallet-v8`

`desktop/Cargo.toml`'s `[[bin]]` is `mutiny-wallet-v8` (it was `mutiny-desktop-v8-ceremony`, a name
older than phase 0C's retirement of the V1 ceremony). The package name `mutiny-desktop-v8` is
unchanged, and the rename does not redefine the scope or branding of the wider Desktop product.
Changed together (commit 4d4f653): the manifest; `build/check-shipping-config.sh` (the default binary
search, the rule set chosen by file name `mutiny-wallet-v8*` = wallet, and a binary under a retired
`mutiny-desktop-v8*` name now FAILS as a stale artefact instead of being scanned as a node);
`build/negative-controls.sh` (the `bin_wallet_*` synthetic binaries and expected messages, and the new
control `bin_wallet_retired_name`; a later commit adds `ship_binaries_default_search`, which no control
covered before: without `BUILD8_BINARIES` the check must find `mutiny-wallet-v8.exe` in
`CARGO_TARGET_DIR/release` and scan it); `build/shipping-configurations-v1.json`; the Windows runner's
`copy_exe`; `README.md`; the active statements of `docs/BUILD-CONFIGURATIONS-V1.md` and
`desktop/docs/PHASE-7-DESKTOP.md`. Observation records made under the old name keep it, with a note.

## W7: the V1 application path is retired; unsupported formats are refused and never changed

**What is retired.** The V1 desktop wallet: Ed25519 keys derived by BIP32
(`m/44'/1297437697'/0'/0'/0'`) from a 24-word BIP-39 phrase, sealed with Argon2id and DPAPI in the
SQLite file `wallet.sqlite`, with its replica, payment, Genesis-binding, admission and firmware
modules. Phase 0C (commit e34bd2c) removed that code from this tree; history keeps every removed file
(`git show 121479b:desktop/src/<file>`; narrative `build/imports/EDITED-AFTER-IMPORT-DESKTOP-V1.md`;
specification `spec/WALLET-V1.md`). This build has no V1 code, no V1 key import, no conversion, no
migration and no default location (the vault root is explicit, W11).

**What is preserved.** Every existing file. A V1 `wallet.sqlite` and anything next to it, an earlier
hybrid vault (format 2), a store written by a newer build, a damaged file: nothing in this build
deletes, overwrites, converts, migrates or "repairs" any of them. The check below runs before
anything can write, and a refused file is left byte-identical: same contents (SHA-256), same length,
same modification time, no file added or removed beside it (tests
`custody_format::tests::unsupported_formats_are_refused_and_left_byte_identical`,
`a_v1_wallet_with_a_hot_journal_is_refused_without_being_rolled_back`,
`a_vault_root_holding_a_v1_wallet_is_refused_before_anything_is_created`). Inside the current vault,
the previous identity after a key rotation is kept until the person retires it (W16). There is no
wallet backup FILE format in this build: the 24-word recovery phrase is the backup.

**How a file is recognised** (`desktop/src/custody_format.rs`). Before the custody lease
(`custody_acl_v2::prepare`, which creates an absent file) and before SQLite opens anything for
writing, the check reads at most the first 100 bytes of the file through a read-only handle (SQLite
header: magic, page size, journal mode, user version, application id) and, only for a SQLite database
that names no application, its table list through SQLite opened read-only AND immutable (no lock, no
journal recovery, no log, no write of any kind). It must come first because opening a database
read-write can change it: SQLite rolls a hot rollback journal back into the main file, and folds a
write-ahead log into it when the last connection closes. The contrast at the end of
`a_v1_wallet_with_a_hot_journal_is_refused_without_being_rolled_back` shows exactly that: a plain
SQLite open of the same refused file changes it and deletes its journal.

| The file at a store's path (or `wallet.sqlite` in the vault folder) | Result |
|---|---|
| absent (and no journal or log of it) | accepted: the store is created |
| empty (the custody lease created it); beside it only a rollback journal whose header SQLite never wrote (first 8 bytes zero: the leftover of this build's own interrupted initialisation, which SQLite discards) | accepted |
| exactly this store's application id and schema version in rollback-journal mode, AND exactly its schema (verified read-only and immutable; since the independent review); its own rollback journal may lie beside it (crash recovery) | accepted |
| a header claiming this store's current format without exactly its schema (with or without a hot journal beside it) | `UnknownDatabase` |
| a V1 wallet database (tables `wallet`, `transactions`, `events`, optionally `signed_payloads`; `wallet` columns `id, version, ciphertext, salt, identity`; no application id), at a store's path or as `wallet.sqlite` in the vault folder | `RetiredV1Wallet` |
| anything else named `wallet.sqlite` in the vault folder | `V1NameInUse` |
| a hybrid vault (application id `MU82`) in format 1 or 2 | `RetiredVaultFormat` |
| a store of this wallet with a higher schema version | `NewerFormat` |
| another store of this wallet under this store's name | `OtherStore` |
| any other SQLite database (another program's, or damaged) | `UnknownDatabase` |
| not SQLite (damaged, truncated, another kind of file) | `NotADatabase` |
| SQLite in write-ahead-log mode (this wallet never writes it) | `WriteAheadLog` |
| a directory, link or reparse point in place of the file, or a file in place of the custody folder | `NotAFile` |
| a `-wal` or `-shm` file beside an accepted file; a journal whose header SQLite wrote beside an empty file; a companion that is not a plain file (directory, link, reparse point); a journal or log without its database | `UnexpectedCompanion` |
| a file that cannot be read | `Unreadable` |

Every refusal is a typed `UnsupportedFormat` whose text names the file, says that it was left exactly
as it was, and says what to do (test `every_refusal_says_what_the_file_is_and_what_to_do`). Where it
runs: `Controller::open` calls `check_vault_root` before anything is created (the V1 slot, the custody
folder, the three stores); `Store::open`, `OperationOutbox::open` and `PreimageVault::open` each call
`check_store` first. The vault's refusal is typed (`store_v2::OpenError::Unsupported`); the outbox and
the preimage store keep their existing refusals (`OUTBOX_INTEGRITY`; the preimage store's
`MALFORMED`), which the controller's earlier typed check pre-empts. The stores' own checks (exact
schema, sealed probe, custody ACL) still follow; this check does not replace them. Limitation: the
check and the open are two steps; a process that can write the custody folder in between (only this
Windows account and SYSTEM, by the custody ACL) could swap the file. That is the same-user host
compromise the custody design already excludes (W10).

**How to recover an old V1 wallet.**

1. Keep `%LOCALAPPDATA%\Mutiny Build8\wallet.sqlite` (the V1 application's fixed location), every copy
   of it, and the written 24-word phrase. This build never opens, changes or deletes that file, and
   refuses a `--vault-root` folder that holds a `wallet.sqlite` (`RetiredV1Wallet`, `V1NameInUse`).
2. The last committed build that opens it is master commit d474110 (also e444c14): its `desktop/`
   package `mutiny-desktop-v8` has no `[[bin]]` entry, so its executable is `mutiny-desktop-v8.exe`,
   and it opens `%LOCALAPPDATA%\Mutiny Build8\wallet.sqlite` under the same Windows account (DPAPI)
   with the wallet password. Build it from history in a separate folder (for example
   `git worktree add <folder> d474110`, then `cargo build --release --locked` in `<folder>\desktop`);
   its V1 dependencies (bip39 3.0.0, ed25519-dalek-bip32 0.3.0, ed25519-dalek 2, getrandom 0.3, argon2
   0.5) are not in this candidate's lockfiles and must be available to Cargo. Do not use the as-found
   sources of 121479b for this: they refuse to start outside tests. NOT verified here: this candidate
   did not rebuild or run the d474110 binary.
3. Or restore the wallet from its 24-word phrase in that build (the V1 derivation is in
   `spec/WALLET-V1.md`).
4. A V1 key is not a key of this build's hybrid wallet (Ed448 + FN-DSA-1024), and this build imports
   none. Whether any record outside the desktop still names a V1 key is not established here.

**Tests** (`desktop/src/custody_format.rs`): `absent_empty_and_current_custody_files_are_accepted`
(the three accepted states for each store, and the real stores reopen what they wrote);
`unsupported_formats_are_refused_and_left_byte_identical` (fifteen cases: the V1 schemas of 121479b
and of d474110, V1 at the outbox's name, format-2 vault, newer vault, outbox and preimage store,
another store's file, a foreign database, random bytes, a truncated header, write-ahead-log mode, a
directory with a file in it, a log beside a current file, a journal without its database; for each the
exact refusal of `check_store`, of the store's own open and of `check_vault_root`, then every file of
the custody folder byte-identical with the same modification time); the hot-journal test above (a
child process interrupts a write to a V1 database inside the custody folder, so SQLite would roll it
back); `a_vault_root_holding_a_v1_wallet_is_refused_before_anything_is_created` (a fresh root opens
through the controller; a root with a V1 `wallet.sqlite` is refused by `Controller::open` with the
readable text and no custody folder is created; `V1NameInUse`; a lone V1 journal; a file in place of
the custody folder); `the_header_parser_and_the_uri_are_exact`; and in `store_v2` the retired V1 file
name is never the vault's.

**Fixes of the independent review** (findings F1, F2, F4). The first version trusted the 100-byte
header alone: a V1 database whose header claimed the current vault format, with an interrupted
write's hot journal beside it, was accepted, and the vault's first read rolled the journal into it
(the reviewer showed a changed SHA-256); and an empty store file with a foreign hot journal beside it
was accepted, after which SQLite deleted that journal. Now a file whose header claims the current
format must also have exactly the store's schema (read through the same read-only, immutable
connection; anything else is `UnknownDatabase`, journal or not), beside an empty file only a journal
whose header SQLite never wrote is accepted, and every companion must be a plain file. Tests:
`a_file_that_only_claims_the_current_format_is_refused_even_with_a_hot_journal` (the reviewer's first
attack, now a negative test, for each store, with and without a hot journal: refused, every file
byte-identical); `an_empty_store_file_accepts_only_a_journal_sqlite_never_wrote` (the second attack,
for each store; the same journal with its header zeroed is accepted);
`a_journal_companion_must_be_a_plain_file`; and `store_v2::tests::filesystem_reopen_recovers_uncommitted_process_crash`
now asserts that a genuine current vault with its own hot journal passes the check, so SQLite's crash
recovery still applies to this build's own files. Limitation: the schema is verified on the main file
as it lies, before any recovery; a file of this build whose schema page itself were torn by a power
loss would be refused (kept unchanged) rather than recovered. Not observed; these stores never change
their schema after creation.

## W11: the vault root is explicit and absolute; no ambient fallback

The vault root comes from exactly one source: the argument `--vault-root <absolute path>`
(`VaultRoot::from_args`, `desktop/src/wallet_controller_v2.rs`). There is no environment variable, no
default folder and no current-directory fallback. No production code of the desktop reads the
environment, the current directory, a home, profile or temporary folder, the registry or the process
arguments: this is what a grep of `desktop/src` shows today, and what the textual tripwire below
watches for the forms it knows (the shipping executable parses no argument at all today: its window
still refuses to start outside tests). Every refusal is a typed `VaultRootError`:

| Input | Refusal |
|---|---|
| no argument / `--vault-root` without a path / anything but exactly `--vault-root <path>` (another flag, an extra or repeated argument, `--vault-root=<path>`) | `Missing` / `MissingValue` / `UnexpectedArguments` |
| an empty path; not valid Unicode | `Empty`; `NotUnicode` |
| relative (`wallet`, `.\wallet`), root-relative (`\Wallets`), drive-relative (`C:`, `C:Wallets`) | `NotAbsolute` |
| UNC (`\server\share`, `//server/share`, `\?\UNC\...`), device (`\.\...`), `\?\GLOBALROOT\...`, volume GUID paths | `NetworkOrDevicePath` |
| a `.`, `..` or empty component | `TraversalComponent` |
| `< > : " \| ? *` or a control character (NUL included) in a component, `/` in a verbatim path; covers alternate data streams | `InvalidCharacter` |
| a component ending in a dot or a space (Windows would strip it) | `TrailingDotOrSpace` |
| a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, the superscript forms, `CONIN$`, `CONOUT$`, with or without extension) | `ReservedName` |
| more than 200 UTF-16 units (`<root>\WalletCustodyV2\operation-outbox-v1.sqlite-journal` must stay within 260) | `TooLong` |

Accepted: a drive path (`X:\...`, `/` also accepted as separator), the verbatim drive form
`\?\X:\...`, one trailing separator, a drive root. The custody folder below the root is fixed
(`WalletCustodyV2`), and `custody_acl_v2` still accepts drive paths only; W11 refuses the excluded
forms at the argument, before anything is touched. Then W7's `check_vault_root` runs.

**The seam for a later launcher (documented; not implemented).** A launcher that holds a path it has
verified itself (one it created and checked, or an installer-registered path it re-verified) passes it
as `--vault-root <path>` on the command line it builds, or calls `VaultRoot::new(path)` (the same
rules). The controller receives only the `VaultRoot`, so the signing flow never learns how the path was
chosen and gains no new input.

**Tests** (`wallet_controller_v2::tests`): `the_vault_root_is_explicit_absolute_and_refused_with_a_typed_reason`
(eight argument forms; 32 path cases, each with its exact `VaultRootError` through `VaultRoot::new` and
through the argument; a non-Unicode path; seven accepted forms; the three store paths below an
accepted root); `no_environment_variable_or_current_directory_changes_the_vault_root` (a child test
process runs with `MUTINY_VAULT_ROOT`, `MUTINY_WALLET_VAULT_ROOT`, `MUTINY_WALLET_ROOT`,
`BUILD8_VAULT_ROOT`, `VAULT_ROOT`, `WALLET_ROOT`, `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOME` and
`PROGRAMDATA` all pointing at another folder, in a current directory that holds a `WalletCustodyV2`
folder: no argument is still `Missing`, a relative root is still refused, an explicit root is exactly
itself); `production_code_reads_no_environment_variable_or_current_directory` (a TEXTUAL tripwire over
every production line of `desktop/src`, recursively, test items skipped). Its first version knew only
`env::var`, `env::args`, the current directory, `home_dir`, three Win32 names and the profile variable
names, so `option_env!`, `std::env::temp_dir()` and an aliased `use std::env as e;` went unnoticed
(the reviewer's surviving mutant M8b). Since the review it also knows `option_env!`/`env!`,
`temp_dir`, any `std::env` path, an `env` imported from `std` in a braced list, and the Win32 calls
`GetCommandLine`, `GetCurrentDirectory`, `SHGetFolderPath`, `ExpandEnvironmentStrings` and the
registry reads `RegGetValue`, `RegQueryValue`, `RegOpenKey`, each with a positive probe. It reads the
sources as text: a read written in a form it does not know is not found. An executable that hands its
arguments to `VaultRoot::from_args`, as the W15 TEST-VALUE executable will, needs an explicit
allow-list entry there. `reserved_names_cover_every_name_windows_treats_as_a_device` records what
this host does with device-like names through `std::fs` (on this Windows 11 host only the exact name
`NUL` behaved as a device; `CON`, `CON.txt`, `CON .txt`, `CONOUT$` were created as plain files) and
requires every name the host treats as a device to be refused; the rules refuse the whole classic set,
`CON .txt` included (review F5: the text before the first dot is compared without trailing spaces).

## W10: protection at rest; queued preimages sealed, including temporary files and crash paths

**The baseline, stated plainly.** Windows DPAPI (CurrentUser scope) plus the restrictive custody ACL
(owner and SYSTEM only, protected, set when a custody file or folder is created and re-verified
exactly at every open by `custody_acl_v2::prepare`; one link; no reparse point; leased) is the
documented Windows baseline. It is **not isolation from another process of the same Windows user**:
any such process can ask DPAPI to unseal, and can read the files and the wallet's memory. A malicious
host process (same user, administrator, SYSTEM, injected code, a debugger) is out of scope. The other
limits of `desktop/docs/PHASE-7-DESKTOP.md` section 4 remain: deleting a row or a file, replacing a
file by an older copy of itself, and the size and count of entries are not protected.

**Every write path** (`preimage_store.rs`, `operation_outbox.rs`, `custody_seal.rs`, `dpapi_v2.rs`,
`store_v2.rs`, `custody_acl_v2.rs`):

| Write path | What reaches disk | Sealed when |
|---|---|---|
| `PreimageVault::add` (`create`, `insert_disclosed`) | one row: a sequence number and DPAPI(condition, preimage) bound to the file and the row | before the INSERT (`custody_seal::seal`): SQLite never receives plaintext |
| `PreimageVault::erase` | the row deleted (`secure_delete` overwrites its cells) | (deletion) |
| `PreimageVault::open` (creation) | the file's random identifier (public) and DPAPI(probe) | before the INSERT |
| `OperationOutbox` insert (`commit`, `replace_partial`) | the record identifier (a public hash), a sequence number, DPAPI(metadata), DPAPI(signed bytes) | both before the INSERT |
| `OperationOutbox` metadata rewrite (`reconcile`, `forget`) | DPAPI(metadata) | before the UPDATE |
| `OperationOutbox` delete and prune | rows deleted (`secure_delete`) | (deletion) |
| `store_v2` (the vault) | each record: the public identity and hex(DPAPI(Argon2id and XChaCha20-Poly1305 sealed key)); the previous identity after a rotation (W16) is a record of the same form in the same file | before the INSERT or UPDATE |
| `custody_acl_v2::prepare` | an empty file (0 bytes) with the exact owner and SYSTEM DACL | (nothing secret) |
| `dpapi_v2` | no file; the plaintext Windows returns is copied to a zeroizing buffer, and Windows' copy is wiped and freed | |
| the SQLite rollback journal (`<store>-journal`) | original page images, therefore sealed values only; created inside the custody folder and inheriting its owner and SYSTEM entries | |
| SQLite temporary files (statement journals, sorts, transient indices) | **in memory since candidate 3** (`PRAGMA temp_store=MEMORY` in `custody_seal::configure` and in the vault). Before, the bundled SQLite (compiled with its default `SQLITE_TEMP_STORE=1`) could write them to the user's temporary folder, outside the custody ACL; they could only have held sealed values | |
| write-ahead log, shared memory | never used (`journal_mode=DELETE`); a `-wal` or `-shm` file beside a custody file is refused before SQLite opens it (W7) | |
| atomic-replace staging files, backup copies | none exist: no store writes a temporary file and renames it, and no backup or old-vault file is written (the previous identity is a record inside the vault) | |
| the payment pool (consensus `mempool_v2`) | complete public payments in clear (transport objects); never a claim: `Replica::queue_signed_payment` refuses every other kind | |
| exports | `Controller::export` returns bytes to its caller; the desktop writes no export file | |

**Crash leftovers.** A process that dies before a commit leaves the store's rollback journal. SQLite
syncs a journal's header (making it "hot") when it commits, or earlier when its page cache spills;
the stores' transactions are small and do not spill, and the tests observe exactly that: a journal
left before the commit has an unwritten header, so SQLite ignores it, never reads it as data, and
replaces and deletes it at the store's next write. A journal whose header was written (a spilled
transaction, or a crash inside SQLite's own commit after its journal sync) is hot and is rolled back
into the file at the next open; W7's check accepts that only beside a file whose exact schema it has
verified. The safety does not rest on either case: the journal holds only sealed values (nothing
reaches SQLite unsealed) and carries the custody folder's inherited owner and SYSTEM access. The
boundaries inside SQLite's commit cannot be injected from this code; at those points SQLite holds only
what this code gave it, which is sealed.

**Where a preimage may appear.** Only inside the authorized settlement payload: the claim, reviewed
with the `DisclosesPreimage` acknowledgement, signed, and queued sealed; `Controller::export` of that
record returns its bytes for delivery. It is in no public partial (a hash lock's partials and the
maker's fill carry the condition, never the preimage), in no `Debug` or `Display` output (wallet-core's
`Preimage` is redacted; `PreimageVault` shows a count, `OperationOutbox` its chain and limits,
wallet-core's `OutboxRecord` and `SignedOperation` lengths; since candidate 3 the service's
`Event::Exported` and `CompletedTrade` show a byte count where their derived `Debug` printed every
byte, which for a claim's export includes the preimage), and in no log (the desktop's production code
neither prints nor logs, and the shipping executable installs an empty panic hook, kept by
`main::tests::binary_guards_stay_in_place`).

**Not protected (stated).** Same-user processes, administrators and SYSTEM; the process memory while
the wallet runs, and therefore what Windows itself may write of that memory: the page file, the
hibernation file, crash dumps. In memory the preimage lives in zeroizing buffers and wallet-core's
`Preimage`, but also in the claim's plan and signed bytes, which are not zeroized (wallet-core's
documented limit).

**Tests.** `preimage_store::tests::no_plaintext_preimage_on_disk_at_any_crash_point` (a child process
killed after sealing, inside the write transaction and after the commit, for an addition and for an
erasure: every file of the folder scanned for the preimage raw and in hexadecimal; the journal left
before a commit has the unwritten header and only the owner's and SYSTEM's inherited access; the
reopen recovers exactly the last commit; the next write removes the stale journal; scanned again;
temporary files in memory); `operation_outbox::tests::a_queued_claim_leaves_no_plaintext_on_disk_at_any_crash_point`
(the same for a signed claim killed before, inside and after its commit) and the existing
`a_queued_claim_leaves_no_plaintext_preimage_in_the_file`; `store_v2::tests::the_vault_keeps_sqlite_temporary_files_in_memory`;
`preimage_store::tests::the_store_debug_output_shows_no_preimage` (and the scanner's own positive
probes); `wallet_controller_v2::tests::a_claim_preimage_reaches_disk_only_sealed_and_leaves_only_in_its_export`
(the controller's whole claim flow; every file of the wallet's folders, chain store and payment pool
included, free of the preimage; the export carries it; the payment pool refuses the claim);
`debug_and_display_output_never_carry_a_preimage` (fourteen renderings along the claim's way, each
free of the preimage in hexadecimal, abbreviated hexadecimal and decimal byte lists);
`a_hash_lock_is_exchanged_as_public_partials_and_completed` (now asserts that neither partial, the
maker's fill nor the complete hash lock carries the preimage); `production_code_neither_prints_nor_logs`.

## W16: the previous identity is retired manually, only after the verified chain establishes the successor

**What happens.** After a confirmed wallet rotation the vault replacement (`Controller::replace_vault`,
phase 7) makes the new identity active and KEEPS the previous identity as a superseded record in the
vault. Nothing deletes it automatically: the vault's `retire_previous` has exactly one production
caller, `Controller::retire_previous_identity`, the person's explicit act with the vault password
(tripwire `only_the_explicit_act_retires_the_previous_identity`, which also checks that the gate runs
before the deletion).

**The gate** (`retirement_allowed`, a pure function; refusals are the typed `RetirementRefusal`): the
kept identity must be the active identity's immediate predecessor in the same lineage (same authority,
generation one lower, another key), otherwise `NotThePredecessor`; and the VERIFIED chain (the locally
replayed canonical store through `ChainView::verified`, never a peer's claim) must record exactly the
active identity's descriptor as the current key of the wallet's authority, otherwise
`SuccessorNotCanonical { chain_generation }`: `None` when the verified chain records no current key
(the rotation is not on it), `Some(1)` when it still records the previous key, `Some(3)` when it has
moved past the vault's active key. A wrong password is `Vault(..)`; nothing is deleted on any refusal.
Certified finality is never rolled back, so once the verified chain records the successor the previous
key cannot become current again.

**What is preserved.** The retirement deletes only the superseded vault record. Like every controller
call that reads the verified view, it first refreshes: the operation outbox is reconciled with the
verified head (statuses move to confirmed, expired or inputs-spent) and SETTLED records beyond the
newest 1,024 (`DEFAULT_MAX_SETTLED`) are pruned; open (pending) records are never pruned. That refresh
is not specific to the retirement and happens at most once per verified head, so the controller test
takes its "before" picture after a refresh at the same head and then compares: the queued and settled
operations (records, bytes, statuses, reservations; the queued rotation itself), the preimage store
and the payment pool are unchanged by the retirement and by each refused attempt; the verified chain
is not written. The previous identity's history on the chain
is the chain's. Recovery after the retirement is the new identity's phrase (`Session::restore_current`
against the verified authority); the previous phrase no longer controls the authority once the
rotation is canonical.

**Funds at the previous identity's address.** They remain spendable by the successor: consensus'
wallet book resolves a registered historic address to its authority's CURRENT descriptor
(`WalletBook::authorize`, `consensus/src/wallet_authority_v1.rs`), and wallet-core's coin selection
uses exactly that rule (`wallet-core/src/ops/select.rs`). The controller test spends a 1,000,000-atom
coin at the previous identity's address with the successor's key after the retirement, and consensus'
`Transaction::verify` accepts that payment against the rotated state's coins and wallet book.

**What the tests run on.** The W16 tests do not run on a chain where a certified block carried the
rotation. They run on hand-built starting states: the public fixture state as a trusted Genesis, to
which the test applies the signed rotation through consensus' `WalletBook::register`/`apply` and edits
the coins (the rotation's funding spent, its outputs and the old-address coin added). "The verified
chain" in this section is the replica's verified view of that starting state.

**What depends on Lane P (P9, "fund from authenticated wallet history").** The retirement gate does
not: it reads only the verified current descriptor of the authority. The old-address spend does: it
exercises today's `WalletBook::authorize` and wallet-core's selection. If P9 changes how a historic
address's funds are authorized or selected, the old-address part of
`retirement_waits_for_the_verified_successor_and_keeps_pending_operations_and_old_funds` must be
re-run and revisited with it.

**Tests** (`wallet_controller_v2::tests`): `retirement_is_allowed_only_when_the_verified_chain_names_the_successor`
(nine cases, every refusal by its exact variant: nothing kept, another wallet's identity kept, a
generation gap, the same key, no current key, the previous key current, a later key current,
undecodable chain bytes, and the allowed case);
`retirement_waits_for_the_verified_successor_and_keeps_pending_operations_and_old_funds` (the
rotation, the replacement, refusals over two chains that do not establish the successor, the wrong
password, the retirement, everything else unchanged, then the successor's spend of the old-address
coin verified by consensus); `only_the_explicit_act_retires_the_previous_identity`; `retirement_refuses_a_kept_identity_that_is_not_the_predecessor` (review M13b: the predecessor check at the controller, over the chain that does establish the successor; nothing deleted); and phase 7's
`a_signed_rotation_and_the_vault_replacement_leave_the_vault_holding_the_new_identity` now asserts the
typed refusal.
