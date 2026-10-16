# Desktop Wallet V8 custody and identity, version 1

> **Status: RETIRED V1 specification, retained for provenance.** Phase 0C (commit e34bd2c) retired the V1
> Ed25519/BIP32 desktop wallet this document specifies (SLIP-0010 Ed25519 identity, Argon2id plus DPAPI custody of the
> BIP39 entropy, the SQLite store and the create/restore ceremony); that code is no longer in the desktop. The active
> wallet is V2: hybrid Ed448 + FN-DSA-1024 custody through crypto-v2 `wallet-custody` (`desktop/src/wallet_v2.rs` and
> the UI-free `wallet-core/`), behind closed production gates. The original text below is unchanged.

Fresh implementation. No Build7 code, keys, database, lockfile or authority imported.

256 bits from Windows OS CSPRNG through getrandom become 24 English BIP39 words.
The BIP39 passphrase is the empty string, distinct from the local unlock password.
SLIP-0010 Ed25519 hardened path: `m/44'/1297437697'/0'/0'/0'`.
The second component is the Mutiny network class, not a claim of SLIP-0044 registration.
Path is fixed for this wallet schema; changing it requires an explicit new schema.

Ed25519 public key is 32 bytes. AddressID is SHA-256 over ASCII
`MUTINY-BUILD8-ADDRESS-V1` followed by one NUL, NetworkID big endian u32
`4d555401`, and public key. Account identity uses `MUTINY-BUILD8-ACCOUNT-V1`
with the same NUL/network/public encoding. Both render lowercase hex.
These are pre-Genesis public identities. Transactions and network objects must
later bind the locked GenesisID; a wallet identity alone does not authorize traffic.

Libraries: bip39 3.0.0, ed25519-dalek-bip32 0.3.0 (SLIP-0010 compatible
hardened Ed25519), ed25519-dalek 2.2.0, RustCrypto Argon2id, Windows DPAPI.
The lockfile records exact resolved dependencies. Published SLIP-0010 vector
tests and a separate Python/OpenSSL-backed public fixture check derivation.

Local custody is DPAPI CurrentUser encrypted 32-byte BIP39 entropy. Optional
entropy is Argon2id v0x13(password, random 16-byte salt), memory 65536 KiB,
iterations 3, parallelism 1, output 32 bytes. Password length minimum 12 Unicode
characters. Parameters are fixed by storage version 1. UI is forbidden for DPAPI.
SQLite stores only encrypted custody, public salt/identity, transaction metadata
and transaction events. FULL synchronous commits and a rollback journal are used.
The recovery phrase restores independently of DPAPI and the previous password.
Existing custody cannot be overwritten by create/restore.

The app has no telemetry, diagnostic file logger, secret CLI arguments or UI
state persistence. Secret inputs are masked; copy is disabled by password widgets,
undo histories are cleared each frame, and the seed display is not selectable.
Windows capture exclusion is requested and must succeed before the UI starts.
This is defense in depth, not protection from malware, a privileged debugger,
camera, OS paging or all screen-capture methods. Owned secrets use zeroization;
third-party GUI/crypto allocations are not claimed to be comprehensively erased.
No real seed screen may be inspected by agent screenshot/UI automation.

Creation displays the phrase once, requires written-backup acknowledgement and
three randomly selected word confirmations. Five minutes without input locks an
unlocked wallet. Clean restore qualification runs in a separate process and empty
profile, accepts the phrase only through UI, checks all three public identities,
persists and reopens encrypted custody, removes the temporary database/profile,
and then writes only a public PASS report. Genesis remains blocked until that
human-operated gate succeeds. Interrupted qualification cannot create PASS.

Transaction persistence supports CREATED, SIGNED, SUBMITTED, PENDING and explicit
CONFIRMED, EXPIRED, SUPERSEDED, INPUT_SPENT, REJECTED terminal outcomes. Each state
change and its reason commit atomically with an event. Validated reorg may return
CONFIRMED to PENDING; ordinary restart/epoch/peer events cannot do so. Network
validation, canonical transaction bytes and actual signing/submission await the
Architect's consensus decisions and node implementation. UI reflects unavailable
balances and disabled payments rather than displaying invented network state.

Primary references: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
and https://github.com/satoshilabs/slips/blob/master/slip-0010.md
and https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
