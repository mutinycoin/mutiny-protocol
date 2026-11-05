# LoRa firmware backup snapshot — 2026-11-05

This dated archival snapshot preserves the Max-Gain LoRa project source,
resolved ESP-IDF config, and a previously compiled application. The repository
root README remains authoritative for production releases: **Mutiny Protocol
V1.0 — Build 6.9 remains the formally locked production release**. This snapshot
does not promote a release or replace that authority.

Included: 20 unchanged source-tree files, one unchanged resolved build config,
and `mutiny_lora_bridge_display.bin` (246,048 bytes). These source/config bytes
match retained inputs from the prior verified application build. The BIN
SHA-256 is
`e4eaa7799a0bb5a934e2b7a52f709b56796dd720b64409df40f04fd68405a97d`.
`MANIFEST.json` records byte counts and SHA-256 values; `SHA256SUMS.txt`
also covers this README and the manifest.

The current `bridge_main.c` is 17,672 bytes, SHA-256
`e0d31d5af3b1e1efbaf71354d039029f7e8f3e42f71d8037ad1be7b2430a9bac`.
It contains TX_POWER_SETTING 22, PA_DUTY_CYCLE 0x04 and PA_HP_MAX 0x02.
Historical comments and integration notes in the preserved source predate some
edits; the exact source and resolved config define this snapshot's settings.

Keep `bridge-overlay` and sibling `components/lora_display` together.
Dependencies are external: ESP-IDF 5.5.5 at commit
`b774170ff46c393eeb5e495ea37936038d3f4f4f`, target esp32s3; GNU Xtensa
GCC 14.2.0 / esp-14.2.0_20260121, CMake 3.30.2 and Ninja 1.12.1.

Excluded from public publication: board flash dumps/layouts, device identifiers,
installation records, old compiled outputs, stale root metadata, historical
logs/caches, external SDK/toolchains, and two auxiliary source-tree files with
local machine paths (`BRIDGE-OVERLAY-DIFF.txt`, `test/run-host-tests.ps1`).
No retained source/config/BIN bytes were edited. Credential/private-key/wallet
pattern inspection found no matches in this payload.

Backup verification checks file integrity only. No rebuild, new hardware test,
flashing, release tagging, or release promotion was performed for this snapshot.
