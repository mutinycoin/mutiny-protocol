# Windows C8 native storage follow-up

Codex (GPT-6), isolated `codex/cand3-clock-windows`, based on source-only ef41009.
Ordinary Node-root offline/locked debug campaigns compile library, binary and all
integration targets; only the named clock storage filters executed. Stable Windows
MSVC 1.98.1, jobs4/test threads2, verified private TMP/TEMP root recorded in evidence.

Final formatted source: state_dir filter **14/14 PASS**, zero ignored (13 meaningful
storage/lock/path tests plus one env-absent child-helper no-op; child-mode executions
are counted with their parent behavior, not extra qualification tests). Native-only
filter on preceding equivalent source **11/11 PASS** (10 meaningful, one helper).
AnchorStore existing filter **14/14 PASS**, zero ignored; these tests use intentional
unchecked/unlocked doubles and are compatibility regressions, not Windows C8 proof.

Exact evidence directory:
`D:/Mutiny/build8-targets/codex-clock-windows-evidence-20261004`.
Final logs `c8-state-final-1.log`, `c8-anchor-final-1.log`; native attempt logs1–5 and
positive attempt logs1–4 remain, including every failed compile/runtime and fixture.
No failed output was deleted or converted to PASS.

## Repairs established by actual native failures

1. Positive1 compile FAIL: add StorageError's standard Error trait for I/O conversion.
2. Positive2: protected creation/checks reached actual replacement, whose root-relative
   Win32 form returned error87. Native source-handle replacement now uses the documented
   absolute target form while the actual full directory chain stays pinned.
3. Positive3 happened to pass, but Native1 revealed the absolute name conversion consumed
   the missing NUL beyond the supplied rename buffer, producing stray UTF16 suffixes in
   retained TEST files. Allocate/copy explicit NUL; FileNameLength excludes it and buffer
   size includes it. Use extended native absolute paths for arbitrarily long fixture
   paths; validated input paths still accept only ordinary absolute drive syntax.
4. Native1 foreign BA-owner seed returned1307; Native2 symbolic-link seed returned1314.
   No privilege/elevation was requested. Actual foreign-owner refusal instead reads only
   SYSTEM-owned `C:/Users` security metadata and verifies unchanged owner/DACL and no lock
   creation. This is the sole read-only existing-path probe; all mutation fixtures are
   newly owned TEST directories. Reparse refusal uses an actual new Microsoft mount-point
   junction seeded successfully via DeviceIoControl with the current token; no privilege
   change. The original failed symbolic-link seed remains a recorded platform limitation.
5. Native4 deterministic directory check/open boundary showed READ_CONTROL-only handles
   did not participate in the intended delete-sharing barrier before the lock existed.
   Request actual directory GENERIC_READ too; Native5 and final state tests establish
   attempted rename is blocked during that boundary and lifetime. No assertion was weakened.

The final native probes exercise strict ACL/null-DACL/foreign grants/DELETE_CHILD and
foreign owner, unchanged unsafe leaf, hardlink and actual reparse, file-ID substitution,
directory pin/reopen boundary, four simultaneous new-store processes with exactly one
winner, actual case alias unable to acquire another lock, abrupt holder exit, child
noninheritance of locks and directories, abrupt create/flush/rename exits with retained
partial temp bytes, native mark-publication failure, explicit failed unlink condition,
real encoded V2 record restart evidence and oldV1 refusal.

## Limits remain open

The positive Windows APIs/process-crash behavior above is software evidence on this
development host. Physical suspend/elapsed/drift/calibration/leap/provider inventory,
supported OS/VM matrix, power-loss and filesystem durability qualification remain open.
File flush succeeds or refuses explicitly; it does not prove directory/device power-loss
persistence. Production HostClock::start is still unsupported on Windows. Every restart
remains unqualified (C4); no same-account/admin antirollback or physical-host binding.
The checked old-target handle is released before publication: malicious same-account
replacement between check and publish remains explicitly outside the foreign-account
ACL/directory pin barrier. No production directory was provisioned, re-ACL'd or purged.
Repeated interrupted temp evidence grows locally and is retained without silent pruning.

C8 behavioral mutants, refreshed Linux regressions and final combined-source/native
campaigns remain required. None of the repaired failed attempts is a mutant kill.

Primary docs: [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info),
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[FSCTL_SET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point),
[REPARSE_DATA_BUFFER](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer).
Native test success is recorded separately from documentation-based design assumptions.

Later source delta: [absolute path spelling follow-up](P-WP-CLOCK-WINDOWS-PATH-SPELLING-20261004.md)
records the separate native positive for ordinary slash aliases. The14/14 results
above remain attached to their own06source bytes; broad changed-source native tests
are not inferred from the narrow follow-up.
