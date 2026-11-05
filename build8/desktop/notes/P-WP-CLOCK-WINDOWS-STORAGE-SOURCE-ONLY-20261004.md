# Windows C8 storage draft — source only

Codex (GPT-6), isolated `codex/cand3-clock-windows` from integration
`2e500abfa70387db3bad1053682d090e065090d0`. No Cargo, native ACL/provisioning,
child process, suspend, or storage qualification campaign was run for this draft.
`rustfmt` and `git diff --check` are source checks only. Archive worktree/evidence untouched.

## Scope and design

Own `node/src/host_clock/state_dir.rs`, its new child `state_dir/windows_storage.rs`,
and `anchor_store.rs` storage dispatch. Other clock issuance/voter/provider files
remain outside this tranche. No dependency, carrier, fee, StateRoot or policy change.
Unix owner checks and I/O are preserved. Windows `HostClock::start` still refuses.

Strict ordinary absolute drive paths exclude UNC/device/stream/DOS-name/dot aliases.
The initial candidate backend accepts only a local fixed drive whose actual handle
reports NTFS persistent ACLs. Open every ancestor without reparse following and
without DELETE sharing; retain the chain for the full store lifetime. Read owner,
DACL, type and volume/file ID from native handles. Trusted ancestor owners/rights
are current user, SYSTEM, Administrators and TrustedInstaller; unknown applicable
write/delete-child/delete/DACL/owner grants and unsupported ACE semantics refuse.

Only a missing final leaf is created, nonrecursively, with an atomic native security
descriptor: current-user owner and protected explicit current-user+SYSTEM full access.
Existing leaves are checked without ACL repair. Records/marks/lock/temps require
current-user owner, protected two-ACE policy, no inherited/foreign grants, no reparse,
ordinary file type and exactly one hard link. Native creation also supplies atomic
security attributes. Metadata operations inspect the actual handle. Mutation reopen
compares the retained preflight ID; directory pins and private ACLs are the foreign
account path barrier. This does not claim to defeat a malicious same account/admin
that changes ACLs, substitutes drive mappings or restores the whole lineage.

The exact native lock handle takes `File::try_lock` and lives in `ClockStateDir`.
No lock file unlink, named mutex, wait, theft or startup record read before lock.
CreateFile handles are explicitly noninheritable and checked with GetHandleInformation.
Concurrent first lock creation only retries OPEN on native FILE_EXISTS, then checks
owner/ACL/identity before locking. A sharing conflict or API failure refuses.

Windows AnchorStore reads, replacement and unlink use this backend. Fresh exclusive
temp has WRITE_THROUGH; native file flush before replacement; handle-relative
FileRenameInfo replacement; native file flush after replacement. A failed stage is
an error, and stale-record removal failure is explicitly StaleNotInvalidated.
Old partial temp is renamed to a private random `.tmp.evidence-*` sibling, preserving
its exact bytes rather than purged. Normal writes leave only the defined current
record/mark, but repeated interrupted writes grow local evidence; no silent pruning.

File flush does **not** establish directory/device power-loss persistence. Native
Windows process-crash results must be measured; storage does not grant restart
qualification even when bytes and sequence are intact. No volume-flush privileges,
production provisioning, existing ACL changes, copied-key antirollback claim,
qualified elapsed source, authenticated calibration or physical association is added.

## Draft native tests and remaining campaign

Draft tests invoke actual positive checked Windows creation/I/O, explicit ACL/owner
refusal with unchanged security snapshots, delete-child/null-DACL/foreign grant/owner
seeds, hardlink and directory reparse aliases, exact file-ID substitution hook,
second process lifetime locking, abrupt owned child exit, noninherited lock/directory
pins, actual abrupt exits at create/flush/rename boundaries, retained partial bytes,
native AnchorStore commit/failed unlink, v1 refusal and same-boot records that never
grant restart qualification. Child fixture processes have owned cleanup guards;
all fixture directories/evidence are retained. Symlink and foreign owner seeds are
required platform fixture capabilities; no silent skip/Unsupported kill claim.

Pending: compile/link/type check; positive runtime before any behavioral kill;
all native tests; simultaneous process-open race and differently spelled real-file
aliases; explicit directory check/open adversarial boundary; failure/permission
changes around mark/record flush; file-ID/ACL/reparse/hardlink/lock/flush behavioral
mutants; Linux regression; supported Windows matrix and filesystem crash semantics.
Do not count an early Unsupported or compilation error as a killed native mutant.

Authentic calibration/source inventory, OS/VM/platform matrix, measured physical
elapsed pairing/drift/suspend/capture/leap margins remain required inputs. C4 restart
is unqualified. This routine C8 draft is not a Windows voting support/qualification PASS.

## Primary API basis

- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew):
  security attrs, noninheritance, reparse flags and lifetime sharing modes.
- [CreateDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw):
  atomic descriptor for the final component; persistent-ACL filesystem requirement.
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo):
  handle owner/DACL lookup and READ_CONTROL; no ACL mutation-race guarantee.
- [GetVolumeInformationByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew):
  actual handle filesystem/ACL flags.
- [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
  and [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle):
  native source handle and directory-relative replacement target.
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers):
  per-file flushing; volume flushing needs administrator privileges and is excluded.

FFI structure/constants inspected against local Windows SDK 10.0.26100.0 source;
that inspection neither fixes a supported OS matrix nor demonstrates API behavior.
