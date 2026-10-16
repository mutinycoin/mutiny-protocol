# Existing physical roles and platform qualification limits

The existing corrected local `D:/Mutiny/build8/spec/PHYSICAL-ROLES-V1.md` was read without changing the original checkout and imported byte-for-byte into candidate 3. SHA-256: b1dc242cf5c528f6ffcbd75688972f4571e1137851d926734590730c140c592f.

Its explicit approved initial roles identify the physical Linux server laptop as the only initial weighted voter, the Vultr cloud server as a zero-weight validator/relay, and the Dell workstation as the Windows source/Desktop/wallet/administration host outside the weighted voter set. That existing role correction does not waive real-TPM, clock or physical-host association checks and does not authorize substituting the Dell if Node A fails. No hardware probing, production admission or provisioning was performed by this import.

The takeover's C8 requirement remains explicit: refusal on Windows is not equivalent ACL enforcement. `ClockStateDir::open` presently implements owner-only startup/path/handle checks on Unix and refuses the unimplemented non-Unix path. Windows voting-node qualification is not established; no change in supported voter scope is inferred from this refusal. Current Windows work is software verification and Desktop TEST-VALUE. Native Unix owner/substitution and two-process lock checks, final clock source review and physical drift/holdover qualification remain distinct work and evidence requirements. Any expansion to a Windows weighted voter requires equivalent ACL protection and elapsed/boot sources before qualification.

The role document was absent from the integration source despite references from the clock preparation note. This import makes that existing local input reviewable; it creates no new protocol rule or production authority.
