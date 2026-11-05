# Architect-corrected Build8 physical roles

The Architect's explicit correction supersedes every earlier conflicting host
assignment. No admission or Genesis was made using the mistaken Dell assignment.

| Machine | Build8 role | Continuity authority |
|---|---|---|
| Physical Linux server laptop, SSH alias mutiny-node2, hostname mutiny-mainnet-02 | Node A; six ESP32 miners | Initial physical voter only after full technical qualification |
| Vultr cloud server | Node B; six ESP32 miners; validation, synchronization, wallet service and relay | Voting weight 0; bond eligibility NO |
| Dell Precision 3561 | Architect development workstation, Codex, source/build, Desktop V8, wallet and administration | Outside the initial weighted voter set; no authorized admission |

Architect selected direct Wi-Fi for production mining: Miners 1–6 connect to
Node A; Miners 7–12 connect to Node B. USB through the Dell is for supervised
provisioning/qualification, not the production mining relay. COM4 remains reserved
for the excluded LoRa campaign. See WORKER-WIFI-TRANSPORT-V1.md.

The Architect confirms physical presence and intended supervised admission of
the Linux server laptop. This does not waive TPM/host checks. Execute every Node
A attestation probe on its host Linux installation. Exclude VM guests, vTPMs,
forwarded/passthrough TPMs and cloud instances. If Linux Node A fails real-TPM
qualification, STOP FOR FORGE; never substitute the Dell automatically.

Node A requires entirely fresh Build8 NodeID, node authentication identity,
TPM-bound Continuity identity, state and Genesis binding. Reuse no Build7 node
keys, identity, peer identity, state or configuration authority. Existing generic
administrative SSH access is transport for qualification, not Build8 authority.

Dell TPM artifacts are renamed workstation-dell-* and retained solely as
non-admission development diagnostics. They are forbidden inputs to Genesis,
Node A enrollment or physical-voter approval. Its wallet recovery public identity
remains valid as the distinct bootstrap recovery authority; this grants the Dell
no Continuity voting weight.

Linux qualification gates: hardware/platform/virtualization inventory; TPM device
and manufacturer; EK certificate chain and possession through ActivateCredential;
new non-exportable P-256 voting key and certified attributes; fresh challenge-bound
quote; measured boot/platform validation; supervised physical-host association;
durable protected key state and restart behavior. No enrollment before all pass.
