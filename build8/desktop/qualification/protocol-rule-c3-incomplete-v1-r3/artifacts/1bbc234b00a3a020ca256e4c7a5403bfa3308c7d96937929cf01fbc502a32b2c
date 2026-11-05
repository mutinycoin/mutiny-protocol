# Build8 D1 candidate lock packet V1

Status: **EXACT CANDIDATE REVIEW PACKET / NOT FINAL MAINNET LOCK / NOT LAUNCH READY**. Date 2026-10-01. Subordinate to [the single canonical specification](BUILD8-TRADING-SYSTEM-V1.md) and supplied Architect directives. No registry, ProtocolFingerprint or Genesis changes accompany this packet.

## 1. Authority and launch scope

ARCHITECT LOCK: supplied Decision Lock sections 1–25 supersede conflicting proposals; the prior 65-section master otherwise controls. T1 is CLOSED / HISTORICAL EVIDENCE BOUNDARY ACCEPTED. D1 engineering is approved; T2 final canonical lock is pending. No unseen section or node-reputation/arbitration power is inferred from the title.

The latest relayed Architect direction is: “I need the all features built into the protocol from day one. Only Desktop App, Mobile App, and Miner Firmware are allowed to be upgraded afterward.” All required protocol features, including trading, must be complete before launch. Wallet-only Desktop 1.0 describes client scope only. Future-rail architecture is not permission to postpone required protocol capabilities into a post-Genesis upgrade. Earlier “implementation may be later” language cannot waive this launch requirement. Required protocol support for each preserved feature must have explicit prelaunch evidence; application delivery can follow only within the allowed client scope. The readiness target is 2026-10-03 18:54 UTC, not permission to bypass requirements. Continue real integration in existing canonical state/proof/node/wallet interfaces; exact ownership and parent-routed shared hooks are recorded inline in the canonical specification. This does not authorize Genesis sealing or activate a production fiat rail.

CODEX IMPLEMENTATION DETAIL: `trade-candidate-v2`, `trade-durable-candidate-v1` and `trade-session-candidate-v1` are isolated, default-disabled candidates. Their providers are copied read-only for qualification. No independent maximum-security campaign source is edited. The exact choices below distinguish implemented behavior from proposed final representation and open integration work. Approval of architecture does not approve these proposed final numeric allocations automatically.

## 2. Types, codecs, hashes and candidate object inventory

All arrays below are fixed-order definite CBOR; integers are unsigned, shortest form. `H32` means exactly 32 bytes, not text. `U64` includes overflow rejection; amounts are `STRIKES:U64` unless explicitly Bitcoin satoshis. Descriptors are bounded binary objects validated by the existing provider. Exact re-encoding rejects alternate forms, trailing bytes, unknown tags/versions, duplicate approval slots and unsorted/duplicate inputs. No floats, scripts supplied as executable adapter policy, or UI-only settlement facts are accepted.

Implemented V2 namespace `N = b"MUTINY-OFFLINE-TRADING-CANDIDATE-V2-20261001"`. `H(d,x)=SHA256(N || 00 || ASCII(d) || 00 || x)`. Context is `(NetworkID:U32, GenesisID:H32, ProtocolFingerprint:H32)`. Explicit object version is 1 inside this candidate namespace; it is not native wire-version 1.

```
Body = [N, 1, NetworkID, GenesisID, ProtocolFingerprint,
        TradeID:H32, ContractHash:H32, OperationGeneration:U64,
        CreatedHeight:U64, ExpiryHeight:U64, Fee:STRIKES,
        [InputID:H32...], Action]
Approval = [slot:U8, descriptor:bstr, Ed448:bstr114, FNDSA1024:bstr1280]
Operation = [Body:bstr, [Approval...], OfferProof:bstr|null]
WalletApprovalPayload = [N, Body:bstr, slot, descriptor:bstr]
OperationID = H("operation", Body)
OutputID(i) = H("output", OperationID || i:U8)
```

Each wallet approval uses current `WalletBook` authority and existing `Domain::Transaction` over that nested candidate payload. BOTH_REQUIRED is mandatory. Exact body identity excludes signature randomness, but an accepted retry must carry the exact persisted envelope bytes; a different envelope for an accepted ID is a conflict. Signed envelope limit is 16,384 bytes; inputs are strictly increasing, at most 16; approvals at most two; descriptors at most 2,048 bytes. Generation must be nonzero; CreatedHeight <= ExpiryHeight.

| Action tag / exact array | Wallet slots and fee payer |
|---|---|
| `[0, OfferID, MakerID, sender, recipient, amount, condition, refund_height, change]` | 0 sender, 1 recipient; sender pays principal+fee |
| `[1, OutputID, recipient, amount, preimage32, change]` | 0 current recipient; recipient supplies separate fee inputs |
| `[2, OutputID, refund_owner, amount, change]` | 0 current refund owner; owner supplies separate fee inputs |
| `[3, OfferID, MakerID, LicenseID, license_generation, seller, buyer, price, payment_destination, change, inclusion_height]` | 0 seller, 1 buyer; buyer pays exact price+fee |
| `[4, OfferID, MakerID, MUT_seller, MUT_buyer, amount, fiat_terms_hash, change]` | 0 seller, 1 buyer; seller pays deposit+fee |
| `[5, OutputID, buyer, seller, amount, fiat_terms_hash, change]` | 0 buyer PAYMENT_SENT/completion; 1 seller PAYMENT_RECEIVED/APPROVE; buyer pays separate fee |
| `[6, TreasuryID, current_generation, current_AddressID, current_descriptor_hash, new_generation, new_AddressID, new_descriptor, change]` | 0 current active Treasury wallet; same wallet pays fee |

All IDs, owners, condition and terms hash in the table are H32. Generations/heights/amounts/change are U64. New descriptor is bounded bstr. Preimage is exactly 32 bytes; shared condition is **plain SHA256(preimage32)**, compatible with Bitcoin's native SHA256 operation. Hash knowledge never replaces wallet authority.

```
OfferBody = [N, 1, NetworkID, GenesisID, ProtocolFingerprint,
             trade_descriptor:bstr, nonce:H32, created_height:U64,
             expiry_height:U64, maker_side:U8, terms]
terms = [0, MUT_STRIKES, BTC_satoshis, BitcoinEnvironment:U8]
      | [1, LicenseID, current_generation, price_STRIKES]
      | [2, MUT_STRIKES, fiat_terms_hash]
OfferID = H("offer", OfferBody)
MakerID = H("trade-identity", trade_descriptor)
OfferProof = [OfferBody:bstr, offer_Ed448:bstr114, offer_FNDSA:bstr1280,
              fill_Ed448:bstr114, fill_FNDSA:bstr1280]
OfferSigningPayload = [N, b"signed-offer", OfferBody:bstr]
FillSigningPayload = [N, b"offer-fill", Body:bstr]
```

Maker side 0 is MUT sender / License seller / fiat MUT seller; side 1 is recipient/buyer. Candidate Bitcoin environments 0/1/2/3 mean mainnet/testnet/signet/regtest. Offer body <=4,096 bytes, proof <=8,192 bytes. Funding tags 0/3/4 require the maker's offer and exact fill signatures plus wallet approvals. Other tags require null proof. Validate derived IDs, full context, matching native terms, inclusion interval inside the offer interval, both hybrid signatures and expected maker role before consumption. Bitcoin quantity/environment are signed but not validated against a Bitcoin transaction by V2.

Candidate trade signatures use independent synthetic Role::Transport keys under nested `Domain::TransportInitiator`. They are never wallet/Node keys or reused live transport keys. This provider seam is not a final Trade role allocation. Current V2 commits ContractHash but has no complete canonical TradeContract parser or two-sided negotiation transcript; that gap must close before deployment.

## 3. Exact records, state and durable representation

The implemented candidate uses `key=H(kind,id)` and `record=CBOR[N,kind:bstr,payload:bstr]`. Payload schemas:

| kind / logical id | Payload |
|---|---|
| `context` / zero32 | `[NetworkID,GenesisID,Fingerprint,height,fee_accumulator_STRIKES]` |
| `coin` / OutputID | `[owner,amount]` |
| `locked` / OutputID | `[TradeID,ContractHash,generation,sender,recipient,amount,created_height,lock_kind]` |
| lock_kind | `[0,condition,refund_height]` or `[1,fiat_terms_hash]` |
| `spent` / OutputID | terminal integer: 0 claimed, 1 refunded, 2 fiat released |
| `consumed` / SingleFillKey | `[TradeID,ContractHash]` |
| `license` / LicenseID | `[owner,generation,active_worker|null,pending_worker|null,assignment_generation,outstanding_lock:bool,rights_from_height,1]` |
| `treasury` / TreasuryID | `[[generation,AddressID,descriptor,effective_height]...]` |
| `receipt` / OperationID | `[H("signed",exact_envelope),inclusion_height,fee_STRIKES]` |
| `wallet` / existing wallet record key | Exact existing `WalletBook.records()` record bytes; no replacement authority format |

The whole offline view has at most 1,024 counted state items. These context/coin/License/receipt copies are fixture machinery, **not a proposal for a parallel canonical monetary ledger**. Native integration must reuse existing UTXOs, wallet authority, LicenseRecord and fee accounting; only genuinely new conditional/consumption/Treasury fields belong in canonical state. A final typed-record adapter and storage-growth/pruning rules are still required.

Durable namespace `S=b"MUTINY-OFFLINE-TRADE-DURABLE-CANDIDATE-V1"`:

```
Snapshot = [S,1,[[record_key,record_bytes]...]]  // strictly key ordered
Receipt = [OperationID,Fee_STRIKES,[OutputID...],inclusion_height]
StateDigest = SHA256(S || 00 || Snapshot)
StoreIdentity = [S,1,N,NetworkID,GenesisID,Fingerprint,16,262144,256,base_height]
meta(id=1, identity, independently_trusted_base, state, sequence)
events(sequence, unique_operation_id, exact_operation, height_BE8,
       fee_floor_STRIKES_BE8, receipt, state_digest)
```

SQLite exclusive create never resets an existing file. Open requires an existing, exact-schema store and independently trusted initial public state including wallet authority. Reconstruct every event through real V2 authorization and compare every receipt/digest/final state. `BEGIN IMMEDIATE` serializes local competing processes; event and state commit together with FULL synchronization and DELETE rollback journal. Bounds are 16 events, 256 KiB snapshot, 256 pages of 4,096 bytes and 1,500ms busy timeout. Exact accepted retry returns its original receipt; ambiguous response never creates a new operation.

This is one local execution journal. It is not chain finality, malicious-storage rollback protection, private-history encryption or the Bitcoin signer/broadcast outbox. Saved passing counterexamples demonstrate coherent rollback divergence and separate-journal double fill. Process-crash qualification does not prove power-loss durability.

## 4. Conditional MUT transitions and time partition

At inclusion height H: context must equal the authenticated state context, H cannot go backward, CreatedHeight <= H <= ExpiryHeight, fee meets section 9, exact approval slot set is present and all authorizations pass. Validate against a tentative state and commit only after every effect and capacity check succeeds; failure changes neither funds, consumption marker nor fees.

LOCK requires positive amount, distinct sender/recipient, refund height R>H and operation expiry<R. Both consent to funding. Sender-owned inputs total exactly principal+fee+change; create the lock at output index 0 and optional sender change at index 1. Consume SingleFillKey atomically.

CLAIM requires the matching unspent lock, same TradeID/ContractHash/generation/amount, current recipient hybrid authorization and SHA256(preimage)=condition. Lock creation height < H < R. Debit separate recipient-owned fee inputs; credit **the full locked principal** directly to recipient at output 0 and optional fee-input change at output 1; remove lock and record Claimed.

REFUND requires the same unspent record and context, current refund-owner hybrid authorization and H>=R. Return the full principal to the original sender, separately pay fees, remove lock and record Refunded. Claim and refund cannot both be eligible at one H or both consume one output. At H=R claim fails and refund may succeed. A signature prepared earlier confers no later claim eligibility. Expired transaction signatures can be refreshed only through an explicitly authorized new operation, never automatic signer retry after ambiguity.

OperationGeneration is an exact contract-generation binding, not permission to increment a counter to reuse an output or offer. Current wallet authority is resolved through the native wallet authority view; retained destination addresses do not revive revoked signing keys. Tests exercise stale wallet generations, context/contract changes, amounts, signature components, 46 boundary/order cases, double effect and atomic failure. Native block ordering/finality integration remains required.

## 5. Single-fill representation and partition behavior

Implemented `SingleFillKey=H("single-fill",CBOR[NetworkID,GenesisID,Fingerprint,OfferID])`. Maker/taker, contract and generation are intentionally excluded. Funding/DvP inserts `[TradeID,ContractHash]` only after maker offer/fill and all wallet authorizations pass. One key is consumed once; refund never reopens it. An exact retry is idempotent, another operation with that offer conflicts. Expired offers cannot resurrect funding.

FORGE ENGINEERING PROPOSAL for final review: retain one minimal canonical consumption/nullifier per economic offer, created in the first successful native funding or DvP operation, not on public listing or chat. No consensus order book or paid listing is introduced. No Bitcoin funding may precede authenticated finality of the unique native value lock in the construction proposed below. Off-chain reservations remain advisory. Independent SQLite journals cannot enforce this rule globally; canonical finality is a prerequisite, not a future client convenience.

Pruning may not make an old identifier spendable: proposed retention through offer expiry plus finality proof, with a canonical non-replay rule, requires an exact bounded storage design and vectors. The candidate conservatively retains consumption forever within its small test bound. This scale limit must not silently become a monetary limit on Treasury trades or a production chain capacity.

## 6. Native License/MUT DvP and rights boundary

The signed operation binds exact LicenseID/current generation, both wallets, payment destination, price, input set/change/fee, TradeID/ContractHash, inclusion height and expiry. Both current wallet authorities must approve. The License must exist under the seller, have the expected generation and have no outstanding lock or pending Worker assignment. A payment or License signature alone has no effect.

On success: debit buyer inputs; credit exact signed price to signed payment destination and buyer change; transfer License ownership to buyer; increment License generation and assignment generation with checked arithmetic; clear active Worker; consume offer; account fee. Apply all effects atomically. Historical seller coins are untouched. The seller may explicitly approve a payment destination different from its own address; this is signed recipient data, not coordinator substitution. Treasury's direct-destination constraint is stricter and cannot use such substitution.

PROPOSED FINAL BOUNDARY: transfer is included at H; new License-derived rights start H+1. Work/reward attribution for block H uses the parent-state owner; H+1 uses the transferred owner and requires fresh valid Worker binding. Candidate stores rights_from_height=H+1 but does not qualify native reward execution. Pending assignments/outstanding locks fail closed rather than being silently cancelled. Prior active Worker no longer obtains rights through the sold License; Worker identity itself is not transferred or destroyed. Rebinding requires new owner authorization and incremented assignment generation. Competing transfer/assignment/rotation operations follow canonical transaction ordering and current pre-state authority; stale generations fail. No seed/private-key transfer occurs.

Before final lock, map these exact proposed effects into existing LicenseRecord, Worker assignment, stale-work rejection and reward code; qualify inclusion-height versus epoch scheduling and wallet rotation interactions end to end. Protocol-issued new License purchase remains a different operation, not DvP/resale.

## 7. Treasury destination and custody

ARCHITECT LOCK: BTC and distinct MUT Treasury each have the Architect as sole operational custodian. No quorum, recovery committee or node/Forge authority. MUT requires the final wallet BOTH_REQUIRED suite. No Treasury amount minimum/maximum/period limit/spend percentage/reserve is imposed. Positive quantities, integer/script/UTXO/dust/fee feasibility are technical constraints only. The Architect chooses exact BTC quantity and MUT consideration at offer creation; no oracle or economic slippage algorithm replaces that decision.

Candidate Destination is `[generation,AddressID,descriptor,effective_height]` under TreasuryID. Descriptor embeds wallet suite and descriptor generation. History begins at generation 1, has consecutive generations and strictly increasing effective heights, rejects reused addresses, and validates descriptor-to-address derivation. Active destination at H is the latest entry with effective_height<=H.

Rotation binds full context, operation ID via signed Body, old generation/address/current-authority descriptor hash, new consecutive generation/address/descriptor and exact fee inputs. There is NO effective-height field and NO scheduled activation (Architect ruling, 2 Oct 2026): finalized inclusion at height H is the effective boundary, recorded as the successor's effective_height=H. Only current active Treasury wallet BOTH_REQUIRED authorizes, within the operation's signed validity window. New destination must already resolve to a valid wallet authority. Same-block competing successors resolve by execution order: the first applies, a later one naming the superseded generation fails WrongGeneration/Context. New offers and commitments use the successor only once it is effective in finalized state; existing offers and trades keep their frozen destination; historical destinations stay recognized where their coins back outstanding reserves; rotation cannot release, erase or migrate reserves and there is no reserve-migration operation. No old history is overwritten. The four-entry history bound fails closed (a fifth rotation is rejected, never truncates history) and remains an open candidate limit. Current-authority wallet-key rotation and Treasury destination rotation are separate transitions.

The local frozen Treasury offer records full context/OfferID/TradeID/ContractHash/TreasuryID/generation/address/creation height/BTC quantity/MUT consideration. Creation resolves the active destination at the supplied trusted height. Later rotation does not mutate it. V2 direct-credit verification binds **the exact funded OfferID**, recipient, principal, original locked output and successful claim output. MUT credit alone cannot mark BTC conversion COMPLETE.

**Open final integration seam:** a local journal or signed historical height is not a global timestamp proving that an unfunded offer existed before rotation. A historical destination inclusion proof proves state at that height, not offer publication time. A compromised/backdated local record could otherwise evade “old generation prohibited for new offers.” Exact final policy must define authenticated offer creation/continuity evidence without adding a consensus order book, generic paid listing or override authority. Proposed engineering direction is independently verified canonical destination evidence plus an Architect-controlled append-only authorization journal; it enforces the honest sole signer's creation policy but is not Byzantine global timestamp proof. Any additional canonical offer commitment would be an explicit D1 representation change for the consolidated review, not an implicit implementation choice.

The future BTC signer must independently validate Architect authorization, trade/contract, exact BTC/MUT terms, frozen destination and evidence, Bitcoin network/inputs/outputs/change/fee, linked replacement and duplicate status. Persist exact signed transaction bytes before broadcast. Lost signer/RPC response enters reconciliation by OperationID/TXID/input set; never request another signature automatically. No arbitrary Bitcoin-signing API or private key enters the engine. These signer/Bitcoin integrations are not implemented by V2/durable/session.

## 8. BTC/MUT construction, clocks and truthful guarantee

PROPOSED CONSTRUCTION FOR ENGINEERING, not an implemented atomic-swap claim: the **MUT payer generates** a fresh 32-byte secret and commits SHA256(secret). Both parties authenticate the full contract. MUT payer first creates the canonical conditional MUT lock with a sufficiently long refund boundary R and consumes the offer. The BTC seller independently verifies finalized MUT output, recipient, exact principal, condition, refund boundary and unique offer consumption. Only then may it authorize/fund a shorter-lived Bitcoin-native hash/time lock. The MUT payer independently verifies exact Bitcoin funding script/output/amount and required best-chain confirmation evidence before claiming BTC; that claim reveals the secret. BTC seller verifies the revealed preimage and claims MUT with its own BOTH_REQUIRED authorization strictly before R. Treasury follows the same flow, with MUT recipient frozen to Treasury.

If the second funding never occurs, MUT payer refunds at R. If neither claim occurs, BTC seller follows its Bitcoin timelocked refund path and MUT payer later refunds MUT. Refund transactions/destinations, script versions, Bitcoin height or median-time-past semantics, transaction locktime/sequence, monitoring and fee funding must be reviewed before either chain locks real value. Bitcoin uses native script/signatures; no Mutiny hybrid authorization is forced onto Bitcoin.

Different chains' heights are not directly comparable. A contract must bind concrete Bitcoin timeout semantics, concrete MUT R, confirmation/finality policies and an evaluated safety interval allowing preimage observation, reorg resolution, fee escalation and MUT claim inclusion. Numeric Bitcoin confirmation depth and margin may be qualified in the adapter campaign, but unsafe or unspecified funding rejects now. A paused adapter does not pause chain deadlines.

A typical Bitcoin timelocked refund branch becomes eligible at its timeout while the hash-claim branch may remain spendable. That is **not** MUT's exclusive H<R claim / H>=R refund partition. A delayed BTC claim after a MUT refund would violate the desired outcome unless online refund/reconciliation and bounded confirmation/liveness assumptions prevent it. An arbitrarily stalled/censored chain or unbounded reorg breaks unconditional atomicity. The guarantee sought is conditional exchange safety under explicitly qualified chain finality, bounded delay, monitoring and fee assumptions, not unconditional “atomic” settlement. Exact script/transaction vectors, adversarial deadline races and asymmetric-stall analysis remain release blockers.

Observe MEMPOOL, INCLUDED, FINALIZED, CONFLICTED and REORGED separately. Reorg revises evidence for the same trade, freezing unsafe effects. RBF is an explicitly authorized linked replacement of that same economic operation; preserve approved recipients/consideration/Treasury destination and old/new TXID history. Mainnet Mutiny pairs with Bitcoin Mainnet; campaigns use explicitly non-production Bitcoin environments. No live Bitcoin action is authorized by this packet.

## 9. Fees, units, size and beneficiary

ARCHITECT LOCK: applicable native trading/value operations require `max(240 STRIKES, otherwise-required canonical native fee)`. This is not 240 MUT and is not a generic paid offer-admission fee. No generic security deposit applies to cryptographically enforced profiles. No new fee beneficiary is proposed.

Existing `transactions_v2.rs` / `hybrid_transaction_v2.rs` require at least signed transaction byte length in native atoms; `execution.rs` adds existing fees to licensed-owner coinbase subsidy. Integrate through that existing mechanism, with no exchange/operator/Architect/mediator wallet. The candidate's caller-supplied STRIKES floor and fee accumulator are test seams, not trustworthy production fee derivation.

**One narrow unit lock item, bundled here:** does current Build8 formally define one native `atom` as one STRIKE? If yes, record the alias explicitly in canonical denomination/schema documentation; do not rescale amounts. Historical evidence says 1 MUT=100,000,000 STRIKES: reviewed Build6.4 source (`libfile_16a82cfd3958819197f4cbcad877b197`, STRIKES_PER_MUT), historical report (`libfile_528795ee8e448191a9f9ac4dae882a4a`), and parent-reported Architect wording dated 2026-08-23 followed by agreement to integer-STRIKE accounting, corroborated by Build5.0.1 source (`libfile_7959c57ece248191912572b79647a846`). The historical Architect thread was not freshly inspected in this slice. Current native code also displays 100,000,000 atoms/MUT but an explicit current atom/STRIKE alias has not been recovered. The native unit adapter stays closed pending that exact binding; this does not reopen the fee amount or allocation.

PROPOSED FINAL SIZE RULE: bound the complete signed native value envelope, including offer/fill/wallet witnesses, at 16,384 bytes initially; native fee metering counts every canonical envelope byte. Separate full contract/evidence objects remain bounded and committed, not unsigned omissions. Validate maximal legitimate envelopes and per-block verification/storage budgets before allocating the limit. Current candidate limits, session bounds and tiny durable store caps are offline engineering parameters, not economic trade-size policy. If exact native metering cannot share existing fee treatment, block only that specific new accounting path and include the exact beneficiary question; no such new beneficiary is presently needed.

## 10. Proposed final numeric and domain allocations

**ALL entries in this section are PROPOSED / UNALLOCATED / NOT IMPLEMENTED.** They are not inserted into a registry or dispatcher. The examined current native operation discriminator recognizes kinds 10–22 in its defined version/arity combinations; 200 is not accepted. Current crypto roles are 1–6; 7 is absent. Recheck the live registries with the security campaign before final approval; this packet is not a reservation against concurrent work.

| Namespace | Proposed number / representation | Consequence |
|---|---|---|
| native operation family | wire version 2, kind 200, `[2,200,Body_bstr,Approvals,OfferProof_bstr_or_null]` | New explicit parser and executor required; candidate namespace must be replaced, all signatures/vectors regenerated |
| nested action | 0 LOCK, 1 CLAIM, 2 REFUND, 3 LicenseDvP, 4 FiatLock, 5 FiatRelease, 6 TreasuryRotate | Semantics in this packet require final review; incomplete fiat recovery prevents production locking |
| crypto identity role | 7 Trade | Independent generated key; existing hybrid primitives; never reuse Role 5 production transport keys |
| trade authentication suite | local Trade-suite ID 1, policy BOTH_REQUIRED=1 | Suite namespace is distinct from wallet-suite numbers; does not introduce new primitives |
| new canonical typed records | 200 ConditionalOutput; 201 OfferConsumption; 202 TreasuryHistory | Registry representation/key-domain allocation still requires exact native adapter and collision review |
| external adapter IDs | 0 MUT_NATIVE; 1 BITCOIN_ONCHAIN; 2 FIAT_EXTERNAL; 3 LIGHTNING; 4 ATOMIC_SWAP_EXTERNAL; 5 OTHER_EXTERNAL_PROOF | Unsupported/unqualified adapter must reject; no opaque evidence bypass |
| contract profile | 0 ordinary hash-linked; 1 License/MUT; 2 Treasury conversion; 3 Fiat/MUT | Treasury remains constrained same market; profile cannot confer consensus privileges |
| clock kind | 0 Mutiny height; 1 Bitcoin height; 2 Bitcoin MTP | Value plus exact chain context; never substitute wall clock or compare cross-chain heights numerically |

Proposed exact domains: `MUTINY-BUILD8-TRADE-OFFER-V1`, `...-FILL-V1`, `...-CONTRACT-V1`, `...-OPERATION-V1`, `...-SINGLE-FILL-V1`, `...-SESSION-BIND-V1`, `...-MESSAGE-V1`, `...-RECEIPT-V1`, and `MUTINY-BUILD8-TREASURY-ROTATE-V1`. Expand each literal prefix before registration; assign provider domain-to-role restrictions explicitly. A new role/domain is not a new cryptographic primitive, but it changes final registry/fingerprint inputs and requires review. Wallet authorization remains the locked wallet suite. Bitcoin authorization remains Bitcoin-native. Session suite reuses the reviewed transport primitives; separate Trade-role handshake support is a provider-integration task, not enabled by this document.

## 11. Proposed complete contract and proof boundary

The following full-contract schema is a **design proposal awaiting codec/vector implementation**, not a claim that V2's opaque ContractHash validates every term. All mandatory arrays have exact lengths; no arbitrary extension map may change economic semantics.

```
Contract = [domain_bstr,1,Context3,TradeID,OfferID,profile,
            maker_descriptor,taker_descriptor,maker_nonce32,taker_nonce32,
            [Leg0,Leg1],Price,Fees,Deposits,Deadlines,RefundPolicy,
            DisputePolicy,FinalityPolicy,TreasuryFreeze|null]
Context3 = [NetworkID,GenesisID,ProtocolFingerprint]
Leg = [asset_kind,chain_id32,quantity_u64,adapter_id,adapter_version,
       recipient_descriptor_hash32,recipient_data_bstr,payment_method_code,
       payment_terms_hash32]
Price = [0,quantity_leg0_u64,quantity_leg1_u64] // exact fixed gross quantities
Fees = [native_fee_STRIKES,max_BTC_fee_sats,max_BTC_feerate,
        fee_payer_leg0,fee_payer_leg1,net_proceeds_leg0,net_proceeds_leg1]
Deposits = [[asset_leg_index,amount,owner,refund_destination]...]
Deadlines = [[purpose,clock_kind,chain_id32,value_u64]...]
RefundPolicy = [version,hash32_of_exact_reviewed_adapter_refund_terms]
DisputePolicy = [0] // crypto: nonbinding mediation + deterministic recovery
FinalityPolicy = [version,hash32_of_exact_reviewed_policy_bytes]
TreasuryFreeze = [TreasuryID,generation,AddressID,descriptor_hash32,
                  destination_anchor_hash32,creation_authorization_hash32]
```

Proposed sublimits: two legs; descriptors<=2,048 bytes; recipient data<=520 bytes; at most two deposits and eight uniquely ordered deadlines; full contract<=8,192 bytes. Payment method and deadline-purpose enum allocations and exact policy-byte schemas remain to be completed before this schema is lockable. Unknown policies reject; a hash pointing to unavailable/unreviewed policy is not authority. Zero deposits for the enforceable crypto profiles are normal. Market-relative ordinary-user pricing needs a separate fully specified bounded model; Treasury always fixes exact quantities. ContractHash commits canonical contract bytes; TradeID derives from context, OfferID and both identities/nonces **excluding** ContractHash, avoiding a cycle. Both trade identities authenticate the contract before wallet funding. DvP and fiat funding still require both spending-wallet consents.

Settlement evidence must use existing StateRoot V2/SettlementProof with authenticated canonical anchors. Prove exact lock/License/Treasury/consumption record key and bytes, context and inclusion/finality, not merely a root supplied by a peer. Presence of a synthetic root proves only the fixture. Absence of a lock alone does not prove successful claim; show the accepted operation and exact resulting principal output/ownership with its anchored state transition. Expired/older proof, wrong root/chain, mismatched recipient/amount/generation, claimed bank receipt and peer-supplied TXID must not authorize value. Proof compaction cannot omit fields needed to reconstruct exact commitments. The final typed-record mappings, fee/size treatment of witnesses and proofs of accepted transitions require integrated vectors before D1 final lock.

## 12. Fiat implementation and policy seams

Fiat is an approved implemented candidate class. Seller first locks exact MUT under the signed contract; buyer waits for independently authenticated deposit finality before sending external fiat directly to seller. Buyer signs PAYMENT_SENT/completion and seller, after checking actual external receipt, signs PAYMENT_RECEIVED/APPROVE. V2 release checks both current wallet signatures on the same exact release, an earlier-height unspent fiat lock, parties/terms/amount and full direct credit to buyer. The normal release is implemented; external bank truth is not mocked into objective finality.

`fiat_timeout` and unilateral refund/dispute authority fail with FiatRecoveryUnspecified. Noncooperation, chargeback/reversibility, deadlines, recovery authority and jurisdiction/rail activation policy were not supplied. No committee, reputation score, binding arbitrator or automatic payment finality is inferred. Required exit paths must be specified, implemented and qualified before production locking; approved normal flow does not make a permanently trapped-deposit design launchable. These are genuine remaining policy seams in this **one consolidated packet**, not reopened D6 class approval.

## 13. Authenticated session integration

Implemented session namespace `Q=b"MUTINY-OFFLINE-TRADE-SESSION-CANDIDATE-V1"`:

```
Binding = [Q,2,NetworkID,GenesisID,Fingerprint,OfferID,TradeID,ContractHash,
           generation,maker_trade_descriptor,taker_trade_descriptor,
           maker_transport_descriptor,taker_transport_descriptor,initial_funding_ID,
           2,1] // existing transport profile/suite, candidate only
BindingID = SHA256(Q || 00 || b"binding" || 00 || Binding)
Message = [Q,1,BindingID,transport_session_ID,sender,sequence,kind,payload]
```

Revision 2 adds BOTH_REQUIRED approvals from each trade identity over CBOR `[Q,b"trade-authorizes-transport-v2",party,Binding_bstr]`, verified before creating the pinned transport context. All four keys must have distinct Ed448 and FN-DSA public components, irrespective of descriptor generation. The provider numeric trade role remains provisional; production registry is unchanged. Claim/Refund/FiatRelease must target `H("output",initial_funding_ID || 0_u8)` using the qualified operation namespace. Original revision 1 failed the saved two-funding regression; its report remains historical evidence. Binding approvals are verified local contract attachments; full network negotiation/attachment serialization remains integration work.

Sender 0 maker/1 taker; kinds 0 binding confirmation, 1 signed operation, 2 receipt, 3 notice. Binding confirmation uses sequence 0 and empty payload; application sequences 1–64. Counterparty descriptor must be independently negotiated/pinned, never trusted from incoming handshake. The actual provider authenticates X448+ML-KEM-1024 establishment with Ed448 AND FN-DSA-1024 and uses HKDF-SHA-512 / ChaCha20-Poly1305. Exact context and endpoint orientation are checked. Both encrypted binding confirmations are required before application traffic. Mismatched contract/offer/trade/generation/funding binding closes the candidate session.

Max message 16,896 bytes, payload 16,384, 121 fragments, 140-byte fragment plaintext, 255-byte encrypted frame; four pending objects, four-message reorder window, fixed 30-second incomplete-object retention. Provider 128-frame replay window also applies; large interleaved/lost flights may require reconnect. Traffic keys/fragments are not persisted. Fresh handshake plus re-encryption of exact signed operations and durable receipt reconciliation prevents repeat effects; no ciphertext/key-state replay on restart. Only opaque authenticated received-message capabilities can reach value application, which still checks wallet/offer signatures. Notice or Receipt cannot bypass that check. No physical transport, anonymity, mailbox/history encryption or fully negotiated contract is claimed.

## 14. Evidence inventory and compatibility

| Evidence | Result and exact scope |
|---|---|
| V1 | 39-test historical snapshot; preserved attribution defect and failure evidence; superseded implementation |
| V2 `trade-candidate-v2/qualification-current.json` | 54 tests; 10 independently reconstructed offer/operation byte vectors; 4,000 bounded hostile inputs over four parsers; 46 claim/refund boundary/order cases; real hybrid synthetic authorization |
| Durable `trade-durable-candidate-v1/qualification.json` | 29 passing tests + one worker entry; 30 subprocesses, 16 abrupt exits and one parent termination; three independent storage vectors; corruption/FULL/BUSY; explicit rollback/separate-store counterexamples |
| Session revision 1, historical `trade-session-candidate-v1/qualification.json` | 18 tests PASS; 2 independent binding/message byte vectors; 2,000 hostile codec cases; real hybrid handshake/AEAD + durable funding/claim/reconnect; 697 immutable source files, live dependency drift 0; Clippy/default-disabled/offline-without-hooks PASS |

Current session revision 2: [qualification-r2](../trade-session-candidate-v1/qualification-r2.json) reports 23 passing tests plus one explicitly invoked crash-worker entry, 2 independent byte vectors, 2,000 no-panic codec cases and combined executor crash/reconnect reconciliation. No raw trade/transport key material reuse remains; final Trade role/domain allocation is still unapproved.

Machine-readable source locks, fresh executable hashes, logs, source archives and byte-vector files accompany each qualification. Tests and vectors are evidence, not policy. Session independent vectors cross-check binding/message bytes and digest, not a second independent cryptographic implementation. Real cryptographic providers operate on synthetic keys/state; chain/finality anchors and fiat terms remain fixtures. No fresh historical Synthetic Exchange inspection, physical/test-value deployment, production or release lock is claimed.

Candidate namespace/version changes are deliberately incompatible; there is no fallback into native operation dispatch. Final tags/domains will invalidate candidate signatures/IDs and require new vectors; do not migrate synthetic balances, keys, trade records or consumed identifiers into Mainnet. No Build7.6 chain/custody/identity carries over. Only verified historical entitlement for twelve fresh Build8 Bootstrap LicenseRecords at new Genesis remains as previously directed. Preserve all old reports/manifests/failing traces.

### Native candidate wire and state mapping

Namespace N = ASCII MUTINY-NATIVE-TRADE-CANDIDATE-V1. Native wire = [N,1,V2_signed_envelope_bstr,[[input_TXID,input_index]...]], bounded to 16,384 bytes. Witnesses must match each signed input hash from the existing UTXO key derivation in exact order. No alternate balance/owner assertion is admitted. Max batch 64 is a candidate engineering bound. Inner V2 signature domains remain provisional and unchanged; these are no final Mainnet opcode allocations.

State record = [N,1,local_tag,record_ID,payload], at most 8,192 bytes. Local tags: 0 conditional lock; 1 consumed offer; 2 applied exact operation; 3 Treasury destination history. Record key is existing domain_hash(N + /record, tag_byte || record_ID). Lock payload = [Context3,TradeID,ContractHash,generation,sender,recipient,amount_STRIKES,created_height,kind], where hash kind=[0,condition,refund_height] and fiat kind=[1,terms_hash]. Consumption payload=[Context3,OfferID,TradeID,ContractHash], keyed by qualified single-fill identity. Applied payload=[native_hash(signed,exact_native_wire),height,fee_atoms], keyed by OperationID. Treasury payload=[Context3,[[generation,address,descriptor,effective_height]...]]. Four retained destination entries are a local bounded candidate limit, not final rotation availability policy; scalable authenticated history remains to implement. Exact bytes/key/digests are independently reconstructed in three native vectors.

Host prepare_candidate_phase verifies committed parent root, uses committed parent wallet authority and applies all operations on the host-validated tentative State copy. Principal moves between existing UTXOs and conditional lock records; claim/refund are exclusive. Result principal output is native OutPoint(OperationID,0), fee change index 1. Claim requires created_height < inclusion_height < refund_height; refund requires inclusion_height >= refund_height. Native coinbase maturity remains the existing rule. Same-height funding/claim is rejected. The entire batch either returns a new State/root/fee total or leaves its inputs unchanged. Receipt reconciliation returns only an exact previously accepted wire hash; no second effects or fees. Existing sparse proof bytes are checked against an independently supplied trusted anchor/root; a preview never grants finality.

### Native state integration checkpoint

The three owned modules `consensus/src/trading_v1.rs`, `consensus/src/trading_v1_tests.rs` and `node/src/trading_service_v1.rs` are now delivered. They compile in the preserved current-source qualification snapshot with four explicit default-off Cargo/module overlays; those shared files have not been edited in the live repository. Qualification: [native integration report](../qualification/trading-native-v1-qualification.json), **18 native-state tests + 1 actual hybrid-store preview test + 23 corrected session tests PASS**, five independent byte vectors, 1,500 native and 2,000 session bounded no-panic inputs. The ignored session worker is invoked by the passing crash/reconnect test. This is OFFLINE native-state integration and canonical-store preview evidence, not complete canonical block commit, physical or production settlement. All five promoted KDF override packages were verified through Cargo metadata for all three build roots. The session-owned root manifest/lock now preserves those overrides; no shared Cargo or security source was replaced.

Native conditional lock/claim/refund and fiat dual-approval normal release consume real State UTXOs, verify current parent WalletBook BOTH_REQUIRED, record minimal consumption/application objects and produce real StateRoot V2 proofs. Rotation uses the current Treasury wallet authority and retains old destination records. Native License DvP returns LicenseHookRequired until coordinated Book ownership/Worker semantics exist. Native Treasury offer-creation/freeze proof and BTC conversion are not established merely by rotation tests. Fee tests explicitly assume one synthetic native atom per STRIKE; ordinary unresolved-unit and production gates reject. Complete-envelope byte fees can exceed 240; the module returns the fee for existing host accounting and creates no fee wallet.

[Exact shared hooks and source preimages](../qualification/trading-native-v1-hooks.json) give the parent a minimal integration handoff: gated dispatch, one fee accumulator, typed restore, existing atomic canonical store and native License rights. Parent must route foreign-file edits. Canonical block commit/reopen, accepted-effect proof, real networking and wallet outbox integration remain. No new parallel balance ledger or production registry entry was created. Failed development/runner attempts and all earlier evidence remain preserved.

### Native revision 2 exact additions

License record local tag 4: [N,1,4,LicenseID,[Context3,owner_generation,current_owner,previous_owner,TransferOperationID,inclusion_height,rights_from_height,assignment_sequence_at_transfer]]. Generation >=2; rights_from_height=inclusion_height+1; current Book owner/genesis and assignment sequence must agree; no active old Worker at the transfer sequence. Missing ownership record for a detached historical Worker generation rejects under native typed validation. Absence of a prior ownership record means the initial generation 1. A second transfer cannot precede the previous H+1 boundary. Pending Worker assignment rejects; there is currently no separate native License ownership-lock primitive. Any future lock must join this exclusion rule. The proposed Book capability/hook is experimental and requires coordinated promotion and full Worker/reward qualification.

Treasury freeze payload = [N,b"treasury-freeze",1,Context3,creation_height,creation_block,creation_root,TreasuryID,TreasuryGeneration,AddressID,TradeID,ContractHash,OfferBody_bstr,current_wallet_descriptor_bstr]. Frozen envelope=[payload_bstr,Ed448_signature_114,FN_DSA_signature_1280], <=8192 bytes. Existing Domain::Transaction signs the fully separated payload; no production domain is allocated. OfferBody already binds exact BTC/MUT integers and Bitcoin environment, and must have Treasury as recipient/maker side, exact current creation height and bounded expiry. Creation independently verifies maker offer signature and current Treasury wallet authority. Persisted decode verifies both wallet signature components; native canonical-store historical verification independently resolves the expected state/root. A current state proof cannot be substituted for the bound creation state. No independent global timestamp is claimed.

Treasury native funding checks exact frozen OfferID/body/TradeID/ContractHash/recipient/amount before ordinary native authorization, UTXO and one-fill execution. Credit verification requires the exact funding and claim accepted receipts and full principal UTXO. Compact proof verification uses three genuine StateRoot V2 inclusion proofs at the independently authenticated same anchor/root: funding receipt, claim receipt and exact claim principal output. Different offer, recipient, amount, receipt, root or anchor rejects. Loss/spending of the current UTXO requires obtaining an appropriate historical inclusion proof rather than inferring absence means failure. Bitcoin evidence is separate.

### Native integration revision 2 (historical checkpoint)

[Fresh R2 qualification](../qualification/trading-native-v1-r2-current-qualification.json) reports **53 distinct tests / 77 passing executions**: 28 native tests with the experimental LicenseBook hook, 25 with that hook disabled, one actual canonical-store test and all 23 session tests. Seven independent byte vectors pass. All 925 captured inputs are unchanged; no live dependency drift. All seven promoted KDF package paths (including Argon2/Blake2) were verified at each Cargo root. This remains OFFLINE candidate evidence. The live shared executor, Book, registry and security sources were not edited by the trading owner.

The reserved-record classifier defect is fixed: indefinite outer arrays, nonminimal array headers and chunked namespace bytes cannot hide a complete trading namespace from strict decoding. The failed reproduction is preserved in the R2 development evidence. Disabled CandidatePolicy rejection and default-off builds pass; host restore must apply the same reservation in both feature modes.

Native License DvP now implements exact seller/buyer BOTH_REQUIRED approvals, real UTXO payment, one-fill consumption, ownership generation, H+1 rights and an opaque Book-transfer capability atomically on the tentative State. The qualified experimental Book overlay rejects stale owner/assignment and pending assignment, clears active Worker, increments assignment sequence and preserves historical Worker/ticket bytes. It is delivered as a reviewable patch, **not installed into foreign Book source**. Normal candidate configuration retains LicenseHookRequired. Tests use explicit synthetic pre-state ownership mappings/public Worker fixtures; pending-state exclusion does not claim new enrollment admission or full block/reward/rebinding qualification.

Treasury creation resolves the current canonical destination through actual CanonicalStore helpers and prepares an immutable exact payload for the separate MUT Treasury wallet's external BOTH_REQUIRED authorization. Decoding, historical verification, old-generation funded continuation, direct native principal credit and exact receipt/UTXO sparse proofs are implemented. No signature request, BTC spend, paid listing, order book or new fee beneficiary is introduced. Historical state authentication still does not prove global offer-creation/publication time; signer-journal and final D1 creation-evidence semantics remain explicit. These proofs qualify the MUT leg only, never conversion COMPLETE.

Both earlier session defects remain closed: exact initial funding/output binding and separate raw trade/transport key material. Saved R1 failure: `trade-session-candidate-v1/evidence-r2/development-history/regression-failing.log`; corrected qualification: `trade-session-candidate-v1/qualification-r2.json`; all 23 tests were freshly rerun in this R2 native report. Final Trade role/domain allocation remains provisional.

The [R2 host delta](../qualification/trading-native-v1-r2-host-delta.txt) and [exact hook manifest](../qualification/trading-native-v1-r2-hooks.json) cover the new candidate License record match, permissive namespace classifier, mandatory detachment validation and experimental Book feature. These extend the earlier hook handoff; parent must route the shared edits. Full canonical commit/reopen, reward/epoch/rebinding, external signer journal, BTC settlement and final D1 rules remain gates.

## 14a. R3 Bitcoin intent, creation witness and journal candidate exacts

Implementation detail only; no final Mainnet tag/domain/Genesis allocation. Native typed restoration now requires the actual bound License record at every reserved transfer key, not key presence. R3 qualification and the reproduction are linked from the canonical specification.

The node's optional `trading-bitcoin-candidate` uses namespace bytes `MUTINY-BITCOIN-OFFLINE-CANDIDATE-V1` (N). Its only Bitcoin network is candidate ID 3 = regtest. Mainnet remains paired with Bitcoin Mainnet in the locked final architecture; this test adapter cannot activate either. Strict definite/minimal CBOR, exact array sizes, bounds and re-encode equality reject aliases/trailing bytes.

TreasurySwapIntent is:

```text
[N,1,3,OperationID,revision,previous_TXID_or_null,
 frozen_Treasury_offer_bstr,exact_native_funding_wire_bstr,
 authenticated_MUT_anchor_bstr,MUT_root,Bitcoin_tip_hash,Bitcoin_tip_height,
 BitcoinTerms,unsigned_Bitcoin_tx_bstr,SHA256_condition,MUT_refund_height,
 b"FIXED-EXACT-ARCHITECT-CONSIDERATION",0]
BitcoinTerms = [Inputs,BTC_recipient_compressed_pubkey,BTC_refund_compressed_pubkey,
 BTC_refund_height,approved_change_script,exact_fee_sat,fee_limit_sat,
 expiry_MUT_height,policy_generation,1]
Input = [exact_previous_Bitcoin_transaction_bstr,vout,approved_P2WPKH_pubkey]
OperationID = SHA256(N || b"/operation" || 0x00 || NetworkID_u32be ||
 GenesisID || ProtocolFingerprint || TradeID || ContractHash)
IntentHash = SHA256(N || b"/intent" || 0x00 || canonical_intent)
```

The nested frozen Treasury body binds TreasuryID, generation, AddressID, exact BTC/MUT integers, maker offer, wallet descriptor and historical creation anchor/root with BOTH_REQUIRED. BTC authorization uses secp256k1/Bitcoin rules, not those hybrid keys. A dedicated signer independently receives the exact approved intent hash, approved watch-only input identities, change script and policy generation. Those are trusted signer-policy inputs, not proof supplied by a peer. Previous transaction bytes authenticate identity/value/script against approved outpoints but do not prove current unspentness or finality.

Local registration in each independent engine/signer journal accepts NEW frozen offers only at CURRENT authenticated CanonicalStore head/root. R3a persists INCOMPLETE first, rechecks current authenticated head/root, then atomically promotes ADMITTED only on equality. Head advancement, store error or crash leaves a durable incomplete tombstone. Historical proof cannot finish admission. Journal user_version 1 is required; nonempty unversioned R3 journals return LegacyJournal and retain all existing operation/signature bytes. Existing exact entries reconcile using historical canonical state after rotation. Thus the implemented local path rejects new backdated/old-generation registration. It cannot prove Byzantine/global first publication or detect a coherent rollback of both trusted stores. No consensus order book, listing transaction or paid listing fee was added. Any extra final consensus creation witness must return with the single exact D1 lock.

Before Bitcoin funding is prepared or signing dispatched, the adapter independently reads verified CanonicalStore history, exact applied funding receipt, still-unspent conditional output and consumed-offer record. It rechecks TradeID/ContractHash/offer/body/context/amount/recipient/condition and expiry. Existing old-generation frozen offers continue unchanged. Candidate fixture safety values (30 MUT blocks remaining, 10 Bitcoin blocks remaining, 2 confirmations) are explicit simulation inputs, not approved final margins, a clock conversion or an economic policy.

The Bitcoin template uses P2WPKH SIGHASH_ALL inputs, an exact P2WSH principal and at most one approved P2WPKH change output. Inputs <=16, transaction bytes <=32768, intent <=131072, previous transaction <=32768; these are provisional technical resource bounds, not Treasury economic caps. Fee limits are exact per-intent authorization. No min/max/period/reserve/slippage oracle policy is introduced.

```text
IF SIZE 32 EQUALVERIFY SHA256 <shared_condition> EQUALVERIFY
   <recipient_pubkey> CHECKSIG
ELSE <Bitcoin_refund_height> CLTV DROP <refund_pubkey> CHECKSIG ENDIF
```

The narrow spender verifier checks exact script, authority, sighash, output and fee template. Refund transaction locktime must meet the height condition with a non-final sequence; Bitcoin inclusion must be strictly later than the transaction's absolute locktime. The claim branch remains spendable after timeout. This verifier is not a full Script VM, witness-commitment proof, general external-transaction monitor or unconditional atomicity guarantee. Production recovery MUST detect a valid shared preimage even when a counterparty's claim spends to a different authorized output/fee structure; rejecting an unapproved template must not suppress a safe MUT claim. Two-leg completion/receipt integration is still absent and remains gated.

Engine and signer databases are separate SQLite WAL/FULL journals with bounded rows, blobs, input reservations, revisions and structural/integrity validation. States: PREPARED -> SIGN_DISPATCHED (includes unknown response) -> SIGNED (exact bytes persisted) -> BROADCAST_PENDING (includes unknown acknowledgement). Reopening SIGN_DISPATCHED permits query/reconciliation only, never a second signing permit. A dedicated signer can return an exact cached response; absent cached bytes remain ambiguous. Identical signed responses reconcile; differing bytes reject. R3a first broadcast_request(store, operation, revision, headers, safety) accepts SIGNED only and freshly validates unspent native funding, deadlines, latest revision and absence of observed delivery/reorg/conflict. It persists BROADCAST_PENDING before returning exact signed bytes. Repeating that method returns Ambiguous. Read-only reconcile_broadcast supplies exact identifiers/bytes for lookup even after expiry/store outage; it grants no retransmission or signing permit. Explicit safe rebroadcast after exact reconciliation remains an engineering seam. Explicit linked replacement uses the same OperationID and monotonically increasing revision, with unchanged frozen offer, funding, inputs, recipient/refund script and consideration; only fee/change changes within the original limit, and a fresh exact authorization is mandatory. Old/new TXIDs remain recorded.

Regtest headers pin genesis, fixed regtest target/PoW, previous hash, median time and accumulated-work fork selection; graph <=4096. Merkle proofs bind exact transaction identity and current best-chain depth. State distinguishes unknown, unconfirmed mempool hint, included, funding-confirmed, reorged and conflicted. Hints cannot finalize. Reorg recomputes status without creating a trade. A conflict freezes effects. This is SPV under a valid-chain assumption, not validation of every block transaction/input. No actual RPC, broadcaster, mainnet difficulty, signet challenge or current UTXO oracle is implemented.

R3 qualifies native canonical funding/rotation commits using synthetic TPM/Continuity/miner setup, twelve Bitcoin tests, eight abrupt subprocess exits, five independent Bitcoin vectors plus five native vectors. Node/OpenSSL independently verifies BIP143 ECDSA in addition to RustBitcoin/libsecp256k1. Physical power loss, real Bitcoin test-value, coherent rollback resistance, complete receipts and production qualification remain. The library source/lock and 24 reachable registry archives are pinned; all seven current KDF overrides and latest worker-session provider files remain intact.

### 14b. R3a review corrections and qualification

qualification/trading-native-v1-r3a-qualification.json: 56 distinct passing tests / 82 executions, ten vectors, ten abrupt exits at nine distinct local boundaries; zero live network acknowledgement tests. Regressions cover actual canonical head advancement, actual store-halted read failure, incomplete registration restart, process exit on both sides of final head read, persisted signed bytes followed by expiry, actual native CLAIM consuming the funding output, BTC refund-margin exhaustion, inclusion/reorg/conflict, and read-only recovery through expiry/outage. Historical R3 count is corrected to 47 passing names (48 listed including ignored worker); modes 6/7 repeat one local boundary. Prior artifacts remain unchanged.

These corrections change local candidate journal/API behavior only. They do not assign production tags, activate consensus, prove current Bitcoin UTXOs, grant global creation-time authority or establish complete cross-chain settlement. Shared host integration is separately owned.

### 14c. R4 offline evidence/recovery exacts — provisional implementation only

The final installed R4 source and qualification are linked from specification revision 11. No production opcode, registry or ProtocolFingerprint change. Recovery cache maxima: 4,000,000 serialized bytes per block, 256 retained complete blocks, 64 MiB aggregate block bytes; 4,096 recovery events/assessments, event <=32,768 bytes and assessment <=4,096 bytes. These are candidate resource bounds, not Treasury economic policy. Missing scan coverage fails closed. Full Script/UTXO/subsidy/deployment/relative-lock consensus validation and mempool status are not inferred from commitments.

Unsigned public assessment CBOR is exactly 25 elements:

```text
[b"MUTINY-OFFLINE-RECOVERY-EVIDENCE-V1",1,OperationID,revision,
 TradeID,ContractHash,BTC_satoshis,MUT_STRIKES,Treasury_AddressID,generation,
 BTC_funding_TXID,BTC_spend_TXID_or_null,MUT_terminal_ID_or_null,
 Bitcoin_tip_hash,native_anchor_bstr,native_root,native_outcome,status,false,
 "SPV_VALID_CHAIN_ASSUMPTION_NOT_PRODUCTION_INCOME",
 funding_block_or_null,spending_block_or_null,funding_fee_sat,
 native_funding_fee_STRIKES,native_terminal_fee_STRIKES_or_null]
```

Candidate local tags only: native outcome 0 Locked/1 Claimed/2 Refunded; assessment 0 Pending/1 BitcoinIncluded/2 BitcoinClaimed/3 BitcoinRefunded/4 Reorged/5 Conflicted/6 SettledUnderSpv/7 RefundedUnderSpv/8 Disputed. Exact ratio BTC/MUT is the fixed price basis; no derived economic price decision. Known fees are separately unit-labelled. No counterparty fee is guessed. Public summaries cannot authorize settlement.

BlockArchive checks full transaction/witness commitments and covered chain spends under an explicit SPV valid-chain assumption; independent full-node validation is still required. RecoveryJournal events use exact OperationID/revision and immutable intent hash for chain references. Revealed-preimage knowledge is durably retained before chain references and remains queryable without headers, archive or RPC. It cannot replace BOTH_REQUIRED or establish payment. Native credit proofs are rooted in the actual authenticated historical inclusion state, preserving evidence after subsequent principal spending. Reorg/conflict revises assessment only, never creates another trade, signature, payment or refund. Separate databases retain old branches and records; no reset/migration of prior campaign evidence.

The 35-test full-run report plus nine-test final retention delta are distinct immutable evidence snapshots (44 executions, 35 distinct names). Eighteen distinct independent vectors; fourteen baseline abrupt exits plus four repeated delta exits (thirteen distinct local boundaries). No Bitcoin executable, actual RPC acknowledgement, real Bitcoin value, full consensus validation, production income or unconditional atomicity claim.

### 14d. R5 completion boundary and pending rebroadcast/replacement policy

No new consensus schema, numeric opcode or fingerprint allocation is introduced. find_by_locked_output is read-only local recovery of the already persisted operation after an ambiguous prepare response; it validates the recovered ID against the exact stored wire/lock. Native completion reuses the existing candidate CLAIM, REFUND and FiatRelease objects and actual CanonicalStore validation. Local journal user_version=1; at most 256 rows; each exact NativeOperation wire <=16,384 bytes. Unique operation and locked-output IDs prevent a local re-preparation/reset. Local stages 0 Draft/approval-pending, 1 Signed, 2 Dispatch-pending, 3 Canonically-applied; per-slot request mask 0..3. These SQLite tags are not production registry allocations. Different participants' journals do not create consensus authority; canonical lock consumption still makes claim and refund mutually exclusive.

Approval purpose derives from the immutable action/slot: CLAIM, REFUND, buyer PAYMENT_SENT or seller receipt approval. Fiat buyer slot 0 must be verified before issuing seller slot 1. Each party signs the same canonical body plus its own slot/descriptor; BOTH_REQUIRED verifies both primitives. Read-only ApprovalQuery, explicit LockedOutputUnavailable and immutable signed_bytes supply exact reconciliation data, never another signing or dispatch permit. A wallet response lost before its bytes are cached stays ambiguous. If fee inputs, expiry or authority become unusable, the current implementation fails closed; no silent completion replacement is provided. Encrypted history, rollback resistance and explicit safe completion-replacement policy remain to qualify.

SpvFundingInspection is a local private-field diagnostic result binding intent hash, TXID, Wtxid, approved inputs and covered chain tip. It checks the implemented P2WPKH signatures and covered unspentness under the declared SPV assumption, but deliberately supplies no full-validation boolean/token or production authorization. A current independently validated Bitcoin chain/UTXO view, conflicting mempool transactions, replacement ancestry, and durable reorg-aware header state must be integrated and qualified before activation. Startup-only Core qualification would not close these gates.

**Pending technical rebroadcast/RBF proposal, not implemented authorization:** reconcile the exact OperationID/revision, all linked TXIDs, exact signed bytes, inputs/outputs, independently validated best-chain and mempool/conflict state. Unknown RPC/signature results are unresolved, never evidence of failure. An eventual explicit exact-byte rebroadcast permit would have to retain the same TXID and recheck current native lock/deadlines, competing revisions, claims/refunds and reorg/conflict state, durably record the attempt before sending, and preserve every outcome. No such permit exists now. An RBF revision additionally needs an explicit linked replacement authorization over its exact new intent; immutable TradeID/contract/consideration/frozen destination/economic effect remain identical, with only reviewed fee/change fields allowed. Old/new TXIDs and bytes stay linked. Observation or disappearance alone authorizes neither resend nor a second signature. Final fee-bump resource rules and race tests remain one integrated adapter qualification item, not new monetary caps/reserve/slippage economics.

Nine distinct R5 qualification tests across ten executions, three independent approval vectors and eight abrupt commit boundaries repeated in sixteen exits supplement preserved R4 evidence. All BTC fixtures/SPV assumptions and simulated fiat attestations are labelled. Native fixture execution and settlement proofs use real reviewed provider/canonical APIs with synthetic authorities. No test-value, full Bitcoin consensus, physical, production-income, or final D1 claim follows.

### 14e. R6 local encrypted state exacts and remaining custody/recovery gates

Local namespaces only: MUTINY-OFFLINE-ENCRYPTED-LOCAL-STATE-V1, OFFLINE-LOCAL-COMPLETION-V1 and MUTINY-OFFLINE-NATIVE-TRADE-AUDIT-V1. These do not allocate production domains/opcodes or alter D1 consensus objects. Native operation bytes, fee rules, wallet BOTH_REQUIRED and recipients remain unchanged.

Strict local CBOR schemas:

```text
context = [namespace_bstr,1,purpose,NetworkID,GenesisID,ProtocolFingerprint,StorageID,key_generation]
AAD = [context_bstr,class,sequence,previous_ciphertext_commitment]
frame = [1,nonce_24_bstr,ciphertext_with_tag_bstr]
head_plaintext = [sequence,commitment_32]
event_plaintext = [kind,body_bstr]
completion_body = [b"OFFLINE-LOCAL-COMPLETION-V1",OperationID,LockedOutputID,
                   exact_native_wire,stage,requested_mask,d0_or_null,d1_or_null]
header_body = [recorded_admission_time_u32,exact_header_80_bstr]
native_public_audit = [b"MUTINY-OFFLINE-NATIVE-TRADE-AUDIT-V1",1,anchor_bstr,root,
 OperationID,WireHash,TradeID,ContractHash,action,principal_STRIKES,recipient,
 fee_STRIKES,"CANONICAL_NATIVE_APPLIED_EXTERNAL_PAYMENT_NOT_ASSERTED",false]
```

Purpose 1 = native completion/history; 2 = regtest headers. Class 0 = authenticated head (sequence zero/zero prior); 1 = event chain. Kinds 0 = completion snapshot, 1 = private note, 2 = native public audit, 3 = Treasury assessment, 4 = header. Audit action 0 claim/1 refund/2 cooperative fiat. Commitments are SHA256(namespace || NUL || label || NUL || bytes), labels empty or frame. Head is updated atomically with the new event under an immediate SQLite transaction and exact previous encrypted-head compare. No key material appears in these records.

Candidate bounds: 4096 events, 196608-byte body, 197632-byte frame, aggregate frames <=64 MiB, database/WAL preflight <=128 MiB each; completion rows <=256, individual private row <=32768 bytes and wire <=16384. Technical resource limits impose no Treasury amount/reserve cap. No compaction/rekey/migration reset is provided; exhaustion fails closed. Whole-store replay must verify strict sequence, AEAD, canonical encodings, hash chain, authenticated head and caller minimum checkpoint. Header replay recomputes the selected branch using the actual regtest verifier. Durable completion replay also verifies hybrid signatures and monotonic request/descriptor/stage progression; canonical authority still controls live actions.

R6 source/hash/evidence and additive dependency wiring are in qualification/trading-native-v1-r6-host-handoff.md. Twelve offline tests, six independent encoding/audit vectors, one published AEAD vector and fourteen process exits do not establish physical power-loss resilience, coherent rollback immunity, full Bitcoin validation or encrypted coverage of every previous journal. Production StorageKey provisioning/wrapping/recovery, protected checkpoint integration and local memory qualification remain closed. This preserves the already locked sole Architect Treasury custody; no new custodian or governance decision is requested.

Remaining policy seams stay consolidated in section 15. Fiat normal release does not decide chargebacks, deadlocks, unilateral refund, jurisdiction, rail activation or binding arbitration. R5a corrects the reviewed startup harness shutdown marker and child cleanup boundaries, but supplies no Bitcoin launch or broadcast authorization. Genesis remains UNSEALED.

### 14f. R6a correction and consolidated storage authority boundary

R6a changes no consensus object, fee, unit, signature transcript or encoded storage record. It makes poisoned state uniformly unreadable/unexportable and makes both checkpoint() APIs fallible. Preserve the R6 qualification as its original snapshot and use qualification/trading-native-v1-r6a-qualification.json for the corrected source. The bounded stale-writer regression reproduces the independently reported underlying-log-only poison condition; every exposed completion read now returns Poisoned until verified reopen. Mutation entry was already closed.

Storage engineering continues without reopening sole Architect Treasury custody. Remaining production integration must identify the approved local-data key provider/wrapping/recovery and a separately protected monotonic checkpoint for each custody domain; distinguish ordinary trader history from Architect-controlled signer history. A host must not silently designate a cloud service, coordinator, node vote or new custodian as that authority. Nonce reservation durability, exact operation/revision identities, torn writes, coherent rollback assumptions and key/nonce-ledger recovery belong in the same final packet. No production key constructor or custody ceremony is authorized here. R7 is subsequently qualified offline as described in 14g; production activation remains closed.

One reviewed R5a non-value startup completed cleanly. Further launches, Bitcoin settlement/test value, signing/broadcast and final Genesis remain unauthorized by that bounded execution. Post-exit recorded PIDs were absent; the independent port read was access-unresolved and was not bypassed.

### 14g. R7 exact local storage representation and consolidated recovery boundary

Candidate-only namespace MUTINY-OFFLINE-ENCRYPTED-JOURNAL-V1; no Mainnet registry/tag/fingerprint commitment. Local kind 1 engine, 2 dedicated signer, 3 recovery, 4 Bitcoin blocks. Context = [namespace_bstr,1,kind,NetworkID,GenesisID,ProtocolFingerprint,StorageID,key_generation]. AAD = [context_bstr,class,counter]. Class 0 authenticates the empty nonce-ledger statement, 1 encrypts each SQLite chunk, 2 encrypts the snapshot head. Nonce = prefix_16 || big_endian_u64(2*counter + data_bit); data_bit=0 only for the immutable ledger statement and 1 for unique encrypted chunks/head. Counter <= floor(i64::MAX/2). Existing approved XChaCha20Poly1305 remains the only encryption primitive.

Head plaintext strict minimal CBOR = [generation,schema_hash,plaintext_hash,total_size,start_counter,chunk_count]. Chunks are sequential 128 KiB slices of SQLite's own memory serialization; total <=128 MiB and <=1024 chunks. Each frame has its own reserved counter; the head uses the next counter. Ledger and snapshot files/WAL are individually preflight bounded at 512 MiB. Logical operation/history bounds still apply. The schema hash binds ordered sqlite_master type/name/table/SQL plus user_version, with SQLite autoindexes excluded. Hashes use SHA256(namespace || NUL || label || NUL || bytes), labels schema/sqlite/head. A restore verifies all AEAD/context/size/counter/head/schema/hash checks in a fresh memory connection and checks the logical journal before use. Logical schemas are local storage formats, not canonical consensus schemas.

Caller checkpoint = {generation,encrypted_head_commitment,nonce_counter,prefix}. A independently retained latest checkpoint rejects older snapshot/ledger generations; nonce reservation survives snapshot failure. Counters are never reset on ambiguous errors. Reopen with missing/inconsistent files fails; no automatic new-store replacement or new operation is allowed. Coherent rollback of all local evidence plus that checkpoint is an explicit assumption, not solved by encrypted files. Production integration must bind key wrapping/recovery and monotonic checkpoint retention to the already approved custody domain. Ordinary trader data and dedicated Architect signer data require separate domains. No new custodian, committee, cloud authority or override is assigned. If approved existing providers suffice, wiring is engineering; any genuinely new recovery authority/rollback-trust choice belongs in the consolidated final packet. Production key/ceremony activation is still unauthorized.

R7 preserves exact signed bytes before exposing a broadcast request, and existing OperationID/revision/replacement histories. Interrupted signing response reconciliation accepts the exact cached response only; it never reauthorizes signing. Native canonical locks/claims/refunds, fiat dual approvals, fee allocation and Treasury frozen destination are unchanged. Safe quiescent migration/rekey/backup compaction and broader history coverage are still engineering gates. No native/Bitcoin settlement guarantee is strengthened merely by storage encryption. See qualification/trading-native-v1-r7-qualification.json and host handoff for source hashes, failure evidence, exact ten-test scope and shared dependency preimages.

### 14h. R7 nonce review hold

Independent source review identified a ledger-only rollback gap in R7. A write can reserve counters above the retained snapshot/checkpoint, encrypt, then crash before publishing the next snapshot. Restoring only the authentic earlier nonce ledger can then pass reopen against the unchanged snapshot/checkpoint and reuse a deterministic data nonce. This is broader than coherent database-plus-ledger-plus-checkpoint rollback. Existing ordinary-crash evidence remains valid within its original scope; it did not test adversarial ledger restoration. R7 encrypted-storage promotion and production remain CLOSED pending a reproduced regression, correction and fresh qualification. Never recreate a missing ledger, reset a trade, or discard signed bytes. R6a poison and fallible-checkpoint requirements remain controlling. R8 migration is staged only and paused on this dependency; no migration is installed or active.

### 14i. R7a local nonce correction and precise remaining rollback boundary

Local namespace V2 replaces the vulnerable writable V1 format. Data-frame wire is the existing R6 strict CBOR [1,random_nonce_24,ciphertext_and_tag]; AAD remains [V2_context_bstr,class,counter], class 1 chunk / 2 head. Every data encryption calls the existing unchanged seal() using fresh OS entropy. The encrypted head plaintext/schema, exact journal bytes, nonce-ledger counter and checkpoint fields otherwise retain their engineering meanings. Counter-derived even nonces authenticate only the fixed empty class-0 ledger statement. Counter rollback can repeat ordinals; it no longer supplies data nonces. This is an existing reviewed random-nonce construction with an explicit entropy assumption, not an external rollback authority or a new cryptographic primitive.

The pre-fix failing regression, fixed exact regression, V1 rejection and full scoped R7/R6a rerun are in qualification/trading-native-v1-r7a-qualification.json and its failing-regression archive. Ordinary crash evidence from R7 remains scoped correctly. Uncommitted ledger-only rollback need not be detectable; fresh data nonce safety is separate from detection. Economic history can still roll back when the snapshot/checkpoint are rolled back or the caller supplies an outdated checkpoint. No missing-ledger recreation, reset-trade path, production key constructor or automatic V1 migration is added. Past V1 ciphertext must not be assumed authentic merely because it decrypts after demonstrated nonce reuse; preserve and independently reconcile exact authorized transactions before any qualified migration. No production keys have been used here.

The already locked custodians do not change. Production storage-key wrapping/recovery and independently retained latest-checkpoint integration remain the same consolidated gate. Approved existing-provider wiring is engineering; no new committee/cloud authority is invented. R8 remains staged, with activation/cutover and source-writer retirement explicitly separate from copying a journal. Genesis and production remain closed.

## 15. Consolidated disposition and next engineering work

Resolved and **not reopened**: D1 candidate direction; 240 STRIKES minimum with existing native fee allocation; Treasury no caps/reserve and exact Architect-set price; sole BTC/MUT Treasury custody; current-authority rotation; direct frozen settlement; no Bitcoin dividends; crypto nonbinding mediation; fiat class and normal dual-approval release. No exchange/Continuity reputation coupling is authorized.

This packet is a reviewable exact candidate baseline, not yet a complete final lock recommendation. Remaining final-D1 work: native typed schema/record adapter and allocations; complete contract/policy codecs; authoritative STRIKE/atom alias; canonical finality and global consumption/pruning; License/Worker/reward integration; Treasury creation/rotation evidence semantics; final Bitcoin script/recovery monitoring, confirmation/clock margins, live replacement and signer/outbox qualification (R3 implements offline subcomponents); final proof/fee/size/compatibility vectors. Most are authorized engineering and continue without questions. The actual policy decisions are the narrow denomination binding if no current authority is recovered, any extra consensus creation-anchor representation required for Treasury guarantees, final rights/time/registry lock, and unsupplied fiat failure/rail policy. No new beneficiary question is needed unless implementation discovers a genuinely new allocation path.

Run complete adversarial/fault/recovery campaigns, two-party separate environments, Bitcoin test-value and physical transport qualification before release review. All required protocol features must meet launch gates before final Mainnet rules/fingerprint/Genesis, even if Desktop first ships only wallet UI. Genesis remains UNSEALED and production activation disabled.

## Candidate 3 amendments: T1 (P3, P4, P9)

Status: PROPOSED-UNFROZEN integration amendment of this imported copy (Lane P work package WP-T1, branch `cand3/p-t1`; Order of 4 October 2026 decisions P3, P4, P9 and Q15; design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 1.a, 4, 5.1, 10 with `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-1(d), AM-3, AM-8, AM-11). Where this section and sections 2, 4 and 6 above differ, this section is the implemented candidate rule. Later work packages (T2: P5 entitlements, T3: P6 Treasury authority, T4: P7 maker offer) append their own sections after this one. Evidence: Windows host, software, TEST-VALUE tests only; nothing here is qualified, frozen or Linux-proven.

### T1.1 Body version 2 (replaces the Body of section 2)

```
Body = [N, 2, NetworkID, GenesisID, ProtocolFingerprint,
        TradeID:H32, ContractHash:H32, OperationGeneration:U64,
        Envelope, Fee:STRIKES, [InputID:H32...], Action]          ; 12 elements
Envelope = [1, first_height:U64, last_height:U64, [reference_height:U64, reference_block:H32], [Precondition...]]
```
The envelope is the operation envelope V1 (`spec/OPERATION-ENVELOPE-AND-CONFIRMATION-V1.md`, `consensus/src/op_envelope_v1.rs`): codec invariants E1-E7 hold in both directions, so a body with an invalid window, reference or precondition list cannot be encoded (`Error::Bounds`), signed, or decoded (`Error::Codec`). It replaces CreatedHeight/ExpiryHeight. Version 1 bodies are refused. OperationID, OutputID, the wallet approval payload and the maker fill payload are unchanged formulas over the version-2 Body, so every signature binds the window, the reference and the preconditions. The LicenseDvp action loses `inclusion_height`: `[3, OfferID, MakerID, LicenseID, license_generation, seller, buyer, price, payment_destination, change]` (10 elements). Code: `consensus/src/trading_v1.rs` (`BODY_VERSION`, `Meta`, `Operation::body`, `Operation::decode_body`).

### T1.2 Inclusion at height H = parent + 1 (replaces "CreatedHeight <= H <= ExpiryHeight" of section 4)

In this order: context; the Applied record of the OperationID (`Duplicate`: the window is never the replay protection); window W `first_height <= H <= last_height` and reference R (the parent block, or the canonical block hash of an older finalized height supplied by the local canonical store through `History` anchors; without an anchor an older reference fails closed) as `NativeError::Envelope(Future | Expired | ReferenceNotCanonical)`; every committed precondition, compared exactly with the facts of the tentative state at the trading validation point (after this block's activation, epoch dividend events and Worker assignments and after the earlier trading items of the block, before any claim) as `NativeError::Stale(tag)`; then fee, approval slots, offer and the action. Advancing the head alone never invalidates an otherwise unchanged operation; nothing is re-based, re-windowed or re-signed.

LOCK: `refund_height > last_height` replaces `operation expiry < R`. CLAIM `H < R` and REFUND `H >= R` keep the ACTUAL inclusion height H; a window that spans R grants nothing more. Every effect (lock creation height, License transfer inclusion height and rights from H+1, Applied height) is recorded at the actual H. The exact `inclusion_height == H` rule of LicenseDvp is removed; its timing is the signed window. Offer binding: `first_height >= offer.created`, `last_height <= offer.expiry` and `offer.created <= H <= offer.expiry` (design 8.2, in terms of the envelope; T4 replaces the offer format).

Entry points: `prepare_batch` (no History: parent references only), `prepare_batch_with_history`, `prepare_candidate_phase(.., history, ..)` (the block trading phase receives the block's authenticated History), `prepare_treasury_funding_with_history`. AM-1(d): `verify_signatures(raw)` checks statelessly every signature an item carries (approvals under their own descriptors, the maker's offer and fill signatures) and the exact approval slot set; `verify_state(..)` performs every other check (never a consensus path; for a pool that recorded `verify_signatures` for the same id and wire hash). AM-3: the assembler previews only the DECLARED fee (`declared_fee`); the complete trial execution validates it.

### T1.3 P3: zero monetary destinations

A zero address is refused in the codec (`Operation::body`, hence encode, decode, id and every signing payload; `Error::Bounds` / `NativeError::Candidate(Bounds)`) in every monetary destination: HashLock sender and recipient, Claim recipient, Refund owner, LicenseDvp buyer (change) and payment_destination, FiatLock seller and buyer, FiatRelease buyer and seller, TreasuryRotate current_address and new_address. A Treasury destination with a zero address is refused (`NativeError::Bounds`) and every credit site refuses a zero owner defensively. A block body cannot even carry such an item (`BlockBody::encode` refuses it). Change 0 (no output), a zero condition, a zero preimage, zero payment terms and the fixed zero maker argument of SingleFillKey remain legal. A zero address is never turned into a burn.

### T1.4 P9: funding from the payer's authenticated lineage (replaces "sender-owned / recipient-owned / buyer-owned inputs" of sections 2, 4 and 6)

Every input must be owned by an address that the approval descriptor of the payer's slot authorizes under the PARENT WalletBook (`WalletBook::authorize`): any authenticated generation of the payer's wallet lineage whose current descriptor that approval is. Payer slots: HashLock sender 0, FiatLock seller 0, Claim recipient 0, Refund owner 0, FiatRelease buyer 0, LicenseDvp buyer 1, TreasuryRotate current address 0. Inputs from several generations may be combined; an unrelated wallet never counts; a rotated-out key authorizes nothing. Amounts, maturity (`created_height < H`, coinbase maturity) and exact conservation are unchanged. The conditional payout stays with the lock's authorized recipient and change returns to the signed payer address; only the fee funding may come from another generation of the lineage. No sponsor slot exists in trading.

### T1.5 Q15: Treasury reserve

Every StateRoot enforces `reserved <= backing` (backing = non-coinbase coins at every address of the Treasury authority's lineage), so any trading debit of Treasury-lineage coins, including fees paid through P9 lineage funding, fails its block if it would consume reserved value. A Treasury whose backing equals its reserve cannot pay a fee until an ordinary transfer to an address of its lineage is included in an EARLIER block (trading inputs must exist before the block).

### T1.6 Tests (TEST-VALUE, Windows host)

`consensus/src/trading_v1_tests.rs` (codec, AM-1(d), AM-3, P3 unit rows); `consensus/tests/zero_destinations_v1.rs` (module `trading`); `consensus/tests/operation_envelope_v1.rs` (module `trading`); `consensus/src/op_envelope_v1_store_tests.rs` (`trading_matrix`); `consensus/tests/lineage_funding_v1.rs`; `consensus/tests/treasury_authority_v1.rs` (reserve rows); `node/src/trading_service_v1.rs` (`envelope_tests`). Index and mutation table: `qualification/candidate-3/P-WP-T1-NOTES.md`.

## Candidate 3 amendments: T3 (P6)

Status: PROPOSED-UNFROZEN integration amendment of this imported copy (Lane P work package WP-T3, branch `cand3/p-t3`; Order of 4 October 2026 decision P6 and W17; design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 7, 10.4-10.5 and 16.1 with `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-8 and AM-9 m9/m10). It amends the TreasuryRotate row of the operation table (`[6, TreasuryID, current_generation, current_AddressID, current_descriptor_hash, new_generation, new_AddressID, new_descriptor, change]`, "0 current active Treasury wallet; same wallet pays fee") and the Treasury destination and rotation paragraphs of section 12 of this packet. Field layout and encodings are unchanged; only who may sign, where a rotation may route, and which records are valid change. Evidence class: Windows host, software, TEST-VALUE only.

### T3.1 The one canonical MUT Treasury authority T

T is `State.dividends.treasury().authority()`: the generation-one AddressID of the Genesis-authenticated Treasury descriptor (`treasury_v1::Treasury`). T's current signing key is `WalletBook::current(T)` (the Genesis descriptor while T was never rotated); T's lineage is every address the WalletBook records under authority T, plus T, which is also exactly the owner set that reserve backing counts. There is no other Treasury identity: TreasuryID in every trading Treasury record and operation MUST equal T. Configuration, a wallet profile or a signed request never creates Treasury authority. The production Genesis Treasury descriptor is the Architect's input (evidence-input-blocked for production; software work uses TEST-VALUE descriptors).

### T3.2 Records (checked for every StateRoot and at every trading entry point, `trading_v1::validate_records`)

Every trading Treasury head, generation and address-index record names TreasuryID = T, and dividends are active (no Treasury record may exist without a Genesis Treasury). The generation-1 destination is exactly the Genesis descriptor at address T. Every destination of generation >= 2 has an address that the WalletBook records under authority T (an address of T's lineage other than T, i.e. registered by a rotation of T's key); its address is derived from its descriptor. Any violation is `NativeError::Record` (the StateRoot hook reports `WrongAnchor`). `treasury_genesis_records` is called with TreasuryID = T.

### T3.3 Two distinct transitions: R1 (who signs for T) and R2 (where new Treasury offers settle)

R1 is the wallet rotation of T's signing key (this base: `Transaction::Rotate`; after WP-R: the funded rotation bundle P2 with authority T): the old key authorizes, the new key proves possession, both bound to the exact plan. R1 changes no trading record.

R2 is the trading TreasuryRotate. In addition to the existing head rule (current_generation/current_AddressID equal the head; new_generation = current + 1) it MUST satisfy, at the inclusion height H against the PARENT WalletBook:

* R2-1: TreasuryID = T, else `NativeError::Authority`.
* R2-3: approval slot 0 is made by T's CURRENT descriptor D (`WalletBook::authorize(T, D)`), not by the key of the trading address; `current_descriptor_hash` = descriptor_hash(D). The approval slot's address (`slot_address(0)`) is T. Else `Authority`.
* R2-4: the new destination is T's current wallet generation: `new_descriptor == WalletBook::current(T)` (so T must have been rotated by an R1 in an EARLIER block), `new_AddressID` is derived from it, and it is unused in T's Treasury history (`Record`). This replaces "New destination must already resolve to a valid wallet authority", which accepted any fresh generation-one wallet. Else `Authority`.
* R2-5: funding by T's lineage under D (P9), fee `max(240, canonical)`, change to current_AddressID; the reserve stays protected by the backing invariant (T1.5).
* Effect unchanged: NO effective-height field; the successor's effective_height is the inclusion height H (Architect ruling of 2 Oct 2026, kept).

Consequences: an unrelated fresh generation-one wallet can neither authorize an R2 nor be routed to; the key of an old destination (including the current trading address's key after a later R1) cannot authorize; a thief of T's current key can route only to the address that key already controls and cannot add a custodian. In one block, R2 (trading phase) sees the pre-R1 authority because R1 executes later (payment phase).

### T3.4 Freeze, history and reserves

The Treasury freeze (`validate_treasury_creation`) additionally requires TreasuryID = T (`Authority`). Under AM-12, an unfunded freeze authorization stays above consensus: a retired-only maker offer cannot first fund after rotation, even with current settlement approvals or an old finalized reference. The current maker must review and sign a new offer. An already finalized funded lock retains its exact terms, `(T, generation, address)`, destinations and claim/refund deadline through rotation, with the existing claim/refund authority rules. Generation history is unbounded and O(1) per lookup (the "four-entry history bound" text of section 12 is superseded by Order P6 "unbounded canonical generation history"). Old destination addresses stay in T's lineage: their coins stay reserve backing and their existing wallet-authorized spends use T's CURRENT key. No reserve migration and no external BTC custody change. The two Treasury rotation unit fixtures now distinguish first-funding refusal from preservation of an already funded lock; their AM-12 source successor is recorded in `qualification/candidate-3/CODEX-AM12-TREASURY-UNIT-PORT-20261005.md`, with runtime qualification pending.

### T3.5 Restore evidence for a new R2 destination (W17; a Treasury-TOOL obligation, NOT consensus-checkable)

Consensus cannot see whether a new key was derived from its backup. Before signing R1's possession and before signing R2, the Treasury tool MUST record, and refuse to sign without, one restore-evidence record per plan:

| Field | Content |
|---|---|
| plan_id | R1: the rotation's identity (this base: `Rotation::identity()`; after WP-R: the funded-rotation bundle id); R2: the trading operation id (`Operation::id()`) |
| authority_id | T (32 bytes) |
| new_descriptor_hash | `trading_v1::descriptor_hash(new_descriptor)` (the function R2's `current_descriptor_hash` uses) |
| derived_from_backup | the check result: the tool re-derived the new key from its backup and the derived public descriptor equals the new descriptor (MATCH / MISMATCH / NOT_PERFORMED; only MATCH permits signing) |
| tool_version | the Treasury tool's exact version |

The encoding, storage and review display are Lane W's (W14/W17). The record is local evidence bound to the exact plan; it is not a consensus object and no consensus rule checks it.

### T3.6 Known limitation (AM-9 m9)

Dividend claims spend Treasury coins implicitly (oldest generation first) and execute before payments. A pending R1 (or any Treasury spend) whose input a same-block claim selects is left out of the block; the pool reports it INPUT_SPENT and the wallet re-signs over the claim's change. Test `claim_and_r1_in_one_block`.

### T3.7 Tests (TEST-VALUE, Windows host)

Real blocks: `consensus/tests/treasury_authority_v1.rs` module `authority` (`fresh_generation_one_wallet_cannot_rotate_treasury_byte_identical`, `r2_requires_current_genesis_authority`, `old_destination_key_cannot_route_after_r1`, `r2_routes_only_to_current_generation`, `trading_treasury_records_must_name_genesis_authority`, `claim_and_r1_in_one_block`) and module `reserve` (WP-T1). Unit: `consensus/src/trading_v1_tests.rs` (`trading_treasury_records_bind_to_the_genesis_authority`, `treasury_freeze_requires_the_genesis_authority`, `treasury_rotate_slot_zero_is_the_authority_not_the_head_address` and the Treasury rotation rows). Index and mutation table: `qualification/candidate-3/P-WP-T3-NOTES.md`.
## Candidate 3 amendments: T4 (P7, the canonical maker-offer format)

Source: Order of 4 Oct 2026, decision P7; `qualification/candidate-3/P-LANE-DESIGN-V1.md` section 8 with `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-6 (WP-T4, branch `cand3/p-t4`). Status: PROPOSED / UNFROZEN; Windows-host software, TEST-VALUE evidence only. This section is THE canonical maker-offer format; it replaces the `OfferBody`/`OfferProof` block and the "Candidate trade signatures use independent synthetic Role::Transport keys" paragraph of section 2, extends section 5 and records two allocations of section 10. Code: `consensus/src/trading_offer_v2.rs` (the former offer code of `trading_v1.rs` moved there; `trading_v1` re-exports it).

### T4.1 OfferBody version 2 and the MakerOffer wire object (replaces the offer block of section 2)

```
OfferBody v2 = [N, 2, NetworkID:U32, GenesisID:H32, ProtocolFingerprint:H32,
                [maker_descriptor:bstr, maker_wallet:H32, maker_side:U8],
                nonce:H32, created_height:U64, expiry_height:U64,
                terms,
                destination:H32,
                condition:H32|null,
                max_fee:STRIKES]                          ; definite array of 13, shortest form
terms      = [0, MUT_STRIKES, BTC_satoshis, BitcoinEnvironment:U8]   ; HashLinked (unchanged)
           | [1, LicenseID, current_generation, price_STRIKES]       ; License (unchanged)
           | [2, MUT_STRIKES, fiat_terms_hash]                       ; Fiat (unchanged)
MakerOffer = [bstr "MUTINY-BUILD8-MAKER-OFFER-V2", OfferBody:bstr, offer_Ed448:bstr114, offer_FNDSA:bstr1280]
OfferProof = [MakerOffer:bstr, fill_Ed448:bstr114, fill_FNDSA:bstr1280]   ; inside Operation (section 2)
OfferID    = H("offer", OfferBody)                 ; unchanged derivation
MakerID    = H("trade-identity", maker_descriptor) ; unchanged derivation
OfferSigningPayload = [N, b"signed-offer", OfferBody:bstr]   under crypto-v2 Domain::TradeOffer  "MUTINY-BUILD8-TRADE-OFFER-V1"
FillSigningPayload  = [N, b"offer-fill", Body:bstr]          under crypto-v2 Domain::TradeFill   "MUTINY-BUILD8-TRADE-FILL-V1"
```

* `maker_descriptor` is the maker's WALLET OWNER descriptor (nonzero generation); `maker_wallet` is the AddressID that settles for the maker; `maker_side` 0 = MUT sender / License seller / fiat MUT seller, 1 = recipient / buyer.
* Encoding refuses (`Bounds`): `created_height > expiry_height`, `maker_side > 1`, zero `maker_wallet` or zero `destination` (P3), a non-null condition on License or Fiat terms, and the unchanged terms bounds; a descriptor that is not a wallet-owner descriptor of a nonzero generation is `Authority` (or `Codec` when it does not decode). Body <= 4,096 bytes; MakerOffer and OfferProof <= 8,192 bytes. Decoding is strict (exact re-encoding, no trailing data); the MakerOffer label is a CBOR BYTE string.
* A body of version 1 is refused with `OfferBinding` (it never settles); any other version or arity is `Codec`.
* MakerOffer is the ONE wire object of a signed maker offer (wallet export/import, node, consensus). The OfferProof embeds the maker's exact MakerOffer bytes, so there is no second encoding of a signed offer.

### T4.2 Consensus checks of a filled offer (`Operation::verify_offer`, in this order)

Nothing else about offers enters consensus (no order book, listing, gossip or storage). For a HashLock, LicenseDvp or FiatLock (any other action requires a null proof; a missing proof is `OfferBinding`):

| # | Check | Error (`Candidate(..)`) | Real-block test (`consensus/tests/maker_offer_v2.rs`) |
|---|---|---|---|
| 1 | offer context == operation context | `Context` | (unchanged) |
| 2 | OfferID and MakerID equal the action's `offer` and `maker` | `OfferBinding` | (unchanged) |
| 3 | maker authority: `maker_wallet == slot_address(maker_side)`; first canonical funding requires `maker_descriptor` to be that maker's CURRENT WalletBook authority at the existing trading phase, before payment transactions (AM-12). Current settlement approvals alone cannot authorize a retired-only unfunded offer; the current maker must review/sign anew. Existing finalized locks retain the existing claim/refund authority rules. | `Authority` | `maker_wallet_must_be_the_maker_sides_slot_address`, `rotation_before_funding_refuses_retired_offer_and_requires_current_review`, `first_funding_before_same_block_rotation_preserves_lock_and_current_refund` |
| 4 | destination: HashLock maker sender -> `sender`, maker recipient -> `recipient`; LicenseDvp maker seller -> `payment_destination`, maker buyer -> `buyer`; FiatLock maker seller -> `seller`, maker buyer -> `buyer`; each must equal `destination` | `OfferBinding` | `taker_cannot_redirect_the_makers_destination` |
| 5 | condition: HashLinked offer with a condition -> `HashLock.condition == condition` | `Condition` | `maker_fixed_condition_cannot_be_swapped` |
| 6 | fee terms: when `fee_payer()` is `maker_wallet`, `fee <= max_fee` | `Fee` | `maker_never_pays_more_than_max_fee` |
| 7 | validity: `first_height >= created_height` and inclusion height >= `created_height` (`Time`); `last_height <= expiry_height` and inclusion height <= `expiry_height` (`Expired`) | `Time` / `Expired` | `operation_window_must_lie_inside_the_offer_window` |
| 8 | exact terms (amount; License, generation, price; amount and fiat terms hash) | `OfferBinding` | (unchanged) |
| 9 | the maker's offer signature (TRADE-OFFER-V1) and fill signature (TRADE-FILL-V1) under `maker_descriptor`; the stateless half `verify_offer_signatures` checks exactly these two (AM-1(d)) | `Signature` | `fill_and_offer_signatures_bind_body_and_domain` |
| 10 | version: only version-2 bodies settle (decoding refuses version 1) | `OfferBinding` | `version_one_offer_body_cannot_settle` |

Every negative is asserted (a) exactly at `prepare_batch` on the parent state, (b) through the production assembler and V2 executor and (c) through `CanonicalStore::commit` of a certified block, with the head, the State records and every store row byte-identical.

### T4.3 Single fill (extends section 5)

`SingleFillKey` and the `Consumed` record are unchanged: one key per (context, OfferID), inserted atomically with the first funding or DvP after every check of T4.2 and every wallet authorization. A second fill of the same offer (another operation, other inputs) is `Duplicate`, in a later block and within the same block (the whole block fails). Test: `maker_offer_settles_once_and_a_second_fill_fails_atomically`.

### T4.4 Allocations (amends section 10; PROPOSED-UNFROZEN, registered in `spec/DOMAIN-REGISTRY-V1.json`)

* crypto-v2 `Domain::TradeOffer` = `MUTINY-BUILD8-TRADE-OFFER-V1` and `Domain::TradeFill` = `MUTINY-BUILD8-TRADE-FILL-V1`, both role **WalletOwner** (AM-6 DEFAULT). The proposed separate crypto role 7 "Trade" of section 10 is NOT allocated; it is ARCHITECT question C.3. The role is decided in exactly one function (`mutiny_crypto_v2::Domain::role()`), so switching to a separate role is one mapping change plus key custody (a crypto-v2 role/derivation change).
* Wire label `MUTINY-BUILD8-MAKER-OFFER-V2` (byte string).

### T4.5 Legacy forms (decode-and-verify only)

Form A (the wallet container `[text "MUTINY-BUILD8-WALLET-MAKER-OFFER-V1", body v1, ed448, fndsa]`) and Form B (a version-1 OfferProof with an all-zero fill signature) are read only by `trading_offer_v2::legacy`, compiled only under `cfg(test)` (no consensus Cargo feature may be added: Architect decision of 3 Oct 2026, guarded by `consensus/tests/rule_set_build_independence.rs`). The adapters verify the version-1 Transport-role signature and return a read-only `LegacyOffer` that cannot be converted, re-encoded or settled; no version-2 decoder accepts either form. Test: `consensus/src/trading_offer_v2_tests.rs::legacy_forms_verify_only_under_cfg`.

### T4.6 Vectors

`qualification/trading-maker-offer-v2-vectors.json` (TEST-VALUE; sha256 `cc5433739899faa30d131357dd7fcb61f21b1bba4844a58c4b068702a4e2a204` at generation): OfferBody, OfferID, MakerID, single-fill key, both signing payloads, MakerOffer, OfferProof and a filled operation (`verify_offer` Ok), and eight negatives (one per check 3, 4, 5, 6, 7 created, 7 expiry, 9 fill, 10 version) with their exact refusal. Generator: `consensus/tests/maker_offer_v2.rs::maker_offer_v2_codec_and_vectors_export` with `BUILD8_EXPORT_MAKER_OFFER_V2=1` (refuses to overwrite); reader: `maker_offer_v2_vectors_reader`. FN-DSA signatures are randomized: readers verify them and never compare them.

## Candidate 3 amendments: T2 (P5)

Status: PROPOSED-UNFROZEN integration amendment of this imported copy (Lane P work package WP-T2, branch `cand3/p-t2`; Order of 4 October 2026 decision P5 and Q17(a); Restart Order L64; design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 6.1-6.8 and 16.1 with `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-10 and AM-11). Where this section and section 6 above differ (in particular "no ... pending Worker assignment" and "Pending assignments ... fail closed rather than being silently cancelled"), this section is the implemented candidate rule. It extends the T1 section above and changes no other section. Evidence: Windows host, software, TEST-VALUE tests only; nothing here is qualified, frozen or Linux-proven.

### T2.1 The commitment (extends section 6 and T1.1)

The Envelope of every LicenseDvp body MUST contain exactly one `LicenseEntitlements` and exactly one `LicenseAssignment` precondition, both naming the sold LicenseID (other preconditions, such as a TreasuryHead, are allowed and checked as usual):
```
LicenseEntitlements = [1, LicenseID, [[award_epoch:U64, share:U64, remaining:U64, claims:U64]...]]   ; every live award account, ascending by award_epoch; [] = none
LicenseAssignment   = [2, LicenseID, assignment_sequence:U64, active_worker:H32|null, pending:H32|null] ; pending = AssignmentID (MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2 over the unsigned binding)
```
`remaining` is the unclaimed amount, `share - remaining` the claimed amount, `claims` the per-award/per-License claim sequence. Both are inside the signed Body, so the seller's and the buyer's approvals (slots 0 and 1) and the maker's fill bind them; a disclosure checkbox is not the commitment. Absence of either, a second one, or one naming another License is `NativeError::Bounds` (code: `trading_v1::sale_commitment`, called in the `apply_one` prologue after the window/reference check). The facts are produced by `op_envelope_v1::entitlement_facts` / `assignment_facts` on VERIFIED state (wallet and consensus use the same functions).

### T2.2 The sale-validation point

Compared FIRST after the window W and the reference R (T1.2), by exact equality, on the tentative state of the block at H: the parent state plus, in this order, `activate_due(epoch)`, `advance_dividends(epoch)` (all of this block's expiries and award boundaries), this block's Worker assignments, `prepare_ticket` and the earlier trading items of the block; BEFORE the claim phase. Relation to epoch-event processing: after it. Trades still execute before claims whatever the listing order. Any difference is `NativeError::Stale(1)` (entitlements) or `Stale(2)` (assignment); the whole block is invalid; nothing is re-based, interpolated or substituted; a fresh review and fresh signatures are required.

| Event between the reference and the validation point | Committed facts change? | Result |
|---|---|---|
| Seller claim of any amount of the sold License (earlier block) | `remaining`, `claims` | `Stale(1)` |
| Award expiry, including one processed at the sale block's own epoch | the account leaves the list | `Stale(1)` |
| New award boundary with the License eligible (also at the sale block's own epoch) | a new account | `Stale(1)` |
| New award boundary with the License not eligible | no | valid |
| Another License's claim or sale | no | valid |
| Assignment scheduled (also earlier in the sale block), activated or cancelled for this License | LicenseAssignment | `Stale(2)` |
| Head advance only | no | valid |
| Seller claim of the sold License in the sale block | (claims run after trades) | the claim fails `StaleOwner`: block invalid |
| Buyer claim of the sold License in the sale block | (claims run after trades) | valid, draws on the committed remainder |

### T2.3 Pending assignment (replaces "Pending assignments/outstanding locks fail closed" of section 6 for pending assignments; Restart Order L64)

The sale cancels the old owner's pending Worker assignment of the sold License (`license_book_v2::Book::transfer_candidate`, which returns the cancelled AssignmentID) and detaches the active Worker as before. The returned id MUST equal the committed `LicenseAssignment.pending` (none = none); a mismatch is `NativeError::Stale(2)` and leaves the Book untouched (`trading_v1::transfer_license_candidate`). There is no silent cancellation: the buyer reviewed exactly what is cancelled. The cancelled assignment never activates. Any other refusal of the Book stays `NativeError::LicenseLocked`. Outstanding License locks: none exist in this candidate (unchanged).

### T2.4 Rights preserved, no award recreated

Award accounts are keyed by LicenseID; the sale changes only the owner and does not touch the dividend ledger. The claimant is always the current owner; the buyer continues the same claim sequence and can claim at most the committed remainder.

### T2.5 Tests (TEST-VALUE, Windows host)

`consensus/tests/license_dvp_entitlements_v1.rs` (real blocks through the production assembler, the V2 executor and `CanonicalStore::commit`, store byte-identity after every rejection; exact `NativeError` at `prepare_batch_with_history` or, for the sale block's own epoch events, on the executor-built tentative state through `prepare_candidate_phase`): `seller_claim_makes_sale_stale_byte_identical`, `expiry_at_the_sale_blocks_own_epoch_makes_sale_stale`, `new_award_makes_sale_stale`, `ineligible_new_award_not_stale`, `sale_without_entitlement_precondition_rejected`, `same_block_seller_claim_after_sale_invalid_buyer_claim_valid`, `committed_pending_assignment_cancelled_uncommitted_one_stales_sale`, `activated_assignment_after_review_stales_sale`, `buyer_claims_remainder_no_award_recreated`, `head_advance_alone_does_not_invalidate`; unit tests `consensus/src/trading_dvp_entitlements_tests.rs`. Index and mutation table: `qualification/candidate-3/P-WP-T2-NOTES.md`.

## Candidate 3 amendment: AM-12 first funding versus existing funded locks

The direct user decision of 4 October 2026, recorded in `qualification/candidate-3/P-LANE-DESIGN-AMENDMENTS-V1.md` AM-12, supersedes earlier rotation-survival wording in this packet for unfunded offers and above-consensus Treasury freeze authorizations. An old freeze or retired-only MakerOffer is not a canonical funded lock and grants no right to new first funding after its maker retires. Current maker review and a new current-signed offer are required; changing settlement approvals or supplying an old finalized reference does not suffice. First funding checks the current maker at the existing trading phase before payment transactions. Already finalized funded locks preserve exact terms, destinations, deadlines and existing claim/refund authority through rotation. This amendment adds no operation, fee, commitment kind or carrier. It records current candidate semantics, not a Production qualification result.

Import provenance remains historical: the original 438-line import had SHA-256 `13809f3c8bd59e71a0dc3c6a22c548aa73d880cd8d3b31e098cda013d05e1aac`. This candidate copy has subsequent T1-T4 amendments and the AM-12 corrections to T3.4 and T4.2 row 3; it is not a verbatim copy of that import. See `spec/imports/BUILD8-TRADING-D1-LOCK-PACKET-V1.md.identity.txt` for the original identity and amendment record. The original checkout is unchanged.
