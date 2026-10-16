# A2 public recovery wrapper successor (UNFROZEN, source design)

The existing signed RecoveryHistoryV2 record, ReplacementV2, authorization,
native possession proof, old canonical parent-root witnesses and signatures
remain byte-identical. Historical recovery rows and unmarked state keep their
original behavior. No recovery or bootstrap can revive durable A2 NoQuorum.

For the explicitly committed A2 rule only, propose exact canonical outer bytes
`[3,58,exact_signed_RecoveryHistoryV2_record_bytes,exact_public_witness_bytes]`.
Version3/tag58 is a public availability wrapper, not a new signed recovery
authorization, state-history record version, caller authenticity flag or clock.
The original replacement's signed TPM profile commits to the exact witness.
The wrapper must be fully canonical, arity4, shortest encoding, consume all bytes,
re-encode exactly, contain a valid bare V2 inner record, and forbid recursion.

Retain the existing **262144** accepted-recovery journal/transport ceiling and
the witness **131072** bound. The outer encoder enforces their actual combined
encoding<=262144, not independently maximal fields. At the maximum width,
overhead is14 bytes: array1+version1+tag58(2)+two byte-string prefixes(5 each).
Thus witness131072 leaves at most131058 bytes for a maximum-width inner record.
A genuine larger combined input refuses capacity; no chunking, silent truncation
or schema widening. This fit limitation requires explicit review, not a claim
that every individually legal historical record plus maximal witness fits.

The old public record-only verify/accept methods fail closed for marked fresh
recovery. Unmarked state rejects the new wrapper. Full new preparation runs the
unchanged original recovery signature/parent/root/loss/native-possession/owner/
license/descendant checks before staging any new dependency. It then authenticates
the exact public witness at the **finalized canonical parent timestamp**, derives
the replacement's retained lineage from the unchanged parent registry, and adds
the private fully verified dependency row before prospective authority derivation.
Existing terminal targets and stored excluded lineages must reject an affected
replacement; no prospective generation reset defeats prior terminal exclusion.

Canonical acceptance must decode untrusted wrapper structure with a bounded
allocation first, then revalidate exact rule, original inner authorization,
parent/root/block, witness and parent-time binding INSIDE its existing IMMEDIATE
write transaction. The trusted timestamp comes from the matching canonical parent
row/header already verified by the store. Never trust a wrapper or operation time.
Historical journal reads must match parent height/block/root and finalized anchor
and use that historical parent's authenticated time; no current wall clock/network.
Replay retains the exact wrapper bytes in the accepted journal, while the canonical
RecoveryHistory book retains its unchanged original V2 signed record. Retries must
compare the entire exact wrapper, not only Replacement commitment or inner record.

There is no new timestamp argument granting authority to arbitrary callers. A new
crate-internal verifier accepts witness plus time only from these trusted store/
authenticated WorkParent paths; compatibility methods lacking them refuse.
Full first-resumed block execution keeps its canonical WorkParent and new witness
reference time distinct from the containing-H time of new revocation evidence.

Source-only ports now drafted: bounded wrapper module and rule commitment,
Prepared verifier, canonical acceptance/export/retry, accepted-journal revalidation
and finality exact-byte race guard. Native recovery sync calls the same bounded
accept/export interfaces. Exact history/reopen/proof tests and independent full
review remain pending; none is compiled or executed. Existing record schema,
global StateRoot record cap, kind7 transport bound, signatures/domains, original
vectors and Production hardE remain unchanged. No runtime/physical claim.

Required behavioral tests: authentic old unmarked positive unchanged; marked bare
refusal; genuine wrapped positive with exact old-record history bytes; wrong/missing
witness, wrong finalized-parent time, wrapper-H/local-time substitution, context/
profile/generation mismatch, capacity boundary and overrun, duplicate wrapper retry
versus changed public witness, existing finalized descendant, historical reopen/
replay, terminal EK lineage exclusion and durable zero-weight NoQuorum. No signature
stub or current-clock fallback may satisfy these cases.
