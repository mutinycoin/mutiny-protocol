# Worker result clock freshness successor

This records the candidate-3 V2/C3 correction. It changes local authorization of fresh worker
result acceptance, not consensus timestamps, epoch arithmetic, voter weights, production round
deadlines, signature formats or the worker wire protocol.

Before the correction, a deferred-result drain sampled qualified UTC once and used that value
for every worker in the batch. A clock loss after one real receipt could still authorize the
next receipt and credit. The direct qualified Result handler also sampled before canonical
binding, so a blocking state read could outlive qualification without another check.

The corrected drain samples each entry, compares its Genesis-relative MiningEpoch with the
first entry's epoch, and removes that entry only after this gate. Loss or an epoch transition
leaves that entry and the rest held. After canonical synchronization and binding, a second
fresh qualified reading must still be in the bound epoch immediately before acceptance.
The direct Result path performs the same final check. If it fails, the ordinary bounded
holding/exact retransmission path runs: a fresh result receives a heartbeat with no new
receipt or credit; an exact previously accepted result can return its stored receipt.

A later drain revalidates the canonical binding at its current epoch. Existing invalid or
stale binding/storage failure behavior remains explicit: the held entry is dropped and the
device retries its durable outbox. Candidate preservation may fail after the observation
checkpoint was committed; the retry then retrieves the existing receipt and earns no second
credit. The processed-entry count is not a claim that every failed preservation was uncredited.

The regressions use two of the existing public fixture's licensed workers, actual issued
authorities, PoW, execution, observation signatures and candidate preservation. Controlled
time changes after the first preservation or after the initial binding reading expose the
boundary without sleeps, increased production deadlines or fabricated protocol decisions.
They assert remaining-queue preservation, fresh revalidation, once-only credit and exact
receipt retransmission. A separate controlled driver probe tests the ordinary round-1 6s
prevote/precommit intervals, held lock, no fabricated nil prevote, nil precommit reservation
and exact replay without extra counter consumption.

These are Windows software TEST-VALUE results. They do not qualify physical clock accuracy,
native TPM custody, safe ancestor/ACL storage, total-blackout restart survival, production
launch, or the complete Clock lane. Historical failed baseline runs and malformed first
fixture attempts remain historical failures. Their results are not transferred to this
successor's source identity. Public successor fixtures and closed attempt logs are retained
in the task evidence; final source/log hashes identify the exact tested bytes.
