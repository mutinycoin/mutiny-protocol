#ifndef BUILD8_OBSERVATION_STORE_V2_H
#define BUILD8_OBSERVATION_STORE_V2_H
#include "observation_v2.h"
#define BUILD8_OBSERVATION_STATE_V2_MAX 919u
#define BUILD8_OBSERVATION_PENDING_V2_MAX 544u
#define BUILD8_OBSERVATION_COMPACT_V2_BYTES 73u
/* Public operational state only. Checksum detects corruption, not malicious
 * storage replacement or rollback. Node checkpoint checks remain mandatory.
 * Dedicated V2 storage, no legacy namespaces or automatic migration/reset.
 * A single owner serializes the entire load/validate/commit/readback operation.
 * read:1 present,0 absent,-1 fault; write:1 durably committed,0 uncertain/fault.
 * Callbacks are trusted local code, never supplied by a network message. */
typedef struct {void *context;int (*read)(void *,uint8_t *,size_t,size_t *);
    int (*write)(void *,const uint8_t *,size_t);} build8_observation_store_v2;
typedef struct {uint8_t genesis[32],fingerprint[32],license[32],worker[32];} build8_observation_scope_v2;
typedef struct {
    uint64_t sequence,total;
    uint8_t chain[32],last_result[32],last_coordinator[32],last_previous[32];
    uint8_t pending_coordinator[32],pending_id[32],pending[544];
    uint16_t pending_length;
} build8_observation_state_v2;
/* Explicit fresh provisioning only. Ordinary startup calls restore and treats
 * missing data as failure. Never call initialize as error recovery. */
int build8_observation_store_v2_initialize(const build8_observation_store_v2 *,
    const build8_observation_scope_v2 *,build8_v2_domain_hash);
int build8_observation_store_v2_restore(const build8_observation_store_v2 *,
    const build8_observation_scope_v2 *,build8_v2_domain_hash,build8_observation_state_v2 *);
/* Maintenance compaction of a fully acknowledged checkpoint only. Preserves
 * sequence, total (=sequence for this accepted-only codec), scope and chain.
 * Removes only the duplicate-receipt cache. No pending work may be discarded.
 * After restore, acquire fresh accounted work before any new found-work handoff;
 * an old duplicate receipt with no cache is ignored (return0), never credited. */
int build8_observation_store_v2_compact(const build8_observation_store_v2 *,
    const build8_observation_scope_v2 *,build8_v2_domain_hash,uint8_t[73]);
/* Work bytes and coordinator identity come from the owner task's frozen,
 * genuinely validated found-work handoff. This function does not grant work
 * authority or independently verify PoW/Node authorization. */
int build8_observation_store_v2_queue(const build8_observation_store_v2 *,
    const build8_observation_scope_v2 *,const uint8_t *,size_t,const uint8_t[32],build8_v2_domain_hash);
int build8_observation_store_v2_submission(const build8_observation_state_v2 *,uint8_t *,size_t,size_t *);
/* Both hybrid signatures are mandatory. Descriptor identity must match the
 * stored pending coordinator, not a field adopted from the incoming receipt.
 * Success only after atomic blob commit and exact readback. RUN is untouched.
 * Objects/buffers/workspace/backend state must be live and mutually disjoint. */
int build8_observation_store_v2_receipt(const build8_observation_store_v2 *,
    const build8_observation_scope_v2 *,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
#endif
