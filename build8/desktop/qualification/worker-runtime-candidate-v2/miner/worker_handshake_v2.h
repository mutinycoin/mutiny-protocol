#ifndef BUILD8_WORKER_HANDSHAKE_V2_H
#define BUILD8_WORKER_HANDSHAKE_V2_H
#include "worker_v2_candidate.h"
#include "worker_session_auth_v2.h"
#include "worker_frame_v2.h"
/* Entirely local trusted adapters. Caller holds the same maintenance/store
 * serialization lock for each complete call. No network-supplied callbacks,
 * context, clock, entropy or authority records. Never copy/serialize pending
 * memory. Storage may be freed/reused only after clear/consumption.
 * Entropy provider must be separately qualified for the actual hardware state.
 * This candidate performs no device I/O or automatic application activation. */
typedef struct {
    const build8_v2_private_backend *private_store;
    const build8_v2_store *public_store;
    const build8_enrollment_v2_context *current;
    const uint8_t *node_descriptor;size_t node_descriptor_length;
    build8_v2_domain_hash h256,h512;
    void *verification_workspace;size_t verification_workspace_length;
    void *platform;
    int (*entropy)(void *,uint8_t *,size_t);
    uint64_t (*clock_ms)(void *);
} build8_worker_local_v2;
typedef struct build8_worker_pending_v2 build8_worker_pending_v2;
size_t build8_worker_pending_v2_size(void);
size_t build8_worker_pending_v2_alignment(void);
/* Caller provides correctly aligned bounded memory, never a private file. */
build8_worker_pending_v2 *build8_worker_pending_v2_init(void *,size_t);
void build8_worker_pending_v2_clear(build8_worker_pending_v2 *);
/* Mandatory owner-task timer tick even when no network data arrives. Trusted
 * monotonic milliseconds only. At 60 seconds or clock rollback, erase and return
 * 0; 1 means still pending, never confirmed. Disconnect/maintenance calls clear. */
int build8_worker_pending_v2_expire(build8_worker_pending_v2 *,uint64_t);
/* Out lengths exact. Failure consumes/clears pending state. Invalid buffer
 * ranges leave output untouched; output is never valid on failure. All state, local
 * authority, backend storage, verification scratch and wire buffers disjoint. */
int build8_worker_pending_v2_begin(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,uint8_t [1722]);
int build8_worker_pending_v2_accept(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,uint8_t [130]);
int build8_worker_pending_v2_finish(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,b8_worker_channel *);
/* Explicit ordinary assignment handshake. current MUST be independently verified
 * and currently active canonical authority, not supplied by a peer or inferred
 * from a local public activation marker. The private birth binding must exactly
 * match it in this first tranche. Same wire/domains/clock/entropy/Finished/erasure
 * rules; all flights stay in the mode selected by begin. No Genesis fallback.
 * Uses the existing dynamic pending size/alignment API, never serialized memory. */
int build8_worker_assignment_pending_v2_begin(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,uint8_t [1722]);
int build8_worker_assignment_pending_v2_accept(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,uint8_t [130]);
int build8_worker_assignment_pending_v2_finish(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,b8_worker_channel *);
/* Separate PUBLIC-journal mode. base layout/legacy storage stays unchanged;
 * journal and current-chain provider are local stable caller-owned objects.
 * Every flight rechecks exact current canonical assignment and full stored
 * proof; slow crypto is bracketed by checks. The runtime MUST call the current
 * authority gate before every frame/work use and retire on denial, besides all
 * existing lease/clock/maintenance rules. No shipping launcher is installed. */
typedef struct {
    build8_worker_local_v2 base;
    const build8_v2_assignment_journal *journal;
    const build8_v2_assignment_authority *authority;
} build8_worker_journal_local_v2;
int build8_worker_journal_pending_v2_begin(build8_worker_pending_v2 *,const build8_worker_journal_local_v2 *,uint64_t,uint64_t,uint8_t[1722]);
int build8_worker_journal_pending_v2_accept(build8_worker_pending_v2 *,const build8_worker_journal_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,uint8_t[130]);
int build8_worker_journal_pending_v2_finish(build8_worker_pending_v2 *,const build8_worker_journal_local_v2 *,uint64_t,uint64_t,
    const uint8_t *,size_t,b8_worker_channel *);
#endif
