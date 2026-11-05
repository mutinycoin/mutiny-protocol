#ifndef BUILD8_WORKER_JOURNAL_RUNTIME_V2_H
#define BUILD8_WORKER_JOURNAL_RUNTIME_V2_H
#include "worker_stream_v2.h"
/* Explicit single-owner ordinary journal route, nonshipping until platform
 * inputs are supplied/qualified. Init only AFTER both Finished, with mining
 * independently initialized from own canonical work context, never an offer.
 * Stable disjoint owner/config/backend/buffers, no peer-provided adapters.
 * No stored authority cache: every frame/work action invokes own-chain gate.
 * The pointer object is never copied/serialized/persisted; no private ABI. */
typedef struct {
    build8_worker_connection_v2 *connection;
    build8_mining_control_v2 *mining;
    const build8_worker_journal_local_v2 *local;
    uint8_t session[64];
    uint64_t height,epoch;
    bool initialized;
} build8_worker_journal_runtime_v2;
size_t build8_worker_journal_runtime_v2_size(void);
size_t build8_worker_journal_runtime_v2_alignment(void);
int build8_worker_journal_runtime_v2_init(build8_worker_journal_runtime_v2 *,build8_worker_connection_v2 *,
    build8_mining_control_v2 *,const build8_worker_journal_local_v2 *,uint64_t,uint64_t);
void build8_worker_journal_runtime_v2_close(build8_worker_journal_runtime_v2 *);
int build8_worker_journal_runtime_v2_gate(build8_worker_journal_runtime_v2 *,bool);
/* Existing request/work deadline/real hybrid signature/nonce/ticket rules stay
 * unchanged. Output staged until post-current gate. Failures retire session and
 * work but retain RUN intent, ticket floor and pending accounting. */
int build8_worker_journal_runtime_v2_request(build8_worker_journal_runtime_v2 *,const uint8_t[32],build8_v2_monotonic_clock,void *);
int build8_worker_journal_runtime_v2_offer(build8_worker_journal_runtime_v2 *,const uint8_t *,size_t,build8_v2_monotonic_clock,void *);
int build8_worker_journal_runtime_v2_nonce(build8_worker_journal_runtime_v2 *,build8_v2_monotonic_clock,void *,uint64_t *);
int build8_worker_journal_runtime_v2_found(build8_worker_journal_runtime_v2 *,const uint8_t[32],uint64_t,
    build8_v2_monotonic_clock,void *,build8_authorized_work *);
int build8_worker_journal_runtime_v2_send(build8_worker_journal_runtime_v2 *,const uint8_t *,size_t);
int build8_worker_journal_runtime_v2_step(build8_worker_journal_runtime_v2 *,build8_worker_stream_v2 *,
    build8_v2_monotonic_clock,build8_worker_stream_read_v2,build8_worker_stream_write_v2,void *,uint8_t *,size_t,size_t *);
#endif
