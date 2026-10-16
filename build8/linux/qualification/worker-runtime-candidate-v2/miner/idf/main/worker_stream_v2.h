#ifndef BUILD8_WORKER_STREAM_V2_H
#define BUILD8_WORKER_STREAM_V2_H
#include "worker_runtime_guard_v2.h"
/* Candidate owner-task stream adapter. No sockets/tasks/radio are started here.
 * Each callback is NONBLOCKING: positive=bytes transferred, zero=would-block,
 * negative=EOF/fault. It must never return more than the requested count.
 * One call performs at most one 1024-byte read OR write and one received event.
 * The caller yields/schedules between calls and supplies current authenticated
 * authority on EVERY call, including idle calls. No automatic reconnection.
 * All objects, callback state, buffers and authority must be live and disjoint.
 * Same single owner as connection/mining; never call from an ISR. */
typedef int (*build8_worker_stream_read_v2)(void *,uint8_t *,size_t);
typedef int (*build8_worker_stream_write_v2)(void *,const uint8_t *,size_t);
typedef struct {
    uint8_t input[1024];
    size_t used,offset;
    uint64_t last_clock;
    bool started,prefer_read;
} build8_worker_stream_v2;
size_t build8_worker_stream_v2_size(void);
/* Initialize once for a fresh connection, not to revive an expired session. */
void build8_worker_stream_v2_init(build8_worker_stream_v2 *);
/* Retires work, erases connection and buffered wire bytes. The socket owner
 * must then close its descriptor; this component never owns a descriptor. */
void build8_worker_stream_v2_close(build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *);
/* Returns CLOSED/MORE/SEND/CONFIRMED/MESSAGE from worker_connection_v2.h.
 * MESSAGE is authenticated transport only: independently validate typed work.
 * CONFIRMED still requires the runtime identity-binding guard before mining.
 * Caller consumes and clears plaintext before its next call. On all other
 * events, written=0 and plaintext is cleared. Maintenance/revocation must call
 * close before changing authority; no transient application authorization. */
int build8_worker_stream_v2_step(build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_local_v2 *,const uint8_t[64],uint64_t,uint64_t,
    build8_v2_monotonic_clock,build8_worker_stream_read_v2,build8_worker_stream_write_v2,void *,
    uint8_t *,size_t,size_t *);

/* Same real bounded stream engine, explicit journal controller/config only.
 * Mandatory own-chain gate around each actual I/O/frame path. No NVS fallback.
 * Same owner task/disjoint stable buffers; failure retires work and session. */
int build8_worker_stream_journal_v2_step(build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_journal_local_v2 *,const uint8_t[64],uint64_t,uint64_t,build8_v2_monotonic_clock,
    build8_worker_stream_read_v2,build8_worker_stream_write_v2,void *,uint8_t *,size_t,size_t *);
#endif
