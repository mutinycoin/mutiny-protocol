#ifndef BUILD8_WORKER_SOCKET_OWNER_V2_H
#define BUILD8_WORKER_SOCKET_OWNER_V2_H
#include "worker_socket_io_v2.h"
#include "worker_stream_v2.h"
#include "worker_maintenance_v2.h"
/* Explicit descriptor ownership, distinct from the borrowed socket adapter.
 * Zero initialize a fresh object. Successful init transfers sole fd ownership;
 * failed init leaves ownership with the caller. Never copy or reinitialize a
 * live/retired object, and never close/reassign its fd elsewhere. One task only.
 * New connections use fresh owner objects and fresh stream/session state. */
typedef struct {build8_worker_socket_io_v2 io;int close_error;bool initialized,closed;} build8_worker_socket_owner_v2;
int build8_worker_socket_owner_v2_init(build8_worker_socket_owner_v2 *,int);
int build8_worker_socket_owner_v2_read(void *,uint8_t *,size_t);
int build8_worker_socket_owner_v2_write(void *,const uint8_t *,size_t);
/* One bounded nonblocking stream step with owned socket I/O. The clock has
 * independent callback state. CLOSED always retires stream/session/work and
 * makes one close attempt; close_error remains available for diagnostics.
 * MESSAGE remains authenticated transport only, requiring typed validation.
 * Same live/disjoint owner-object contract as stream and retirement APIs. */
int build8_worker_socket_owner_v2_step(build8_worker_socket_owner_v2 *,
    build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_local_v2 *,const uint8_t[64],uint64_t,uint64_t,
    build8_v2_monotonic_clock,void *,uint8_t *,size_t,size_t *);
/* Explicit journal route through real owned socket callbacks. Same ownership,
 * clock/close-once/maintenance contracts; every chunk uses current-chain gate.
 * Supported POSIX/ESP targets only; no Windows fake socket/cfg fallback. */
int build8_worker_socket_owner_journal_v2_step(build8_worker_socket_owner_v2 *,
    build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_journal_local_v2 *,const uint8_t[64],uint64_t,uint64_t,
    build8_v2_monotonic_clock,void *,uint8_t *,size_t,size_t *);
/* Retire work and wipe connection/stream before closing the owned descriptor.
 * RUN and accounting are preserved. A close error is sticky and diagnostic;
 * never retry close on a potentially recycled descriptor. Success on an
 * already successfully retired object is idempotent, not renewed authority.
 * Objects and connection backing buffers must be live and mutually disjoint. */
int build8_worker_socket_owner_v2_retire(build8_worker_socket_owner_v2 *,
    build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_mining_control_v2 *);
/* Complete transport retirement before the separately qualified checkpoint
 * parking preparation. Existing maintenance lease remains required throughout
 * the subsequent verified operation/cleanup. Close errors forbid preparation. */
int build8_worker_socket_owner_v2_maintenance(build8_worker_socket_owner_v2 *,
    build8_worker_stream_v2 *,build8_worker_connection_v2 *,build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,build8_v2_domain_hash);
#endif
