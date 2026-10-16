#ifndef BUILD8_WORKER_CONNECTION_V2_H
#define BUILD8_WORKER_CONNECTION_V2_H
#include "worker_v2_nvs.h"
#include "worker_receive_v2.h"
/* Candidate single-owner task controller; no socket, task or radio startup.
 * Caller supplies disjoint live buffers, qualified clock/entropy and trusted
 * current authority. No peer may provide local configuration or context IDs.
 * All calls run on the same owner task; maintenance/revocation signals that
 * task to close immediately. Never copy/serialize this object or its buffers. */
typedef struct {
    build8_worker_pending_v2 *pending;
    build8_worker_receive_v2 receive;
    b8_worker_channel channel;
    uint8_t *rx,*tx;
    size_t tx_length,tx_sent;
    unsigned phase,mode;
    const build8_worker_journal_local_v2 *journal_local;
} build8_worker_connection_v2;
enum {BUILD8_CONNECTION_CLOSED=0,BUILD8_CONNECTION_MORE=1,BUILD8_CONNECTION_SEND=2,
      BUILD8_CONNECTION_CONFIRMED=3,BUILD8_CONNECTION_MESSAGE=4,BUILD8_CONNECTION_BUSY=5};
size_t build8_worker_connection_v2_size(void);
size_t build8_worker_connection_v2_alignment(void);
/* Init requires cleared/released previous ownership; pending memory uses the
 * core size/alignment queries; rx and tx each hold exactly 16444 bytes. */
int build8_worker_connection_v2_start(build8_worker_connection_v2 *,void *,size_t,uint8_t *,uint8_t *,const build8_worker_local_v2 *,uint64_t,uint64_t);
void build8_worker_connection_v2_close(build8_worker_connection_v2 *);
/* Mandatory timer even when idle. now is trusted monotonic milliseconds.
 * Current context/height/epoch must be independently authenticated by the owner.
 * No automatic reconnect or retry after failure. */
int build8_worker_connection_v2_tick(build8_worker_connection_v2 *,const uint8_t [64],uint64_t,uint64_t,uint64_t);
/* Local task query, never a peer claim. Checks timer/current authority first;
 * a still-pending handshake returns 0 without granting application authority. */
int build8_worker_connection_v2_authenticated(build8_worker_connection_v2 *,const uint8_t [64],uint64_t,uint64_t,uint64_t);
/* Returned handshake/ciphertext bytes remain owned by controller. sent confirms
 * only bytes actually accepted by the socket; partial writes are supported. */
const uint8_t *build8_worker_connection_v2_out(const build8_worker_connection_v2 *,size_t *);
int build8_worker_connection_v2_sent(build8_worker_connection_v2 *,size_t);
/* Enqueue one authenticated frame only after confirmation. SEND=queued,
 * BUSY=existing frame retained with no sequence advancement, CLOSED=failure.
 * Caller validates typed message semantics before calling. No dynamic queue. */
int build8_worker_connection_v2_send(build8_worker_connection_v2 *,const uint8_t [64],uint64_t,uint64_t,uint64_t,const uint8_t *,size_t);
/* Plaintext only returned after AEAD authentication. Message event itself does
 * not authorize mining: typed work/canonical authority validation stays required.
 * consumed supports coalesced input, process returned event before continuing.
 * Caller owns plaintext and clears it after the typed handler consumes it.
 * Every caller buffer/output/configuration range must be disjoint. */
int build8_worker_connection_v2_receive(build8_worker_connection_v2 *,const build8_worker_local_v2 *,const uint8_t [64],uint64_t,uint64_t,uint64_t,const uint8_t *,size_t,size_t *,uint8_t *,size_t,size_t *);

/* Explicit PUBLIC journal owner mode. Stable LOCAL config/own-chain provider,
 * no peer-selected mode, no Genesis fallback. Every operation rechecks current
 * canonical exact wire and clock. Legacy mode functions refuse this instance.
 * Callback/provider crypto time counts against existing leases. */
int build8_worker_connection_journal_v2_start(build8_worker_connection_v2 *,void *,size_t,uint8_t *,uint8_t *,const build8_worker_journal_local_v2 *,uint64_t,uint64_t);
int build8_worker_connection_journal_v2_tick(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t);
int build8_worker_connection_journal_v2_authenticated(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t);
const uint8_t *build8_worker_connection_journal_v2_out(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t,size_t *);
int build8_worker_connection_journal_v2_sent(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t,size_t);
int build8_worker_connection_journal_v2_send(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t,const uint8_t *,size_t);
int build8_worker_connection_journal_v2_receive(build8_worker_connection_v2 *,const build8_worker_journal_local_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t,const uint8_t *,size_t,size_t *,uint8_t *,size_t,size_t *);
#endif
