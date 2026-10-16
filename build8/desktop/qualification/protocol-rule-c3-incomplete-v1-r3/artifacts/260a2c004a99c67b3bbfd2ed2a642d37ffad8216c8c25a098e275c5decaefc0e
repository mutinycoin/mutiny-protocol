#ifndef BUILD8_WORKER_FRAME_V2_H
#define BUILD8_WORKER_FRAME_V2_H
#include <stddef.h>
#include <stdint.h>
#define B8_WORKER_PAYLOAD_MAX 16384u
#define B8_WORKER_FRAME_MAX (44u+B8_WORKER_PAYLOAD_MAX+16u)
/* Single-owner, memory-only candidate. Never copy/serialize an active channel.
 * Initialize ONLY from completed mutually authenticated Worker V2 handshake.
 * Context is the exact ContextID, not a peer-supplied trust root. No device I/O.
 * Every operation receives independently recomputed current canonical context,
 * height and epoch. Keys are derived traffic keys, never wallet/identity keys. */
typedef struct {
    uint8_t context[64],id[32],tx_key[32],rx_key[32],tx_prefix[4],rx_prefix[4];
    uint64_t confirmed_ms,last_ms,next_tx,next_rx,tx_bytes,rx_bytes,effective_epoch,until_height;
    uint32_t active;uint8_t worker;
} b8_worker_channel;
size_t b8_worker_channel_size(void);
size_t b8_worker_channel_alignment(void);
void b8_worker_channel_clear(b8_worker_channel *);
/* Owner-task timer, including idle connections. Recompute trusted authority
 * first; invalid authority, clock rollback or one-hour expiry erases keys.
 * Disconnect/maintenance must clear immediately. Never call concurrently. */
int b8_worker_channel_expire(b8_worker_channel *,const uint8_t[64],uint64_t,uint64_t,uint64_t);
/* The last two arguments are the binding's effective_epoch (no traffic before it) and its
 * valid_until_height. The latter is the consensus INCLUSION deadline of the assignment, not a
 * session expiry (Order Q17, amendment AM-7): it is recorded and never ends the channel, so a
 * caller may pass the binding value or 0 with the same effect. The channel ends on the one-hour
 * lifetime, clock rollback, height 0, an epoch before effective_epoch, or a current ContextID
 * that differs (reassignment, sale, owner, configuration or Node key generation). */
int b8_worker_channel_init(b8_worker_channel *,const uint8_t[64],const uint8_t[32],
    const uint8_t[32],const uint8_t[32],const uint8_t[4],const uint8_t[4],
    uint8_t,uint64_t,uint64_t,uint64_t,uint64_t);
/* Input, output, lengths, context and channel memory must be disjoint.
 * Sizes are explicit. On any failure the channel closes; no output is valid
 * unless return==1. On alias errors only the channel is cleared (overlapping
 * storage is therefore invalid); otherwise the bounded output is cleared.
 * now_ms is trusted monotonic clock, not a peer timestamp. */
int b8_worker_seal(b8_worker_channel *,const uint8_t[64],uint64_t,uint64_t,uint64_t,
    const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int b8_worker_open(b8_worker_channel *,const uint8_t[64],uint64_t,uint64_t,uint64_t,
    const uint8_t *,size_t,uint8_t *,size_t,size_t *);
#endif
