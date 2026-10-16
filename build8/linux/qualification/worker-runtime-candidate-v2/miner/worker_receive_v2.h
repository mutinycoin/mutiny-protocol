#ifndef BUILD8_WORKER_RECEIVE_V2_H
#define BUILD8_WORKER_RECEIVE_V2_H
#include <stddef.h>
#include <stdint.h>
#define BUILD8_WORKER_RECEIVE_MAX 16444u
enum {BUILD8_WORKER_RX_RESPONSE=1,BUILD8_WORKER_RX_FINISHED=2,BUILD8_WORKER_RX_FRAME=3};
/* Single-owner byte assembly only. Completion grants NO authentication or work
 * authority. Owner chooses the phase only after the corresponding crypto step.
 * Keep state/storage alive and disjoint; never copy an initialized receiver.
 * Clear on disconnect, deadline, maintenance and every failed crypto step. */
typedef struct {uint8_t *storage;size_t capacity,used,target;unsigned kind,ready;} build8_worker_receive_v2;
int build8_worker_receive_v2_init(build8_worker_receive_v2 *,uint8_t *,size_t,unsigned);
void build8_worker_receive_v2_clear(build8_worker_receive_v2 *);
/* Returns 1 for accepted bytes (possibly incomplete), 0 for failure. consumed
 * permits coalesced records: handle a completed message before feeding the
 * remaining bytes into a newly initialized receiver. No implicit phase change.
 * All input/output/state/storage ranges must be disjoint. A ready receiver
 * rejects further bytes until its owner has authenticated/handled and reset it. */
int build8_worker_receive_v2_feed(build8_worker_receive_v2 *,const uint8_t *,size_t,size_t *);
/* Public unauthenticated wire bytes only; valid until reset/clear. */
const uint8_t *build8_worker_receive_v2_message(const build8_worker_receive_v2 *,size_t *);
#endif
