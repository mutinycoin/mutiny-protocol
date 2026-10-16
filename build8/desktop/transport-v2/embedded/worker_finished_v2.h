#ifndef BUILD8_WORKER_FINISHED_V2_H
#define BUILD8_WORKER_FINISHED_V2_H
#include <stdint.h>
#include <stddef.h>
/* Candidate Finished key confirmation: sender 0=Worker, 1=Node. This does not
 * itself authenticate identity or activate a channel. Caller supplies the
 * corresponding directional key/prefix and exact authenticated transcript.
 * All buffers must be disjoint; tag always exactly 16 bytes. Nonce sequence
 * zero is reserved for Finished and must never be reused for application data.
 * Invalid buffer ranges leave output untouched; other generation errors clear it. */
int b8_worker_finished_v2(const uint8_t [32],const uint8_t [4],const uint8_t [64],uint8_t,uint8_t [16]);
int b8_worker_verify_finished_v2(const uint8_t [32],const uint8_t [4],const uint8_t [64],uint8_t,const uint8_t *,size_t);
#endif
