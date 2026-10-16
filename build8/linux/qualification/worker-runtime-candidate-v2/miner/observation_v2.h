#ifndef BUILD8_OBSERVATION_V2_H
#define BUILD8_OBSERVATION_V2_H
#include "enrollment_v2.h"
#define BUILD8_OBSERVATION_V2_BODY 278
#define BUILD8_OBSERVATION_V2_RECEIPT 1672
/* All fields come from verified ACTIVE enrollment and the independently
 * retained pending result/checkpoint, never from the incoming receipt.
 * result is the approved ResultID of the exact retained Work bytes. */
typedef struct {
    uint8_t genesis[32],fingerprint[32],license[32],worker[32],coordinator[32],result[32],previous[32];
    uint64_t sequence,prior_total;
} build8_observation_v2_context;
/* Pure bounded candidate verifier. No allocation, signing, RNG, storage or RF.
 * Requires both signatures, exact context and accounting progression. Does not
 * establish finality or update persistent counters. All ranges must be disjoint.
 * Trusted local hash adapters; FN workspace4127..65536 bytes. */
int build8_observation_v2_verify(const uint8_t *,size_t,const build8_observation_v2_context *,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
#endif
