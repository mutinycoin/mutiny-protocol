#ifndef BUILD8_WORK_V2_H
#define BUILD8_WORK_V2_H
#include "work_codec.h"
#include "enrollment_v2.h"
/* Candidate-only allocation-free hybrid node work verification. Context is
 * pinned by canonical enrollment and independently authenticated parent/job
 * state, never copied from the incoming envelope. Node validators additionally
 * enforce historical MTP, execution, licensed state, PoW and finality.
 * Caller ranges must be disjoint. After initial pointer, size and overlap
 * checks, output is cleared before parsing. Invalid ranges are not mutated.
 * FN workspace minimum 4127 bytes. No flash, NVS, keys or radio operations. */
int build8_decode_authorized_work_v2(const uint8_t *,size_t,const build8_work_context *,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,build8_authorized_work *);
#endif
