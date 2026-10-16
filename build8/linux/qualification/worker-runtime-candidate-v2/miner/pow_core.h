#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "mbedtls/sha256.h"
#include "pow_work.h"
typedef struct {
    uint8_t bytes[BUILD8_WORK_CAPACITY] __attribute__((aligned(4)));
    size_t length,nonce_offset,prefix_length;
    uint8_t target[32];
    mbedtls_sha256_context prefix;
} build8_job;
bool build8_prepare(build8_job*,const build8_header*);
void build8_hash_nonce(build8_job*,uint64_t nonce,unsigned path,uint8_t digest[32]);
bool build8_meets_target(const uint8_t digest[32],const uint8_t target[32]);
/* Path 0: full ROM hardware hashing. Path 1: Mbed TLS fixed-prefix SHA clone.
 * Both use the identical search bytes. Caller supplies exclusive SHA ownership.
 * Preparation MUST run for every changed assignment; a context is not shared
 * across Worker/ticket/time/parent changes. No nonce wrap is allowed by caller.
 */
