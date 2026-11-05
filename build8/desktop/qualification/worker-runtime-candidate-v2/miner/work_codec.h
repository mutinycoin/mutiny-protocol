#ifndef BUILD8_WORK_CODEC_H
#define BUILD8_WORK_CODEC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t network;
    uint8_t genesis[32], fingerprint[32], parent[32];
    uint64_t height, timestamp;
    uint8_t body[32], state[32], license[32], worker[32];
    uint64_t assignment, ticket;
    uint8_t coordinator[32], target[32];
    uint64_t nonce_start, nonce_end, epoch;
    uint8_t authority[32];
} build8_authorized_work;
typedef struct {
    uint8_t genesis[32], fingerprint[32], parent[32], license[32], worker[32], coordinator[32], target[32];
    uint64_t height, genesis_timestamp, assignment, last_ticket;
} build8_work_context;
/* Verify strict Ed25519 over H(WORK-AUTHORITY, unsigned CBOR), return that ID.
 * The callback must not substitute the untrusted ticket's key for the pinned key. */
typedef bool (*build8_verify_work)(const uint8_t *, size_t, const uint8_t[64], const uint8_t[32], uint8_t[32]);
bool build8_decode_authorized_work(const uint8_t *, size_t, const build8_work_context *, build8_verify_work, build8_authorized_work *);
/* Inclusive search, including UINT64_MAX exactly once; false means exhausted. */
bool build8_next_nonce(uint64_t current, uint64_t end, uint64_t *next);
#endif
