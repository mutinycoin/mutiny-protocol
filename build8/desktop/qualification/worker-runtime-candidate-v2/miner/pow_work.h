#ifndef BUILD8_POW_WORK_H
#define BUILD8_POW_WORK_H
#include <stdint.h>
#include <stddef.h>
#define BUILD8_WORK_CAPACITY 512
typedef struct {
    uint32_t network;
    uint8_t genesis[32], fingerprint[32], parent[32];
    uint64_t height,timestamp;
    uint8_t body[32],state[32],license[32],worker[32],authority[32],target[32];
    uint64_t nonce;
} build8_header;
/* Exact existing PoW encoder; caller supplies BUILD8_WORK_CAPACITY bytes. */
size_t build8_encode_work(const build8_header*,uint8_t*,size_t offsets[14]);
#endif
