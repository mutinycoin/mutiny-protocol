#ifndef BUILD8_FRAME_AEAD_MBEDTLS_V1_H
#define BUILD8_FRAME_AEAD_MBEDTLS_V1_H
#include "frame_v2.h"
/* Node/relay traffic key ONLY. Never initialize with wallet/owner secrets.
 * Key comes from the authenticated fresh handshake, not public wire input.
 * Caller controls custody and synchronizes access. No key serialization API. */
typedef struct { uint8_t key[32]; uint32_t initialized; } b8_frame_aead_key;
int b8_frame_aead_init(b8_frame_aead_key *key,const uint8_t raw[32]);
void b8_frame_aead_clear(b8_frame_aead_key *key);
int b8_frame_mbedtls_open(void *key,const uint8_t nonce[12],const uint8_t aad[99],
    const uint8_t *cipher,size_t length,uint8_t *plain);
int b8_frame_mbedtls_seal(void *key,const uint8_t nonce[12],const uint8_t aad[99],
    const uint8_t *plain,size_t length,uint8_t *cipher);
#endif
