#include "aead_mbedtls_v1.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#define KEY_MAGIC UINT32_C(0x42384b32)
void b8_frame_aead_clear(b8_frame_aead_key *key) {
    if(key)mbedtls_platform_zeroize(key,sizeof(*key));
}
int b8_frame_aead_init(b8_frame_aead_key *key,const uint8_t raw[32]) {
    uint8_t copy[32];
    if(!key)return 0;
    if(!raw){b8_frame_aead_clear(key);return 0;}
    /* Input may alias the current key, e.g. a caller refreshing its wrapper.
     * Never erase the source and silently replace the traffic key with zero. */
    memcpy(copy,raw,32);
    b8_frame_aead_clear(key);
    memcpy(key->key,copy,32);key->initialized=KEY_MAGIC;
    mbedtls_platform_zeroize(copy,sizeof(copy));return 1;
}
int b8_frame_mbedtls_open(void *provider,const uint8_t nonce[12],const uint8_t aad[99],
    const uint8_t *cipher,size_t length,uint8_t *plain) {
    b8_frame_aead_key *key=(b8_frame_aead_key *)provider;
    mbedtls_chachapoly_context ctx;int result;
    if(!key || key->initialized!=KEY_MAGIC || !nonce || !aad || !cipher || !plain || length<17 || length>156)return 0;
    mbedtls_chachapoly_init(&ctx);
    result=mbedtls_chachapoly_setkey(&ctx,key->key);
    if(!result)result=mbedtls_chachapoly_auth_decrypt(&ctx,length-16,nonce,aad,99,cipher+length-16,cipher,plain);
    mbedtls_chachapoly_free(&ctx);
    if(result)mbedtls_platform_zeroize(plain,length-16);
    return result==0;
}
int b8_frame_mbedtls_seal(void *provider,const uint8_t nonce[12],const uint8_t aad[99],
    const uint8_t *plain,size_t length,uint8_t *cipher) {
    b8_frame_aead_key *key=(b8_frame_aead_key *)provider;
    mbedtls_chachapoly_context ctx;int result;
    if(!key || key->initialized!=KEY_MAGIC || !nonce || !aad || !plain || !cipher || !length || length>140)return 0;
    mbedtls_chachapoly_init(&ctx);
    result=mbedtls_chachapoly_setkey(&ctx,key->key);
    if(!result)result=mbedtls_chachapoly_encrypt_and_tag(&ctx,length,nonce,aad,99,plain,cipher,cipher+length);
    mbedtls_chachapoly_free(&ctx);
    if(result)mbedtls_platform_zeroize(cipher,length+16);
    return result==0;
}
