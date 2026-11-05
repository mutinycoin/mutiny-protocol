/* Bounded domain composition around unmodified pinned Mbed TLS hash code. */
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#ifndef BUILD8_QUAL_EXTERNAL_ZEROIZE
void mbedtls_platform_zeroize(void *p,size_t n) {volatile uint8_t *v=p;while(n--)*v++=0;}
#endif
static size_t domain_size(const char *domain) {
    if(!domain)return 0;
    for(size_t n=0;n<64;n++)if(!domain[n])return n+1;
    return 0;
}
int build8_v2_mbed_hash256(const char *domain,const uint8_t *p,size_t n,uint8_t *out) {
    size_t dn=domain_size(domain);if(!dn||!p||!out||n>2775)return 0;
    mbedtls_sha256_context c;mbedtls_sha256_init(&c);
    int ok=mbedtls_sha256_starts(&c,0)==0
        &&mbedtls_sha256_update(&c,(const uint8_t *)domain,dn)==0
        &&mbedtls_sha256_update(&c,p,n)==0&&mbedtls_sha256_finish(&c,out)==0;
    mbedtls_sha256_free(&c);return ok;
}
int build8_v2_mbed_hash512(const char *domain,const uint8_t *p,size_t n,uint8_t *out) {
    size_t dn=domain_size(domain);if(!dn||!p||!out||n>512)return 0;
    mbedtls_sha512_context c;mbedtls_sha512_init(&c);
    int ok=mbedtls_sha512_starts(&c,0)==0
        &&mbedtls_sha512_update(&c,(const uint8_t *)domain,dn)==0
        &&mbedtls_sha512_update(&c,p,n)==0&&mbedtls_sha512_finish(&c,out)==0;
    mbedtls_sha512_free(&c);return ok;
}
/* Separate larger public-policy boundary; enrollment bounds stay unchanged. */
int build8_release_mbed_hash256(const char *domain,const uint8_t *p,size_t n,uint8_t *out) {
    size_t dn=domain_size(domain);if(!dn||!p||!out||n>5800)return 0;
    mbedtls_sha256_context c;mbedtls_sha256_init(&c);
    int ok=mbedtls_sha256_starts(&c,0)==0
        &&mbedtls_sha256_update(&c,(const uint8_t *)domain,dn)==0
        &&mbedtls_sha256_update(&c,p,n)==0&&mbedtls_sha256_finish(&c,out)==0;
    mbedtls_sha256_free(&c);return ok;
}
int build8_release_mbed_hash512(const char *domain,const uint8_t *p,size_t n,uint8_t *out) {
    size_t dn=domain_size(domain);if(!dn||!p||!out||n>5900)return 0;
    mbedtls_sha512_context c;mbedtls_sha512_init(&c);
    int ok=mbedtls_sha512_starts(&c,0)==0
        &&mbedtls_sha512_update(&c,(const uint8_t *)domain,dn)==0
        &&mbedtls_sha512_update(&c,p,n)==0&&mbedtls_sha512_finish(&c,out)==0;
    mbedtls_sha512_free(&c);return ok;
}
