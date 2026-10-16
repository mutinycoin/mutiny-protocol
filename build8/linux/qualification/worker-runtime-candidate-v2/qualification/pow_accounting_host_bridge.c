/* Actual unchanged PoW codec/software hash implementation. ROM operations are
 * unavailable on the host and abort; this fixture never claims hardware SHA. */
#ifdef _MSC_VER
#define __attribute__(x)
#endif
#include "../miner/pow_core.c"
#include <stdlib.h>
void ets_sha_init(ROM_SHA_CTX *p){(void)p;abort();}
void ets_sha_update(ROM_SHA_CTX *p,int n,const uint8_t *b,size_t z){(void)p;(void)n;(void)b;(void)z;abort();}
void ets_sha_finish(ROM_SHA_CTX *p,int n,uint8_t *b){(void)p;(void)n;(void)b;abort();}
