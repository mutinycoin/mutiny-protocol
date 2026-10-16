#include "worker_kdf_v2.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha512.h"
#include "mbedtls/platform_util.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
/* Only SHA-512 contexts and byte HMAC pads are allocated in this profile. */
typedef union {mbedtls_sha512_context align;uint8_t bytes[256];} slot;
static slot pool[2];static uint8_t used[2];
static atomic_bool active;
_Static_assert(sizeof(mbedtls_sha512_context)<=256,"SHA512 exceeds fixed KDF slot");
#ifdef BUILD8_KDF_TESTS
static int fail_at=-1,allocations;
int b8_worker_kdf_test_fail_allocation(int n){if(atomic_load(&active))return 0;fail_at=n;return 1;}
int b8_worker_kdf_test_pool_clear(void){
    if(atomic_load(&active))return 0;
    const uint8_t *p=(const uint8_t *)pool;unsigned value=0;
    for(size_t i=0;i<sizeof pool;i++)value|=p[i];
    return !value&&!used[0]&&!used[1];
}
#endif
void *b8_kdf_calloc(size_t n,size_t size){
    if(!atomic_load(&active)||!n||!size||n>256/size)return NULL;
#ifdef BUILD8_KDF_TESTS
    if(allocations++==fail_at)return NULL;
#endif
    for(unsigned i=0;i<2;i++)if(!used[i]){used[i]=1;memset(pool[i].bytes,0,sizeof pool[i].bytes);return pool[i].bytes;}
    return NULL;
}
void b8_kdf_free(void *p){
    if(!p)return;
    for(unsigned i=0;i<2;i++)if(p==pool[i].bytes){mbedtls_platform_zeroize(&pool[i],sizeof pool[i]);used[i]=0;return;}
}
static int disjoint(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;if(!a||!b||an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 0;
    return x+an<=y||y+bn<=x;
}
int b8_worker_kdf_v2(const uint8_t x[56],const uint8_t kem[32],const uint8_t th[64],uint8_t out[104]){
    if(!disjoint(x,56,kem,32)||!disjoint(x,56,th,64)||!disjoint(x,56,out,104)
        ||!disjoint(kem,32,th,64)||!disjoint(kem,32,out,104)||!disjoint(th,64,out,104))return 0;
    memset(out,0,104);bool expected=false;
    if(!atomic_compare_exchange_strong(&active,&expected,true))return 0;
    uint8_t ikm[88];memcpy(ikm,x,56);memcpy(ikm+56,kem,32);
#ifdef BUILD8_KDF_TESTS
    allocations=0;
#endif
    static const uint8_t info[]="MUTINY-BUILD8-WORKER-SESSION-KEYS-V2";
    int ok=mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),th,64,ikm,sizeof ikm,
        info,sizeof info,out,104)==0;
    mbedtls_platform_zeroize(ikm,sizeof ikm);
    mbedtls_platform_zeroize(pool,sizeof pool);memset(used,0,sizeof used);
    if(!ok)mbedtls_platform_zeroize(out,104);
    atomic_store(&active,false);return ok;
}
