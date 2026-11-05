/* Qualification adapter: bounded SHAKE256 contexts, no replacement ECC math.
 * Native thread-local pool; embedded/global pool uses atomic slot ownership.
 * This adapter and its target integration require separate production review.
 */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "inner.h"
struct build8_qual_md_ctx { shake_context state; unsigned used,phase; };
struct build8_qual_md { unsigned tag; };
#if defined(__XTENSA__) || defined(BUILD8_QUAL_GLOBAL_HASH_POOL)
#define LOCAL
#elif defined(_MSC_VER)
#define LOCAL __declspec(thread)
#else
#define LOCAL _Thread_local
#endif
static LOCAL EVP_MD_CTX pool[4];
static LOCAL volatile unsigned slots;
#ifdef BUILD8_QUALIFICATION
/* Public test harness only. No fault-control symbol in ordinary builds. */
static LOCAL unsigned final_fault;
static LOCAL unsigned scalar_cleanses;
void build8_qual_fail_final(unsigned nth) { final_fault=nth;scalar_cleanses=0; }
unsigned build8_qual_scalar_cleanses(void) { return scalar_cleanses; }
#endif
#ifdef _MSC_VER
#include <intrin.h>
static unsigned slots_load(void) { return (unsigned)_InterlockedCompareExchange((volatile long *)&slots,0,0); }
static int slots_claim(unsigned old,unsigned next) { return (unsigned)_InterlockedCompareExchange((volatile long *)&slots,(long)next,(long)old)==old; }
static void slots_release(unsigned bit) { _InterlockedAnd((volatile long *)&slots,(long)~bit); }
#else
static unsigned slots_load(void) { return __atomic_load_n(&slots,__ATOMIC_ACQUIRE); }
static int slots_claim(unsigned old,unsigned next) { return __atomic_compare_exchange_n(&slots,&old,next,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE); }
static void slots_release(unsigned bit) { __atomic_fetch_and(&slots,~bit,__ATOMIC_RELEASE); }
#endif
static EVP_MD shake256_md={256};
void OPENSSL_cleanse(void *p,size_t n) {
#ifdef BUILD8_QUALIFICATION
    /* Curve448 scalars are exactly 56 bytes on the supported 32/64-bit paths. */
    if(n==56)scalar_cleanses++;
#endif
    volatile unsigned char *v=p;while(n--)*v++=0;
}
/* Startup only, before any caller: ROM load_ram does not initialize .bss. */
void build8_qual_hash_contexts_reset(void) { OPENSSL_cleanse(pool,sizeof pool);slots=0; }
EVP_MD_CTX *EVP_MD_CTX_new(void) {
    for(unsigned attempt=0;attempt<16;attempt++) {
        unsigned old=slots_load();
        if((old&15)==15)return NULL;
        for(unsigned i=0;i<4;i++)if(!(old&(1u<<i))) {
            if(slots_claim(old,old|(1u<<i))) {
                OPENSSL_cleanse(&pool[i],sizeof pool[i]);pool[i].used=1;return &pool[i];
            }
            break;
        }
    }
    return NULL;
}
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    if(!ctx)return;
    for(unsigned i=0;i<4;i++)if(ctx==&pool[i]) {
        OPENSSL_cleanse(ctx,sizeof *ctx);slots_release(1u<<i);return;
    }
}
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx,const char *name,const char *properties) {
    return !ctx && !properties && name && strcmp(name,"SHAKE256")==0 ? &shake256_md : NULL;
}
void EVP_MD_free(EVP_MD *md) {(void)md;}
int EVP_DigestInit_ex(EVP_MD_CTX *ctx,const EVP_MD *md,void *engine) {
    if(!ctx || !ctx->used || md!=&shake256_md || engine)return 0;
    shake_init(&ctx->state,256);ctx->phase=1;return 1;
}
int EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *data,size_t n) {
    if(!ctx || !ctx->used || ctx->phase!=1 || (n&&!data))return 0;
    if(n)shake_inject(&ctx->state,data,n);return 1;
}
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx,unsigned char *out,size_t n) {
    if(!ctx || !ctx->used || ctx->phase!=1 || !out || n>114)return 0;
#ifdef BUILD8_QUALIFICATION
    if(final_fault && --final_fault==0)return 0;
#endif
    shake_flip(&ctx->state);shake_extract(&ctx->state,out,n);ctx->phase=2;return 1;
}
unsigned build8_qual_hash_contexts_used(void) {
    unsigned bits=slots_load(),total=0;for(unsigned i=0;i<4;i++)total+=(bits>>i)&1;return total;
}
