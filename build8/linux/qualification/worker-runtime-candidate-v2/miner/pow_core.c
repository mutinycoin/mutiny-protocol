#include "pow_core.h"
#include <string.h>
typedef struct { bool start; uint32_t total_input_bits[4]; } ROM_SHA_CTX;
extern void ets_sha_init(ROM_SHA_CTX*);
extern void ets_sha_update(ROM_SHA_CTX*,int,const uint8_t*,size_t);
extern void ets_sha_finish(ROM_SHA_CTX*,int,uint8_t*);
static size_t number(uint8_t *out,unsigned major,uint64_t n) {
    if(n<24){out[0]=(uint8_t)((major<<5)|n);return 1;}
    unsigned size=n<=255?1:n<=65535?2:n<=UINT32_MAX?4:8;
    out[0]=(uint8_t)((major<<5)|(size==1?24:size==2?25:size==4?26:27));
    for(unsigned i=0;i<size;i++)out[i+1]=(uint8_t)(n>>(8*(size-1-i)));
    return size+1;
}
static size_t blob(uint8_t *out,const uint8_t *data,size_t n) {
    size_t k=number(out,2,n);memcpy(out+k,data,n);return k+n;
}
size_t build8_encode_work(const build8_header *h,uint8_t *out,size_t offsets[14]) {
    static const char domain[]="MUTINY-BUILD8-WORK-V1";
    size_t at=sizeof(domain);memcpy(out,domain,at);out[at++]=0x8e;
    offsets[0]=at;at+=number(out+at,0,1);
    offsets[1]=at;at+=number(out+at,0,h->network);
    const uint8_t *early[]={h->genesis,h->fingerprint,h->parent};
    for(unsigned i=0;i<3;i++){offsets[i+2]=at;at+=blob(out+at,early[i],32);}
    offsets[5]=at;at+=number(out+at,0,h->height);
    offsets[6]=at;at+=number(out+at,0,h->timestamp);
    const uint8_t *late[]={h->body,h->state,h->license,h->worker,h->authority,h->target};
    for(unsigned i=0;i<6;i++){offsets[i+7]=at;at+=blob(out+at,late[i],32);}
    uint8_t nonce[8];for(unsigned i=0;i<8;i++)nonce[i]=(uint8_t)(h->nonce>>(56-i*8));
    offsets[13]=at;at+=blob(out+at,nonce,8);return at;
}
static void hardware_sha(const uint8_t *b,size_t n,uint8_t out[32]) {
    ROM_SHA_CTX ctx;ets_sha_init(&ctx);
    while(n){size_t take=n>64?64:n;ets_sha_update(&ctx,1,b,take*8);b+=take;n-=take;}
    ets_sha_finish(&ctx,1,out);
}
bool build8_prepare(build8_job *job,const build8_header *header) {
    size_t offsets[14];job->length=build8_encode_work(header,job->bytes,offsets);
    if(job->length>BUILD8_WORK_CAPACITY)return false;
    job->nonce_offset=job->length-8;job->prefix_length=job->nonce_offset/64*64;
    memcpy(job->target,header->target,32);
    mbedtls_sha256_init(&job->prefix);
    return mbedtls_sha256_starts(&job->prefix,0)==0 &&
        mbedtls_sha256_update(&job->prefix,job->bytes,job->prefix_length)==0;
}
void build8_hash_nonce(build8_job *job,uint64_t nonce,unsigned path,uint8_t digest[32]) {
    uint8_t first[32] __attribute__((aligned(4)));
    for(unsigned i=0;i<8;i++)job->bytes[job->nonce_offset+i]=(uint8_t)(nonce>>(56-i*8));
    if(path==0){hardware_sha(job->bytes,job->length,first);hardware_sha(first,32,digest);}
    else {
        mbedtls_sha256_context ctx;mbedtls_sha256_clone(&ctx,&job->prefix);
        mbedtls_sha256_update(&ctx,job->bytes+job->prefix_length,job->length-job->prefix_length);
        mbedtls_sha256_finish(&ctx,first);
        mbedtls_sha256_starts(&ctx,0);mbedtls_sha256_update(&ctx,first,32);mbedtls_sha256_finish(&ctx,digest);
        mbedtls_sha256_free(&ctx);
    }
}
bool build8_meets_target(const uint8_t digest[32],const uint8_t target[32]) {
    unsigned nonzero=0;for(unsigned i=0;i<32;i++)nonzero|=target[i];if(!nonzero)return false;
    for(unsigned i=0;i<32;i++){if(digest[i]<target[i])return true;if(digest[i]>target[i])return false;}
    return true;
}
