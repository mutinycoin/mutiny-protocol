#include "worker_accounting_v2.h"
#include "pow_work.h"
#include <string.h>
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return a&&b&&an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
static int scope_matches(const build8_observation_scope_v2 *s,const build8_work_context *c){
    return !memcmp(s->genesis,c->genesis,32)&&!memcmp(s->fingerprint,c->fingerprint,32)
        &&!memcmp(s->license,c->license,32)&&!memcmp(s->worker,c->worker,32);
}
static int owner(build8_worker_accounting_v2 *a,build8_mining_control_v2 *c){
    if(!a||!c||!separate(a,sizeof *a,c,sizeof *c))return 0;
    if(!a->initialized||!c->initialized||a->pending_length>sizeof a->pending
       ||!scope_matches(&a->scope,&c->context)){
        build8_mining_v2_accounting(c,true);return 0;
    }
    return 1;
}
static int extra(const build8_worker_accounting_v2 *a,const build8_mining_control_v2 *c,
    const build8_observation_store_v2 *s,const void *p,size_t n){
    return separate(a,sizeof *a,p,n)&&separate(c,sizeof *c,p,n)&&separate(s,sizeof *s,p,n);
}
static int backend(build8_worker_accounting_v2 *a,build8_mining_control_v2 *c,
    const build8_observation_store_v2 *s,build8_v2_domain_hash hash){
    if(!owner(a,c))return 0;
    if(!s||!hash||!s->read||!s->write||!separate(a,sizeof *a,s,sizeof *s)||!separate(c,sizeof *c,s,sizeof *s)){
        build8_mining_v2_accounting(c,true);return 0;
    }
    return 1;
}
int build8_worker_accounting_v2_init(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_scope_v2 *s){
    if(!a||!c||!s||!separate(a,sizeof *a,c,sizeof *c)||!separate(a,sizeof *a,s,sizeof *s)
       ||!separate(c,sizeof *c,s,sizeof *s)||a->initialized||!c->initialized)return 0;
    build8_mining_v2_accounting(c,true);
    if(!scope_matches(s,&c->context))return 0;
    const uint8_t *parts[]={s->genesis,s->fingerprint,s->license,s->worker};
    for(size_t j=0;j<4;j++){uint8_t any=0;for(size_t i=0;i<32;i++)any|=parts[j][i];if(!any)return 0;}
    memset(a,0,sizeof *a);a->scope=*s;a->initialized=true;return 1;
}
static int load(build8_worker_accounting_v2 *a,build8_mining_control_v2 *c,
    const build8_observation_store_v2 *s,build8_v2_domain_hash hash,build8_observation_state_v2 *v){
    if(!backend(a,c,s,hash))return 0;
    if(a->pending_length){
        build8_mining_v2_accounting(c,true);
        if(!build8_observation_store_v2_queue(s,&a->scope,a->pending,a->pending_length,a->coordinator,hash))return 0;
        /* Queue success includes durable readback or exact durable retry. */
        memset(a->pending,0,sizeof a->pending);memset(a->coordinator,0,32);a->pending_length=0;
    }
    if(!build8_observation_store_v2_restore(s,&a->scope,hash,v)){
        build8_mining_v2_accounting(c,true);return 0;
    }
    build8_mining_v2_accounting(c,v->pending_length!=0);return 1;
}
int build8_worker_accounting_v2_sync(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_store_v2 *s,build8_v2_domain_hash hash){
    build8_observation_state_v2 v;return load(a,c,s,hash,&v);
}
int build8_worker_accounting_v2_found(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const uint8_t authority[32],uint64_t nonce,
    build8_v2_monotonic_clock clock,void *arg){
    if(!owner(a,c)||!authority||!separate(a,sizeof *a,authority,32)
       ||!separate(c,sizeof *c,authority,32)||a->pending_length)return 0;
    build8_authorized_work w;
    if(!build8_mining_v2_found(c,authority,nonce,clock,arg,&w))return 0;
    build8_header h={0};h.network=w.network;h.height=w.height;h.timestamp=w.timestamp;h.nonce=nonce;
#define COPY(name) memcpy(h.name,w.name,32)
    COPY(genesis);COPY(fingerprint);COPY(parent);COPY(body);COPY(state);
    COPY(license);COPY(worker);COPY(authority);COPY(target);
#undef COPY
    size_t offsets[14];a->pending_length=(uint16_t)build8_encode_work(&h,a->pending,offsets);
    memcpy(a->coordinator,w.coordinator,32);return 1;
}
static void put64(uint8_t *out,uint64_t v){for(size_t i=0;i<8;i++)out[i]=(uint8_t)(v>>(56-8*i));}
int build8_worker_accounting_v2_request(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_store_v2 *s,build8_v2_domain_hash hash,
    const uint8_t nonce[32],build8_v2_monotonic_clock clock,void *arg,uint8_t out[73]){
    if(!backend(a,c,s,hash)||!extra(a,c,s,nonce,32)||!extra(a,c,s,out,73)||!separate(nonce,32,out,73))return 0;
    build8_observation_state_v2 v;
    if(!load(a,c,s,hash,&v)||v.pending_length||v.sequence==UINT64_MAX
       ||!build8_mining_v2_request(c,nonce,clock,arg))return 0;
    out[0]=5;memcpy(out+1,nonce,32);put64(out+33,v.sequence);memcpy(out+41,v.chain,32);return 1;
}
int build8_worker_accounting_v2_submission(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_store_v2 *s,build8_v2_domain_hash hash,
    uint8_t *out,size_t cap,size_t *written){
    if(!backend(a,c,s,hash)||cap<586||!extra(a,c,s,out,cap)||!extra(a,c,s,written,sizeof *written)
       ||!separate(out,cap,written,sizeof *written))return 0;
    *written=0;build8_observation_state_v2 v;uint8_t raw[585];size_t n=0;
    if(!load(a,c,s,hash,&v)||!build8_observation_store_v2_submission(&v,raw,sizeof raw,&n))return 0;
    out[0]=3;memcpy(out+1,raw,n);*written=n+1;return 1;
}
int build8_worker_accounting_v2_receipt(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_store_v2 *s,
    const uint8_t *raw,size_t n,const uint8_t *desc,size_t dn,build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,void *ws,size_t wn){
    if(!backend(a,c,s,h256)||!extra(a,c,s,raw,n)||!extra(a,c,s,desc,dn)||!extra(a,c,s,ws,wn)
       ||!separate(raw,n,desc,dn)||!separate(raw,n,ws,wn)||!separate(desc,dn,ws,wn))return 0;
    build8_observation_state_v2 v;
    if(!load(a,c,s,h256,&v))return 0;
    if(!build8_observation_store_v2_receipt(s,&a->scope,raw,n,desc,dn,h256,h512,ws,wn)){
        /* May have committed: only a subsequent successful restore can unblock. */
        build8_mining_v2_accounting(c,true);return 0;
    }
    return load(a,c,s,h256,&v);
}
int build8_worker_accounting_v2_receipt_packet(build8_worker_accounting_v2 *a,
    build8_mining_control_v2 *c,const build8_observation_store_v2 *s,const uint8_t *raw,size_t n,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *ws,size_t wn){
    if(!backend(a,c,s,h256)||!raw||n<1677||n>3724||!extra(a,c,s,raw,n)
       ||!extra(a,c,s,ws,wn)||!separate(raw,n,ws,wn)||raw[0]!=4||raw[1]!=2)return 0;
    size_t dn=((size_t)raw[2]<<8)|raw[3];
    if(!dn||dn>2048||n!=4+dn+1672)return 0;
    return build8_worker_accounting_v2_receipt(a,c,s,raw+4+dn,1672,raw+4,dn,h256,h512,ws,wn);
}
