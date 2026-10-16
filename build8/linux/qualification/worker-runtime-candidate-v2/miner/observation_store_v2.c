#include "observation_store_v2.h"
#include <string.h>
_Static_assert(sizeof(build8_observation_scope_v2)==128,"scope codec");
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
static int nonzero(const uint8_t *p,size_t n){uint8_t v=0;for(size_t i=0;i<n;i++)v|=p[i];return v!=0;}
static uint64_t read64(const uint8_t *p){uint64_t v=0;for(size_t i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static void write64(uint8_t *p,uint64_t v){for(size_t i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));}
static int inputs(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *p,build8_v2_domain_hash hash){
    return s&&s->read&&p&&hash&&separate(s,sizeof *s,p,sizeof *p)
        &&nonzero(p->genesis,32)&&nonzero(p->fingerprint,32)&&nonzero(p->license,32)&&nonzero(p->worker,32);
}
typedef struct {const uint8_t *p;size_t n,at;} reader;
static int number(reader *r,unsigned major,uint64_t *value){
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;if((b>>5)!=major||a>27)return 0;
    if(a<24){*value=a;return 1;}
    unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
    uint64_t v=0;for(unsigned i=0;i<count;i++)v=(v<<8)|r->p[r->at++];
    if(v<24||(count>1&&v<((uint64_t)1<<(8*(count/2)))))return 0;
    *value=v;return 1;
}
static int exact(reader *r,unsigned major,uint64_t want){uint64_t v;return number(r,major,&v)&&v==want;}
static const uint8_t *blob(reader *r,size_t n){uint64_t length;
    if(!number(r,2,&length)||length!=n||n>r->n-r->at)return NULL;
    const uint8_t *p=r->p+r->at;r->at+=n;return p;
}
static int same(reader *r,const uint8_t *want){const uint8_t *p=blob(r,32);return p&&!memcmp(p,want,32);}
static int work_valid(const uint8_t *raw,size_t n,const build8_observation_scope_v2 *scope){
    static const char domain[]="MUTINY-BUILD8-WORK-V1";
    if(!raw||n<=sizeof domain||n>544||memcmp(raw,domain,sizeof domain))return 0;
    reader r={raw,n,sizeof domain};uint64_t height,time;const uint8_t *authority,*target;
    return exact(&r,4,14)&&exact(&r,0,1)&&exact(&r,0,0x4d555401)
        &&same(&r,scope->genesis)&&same(&r,scope->fingerprint)&&blob(&r,32)
        &&number(&r,0,&height)&&height&&number(&r,0,&time)&&blob(&r,32)&&blob(&r,32)
        &&same(&r,scope->license)&&same(&r,scope->worker)
        &&(authority=blob(&r,32))&&nonzero(authority,32)
        &&(target=blob(&r,32))&&nonzero(target,32)&&blob(&r,8)&&r.at==r.n;
}
static int valid_state(const build8_observation_state_v2 *v,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash){
    if(v->total>v->sequence||v->pending_length>544)return 0;
    if(!v->sequence){if(v->total||nonzero(v->chain,32)||nonzero(v->last_result,32)||nonzero(v->last_coordinator,32)||nonzero(v->last_previous,32))return 0;}
    else {
        if(!v->total||!nonzero(v->chain,32))return 0;
        int cache=nonzero(v->last_result,32)||nonzero(v->last_coordinator,32)||nonzero(v->last_previous,32);
        if(cache&&(!nonzero(v->last_result,32)||!nonzero(v->last_coordinator,32)
            ||(v->sequence==1&&nonzero(v->last_previous,32))
            ||(v->sequence>1&&!nonzero(v->last_previous,32))))return 0;
        if(!cache&&v->total!=v->sequence)return 0;
    }
    if(!v->pending_length)return !nonzero(v->pending_id,32)&&!nonzero(v->pending_coordinator,32);
    uint8_t id[32];return v->sequence!=UINT64_MAX&&nonzero(v->pending_coordinator,32)
        &&work_valid(v->pending,v->pending_length,scope)
        &&hash("MUTINY-BUILD8-OBSERVATION-RESULT-V1",v->pending,v->pending_length,id)
        &&!memcmp(id,v->pending_id,32)&&nonzero(id,32);
}
static size_t encode(const build8_observation_scope_v2 *scope,const build8_observation_state_v2 *v,build8_v2_domain_hash hash,uint8_t raw[919]){
    if(!valid_state(v,scope,hash))return 0;
    static const uint8_t prefix[5]={3,0x4d,0x55,0x54,1};memcpy(raw,prefix,5);memcpy(raw+5,scope,128);
    write64(raw+133,v->sequence);write64(raw+141,v->total);
    const uint8_t *fields[]={v->chain,v->last_result,v->last_coordinator,v->last_previous,v->pending_coordinator,v->pending_id};
    for(size_t i=0;i<6;i++)memcpy(raw+149+32*i,fields[i],32);
    raw[341]=(uint8_t)(v->pending_length>>8);raw[342]=(uint8_t)v->pending_length;
    memcpy(raw+343,v->pending,v->pending_length);size_t n=343+v->pending_length;
    if(!hash("MUTINY-BUILD8-WORKER-OBSERVATION-STATE-V3",raw,n,raw+n))return 0;
    return n+32;
}
static int load(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash,build8_observation_state_v2 *v){
    uint8_t raw[919],digest[32];size_t n=0;memset(v,0,sizeof *v);
    if(s->read(s->context,raw,sizeof raw,&n)!=1||n>sizeof raw)return 0;
    if(n==73&&raw[0]==4){
        uint8_t input[169];memcpy(input,scope,128);memcpy(input+128,raw,41);
        if(!hash("MUTINY-BUILD8-WORKER-OBSERVATION-COMPACT-V4",input,sizeof input,digest)||memcmp(digest,raw+41,32))return 0;
        v->sequence=v->total=read64(raw+1);memcpy(v->chain,raw+9,32);
        if(valid_state(v,scope,hash))return 1;
        memset(v,0,sizeof *v);return 0;
    }
    if(n<375)return 0;
    static const uint8_t prefix[5]={3,0x4d,0x55,0x54,1};
    size_t length=((size_t)raw[341]<<8)|raw[342];
    if(memcmp(raw,prefix,5)||memcmp(raw+5,scope,128)||length>544||n!=375+length
        ||!hash("MUTINY-BUILD8-WORKER-OBSERVATION-STATE-V3",raw,n-32,digest)||memcmp(digest,raw+n-32,32))return 0;
    v->sequence=read64(raw+133);v->total=read64(raw+141);
    uint8_t *fields[]={v->chain,v->last_result,v->last_coordinator,v->last_previous,v->pending_coordinator,v->pending_id};
    for(size_t i=0;i<6;i++)memcpy(fields[i],raw+149+32*i,32);
    v->pending_length=(uint16_t)length;memcpy(v->pending,raw+343,length);
    if(valid_state(v,scope,hash))return 1;
    memset(v,0,sizeof *v);return 0;
}
static int persist(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash,const build8_observation_state_v2 *v){
    uint8_t raw[919],check[919];size_t n=encode(scope,v,hash,raw),got=0;
    return n&&s->write&&s->write(s->context,raw,n)==1
        &&s->read(s->context,check,sizeof check,&got)==1&&got==n&&!memcmp(raw,check,n);
}
int build8_observation_store_v2_initialize(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash){
    if(!inputs(s,scope,hash)||!s->write)return 0;
    uint8_t existing[919];size_t n=0;if(s->read(s->context,existing,sizeof existing,&n)!=0)return 0;
    build8_observation_state_v2 empty={0};return persist(s,scope,hash,&empty);
}
int build8_observation_store_v2_restore(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash,build8_observation_state_v2 *out){
    if(!inputs(s,scope,hash)||!out||!separate(s,sizeof *s,out,sizeof *out)||!separate(scope,sizeof *scope,out,sizeof *out))return 0;
    return load(s,scope,hash,out);
}
int build8_observation_store_v2_compact(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash,uint8_t out[73]){
    if(!inputs(s,scope,hash)||!out||!separate(s,sizeof *s,out,73)||!separate(scope,sizeof *scope,out,73))return 0;
    build8_observation_state_v2 v;if(!load(s,scope,hash,&v)||v.pending_length||v.sequence!=v.total)return 0;
    uint8_t raw[73],input[169];raw[0]=4;write64(raw+1,v.sequence);memcpy(raw+9,v.chain,32);
    memcpy(input,scope,128);memcpy(input+128,raw,41);
    if(!hash("MUTINY-BUILD8-WORKER-OBSERVATION-COMPACT-V4",input,sizeof input,raw+41))return 0;
    memcpy(out,raw,sizeof raw);return 1;
}
int build8_observation_store_v2_queue(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,const uint8_t *raw,size_t n,const uint8_t coordinator[32],build8_v2_domain_hash hash){
    if(!inputs(s,scope,hash)||!s->write||!raw||!coordinator||!n||n>544||!nonzero(coordinator,32)
        ||!separate(s,sizeof *s,raw,n)||!separate(scope,sizeof *scope,raw,n)
        ||!separate(s,sizeof *s,coordinator,32)||!separate(scope,sizeof *scope,coordinator,32)||!separate(raw,n,coordinator,32))return 0;
    build8_observation_state_v2 v;uint8_t id[32];
    if(!load(s,scope,hash,&v)||!work_valid(raw,n,scope)||!hash("MUTINY-BUILD8-OBSERVATION-RESULT-V1",raw,n,id))return 0;
    if(v.pending_length)return n==v.pending_length&&!memcmp(raw,v.pending,n)&&!memcmp(coordinator,v.pending_coordinator,32);
    if(!memcmp(id,v.last_result,32))return !memcmp(coordinator,v.last_coordinator,32);
    if(v.sequence==UINT64_MAX)return 0;
    v.pending_length=(uint16_t)n;memcpy(v.pending,raw,n);memcpy(v.pending_id,id,32);memcpy(v.pending_coordinator,coordinator,32);
    return persist(s,scope,hash,&v);
}
int build8_observation_store_v2_submission(const build8_observation_state_v2 *v,uint8_t *raw,size_t capacity,size_t *written){
    if(!v||!raw||!written||!separate(v,sizeof *v,raw,capacity)||!separate(v,sizeof *v,written,sizeof *written)||!separate(raw,capacity,written,sizeof *written))return 0;
    *written=0;if(!v->pending_length||v->pending_length>544||v->sequence==UINT64_MAX||capacity<41u+v->pending_length)return 0;
    raw[0]=2;write64(raw+1,v->sequence+1);memcpy(raw+9,v->chain,32);memcpy(raw+41,v->pending,v->pending_length);
    *written=41u+v->pending_length;return 1;
}
int build8_observation_store_v2_receipt(const build8_observation_store_v2 *s,const build8_observation_scope_v2 *scope,const uint8_t *raw,size_t n,const uint8_t *desc,size_t dn,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *ws,size_t wn){
    if(!inputs(s,scope,h256)||!s->write||!raw||!desc||!ws||!h512||n!=1672||!dn||dn>2048||wn<4127||wn>65536)return 0;
    const void *parts[]={s,scope,raw,desc,ws};size_t sizes[]={sizeof *s,sizeof *scope,n,dn,wn};
    for(size_t i=0;i<5;i++)for(size_t j=0;j<i;j++)if(!separate(parts[i],sizes[i],parts[j],sizes[j]))return 0;
    build8_observation_state_v2 v;if(!load(s,scope,h256,&v))return 0;
    build8_observation_v2_context c={0};memcpy(c.genesis,scope->genesis,32);memcpy(c.fingerprint,scope->fingerprint,32);
    memcpy(c.license,scope->license,32);memcpy(c.worker,scope->worker,32);
    if(v.pending_length){
        if(v.sequence==UINT64_MAX||v.total==UINT64_MAX)return 0;
        c.sequence=v.sequence+1;c.prior_total=v.total;memcpy(c.previous,v.chain,32);
        memcpy(c.result,v.pending_id,32);memcpy(c.coordinator,v.pending_coordinator,32);
    }else{
        if(!v.sequence||!v.total||!nonzero(v.last_result,32))return 0;
        c.sequence=v.sequence;c.prior_total=v.total-1;memcpy(c.previous,v.last_previous,32);
        memcpy(c.result,v.last_result,32);memcpy(c.coordinator,v.last_coordinator,32);
    }
    if(!build8_observation_v2_verify(raw,n,&c,desc,dn,h256,h512,ws,wn))return 0;
    if(!v.pending_length)return !memcmp(v.chain,raw+246,32);
    v.sequence++;v.total++;memcpy(v.last_previous,v.chain,32);memcpy(v.chain,raw+246,32);
    memcpy(v.last_result,v.pending_id,32);memcpy(v.last_coordinator,v.pending_coordinator,32);
    memset(v.pending,0,sizeof v.pending);memset(v.pending_id,0,32);memset(v.pending_coordinator,0,32);v.pending_length=0;
    return persist(s,scope,h256,&v);
}
