#include "work_v2.h"
#include "fndsa.h"
#include <string.h>
extern int build8_qual_ed448_verify(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
extern int build8_qual_ed448_public_valid(const uint8_t *,size_t);
typedef struct{const uint8_t *p;size_t n,at;} reader;
static int num(reader *r,unsigned major,uint64_t *out){
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;
    if((b>>5)!=major||a>27)return 0;
    if(a<24){*out=a;return 1;}
    unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
    uint64_t v=0;for(unsigned i=0;i<count;i++)v=(v<<8)|r->p[r->at++];
    if(v<24||(count>1&&v<((uint64_t)1<<(8*(count/2)))))return 0;
    *out=v;return 1;
}
static int exact(reader *r,unsigned major,uint64_t value){uint64_t v;return num(r,major,&v)&&v==value;}
static const uint8_t *blob(reader *r,size_t *length){uint64_t n;
    if(!num(r,2,&n)||n>r->n-r->at)return NULL;
    const uint8_t *p=r->p+r->at;r->at+=(size_t)n;*length=(size_t)n;return p;}
static const uint8_t *fixed(reader *r,size_t length){size_t n;const uint8_t *p=blob(r,&n);return p&&n==length?p:NULL;}
static int copy(reader *r,uint8_t *out,size_t n){const uint8_t *p=fixed(r,n);if(!p)return 0;memcpy(out,p,n);return 1;}
static int nonce(reader *r,uint64_t *out){const uint8_t *p=fixed(r,8);if(!p)return 0;*out=0;for(unsigned i=0;i<8;i++)*out=(*out<<8)|p[i];return 1;}
static int string(reader *r,const char *want){uint64_t n;size_t length=strlen(want);
    if(!num(r,3,&n)||n!=length||n>r->n-r->at||memcmp(r->p+r->at,want,length))return 0;
    r->at+=length;return 1;}
static int disjoint(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 0;
    return x+an<=y||y+bn<=x;}
static int fn_public(const uint8_t *p){
    if(p[0]!=0x0a)return 0;
    uint32_t acc=0;unsigned bits=0;size_t at=1;
    for(unsigned i=0;i<1024;i++){while(bits<14){acc|=(uint32_t)p[at++]<<bits;bits+=8;}
        if((acc&16383u)>=12289u)return 0;
        acc>>=14;bits-=14;}return at==1793&&bits==0;
}
int build8_decode_authorized_work_v2(const uint8_t *wire,size_t n,const build8_work_context *ctx,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,build8_authorized_work *out){
    if(!wire||!ctx||!out||!workspace||!h256||!h512||n>8192||wn<4127||wn>65536)return 0;
    if(!disjoint(wire,n,out,sizeof *out)||!disjoint(wire,n,workspace,wn)||!disjoint(wire,n,ctx,sizeof *ctx)
        ||!disjoint(ctx,sizeof *ctx,out,sizeof *out)||!disjoint(ctx,sizeof *ctx,workspace,wn)||!disjoint(out,sizeof *out,workspace,wn))return 0;
    memset(out,0,sizeof *out);
    reader e={wire,n,0};size_t un,dn,workn;const uint8_t *unsigned_bytes,*ed_sig,*fn_sig;
    if(!exact(&e,4,4)||!exact(&e,0,2)||!(unsigned_bytes=blob(&e,&un))||un>4096
        ||!(ed_sig=fixed(&e,114))||!(fn_sig=fixed(&e,1280))||fn_sig[0]!=0x3a||e.at!=e.n)return 0;
    reader u={unsigned_bytes,un,0};const uint8_t *work,*desc;
    if(!exact(&u,4,3)||!exact(&u,0,2)||!(work=blob(&u,&workn))||workn>1024
        ||!(desc=blob(&u,&dn))||dn>2048||u.at!=u.n)return 0;
    reader d={desc,dn,0};uint64_t generation;const uint8_t *ed,*fn;
    if(!exact(&d,4,8)||!exact(&d,0,1)||!exact(&d,0,0x4d555401)||!exact(&d,0,6)
        ||!num(&d,0,&generation)||!generation||!string(&d,"MUTINY-NODE-HYBRID-ED448-FNDSA1024-V1")
        ||!string(&d,"MUTINY-FNDSA1024-PORNIN-20260722-V1")||!(ed=fixed(&d,57))||!(fn=fixed(&d,1793))
        ||d.at!=d.n||!fn_public(fn)||!build8_qual_ed448_public_valid(ed,57))return 0;
    uint8_t digest[64];if(!h256("MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2",desc,dn,digest)||memcmp(digest,ctx->coordinator,32))return 0;
    reader r={work,workn,0};build8_authorized_work a={0};
    if(!exact(&r,4,18)||!exact(&r,0,1)||!exact(&r,0,0x4d555401))return 0;
    a.network=0x4d555401;
    if(!copy(&r,a.genesis,32)||!copy(&r,a.fingerprint,32)||!copy(&r,a.parent,32)||!num(&r,0,&a.height)||!num(&r,0,&a.timestamp)
        ||!copy(&r,a.body,32)||!copy(&r,a.state,32)||!copy(&r,a.license,32)||!copy(&r,a.worker,32)
        ||!num(&r,0,&a.assignment)||!num(&r,0,&a.ticket)||!copy(&r,a.coordinator,32)||!copy(&r,a.target,32)
        ||!nonce(&r,&a.nonce_start)||!nonce(&r,&a.nonce_end)||!num(&r,0,&a.epoch)||r.at!=r.n)return 0;
    if(memcmp(a.genesis,ctx->genesis,32)||memcmp(a.fingerprint,ctx->fingerprint,32)||memcmp(a.parent,ctx->parent,32)
        ||memcmp(a.license,ctx->license,32)||memcmp(a.worker,ctx->worker,32)||memcmp(a.coordinator,ctx->coordinator,32)
        ||memcmp(a.target,ctx->target,32)||a.height!=ctx->height||!a.height||a.assignment!=ctx->assignment
        ||a.ticket<=ctx->last_ticket||a.nonce_start>a.nonce_end||a.timestamp<ctx->genesis_timestamp
        ||a.epoch!=(a.timestamp-ctx->genesis_timestamp)/60)return 0;
    unsigned nonzero=0;for(unsigned i=0;i<32;i++)nonzero|=a.target[i];if(!nonzero)return 0;
    if(!h512("MUTINY-BUILD8-NODE-WORK-AUTHORIZATION-V2",unsigned_bytes,un,digest)
        ||!build8_qual_ed448_verify(ed,57,ed_sig,114,digest,64)
        ||!fndsa_verify_temp(fn_sig,1280,fn,1793,NULL,0,FNDSA_HASH_ID_RAW,digest,64,workspace,wn)
        ||!h256("MUTINY-BUILD8-HYBRID-WORK-AUTHORITY-ID-V2",unsigned_bytes,un,a.authority))return 0;
    *out=a;return 1;
}
