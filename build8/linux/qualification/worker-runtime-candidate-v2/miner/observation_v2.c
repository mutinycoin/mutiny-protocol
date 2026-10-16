#include "observation_v2.h"
#include "fndsa.h"
#include <string.h>
extern int build8_qual_ed448_verify(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
extern int build8_qual_ed448_public_valid(const uint8_t *,size_t);
typedef struct {const uint8_t *p;size_t n,at;} reader;
static int num(reader *r,unsigned major,uint64_t *v){
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;if((b>>5)!=major||a>27)return 0;
    if(a<24){*v=a;return 1;}unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
    uint64_t n=0;for(unsigned i=0;i<count;i++)n=(n<<8)|r->p[r->at++];
    if(n<24||(count>1&&n<((uint64_t)1<<(8*(count/2)))))return 0;
    *v=n;return 1;
}
static int exact(reader *r,unsigned major,uint64_t expected){uint64_t n;return num(r,major,&n)&&n==expected;}
static const uint8_t *fixed(reader *r,size_t wanted){uint64_t n;
    if(!num(r,2,&n)||n!=wanted||n>r->n-r->at)return NULL;
    const uint8_t *p=r->p+r->at;r->at+=(size_t)n;return p;}
static int string(reader *r,const char *s){uint64_t n;size_t length=strlen(s);
    if(!num(r,3,&n)||n!=length||n>r->n-r->at||memcmp(r->p+r->at,s,length))return 0;
    r->at+=length;return 1;}
static int nz(const uint8_t *p,size_t n){unsigned x=0;for(size_t i=0;i<n;i++)x|=p[i];return x!=0;}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(56-8*i));}
static int apart(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 0;
    return x+an<=y||y+bn<=x;}
int build8_observation_v2_verify(const uint8_t *raw,size_t n,const build8_observation_v2_context *c,
    const uint8_t *desc,size_t dn,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *ws,size_t wn){
    if(!raw||!c||!desc||!h256||!h512||!ws||n!=1672||dn>2048||wn<4127||wn>65536)return 0;
    if(!apart(raw,n,c,sizeof *c)||!apart(raw,n,desc,dn)||!apart(raw,n,ws,wn)
        ||!apart(c,sizeof *c,desc,dn)||!apart(c,sizeof *c,ws,wn)||!apart(desc,dn,ws,wn))return 0;
    if(!c->sequence||c->prior_total>=c->sequence||c->prior_total==UINT64_MAX
        ||((c->sequence==1)==nz(c->previous,32))||!nz(c->genesis,32)||!nz(c->fingerprint,32)
        ||!nz(c->license,32)||!nz(c->worker,32)||!nz(c->coordinator,32)||!nz(c->result,32))return 0;
    uint8_t body[278]={3,0x4d,0x55,0x54,0x01},chain[81],digest[64];
    memcpy(body+5,c->genesis,32);memcpy(body+37,c->fingerprint,32);memcpy(body+69,c->license,32);
    memcpy(body+101,c->worker,32);memcpy(body+133,c->result,32);memcpy(body+165,c->coordinator,32);
    put64(body+197,c->sequence);memcpy(body+205,c->previous,32);body[237]=1;put64(body+238,c->prior_total+1);
    put64(chain,c->sequence);memcpy(chain+8,c->previous,32);memcpy(chain+40,c->result,32);chain[72]=1;put64(chain+73,c->prior_total+1);
    if(!h256("MUTINY-BUILD8-OBSERVATION-CHAIN-V1",chain,sizeof chain,body+246)||memcmp(raw,body,sizeof body))return 0;
    reader r={desc,dn,0};uint64_t generation;const uint8_t *ed,*fn;
    if(!exact(&r,4,8)||!exact(&r,0,1)||!exact(&r,0,0x4d555401)||!exact(&r,0,6)
        ||!num(&r,0,&generation)||!generation
        ||!string(&r,"MUTINY-NODE-HYBRID-ED448-FNDSA1024-V1")
        ||!string(&r,"MUTINY-FNDSA1024-PORNIN-20260722-V1")
        ||!(ed=fixed(&r,57))||!(fn=fixed(&r,1793))||r.at!=r.n||fn[0]!=0x0a
        ||!build8_qual_ed448_public_valid(ed,57))return 0;
    uint32_t acc=0;unsigned bits=0;size_t at=1;
    for(unsigned i=0;i<1024;i++){while(bits<14){acc|=(uint32_t)fn[at++]<<bits;bits+=8;}
        if((acc&16383u)>=12289u)return 0;
        acc>>=14;bits-=14;}
    if(at!=1793||bits||!h256("MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2",desc,dn,digest)
        ||memcmp(digest,c->coordinator,32)||raw[392]!=0x3a)return 0;
    if(!h512("MUTINY-BUILD8-NODE-OBSERVATION-RECEIPT-V3",body,sizeof body,digest)
        ||!build8_qual_ed448_verify(ed,57,raw+278,114,digest,64))return 0;
    return fndsa_verify_temp(raw+392,1280,fn,1793,NULL,0,FNDSA_HASH_ID_RAW,digest,64,ws,wn)==1;
}
