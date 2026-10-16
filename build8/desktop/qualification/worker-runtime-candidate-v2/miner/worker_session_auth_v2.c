#include "worker_session_auth_v2.h"
#include "fndsa.h"
#include <string.h>
extern int build8_qual_ed448_verify(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
extern int build8_qual_ed448_public_valid(const uint8_t *,size_t);
typedef struct {const uint8_t *p;size_t n,at;} reader;
static int num(reader *r,unsigned major,uint64_t *v) {
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;if((b>>5)!=major||a>27)return 0;
    if(a<24){*v=a;return 1;}
    unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
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
static int nonzero(const uint8_t *p,size_t n){unsigned x=0;for(size_t i=0;i<n;i++)x|=p[i];return x!=0;}
static int node(const uint8_t *p,size_t n,const uint8_t pinned[32],build8_v2_domain_hash h256,
    const uint8_t **ed,const uint8_t **fn) {
    if(!p||n>2048||!h256)return 0;
    reader r={p,n,0};uint64_t generation;uint8_t id[32];
    if(!exact(&r,4,8)||!exact(&r,0,1)||!exact(&r,0,0x4d555401)||!exact(&r,0,6)
        ||!num(&r,0,&generation)||!generation
        ||!string(&r,"MUTINY-NODE-HYBRID-ED448-FNDSA1024-V1")
        ||!string(&r,"MUTINY-FNDSA1024-PORNIN-20260722-V1")
        ||!(*ed=fixed(&r,57))||!(*fn=fixed(&r,1793))||r.at!=r.n
        ||(*fn)[0]!=0x0a||!build8_qual_ed448_public_valid(*ed,57))return 0;
    /* Exact pinned profile public encoding: 1024 little-endian 14-bit residues. */
    uint32_t acc=0;unsigned bits=0;size_t at=1;
    for(unsigned i=0;i<1024;i++){
        while(bits<14){acc|=(uint32_t)(*fn)[at++]<<bits;bits+=8;}
        if((acc&16383u)>=12289u)return 0;
        acc>>=14;bits-=14;
    }
    return at==1793&&bits==0&&h256("MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2",p,n,id)&&!memcmp(id,pinned,32);
}
int build8_worker_session_context_v2(const build8_enrollment_v2_context *c,const uint8_t worker[57],
    const uint8_t *descriptor,size_t dn,build8_v2_domain_hash h256,build8_v2_domain_hash h512,uint8_t out[64]) {
    if(!out)return 0;
    memset(out,0,64);
    if(!c||!worker||!h256||!h512||!nonzero(c->genesis,32)||!nonzero(c->fingerprint,32))return 0;
    const uint8_t *ed,*fn;if(!node(descriptor,dn,c->coordinator,h256,&ed,&fn))return 0;
    uint8_t raw[2570];size_t un=0;
    raw[0]=2;raw[1]=1;raw[2]=0x4d;raw[3]=0x55;raw[4]=0x54;raw[5]=1;
    if(!build8_enrollment_v2_unsigned(c,worker,h256,raw+8,512,&un))return 0;
    raw[6]=(uint8_t)(un>>8);raw[7]=(uint8_t)un;
    raw[8+un]=(uint8_t)(dn>>8);raw[9+un]=(uint8_t)dn;memcpy(raw+10+un,descriptor,dn);
    if(!h512("MUTINY-BUILD8-WORKER-SESSION-CONTEXT-V2",raw,10+un+dn,out)){memset(out,0,64);return 0;}
    return 1;
}
int build8_worker_session_verify_node_v2(const build8_enrollment_v2_context *c,const uint8_t worker[57],
    const uint8_t *descriptor,size_t dn,const uint8_t *hello,size_t hn,const uint8_t *response,size_t rn,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t out[64]) {
    if(!out)return 0;
    memset(out,0,64);
    if(!c||!hello||!response||hn!=BUILD8_WORKER_HELLO_V2_LENGTH||rn!=BUILD8_WORKER_RESPONSE_V2_LENGTH
        ||!workspace||wn<4127||wn>65536||!h256||!h512)return 0;
    uint8_t context[64],raw[3378],transcript[64],intent[64];const uint8_t *ed,*fn;
    if(!build8_worker_session_context_v2(c,worker,descriptor,dn,h256,h512,context)
        ||!node(descriptor,dn,c->coordinator,h256,&ed,&fn)||hello[0]!=2||hello[1]!=1
        ||memcmp(hello+2,context,64)||!nonzero(hello+66,32)||!nonzero(hello+98,56)
        ||!nonzero(response,32)||!nonzero(response+32,56)||!memcmp(hello+66,response,32))return 0;
    memcpy(raw,hello,1722);memcpy(raw+1722,response,1656);
    if(response[1770]!=0x3a||!h512("MUTINY-BUILD8-WORKER-SESSION-TRANSCRIPT-V2",raw,sizeof raw,transcript)
        ||!h512("MUTINY-BUILD8-NODE-WORKER-SESSION-V2",transcript,64,intent)
        ||!build8_qual_ed448_verify(ed,57,response+1656,114,intent,64)
        ||!fndsa_verify_temp(response+1770,1280,fn,1793,NULL,0,FNDSA_HASH_ID_RAW,intent,64,workspace,wn))return 0;
    memcpy(out,transcript,64);return 1;
}
