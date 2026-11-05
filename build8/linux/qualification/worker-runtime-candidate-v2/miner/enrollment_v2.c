/* Allocation-free canonical V2 parser. Qualification candidate, not yet linked
 * into an activated miner image. Existing V1 authority is never accepted here. */
#include "enrollment_v2.h"
#include "fndsa.h"
#include <string.h>
extern int build8_qual_ed448_verify(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
extern int build8_qual_ed448_public_valid(const uint8_t *,size_t);
typedef struct {const uint8_t *p;size_t n,at;} reader;
typedef struct {uint8_t *p;size_t n,at;int ok;} writer;
static void put(writer *w,uint8_t value) {if(w->at>=w->n){w->ok=0;return;}w->p[w->at++]=value;}
static void integer(writer *w,unsigned major,uint64_t value) {
    if(value<24){put(w,(uint8_t)((major<<5)|value));return;}
    unsigned n=value<=255?1:value<=65535?2:value<=UINT32_MAX?4:8;
    put(w,(uint8_t)((major<<5)|(n==1?24:n==2?25:n==4?26:27)));
    for(unsigned i=n;i;i--)put(w,(uint8_t)(value>>(8*(i-1))));
}
static void data(writer *w,unsigned major,const uint8_t *p,size_t n) {
    integer(w,major,n);for(size_t i=0;i<n;i++)put(w,p[i]);
}
int build8_enrollment_v2_worker_id(const build8_enrollment_v2_context *c,const uint8_t worker[57],
    build8_v2_domain_hash hash256,uint8_t out[32]) {
    if(!c||!worker||!hash256||!out)return 0;
    uintptr_t o=(uintptr_t)out,a=(uintptr_t)c,b=(uintptr_t)worker;
    if(32>UINTPTR_MAX-o||sizeof *c>UINTPTR_MAX-a||57>UINTPTR_MAX-b
        ||!(o+32<=a||a+sizeof *c<=o)||!(o+32<=b||b+57<=o))return 0;
    memset(out,0,32);
    if(!build8_qual_ed448_public_valid(worker,57))return 0;
    static const uint8_t suite[]="MUTINY-WORKER-ED448-V1";
    uint8_t raw[256],id[32];writer i={raw,sizeof raw,0,1};
    integer(&i,4,6);integer(&i,0,2);integer(&i,0,0x4d555401);
    data(&i,2,c->genesis,32);data(&i,2,c->license,32);data(&i,3,suite,sizeof suite-1);data(&i,2,worker,57);
    if(!i.ok||!hash256("MUTINY-BUILD8-WORKER-ID-V2",raw,i.at,id))return 0;
    memcpy(out,id,32);return 1;
}
int build8_enrollment_v2_unsigned(const build8_enrollment_v2_context *c,const uint8_t worker[57],
    build8_v2_domain_hash hash256,uint8_t *out,size_t capacity,size_t *length) {
    if(!c||!worker||!hash256||!out||!length||!c->owner_generation||!c->configuration_generation||!c->assignment_generation)return 0;
    static const uint8_t suite[]="MUTINY-WORKER-ED448-V1";
    uint8_t id[32];if(!build8_enrollment_v2_worker_id(c,worker,hash256,id))return 0;
    writer w={out,capacity,0,1};integer(&w,4,16);integer(&w,0,2);integer(&w,0,0x4d555401);
    data(&w,2,c->genesis,32);data(&w,2,c->fingerprint,32);data(&w,2,c->license,32);data(&w,2,c->owner_descriptor,32);
    integer(&w,0,c->owner_generation);data(&w,3,suite,sizeof suite-1);data(&w,2,worker,57);data(&w,2,id,32);
    data(&w,2,c->coordinator,32);integer(&w,0,c->configuration_generation);data(&w,2,c->device_mac,6);
    integer(&w,0,c->assignment_generation);integer(&w,0,c->effective_epoch);integer(&w,0,c->valid_until_height);
    if(!w.ok||w.at>512)return 0;
    *length=w.at;return 1;
}
static int num(reader *r,unsigned major,uint64_t *out) {
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;if((b>>5)!=major || a>27)return 0;
    if(a<24){*out=a;return 1;}
    unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
    uint64_t v=0;for(unsigned i=0;i<count;i++)v=(v<<8)|r->p[r->at++];
    if(v<24 || (count>1&&v<((uint64_t)1<<(8*(count/2)))))return 0;
    *out=v;return 1;
}
static int exact(reader *r,unsigned major,uint64_t want) {uint64_t v;return num(r,major,&v)&&v==want;}
static const uint8_t *blob(reader *r,size_t wanted) {
    uint64_t n;if(!num(r,2,&n)||n!=wanted||n>r->n-r->at)return NULL;
    const uint8_t *p=r->p+r->at;r->at+=(size_t)n;return p;
}
static int string(reader *r,const char *want) {
    uint64_t n;size_t length=strlen(want);
    if(!num(r,3,&n)||n!=length||n>r->n-r->at||memcmp(r->p+r->at,want,length))return 0;
    r->at+=length;return 1;
}
typedef struct {
    const uint8_t *worker,*owner_ed,*owner_fn,*gid,*fingerprint,*license,*owner_id,*coordinator,*mac;
    uint64_t owner_generation,configuration,assignment,epoch,until;
} authority;
static int validate_context(const uint8_t *unsigned_bytes,size_t expected_length,const uint8_t *owner,size_t owner_length,
    int genesis,build8_v2_domain_hash hash256,authority *out) {
    if(!unsigned_bytes||!owner||!hash256||!out||expected_length>512||owner_length>2048||(genesis!=0&&genesis!=1))return 0;
    reader b={unsigned_bytes,expected_length,0};
    const uint8_t *gid,*fingerprint,*license,*owner_id,*worker,*worker_id,*coordinator,*mac;uint64_t owner_gen,config,assignment,epoch,until;
    if(!exact(&b,4,16)||!exact(&b,0,2)||!exact(&b,0,0x4d555401)
        ||!(gid=blob(&b,32))||!(fingerprint=blob(&b,32))||!(license=blob(&b,32))||!(owner_id=blob(&b,32))
        ||!num(&b,0,&owner_gen)||!owner_gen)return 0;
    size_t suite_start=b.at;
    if(!string(&b,"MUTINY-WORKER-ED448-V1")||!(worker=blob(&b,57)))return 0;
    size_t suite_key_length=b.at-suite_start;
    if(!(worker_id=blob(&b,32))||!(coordinator=blob(&b,32))||!num(&b,0,&config)||!config
        ||!(mac=blob(&b,6))||!num(&b,0,&assignment)||!assignment||!num(&b,0,&epoch)||!num(&b,0,&until)||b.at!=b.n)return 0;
    if(genesis&&(config!=1||assignment!=1||epoch||until))return 0;
    if(!build8_qual_ed448_public_valid(worker,57))return 0;
    reader d={owner,owner_length,0};uint64_t generation;const uint8_t *owner_ed,*owner_fn;
    if(!exact(&d,4,9)||!exact(&d,0,1)||!exact(&d,0,0x4d555401)||!exact(&d,0,1)
        ||!num(&d,0,&generation)||generation!=owner_gen
        ||!exact(&d,0,1)||!exact(&d,0,1) /* numeric wallet suite 1, BOTH_REQUIRED policy 1 */
        ||!string(&d,"MUTINY-FNDSA1024-PORNIN-20260722-V1")
        ||!(owner_ed=blob(&d,57))||!(owner_fn=blob(&d,1793))||d.at!=d.n||owner_fn[0]!=0x0a)return 0;
    uint8_t digest[64],identity[256];size_t used=0;
    if(!hash256("MUTINY-BUILD8-OWNER-AUTH-DESCRIPTOR-V2",owner,owner_length,digest)||memcmp(digest,owner_id,32))return 0;
    const uint8_t prefix[]={0x86,2,0x1a,0x4d,0x55,0x54,1};
    memcpy(identity,prefix,sizeof prefix);used=sizeof prefix;
    identity[used++]=0x58;identity[used++]=32;memcpy(identity+used,gid,32);used+=32;
    identity[used++]=0x58;identity[used++]=32;memcpy(identity+used,license,32);used+=32;
    if(suite_key_length>sizeof identity-used)return 0;
    memcpy(identity+used,unsigned_bytes+suite_start,suite_key_length);used+=suite_key_length;
    if(!hash256("MUTINY-BUILD8-WORKER-ID-V2",identity,used,digest)||memcmp(digest,worker_id,32))return 0;
    out->worker=worker;out->owner_ed=owner_ed;out->owner_fn=owner_fn;out->epoch=epoch;out->until=until;
    out->gid=gid;out->fingerprint=fingerprint;out->license=license;out->owner_id=owner_id;out->coordinator=coordinator;out->mac=mac;
    out->owner_generation=owner_gen;out->configuration=config;out->assignment=assignment;return 1;
}
static int candidate_valid(const uint8_t *raw,size_t n,const uint8_t *owner,size_t on,
    const uint8_t public_key[57],const uint8_t proof[114],build8_v2_domain_hash h256,build8_v2_domain_hash h512,int genesis) {
    authority a;uint8_t intent[64];
    if(!public_key||!proof||!h512||!validate_context(raw,n,owner,on,genesis,h256,&a)
        ||(!genesis&&(!a.epoch||!a.until))
        ||memcmp(public_key,a.worker,57)||!h512("MUTINY-BUILD8-WORKER-POSSESSION-V2",raw,n,intent))return 0;
    return build8_qual_ed448_verify(a.worker,57,proof,114,intent,64);
}
int build8_enrollment_v2_candidate_valid(const uint8_t *raw,size_t n,const uint8_t *owner,size_t on,
    const uint8_t public_key[57],const uint8_t proof[114],build8_v2_domain_hash h256,build8_v2_domain_hash h512) {
    return candidate_valid(raw,n,owner,on,public_key,proof,h256,h512,1);
}
int build8_enrollment_v2_assignment_candidate_valid(const uint8_t *raw,size_t n,const uint8_t *owner,size_t on,
    const uint8_t public_key[57],const uint8_t proof[114],build8_v2_domain_hash h256,build8_v2_domain_hash h512) {
    return candidate_valid(raw,n,owner,on,public_key,proof,h256,h512,0);
}
int build8_enrollment_v2_verify(const uint8_t *encoded,size_t length,
    const uint8_t *expected,size_t expected_length,const uint8_t *owner,size_t owner_length,
    int genesis,build8_v2_domain_hash hash256,build8_v2_domain_hash hash512,void *workspace,size_t wn) {
    if(!encoded||!expected||!owner||!hash256||!hash512||!workspace||wn<4127
        ||length>2048||expected_length>512||owner_length>2048||(genesis!=0&&genesis!=1))return 0;
    reader e={encoded,length,0};uint64_t unsigned_length;
    if(!exact(&e,4,4)||!num(&e,2,&unsigned_length)||unsigned_length!=expected_length||unsigned_length>e.n-e.at)return 0;
    const uint8_t *unsigned_bytes=e.p+e.at;e.at+=(size_t)unsigned_length;
    if(memcmp(unsigned_bytes,expected,expected_length))return 0;
    const uint8_t *oe,*of,*ws;
    if(!(oe=blob(&e,114))||!(of=blob(&e,1280))||!(ws=blob(&e,114))||e.at!=e.n||of[0]!=0x3a)return 0;
    authority a;uint8_t digest[64];
    if(!validate_context(unsigned_bytes,expected_length,owner,owner_length,genesis,hash256,&a))return 0;
    if(!hash512("MUTINY-BUILD8-MINER-ENROLLMENT-OWNER-V2",unsigned_bytes,expected_length,digest)
        ||!build8_qual_ed448_verify(a.owner_ed,57,oe,114,digest,64)
        ||!fndsa_verify_temp(of,1280,a.owner_fn,1793,NULL,0,FNDSA_HASH_ID_RAW,digest,64,workspace,wn))return 0;
    if(!hash512("MUTINY-BUILD8-WORKER-POSSESSION-V2",unsigned_bytes,expected_length,digest)
        ||!build8_qual_ed448_verify(a.worker,57,ws,114,digest,64))return 0;
    return 1;
}
/* Explicit ordinary API only: generic verifier's genesis=0 behavior remains
 * unchanged because it also serves structural validation shared by callers. */
int build8_enrollment_v2_assignment_context_valid(const uint8_t *expected,size_t expected_length,
    const uint8_t *owner,size_t owner_length,build8_v2_domain_hash hash256) {
    authority a;
    return validate_context(expected,expected_length,owner,owner_length,0,hash256,&a)&&a.epoch&&a.until;
}
int build8_enrollment_v2_assignment_verify(const uint8_t *encoded,size_t length,
    const uint8_t *expected,size_t expected_length,const uint8_t *owner,size_t owner_length,
    build8_v2_domain_hash hash256,build8_v2_domain_hash hash512,void *workspace,size_t wn) {
    if(!build8_enrollment_v2_assignment_context_valid(expected,expected_length,owner,owner_length,hash256))return 0;
    return build8_enrollment_v2_verify(encoded,length,expected,expected_length,owner,owner_length,
        0,hash256,hash512,workspace,wn);
}
int build8_enrollment_v2_assignment_decode(const uint8_t *raw,size_t n,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_enrollment_v2_context *context,uint8_t worker[57]) {
    const void *p[]={raw,owner,context,worker};size_t z[]={n,on,sizeof *context,57};
    if(!context||!worker||!raw||!owner||!n||n>512||!on||on>2048)return 0;
    for(unsigned i=0;i<4;i++){
        uintptr_t x=(uintptr_t)p[i];if(z[i]>UINTPTR_MAX-x)return 0;
        for(unsigned k=0;k<i;k++){uintptr_t y=(uintptr_t)p[k];if(!(x+z[i]<=y||y+z[k]<=x))return 0;}
    }
    memset(context,0,sizeof *context);memset(worker,0,57);authority a;
    if(!validate_context(raw,n,owner,on,0,h256,&a)||!a.epoch||!a.until)return 0;
    memcpy(context->genesis,a.gid,32);memcpy(context->fingerprint,a.fingerprint,32);
    memcpy(context->license,a.license,32);memcpy(context->owner_descriptor,a.owner_id,32);
    memcpy(context->coordinator,a.coordinator,32);memcpy(context->device_mac,a.mac,6);
    context->owner_generation=a.owner_generation;context->configuration_generation=a.configuration;
    context->assignment_generation=a.assignment;context->effective_epoch=a.epoch;context->valid_until_height=a.until;
    memcpy(worker,a.worker,57);return 1;
}
int build8_enrollment_v2_assignment_scope_matches(const uint8_t *birth,size_t bn,const uint8_t *birth_owner,size_t bon,
    const uint8_t *current,size_t cn,const uint8_t *current_owner,size_t con,build8_v2_domain_hash h256) {
    authority a,b;
    if(!validate_context(birth,bn,birth_owner,bon,0,h256,&a)||!a.epoch||!a.until
        ||!validate_context(current,cn,current_owner,con,0,h256,&b)||!b.epoch||!b.until)return 0;
    return !memcmp(a.gid,b.gid,32)&&!memcmp(a.fingerprint,b.fingerprint,32)&&!memcmp(a.license,b.license,32)
        &&!memcmp(a.mac,b.mac,6)&&!memcmp(a.worker,b.worker,57)&&b.assignment>=a.assignment;
}
