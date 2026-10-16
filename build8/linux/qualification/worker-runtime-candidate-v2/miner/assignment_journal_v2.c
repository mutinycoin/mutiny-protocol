#include "assignment_journal_v2.h"
#include "worker_session_auth_v2.h"
#include <string.h>
typedef struct {const uint8_t *p;size_t n,at;} reader;
static int number(reader *r,unsigned major,uint64_t *out){
    if(r->at>=r->n)return 0;
    unsigned b=r->p[r->at++],a=b&31;if((b>>5)!=major||a>27)return 0;
    if(a<24){*out=a;return 1;}
    unsigned count=1u<<(a-24);if(count>r->n-r->at)return 0;
    uint64_t n=0;for(unsigned i=0;i<count;i++)n=(n<<8)|r->p[r->at++];
    if(n<24||(count>1&&n<((uint64_t)1<<(8*(count/2)))))return 0;
    *out=n;return 1;
}
static int exact(reader *r,unsigned major,uint64_t want){uint64_t n;return number(r,major,&n)&&n==want;}
static const uint8_t *bytes(reader *r,size_t maximum,size_t *length){
    uint64_t n;if(!number(r,2,&n)||!n||n>maximum||n>r->n-r->at)return NULL;
    const uint8_t *p=r->p+r->at;r->at+=(size_t)n;*length=(size_t)n;return p;
}
static int apart(const void *a,size_t an,const void *b,size_t bn){
    if((an&&!a)||(bn&&!b))return 0;
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(!an||!bn||x+an<=y||y+bn<=x);
}
static int backend(const build8_v2_assignment_journal *j){return j&&j->slots&&j->slots<=BUILD8_V2_JOURNAL_SLOTS_MAX
    &&j->read&&j->append&&j->read_marker&&j->append_marker;}
static int provider(const build8_v2_assignment_authority *a){return a&&a->candidate&&a->active;}
static int parameters(const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *a,
    const uint8_t *id,const build8_enrollment_v2_context *expected,void *workspace,size_t wn,
    const uint8_t *raw,size_t n,uint8_t *out,size_t capacity,size_t *length){
    if(!backend(j)||!provider(a)||wn<4127||wn>65536)return 0;
    const void *p[]={j,a,id,expected,workspace,raw,out,length};
    size_t z[]={sizeof *j,sizeof *a,id?32:0,expected?sizeof *expected:0,wn,n,capacity,length?sizeof *length:0};
    for(unsigned i=0;i<8;i++)for(unsigned k=0;k<i;k++)if(!apart(p[i],z[i],p[k],z[k]))return 0;
    return 1;
}
int build8_v2_assignment_view_verify(const uint8_t *raw,size_t n,build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,void *workspace,size_t wn,build8_v2_assignment_view *out){
    if(!out||!raw||!n||n>BUILD8_V2_ASSIGNMENT_BYTES_MAX||!h256||!h512||wn<4127||wn>65536
        ||!apart(raw,n,out,sizeof *out)||!apart(workspace,wn,out,sizeof *out)||!apart(raw,n,workspace,wn))return 0;
    memset(out,0,sizeof *out);build8_v2_assignment_view v={0};reader r={raw,n,0};
    if(!exact(&r,4,5)||!exact(&r,0,2)||!exact(&r,0,10)
        ||!(v.enrollment=bytes(&r,2048,&v.enrollment_length))
        ||!(v.owner=bytes(&r,2048,&v.owner_length))||!(v.node=bytes(&r,2048,&v.node_length))||r.at!=r.n)return 0;
    reader e={v.enrollment,v.enrollment_length,0};uint8_t context[64];
    if(!exact(&e,4,4)||!(v.unsigned_binding=bytes(&e,512,&v.unsigned_length))
        ||!build8_enrollment_v2_assignment_decode(v.unsigned_binding,v.unsigned_length,v.owner,v.owner_length,h256,&v.context,v.worker)
        ||!build8_enrollment_v2_assignment_verify(v.enrollment,v.enrollment_length,v.unsigned_binding,v.unsigned_length,
            v.owner,v.owner_length,h256,h512,workspace,wn)
        ||!build8_worker_session_context_v2(&v.context,v.worker,v.node,v.node_length,h256,h512,context)
        ||!h256("MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2",v.unsigned_binding,v.unsigned_length,v.id))return 0;
    *out=v;return 1;
}
static int marker(const build8_v2_assignment_view *v,build8_v2_domain_hash h256,uint8_t out[40]){
    static const uint8_t magic[8]={'B','8','V','2','A','C','T',1};
    memcpy(out,magic,8);return h256("MUTINY-BUILD8-ENROLLMENT-ACTIVATION-V2",v->enrollment,v->enrollment_length,out+8);
}
/* Verify every occupied slot, marker and duplicate, including unrelated IDs.
 * Corrupt/partial/orphaned records are never skipped or silently discarded.
 * Work/storage is bounded by <=32 public slots, not an unbounded cached bit. */
static int scan(const build8_v2_assignment_journal *j,const uint8_t id[32],
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,
    uint8_t *found,size_t *length,size_t *slot,size_t *empty,int *activated){
    uint8_t raw[BUILD8_V2_ASSIGNMENT_BYTES_MAX],seen[BUILD8_V2_JOURNAL_SLOTS_MAX][32];size_t count=0;
    int result=BUILD8_V2_JOURNAL_NOT_FOUND;*length=0;*empty=j->slots;*activated=0;
    for(size_t i=0;i<j->slots;i++){
        size_t n=0,mn=0;uint8_t got[40],wanted[40];build8_v2_assignment_view v;
        int present=j->read(j->context,i,raw,sizeof raw,&n);
        int active=j->read_marker(j->context,i,got,sizeof got,&mn);
        if(present==0){
            if(n||active!=0||mn)return BUILD8_V2_JOURNAL_FAULT;
            if(*empty==j->slots)*empty=i;continue;
        }
        if(present!=1||!n||n>sizeof raw||(active!=0&&active!=1)||(active==0&&mn)
            ||!build8_v2_assignment_view_verify(raw,n,h256,h512,workspace,wn,&v))return BUILD8_V2_JOURNAL_FAULT;
        for(size_t k=0;k<count;k++)if(!memcmp(seen[k],v.id,32))return BUILD8_V2_JOURNAL_CONFLICT;
        memcpy(seen[count++],v.id,32);
        if(active==1&&(mn!=40||!marker(&v,h256,wanted)||memcmp(got,wanted,40)))return BUILD8_V2_JOURNAL_FAULT;
        if(!memcmp(id,v.id,32)){
            memcpy(found,raw,n);*length=n;*slot=i;*activated=active;
            result=BUILD8_V2_JOURNAL_STORED;
        }
    }
    return result;
}
static int same_expected(const build8_v2_assignment_view *v,const build8_enrollment_v2_context *expected,
    uint64_t height,uint64_t epoch,build8_v2_domain_hash h256){
    uint8_t raw[512];size_t n=0;
    return expected&&height&&epoch>=expected->effective_epoch&&expected->effective_epoch&&expected->valid_until_height
        &&build8_enrollment_v2_unsigned(expected,v->worker,h256,raw,sizeof raw,&n)
        &&n==v->unsigned_length&&!memcmp(raw,v->unsigned_binding,n);
}
static int candidate_current(const build8_v2_assignment_authority *a,const build8_v2_assignment_view *v){
    return a->candidate(a->context,v->unsigned_binding,v->unsigned_length,v->owner,v->owner_length,v->node,v->node_length)==1;
}
int build8_v2_assignment_journal_put(const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *a,
    const uint8_t *raw,size_t n,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t id[32]){
    if(!id||!parameters(j,a,id,NULL,workspace,wn,raw,n,NULL,0,NULL))return BUILD8_V2_JOURNAL_FAULT;
    memset(id,0,32);build8_v2_assignment_view v;uint8_t stored[BUILD8_V2_ASSIGNMENT_BYTES_MAX];
    size_t sn=0,slot=0,empty=0;int activated=0;
    if(!build8_v2_assignment_view_verify(raw,n,h256,h512,workspace,wn,&v))return BUILD8_V2_JOURNAL_FAULT;
    int status=scan(j,v.id,h256,h512,workspace,wn,stored,&sn,&slot,&empty,&activated);
    if(status<0)return status;
    if(status==BUILD8_V2_JOURNAL_STORED){
        if(sn!=n||memcmp(raw,stored,n))return BUILD8_V2_JOURNAL_CONFLICT;
        /* Receipt of already durable exact bytes only; never live authority.
         * A stale/cancelled duplicate still has its audit record preserved. */
        memcpy(id,v.id,32);return BUILD8_V2_JOURNAL_STORED;
    }
    if(!candidate_current(a,&v))return BUILD8_V2_JOURNAL_DENIED;
    if(empty==j->slots)return BUILD8_V2_JOURNAL_FULL;
    if(!candidate_current(a,&v))return BUILD8_V2_JOURNAL_DENIED;
    if(j->append(j->context,empty,raw,n)!=1)return BUILD8_V2_JOURNAL_FAULT;
    sn=0;
    if(j->read(j->context,empty,stored,sizeof stored,&sn)!=1||sn!=n||sn>sizeof stored||memcmp(stored,raw,n)
        ||!build8_v2_assignment_view_verify(stored,sn,h256,h512,workspace,wn,&v))return BUILD8_V2_JOURNAL_FAULT;
    uint8_t wanted_id[32];memcpy(wanted_id,v.id,32);
    status=scan(j,wanted_id,h256,h512,workspace,wn,stored,&sn,&slot,&empty,&activated);
    if(status!=BUILD8_V2_JOURNAL_STORED||sn!=n||memcmp(stored,raw,n)
        ||!build8_v2_assignment_view_verify(stored,sn,h256,h512,workspace,wn,&v))return BUILD8_V2_JOURNAL_FAULT;
    if(!candidate_current(a,&v))return BUILD8_V2_JOURNAL_DENIED;
    memcpy(id,v.id,32);return BUILD8_V2_JOURNAL_STORED;
}
int build8_v2_assignment_journal_restore(const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *a,
    const uint8_t id[32],const build8_enrollment_v2_context *expected,uint64_t height,uint64_t epoch,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t *out,size_t capacity,size_t *length){
    if(!out||!length||capacity<BUILD8_V2_ASSIGNMENT_BYTES_MAX||capacity>65536||!id||!expected
        ||!parameters(j,a,id,expected,workspace,wn,NULL,0,out,capacity,length))return BUILD8_V2_JOURNAL_FAULT;
    memset(out,0,capacity);*length=0;size_t n=0,slot=0,empty=0;int activated=0;build8_v2_assignment_view v;
    int status=scan(j,id,h256,h512,workspace,wn,out,&n,&slot,&empty,&activated);
    if(status!=BUILD8_V2_JOURNAL_STORED){memset(out,0,capacity);return status;}
    if(!build8_v2_assignment_view_verify(out,n,h256,h512,workspace,wn,&v)
        ||!same_expected(&v,expected,height,epoch,h256))goto fault;
    if(a->active(a->context,out,n,height,epoch)!=1){memset(out,0,capacity);return BUILD8_V2_JOURNAL_DENIED;}
    if(!activated){memset(out,0,capacity);return BUILD8_V2_JOURNAL_PENDING;}
    // Last current canonical read after all signature/marker work.
    if(a->active(a->context,out,n,height,epoch)!=1){memset(out,0,capacity);return BUILD8_V2_JOURNAL_DENIED;}
    *length=n;return BUILD8_V2_JOURNAL_ACTIVE;
fault:memset(out,0,capacity);return BUILD8_V2_JOURNAL_FAULT;
}
int build8_v2_assignment_journal_activate(const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *a,
    const uint8_t id[32],const build8_enrollment_v2_context *expected,uint64_t height,uint64_t epoch,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn){
    if(!id||!expected||!parameters(j,a,id,expected,workspace,wn,NULL,0,NULL,0,NULL))return BUILD8_V2_JOURNAL_FAULT;
    uint8_t raw[BUILD8_V2_ASSIGNMENT_BYTES_MAX],got[40],wanted[40];size_t n=0,mn=0,slot=0,empty=0;int activated=0;
    build8_v2_assignment_view v;
    int status=scan(j,id,h256,h512,workspace,wn,raw,&n,&slot,&empty,&activated);
    if(status!=BUILD8_V2_JOURNAL_STORED)return status;
    if(!build8_v2_assignment_view_verify(raw,n,h256,h512,workspace,wn,&v)
        ||!same_expected(&v,expected,height,epoch,h256)||!marker(&v,h256,wanted))return BUILD8_V2_JOURNAL_FAULT;
    if(a->active(a->context,raw,n,height,epoch)!=1)return BUILD8_V2_JOURNAL_DENIED;
    if(!activated){
        if(j->append_marker(j->context,slot,wanted,sizeof wanted)!=1)return BUILD8_V2_JOURNAL_FAULT;
        if(j->read_marker(j->context,slot,got,sizeof got,&mn)!=1||mn!=40||memcmp(got,wanted,40))return BUILD8_V2_JOURNAL_FAULT;
    }
    status=scan(j,id,h256,h512,workspace,wn,raw,&n,&slot,&empty,&activated);
    if(status!=BUILD8_V2_JOURNAL_STORED||!activated
        ||!build8_v2_assignment_view_verify(raw,n,h256,h512,workspace,wn,&v)
        ||!same_expected(&v,expected,height,epoch,h256))return BUILD8_V2_JOURNAL_FAULT;
    // A head change after durable publication leaves the public evidence in
    // place, but cannot grant live authority or make restoration skip the chain.
    if(a->active(a->context,raw,n,height,epoch)!=1)return BUILD8_V2_JOURNAL_DENIED;
    return BUILD8_V2_JOURNAL_ACTIVE;
}
