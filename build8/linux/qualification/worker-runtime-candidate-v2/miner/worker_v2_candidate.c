/* Device-local Ed448 candidate custody. Qualification candidate only.
 * The persistence digest detects damage, not malicious physical flash rewriting.
 * Pending possession proves a Worker key; it grants no mining/session authority. */
#include "worker_v2_candidate.h"
#include "worker_session_auth_v2.h"
#include <string.h>
extern int ossl_ed448_public_from_private(void *,uint8_t *,const uint8_t *,const char *);
extern int ossl_ed448_sign(void *,uint8_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *,const uint8_t *,size_t,uint8_t,const char *);
extern void OPENSSL_cleanse(void *,size_t);
extern int build8_qual_ed448_verify(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
static const uint8_t magic[8]={'B','8','V','2','K','E','Y',1};
static int candidate_valid(const uint8_t *raw,size_t n,const uint8_t *owner,size_t on,
    const uint8_t public_key[57],const uint8_t proof[114],build8_v2_domain_hash h256,build8_v2_domain_hash h512,int genesis) {
    return genesis?build8_enrollment_v2_candidate_valid(raw,n,owner,on,public_key,proof,h256,h512)
        :build8_enrollment_v2_assignment_candidate_valid(raw,n,owner,on,public_key,proof,h256,h512);
}
static int unpack(const uint8_t *raw,size_t n,build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out,int genesis) {
    if(n<8+57+4+114+32||n>BUILD8_V2_PRIVATE_RECORD_MAX||memcmp(raw,magic,8))return 0;
    size_t un=((size_t)raw[65]<<8)|raw[66],on=((size_t)raw[67]<<8)|raw[68];
    if(un>512||on>2048||n!=69+un+on+114+32)return 0;
    uint8_t check[32],public_key[57];int ok=0;
    if(!h256("MUTINY-BUILD8-WORKER-PRIVATE-RECORD-V2",raw,n-32,check)||memcmp(check,raw+n-32,32)
        ||!ossl_ed448_public_from_private(NULL,public_key,raw+8,NULL))goto done;
    if(!candidate_valid(raw+69,un,raw+69+un,on,public_key,raw+69+un+on,h256,h512,genesis))goto done;
    memset(out,0,sizeof *out);memcpy(out->unsigned_binding,raw+69,un);out->unsigned_length=un;
    memcpy(out->owner_descriptor,raw+69+un,on);out->owner_length=on;
    memcpy(out->worker_public,public_key,57);memcpy(out->possession,raw+69+un+on,114);ok=1;
done:
    OPENSSL_cleanse(check,sizeof check);OPENSSL_cleanse(public_key,sizeof public_key);return ok;
}
static int candidate_public(const build8_v2_private_backend *b,build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,build8_v2_public_candidate *out,int genesis) {
    if(!b||!b->read||!h256||!h512||!out)return 0;
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX];size_t n=0;
    int ok=b->read(b->context,raw,sizeof raw,&n)==1&&unpack(raw,n,h256,h512,out,genesis);
    OPENSSL_cleanse(raw,sizeof raw);if(!ok)memset(out,0,sizeof *out);return ok;
}
static int candidate_prepare(const build8_v2_private_backend *b,const build8_enrollment_v2_context *context,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out,int genesis) {
    if(!b||!b->read||!b->write||!b->entropy||!context||!owner||on>2048||!h256||!h512||!out)return 0;
    if(!genesis&&(!context->effective_epoch||!context->valid_until_height)){memset(out,0,sizeof *out);return 0;}
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],readback[BUILD8_V2_PRIVATE_RECORD_MAX],public_key[57],intent[64],unsigned_bytes[512];
    size_t n=0,un=0,rn=0;int ok=0,status=b->read(b->context,raw,sizeof raw,&n);
    if(status==1) {
        if(!unpack(raw,n,h256,h512,out,genesis)||!build8_enrollment_v2_unsigned(context,out->worker_public,h256,unsigned_bytes,sizeof unsigned_bytes,&un)
            ||out->unsigned_length!=un||memcmp(out->unsigned_binding,unsigned_bytes,un)||out->owner_length!=on||memcmp(out->owner_descriptor,owner,on))goto done;
        ok=1;goto done;
    }
    if(status!=0)goto done; /* Never repair a read error with a fresh identity. */
    memcpy(raw,magic,8);
    if(!b->entropy(b->context,raw+8,57))goto done;
    /* Detect catastrophic stuck output. This is not an entropy estimator and
     * does not replace manufacturer startup/source qualification. */
    unsigned different=0,changing_words=0;
    for(size_t i=1;i<57;i++)different|=raw[8+i]^raw[8];
    for(size_t i=4;i<56;i++)changing_words|=raw[8+i]^raw[8+(i%4)];
    if(!different||!changing_words||!ossl_ed448_public_from_private(NULL,public_key,raw+8,NULL)
        ||!build8_enrollment_v2_unsigned(context,public_key,h256,unsigned_bytes,sizeof unsigned_bytes,&un))goto done;
    raw[65]=(uint8_t)(un>>8);raw[66]=(uint8_t)un;raw[67]=(uint8_t)(on>>8);raw[68]=(uint8_t)on;
    memcpy(raw+69,unsigned_bytes,un);memcpy(raw+69+un,owner,on);n=69+un+on+114+32;
    if(!h512("MUTINY-BUILD8-WORKER-POSSESSION-V2",unsigned_bytes,un,intent)
        ||!ossl_ed448_sign(NULL,raw+69+un+on,intent,64,public_key,raw+8,NULL,0,0,NULL)
        ||!candidate_valid(unsigned_bytes,un,owner,on,public_key,raw+69+un+on,h256,h512,genesis)
        ||!h256("MUTINY-BUILD8-WORKER-PRIVATE-RECORD-V2",raw,n-32,raw+n-32))goto done;
    if(!b->write(b->context,raw,n)||b->read(b->context,readback,sizeof readback,&rn)!=1||rn!=n
        ||memcmp(raw,readback,n)||!unpack(readback,rn,h256,h512,out,genesis))goto done;
    ok=1;
done:
    OPENSSL_cleanse(raw,sizeof raw);OPENSSL_cleanse(readback,sizeof readback);OPENSSL_cleanse(public_key,sizeof public_key);
    OPENSSL_cleanse(intent,sizeof intent);OPENSSL_cleanse(unsigned_bytes,sizeof unsigned_bytes);
    if(!ok)memset(out,0,sizeof *out);
    return ok;
}
static int sign_session(const build8_v2_private_backend *b,const build8_v2_store *store,
    const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,const uint8_t transcript[64],
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t signature[114],int genesis) {
    if(!signature)return 0;
    memset(signature,0,114);
    if(!b||!b->read||!store||!context||!transcript||!h256||!h512||!workspace
        ||!height||epoch<context->effective_epoch
        ||(!genesis&&(!context->effective_epoch||!context->valid_until_height)))return 0;
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],expected[512],intent[64];
    build8_v2_public_candidate candidate;size_t n=0,en=0;int ok=0;
    if(b->read(b->context,raw,sizeof raw,&n)!=1||!unpack(raw,n,h256,h512,&candidate,genesis)
        ||!build8_enrollment_v2_unsigned(context,candidate.worker_public,h256,expected,sizeof expected,&en)
        ||en!=candidate.unsigned_length||memcmp(expected,candidate.unsigned_binding,en)
        ||(genesis?build8_v2_restore:build8_v2_assignment_restore)(store,expected,en,candidate.owner_descriptor,candidate.owner_length,
            h256,h512,workspace,wn)!=BUILD8_V2_ACTIVE)goto done;
    if(!h512("MUTINY-BUILD8-WORKER-SESSION-POSSESSION-V2",transcript,64,intent)
        ||!ossl_ed448_sign(NULL,signature,intent,64,candidate.worker_public,raw+8,NULL,0,0,NULL)
        ||!build8_qual_ed448_verify(candidate.worker_public,57,signature,114,intent,64))goto done;
    ok=1;
done:
    OPENSSL_cleanse(raw,sizeof raw);OPENSSL_cleanse(expected,sizeof expected);
    OPENSSL_cleanse(intent,sizeof intent);OPENSSL_cleanse(&candidate,sizeof candidate);
    if(!ok)OPENSSL_cleanse(signature,114);
    return ok;
}
int build8_v2_candidate_public(const build8_v2_private_backend *b,build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    return candidate_public(b,h256,h512,out,1);
}
int build8_v2_assignment_candidate_public(const build8_v2_private_backend *b,build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    return candidate_public(b,h256,h512,out,0);
}
int build8_v2_candidate_prepare(const build8_v2_private_backend *b,const build8_enrollment_v2_context *context,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    return candidate_prepare(b,context,owner,on,h256,h512,out,1);
}
int build8_v2_assignment_candidate_prepare(const build8_v2_private_backend *b,const build8_enrollment_v2_context *context,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    return candidate_prepare(b,context,owner,on,h256,h512,out,0);
}
int build8_v2_candidate_sign_session(const build8_v2_private_backend *b,const build8_v2_store *store,
    const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,const uint8_t transcript[64],
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t signature[114]) {
    return sign_session(b,store,context,height,epoch,transcript,h256,h512,workspace,wn,signature,1);
}
int build8_v2_assignment_candidate_sign_session(const build8_v2_private_backend *b,const build8_v2_store *store,
    const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,const uint8_t transcript[64],
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t signature[114]) {
    return sign_session(b,store,context,height,epoch,transcript,h256,h512,workspace,wn,signature,0);
}
/* New journal entry points reject aliases before clearing any caller output.
 * Backend context pointees remain trusted LOCAL provider-owned memory. */
static int journal_apart(const void **p,const size_t *z,unsigned count){
    for(unsigned i=0;i<count;i++)if(z[i]){
        uintptr_t x=(uintptr_t)p[i];if(!p[i]||z[i]>UINTPTR_MAX-x)return 0;
        for(unsigned k=0;k<i;k++)if(z[k]){uintptr_t y=(uintptr_t)p[k];if(!(x+z[i]<=y||y+z[k]<=x))return 0;}
    }return 1;
}
int build8_v2_assignment_candidate_reprove(const build8_v2_private_backend *b,const build8_v2_assignment_authority *a,
    const build8_enrollment_v2_context *context,const uint8_t *owner,size_t on,const uint8_t *node,size_t nn,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out){
    const void *p[]={b,a,context,owner,node,out};
    size_t z[]={sizeof *b,sizeof *a,sizeof *context,on,nn,sizeof *out};
    if(!out||on>2048||nn>2048||!journal_apart(p,z,6))return 0;
    memset(out,0,sizeof *out);
    if(!b||!b->read||!a||!a->candidate||!a->active||!context||!context->effective_epoch||!context->valid_until_height
        ||!owner||!on||on>2048||!node||!nn||nn>2048||!h256||!h512)return 0;
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],unsigned_bytes[512],intent[64],session[64];
    build8_v2_public_candidate birth;size_t n=0,un=0;int ok=0;
    if(b->read(b->context,raw,sizeof raw,&n)!=1||!unpack(raw,n,h256,h512,&birth,0)
        ||!build8_enrollment_v2_unsigned(context,birth.worker_public,h256,unsigned_bytes,sizeof unsigned_bytes,&un)
        ||!build8_enrollment_v2_assignment_scope_matches(birth.unsigned_binding,birth.unsigned_length,birth.owner_descriptor,birth.owner_length,
            unsigned_bytes,un,owner,on,h256)
        ||!build8_worker_session_context_v2(context,birth.worker_public,node,nn,h256,h512,session)
        ||a->candidate(a->context,unsigned_bytes,un,owner,on,node,nn)!=1
        ||!h512("MUTINY-BUILD8-WORKER-POSSESSION-V2",unsigned_bytes,un,intent)
        ||!ossl_ed448_sign(NULL,out->possession,intent,64,birth.worker_public,raw+8,NULL,0,0,NULL)
        ||!build8_enrollment_v2_assignment_candidate_valid(unsigned_bytes,un,owner,on,birth.worker_public,out->possession,h256,h512)
        ||a->candidate(a->context,unsigned_bytes,un,owner,on,node,nn)!=1)goto done;
    memcpy(out->unsigned_binding,unsigned_bytes,un);out->unsigned_length=un;
    memcpy(out->owner_descriptor,owner,on);out->owner_length=on;memcpy(out->worker_public,birth.worker_public,57);ok=1;
done:
    OPENSSL_cleanse(raw,sizeof raw);OPENSSL_cleanse(unsigned_bytes,sizeof unsigned_bytes);OPENSSL_cleanse(intent,sizeof intent);
    OPENSSL_cleanse(session,sizeof session);OPENSSL_cleanse(&birth,sizeof birth);if(!ok)memset(out,0,sizeof *out);return ok;
}
static int journal_current(const build8_v2_private_backend *b,const build8_v2_assignment_journal *j,
    const build8_v2_assignment_authority *a,const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],build8_v2_public_candidate *birth,
    uint8_t record[BUILD8_V2_ASSIGNMENT_BYTES_MAX],size_t *record_length,build8_v2_assignment_view *view){
    if(!b||!b->read||!j||!a||!a->candidate||!a->active||!context||!height||epoch<context->effective_epoch
        ||!context->effective_epoch||!context->valid_until_height||!h256||!h512||!workspace)return 0;
    size_t n=0,un=0;uint8_t expected[512],id[32];
    return b->read(b->context,raw,BUILD8_V2_PRIVATE_RECORD_MAX,&n)==1&&unpack(raw,n,h256,h512,birth,0)
        &&build8_enrollment_v2_unsigned(context,birth->worker_public,h256,expected,sizeof expected,&un)
        &&h256("MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2",expected,un,id)
        &&build8_v2_assignment_journal_restore(j,a,id,context,height,epoch,h256,h512,workspace,wn,
            record,BUILD8_V2_ASSIGNMENT_BYTES_MAX,record_length)==BUILD8_V2_JOURNAL_ACTIVE
        &&build8_v2_assignment_view_verify(record,*record_length,h256,h512,workspace,wn,view)
        &&build8_enrollment_v2_assignment_scope_matches(birth->unsigned_binding,birth->unsigned_length,birth->owner_descriptor,birth->owner_length,
            view->unsigned_binding,view->unsigned_length,view->owner,view->owner_length,h256);
}
int build8_v2_assignment_journal_current(const build8_v2_private_backend *b,const build8_v2_assignment_journal *j,
    const build8_v2_assignment_authority *a,const build8_enrollment_v2_context *context,const uint8_t *node,size_t nn,
    uint64_t height,uint64_t epoch,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,
    uint8_t worker[57],uint8_t session[64]){
    const void *p[]={b,j,a,context,node,workspace,worker,session};
    size_t z[]={sizeof *b,sizeof *j,sizeof *a,sizeof *context,nn,wn,57,64};
    if(!worker||!session||nn>2048||wn<4127||wn>65536||!journal_apart(p,z,8))return 0;
    memset(worker,0,57);memset(session,0,64);
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],record[BUILD8_V2_ASSIGNMENT_BYTES_MAX];size_t rn=0;int ok=0;
    build8_v2_public_candidate birth;build8_v2_assignment_view view;
    if(!journal_current(b,j,a,context,height,epoch,h256,h512,workspace,wn,raw,&birth,record,&rn,&view)
        ||!node||nn!=view.node_length||memcmp(node,view.node,nn)
        ||!build8_worker_session_context_v2(context,birth.worker_public,node,nn,h256,h512,session)
        ||a->active(a->context,record,rn,height,epoch)!=1)goto done;
    memcpy(worker,birth.worker_public,57);ok=1;
done:
    OPENSSL_cleanse(raw,sizeof raw);OPENSSL_cleanse(&birth,sizeof birth);if(!ok){memset(worker,0,57);memset(session,0,64);}return ok;
}
int build8_v2_assignment_journal_sign_session(const build8_v2_private_backend *b,const build8_v2_assignment_journal *j,
    const build8_v2_assignment_authority *a,const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,const uint8_t transcript[64],
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t signature[114]){
    const void *p[]={b,j,a,context,transcript,workspace,signature};
    size_t z[]={sizeof *b,sizeof *j,sizeof *a,sizeof *context,64,wn,114};
    if(!signature||wn<4127||wn>65536||!journal_apart(p,z,7))return 0;
    memset(signature,0,114);if(!transcript)return 0;
    uint8_t raw[BUILD8_V2_PRIVATE_RECORD_MAX],record[BUILD8_V2_ASSIGNMENT_BYTES_MAX],intent[64];size_t rn=0;int ok=0;
    build8_v2_public_candidate birth;build8_v2_assignment_view view;
    if(!journal_current(b,j,a,context,height,epoch,h256,h512,workspace,wn,raw,&birth,record,&rn,&view)
        ||!h512("MUTINY-BUILD8-WORKER-SESSION-POSSESSION-V2",transcript,64,intent)
        ||!ossl_ed448_sign(NULL,signature,intent,64,birth.worker_public,raw+8,NULL,0,0,NULL)
        ||!build8_qual_ed448_verify(birth.worker_public,57,signature,114,intent,64)
        ||a->active(a->context,record,rn,height,epoch)!=1)goto done;
    ok=1;
done:
    OPENSSL_cleanse(raw,sizeof raw);OPENSSL_cleanse(&birth,sizeof birth);OPENSSL_cleanse(intent,sizeof intent);
    if(!ok)OPENSSL_cleanse(signature,114);return ok;
}
