#include "worker_handshake_v2.h"
#include "worker_kdf_v2.h"
#include "worker_finished_v2.h"
#include <string.h>
extern void OPENSSL_cleanse(void *,size_t);
extern void ossl_x448_public_from_private(uint8_t *,const uint8_t *);
extern int ossl_x448(uint8_t *,const uint8_t *,const uint8_t *);
extern int build8_transport_mlkem1024_keypair_derand(uint8_t *,uint8_t *,const uint8_t *);
extern int build8_transport_mlkem1024_dec(uint8_t *,const uint8_t *,const uint8_t *);
#define PENDING_HELLO UINT32_C(0x42574831)
#define PENDING_FINISH UINT32_C(0x42574832)
struct build8_worker_pending_v2 {
    uint8_t context[64],worker[57],hello[1722],x[56],kem[3168],keys[104],transcript[64];
    uint64_t started,last;uint32_t phase,ordinary;
};
size_t build8_worker_pending_v2_size(void){return sizeof(build8_worker_pending_v2);}
size_t build8_worker_pending_v2_alignment(void){return _Alignof(build8_worker_pending_v2);}
void build8_worker_pending_v2_clear(build8_worker_pending_v2 *s){if(s)OPENSSL_cleanse(s,sizeof *s);}
build8_worker_pending_v2 *build8_worker_pending_v2_init(void *p,size_t n){
    if(!p||n<sizeof(build8_worker_pending_v2)||(uintptr_t)p%_Alignof(build8_worker_pending_v2))return NULL;
    build8_worker_pending_v2 *s=p;build8_worker_pending_v2_clear(s);return s;
}
static int nonzero(const uint8_t *p,size_t n){unsigned v=0;for(size_t i=0;i<n;i++)v|=p[i];return v!=0;}
/* Catastrophic stuck/repeating-word rejection only, never an entropy estimate. */
static int entropy_sane(const uint8_t *p,size_t n){
    unsigned different=0,changing_words=0;
    for(size_t i=1;i<n;i++)different|=p[i]^p[0];
    for(size_t i=4;i<n;i++)changing_words|=p[i]^p[i%4];
    return different&&changing_words;
}
/* Explicit journal mode uses only its current-chain journal backend for
 * public authority. Legacy public_store is optional range-only compatibility
 * in that mode; ordinary/Genesis still require their exact public store. */
static int local(const build8_worker_local_v2 *a,int mode){return (mode==0||mode==1||mode==2)
    &&a&&a->private_store&&(mode==2||a->public_store)&&a->current
    &&a->node_descriptor&&a->h256&&a->h512&&a->verification_workspace&&a->verification_workspace_length>=4127
    &&a->verification_workspace_length<=65536&&a->clock_ms;}
static int buffers(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,const uint8_t *wire,size_t n,void *out,size_t on,int mode){
    if(!s||!out||!local(a,mode)||a->node_descriptor_length>2048||n>3050||(n&&!wire))return 0;
    const void *p[]={s,a,a->current,a->node_descriptor,a->verification_workspace,a->private_store,a->public_store,wire,out};
    size_t z[]={sizeof *s,sizeof *a,sizeof *a->current,a->node_descriptor_length,a->verification_workspace_length,
        sizeof *a->private_store,a->public_store?sizeof *a->public_store:0,n,on};
    for(unsigned i=0;i<9;i++)if(z[i]){
        uintptr_t x=(uintptr_t)p[i];if(z[i]>UINTPTR_MAX-x)return 0;
        for(unsigned j=0;j<i;j++)if(z[j]){uintptr_t y=(uintptr_t)p[j];if(!(x+z[i]<=y||y+z[j]<=x))return 0;}
    }return 1;
}
static int journal_buffers(const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain,
    build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,const uint8_t *wire,size_t n,void *out,size_t on){
    if(!j||!chain||!j->slots||j->slots>BUILD8_V2_JOURNAL_SLOTS_MAX||!j->read||!j->append||!j->read_marker||!j->append_marker
        ||!chain->candidate||!chain->active)return 0;
    const void *p[]={j,chain,s,a,a->current,a->node_descriptor,a->verification_workspace,a->private_store,a->public_store,wire,out};
    size_t z[]={sizeof *j,sizeof *chain,sizeof *s,sizeof(build8_worker_journal_local_v2),sizeof *a->current,a->node_descriptor_length,
        a->verification_workspace_length,sizeof *a->private_store,a->public_store?sizeof *a->public_store:0,n,on};
    for(unsigned i=0;i<11;i++)if(z[i]){
        uintptr_t x=(uintptr_t)p[i];if(!p[i]||z[i]>UINTPTR_MAX-x)return 0;
        for(unsigned k=0;k<i;k++)if(z[k]){uintptr_t y=(uintptr_t)p[k];if(!(x+z[i]<=y||y+z[k]<=x))return 0;}
    }return 1;
}
static int time_valid(build8_worker_pending_v2 *s,uint64_t now){
    if(now<s->last||now<s->started||now-s->started>=60000)return 0;
    s->last=now;return 1;
}
static int live(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a){return time_valid(s,a->clock_ms(a->platform));}
int build8_worker_pending_v2_expire(build8_worker_pending_v2 *s,uint64_t now){
    if(s&&(s->phase==PENDING_HELLO||s->phase==PENDING_FINISH)&&time_valid(s,now))return 1;
    build8_worker_pending_v2_clear(s);return 0;
}
static int authority(const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,uint8_t worker[57],uint8_t context[64],int mode,
    const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain){
    if(!local(a,mode)||!height||epoch<a->current->effective_epoch)return 0;
    if(mode==2)return build8_v2_assignment_journal_current(a->private_store,j,chain,a->current,a->node_descriptor,a->node_descriptor_length,
        height,epoch,a->h256,a->h512,a->verification_workspace,a->verification_workspace_length,worker,context);
    if(mode!=0&&mode!=1)return 0;
    if(!mode&&(!a->current->effective_epoch||!a->current->valid_until_height))return 0;
    build8_v2_public_candidate c;uint8_t expected[512];size_t n=0;int ok=0;
    if(!(mode?build8_v2_candidate_public:build8_v2_assignment_candidate_public)(a->private_store,a->h256,a->h512,&c)
        ||!build8_enrollment_v2_unsigned(a->current,c.worker_public,a->h256,expected,sizeof expected,&n)
        ||n!=c.unsigned_length||memcmp(expected,c.unsigned_binding,n)
        ||(mode?build8_v2_restore:build8_v2_assignment_restore)(a->public_store,expected,n,c.owner_descriptor,c.owner_length,
            a->h256,a->h512,a->verification_workspace,a->verification_workspace_length)!=BUILD8_V2_ACTIVE
        ||!build8_worker_session_context_v2(a->current,c.worker_public,a->node_descriptor,a->node_descriptor_length,
            a->h256,a->h512,context))goto done;
    memcpy(worker,c.worker_public,57);ok=1;
done:OPENSSL_cleanse(&c,sizeof c);OPENSSL_cleanse(expected,sizeof expected);return ok;
}
static int current(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,int mode,
    const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain){
    uint8_t worker[57],context[64];return s->ordinary==(uint32_t)mode&&authority(a,height,epoch,worker,context,mode,j,chain)
        &&!memcmp(worker,s->worker,57)&&!memcmp(context,s->context,64);
}
static int begin(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,uint8_t hello[1722],int mode,
    const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain){
    if(!buffers(s,a,NULL,0,hello,1722,mode)){build8_worker_pending_v2_clear(s);return 0;}
    if(mode==2&&!journal_buffers(j,chain,s,a,NULL,0,hello,1722)){build8_worker_pending_v2_clear(s);return 0;}
    memset(hello,0,1722);uint8_t entropy[152];int ok=0;
    if(s->phase||!local(a,mode)||!a->entropy)goto done;
    s->ordinary=(uint32_t)mode;
    s->started=s->last=a->clock_ms(a->platform);
    if(!authority(a,height,epoch,s->worker,s->context,mode,j,chain)||!live(s,a)
        ||!a->entropy(a->platform,entropy,sizeof entropy)
        ||!entropy_sane(entropy,56)||!entropy_sane(entropy+56,64)||!entropy_sane(entropy+120,32))goto done;
    memcpy(s->x,entropy,56);s->hello[0]=2;s->hello[1]=1;memcpy(s->hello+2,s->context,64);memcpy(s->hello+66,entropy+120,32);
    ossl_x448_public_from_private(s->hello+98,s->x);
    if(build8_transport_mlkem1024_keypair_derand(s->hello+154,s->kem,entropy+56)!=0||!live(s,a)
        ||(mode==2&&!current(s,a,height,epoch,mode,j,chain)))goto done;
    s->phase=PENDING_HELLO;memcpy(hello,s->hello,1722);ok=1;
done:OPENSSL_cleanse(entropy,sizeof entropy);if(!ok){build8_worker_pending_v2_clear(s);memset(hello,0,1722);}return ok;
}
static int accept(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *response,size_t n,uint8_t finish[130],int mode,
    const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain){
    if(!buffers(s,a,response,n,finish,130,mode)){build8_worker_pending_v2_clear(s);return 0;}
    if(mode==2&&!journal_buffers(j,chain,s,a,response,n,finish,130)){build8_worker_pending_v2_clear(s);return 0;}
    memset(finish,0,130);uint8_t x[56],kem[32];int ok=0;
    if(!local(a,mode)||s->phase!=PENDING_HELLO||!response||n!=3050||!live(s,a)||!current(s,a,height,epoch,mode,j,chain)
        ||!build8_worker_session_verify_node_v2(a->current,s->worker,a->node_descriptor,a->node_descriptor_length,
            s->hello,1722,response,n,a->h256,a->h512,a->verification_workspace,a->verification_workspace_length,s->transcript)
        ||!live(s,a)||!ossl_x448(x,s->x,response+32)||!nonzero(x,56)
        ||build8_transport_mlkem1024_dec(kem,response+88,s->kem)!=0
        ||!b8_worker_kdf_v2(x,kem,s->transcript,s->keys)||!live(s,a)
        ||!(mode==2?build8_v2_assignment_journal_sign_session(a->private_store,j,chain,a->current,height,epoch,s->transcript,
                a->h256,a->h512,a->verification_workspace,a->verification_workspace_length,finish)
            :(mode?build8_v2_candidate_sign_session:build8_v2_assignment_candidate_sign_session)(a->private_store,a->public_store,a->current,height,epoch,s->transcript,
                a->h256,a->h512,a->verification_workspace,a->verification_workspace_length,finish))
        ||!b8_worker_finished_v2(s->keys,s->keys+64,s->transcript,0,finish+114)||!live(s,a)
        ||(mode==2&&!current(s,a,height,epoch,mode,j,chain)))goto done;
    OPENSSL_cleanse(s->x,sizeof s->x);OPENSSL_cleanse(s->kem,sizeof s->kem);OPENSSL_cleanse(s->hello,sizeof s->hello);
    s->phase=PENDING_FINISH;ok=1;
done:OPENSSL_cleanse(x,sizeof x);OPENSSL_cleanse(kem,sizeof kem);
    if(!ok){build8_worker_pending_v2_clear(s);memset(finish,0,130);}return ok;
}
static int finish(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *tag,size_t n,b8_worker_channel *channel,int mode,
    const build8_v2_assignment_journal *j,const build8_v2_assignment_authority *chain){
    if(!buffers(s,a,tag,n,channel,sizeof *channel,mode)){build8_worker_pending_v2_clear(s);return 0;}
    if(mode==2&&!journal_buffers(j,chain,s,a,tag,n,channel,sizeof *channel)){build8_worker_pending_v2_clear(s);return 0;}
    b8_worker_channel_clear(channel);int ok=0;
    if(!local(a,mode)||s->phase!=PENDING_FINISH||!live(s,a)||!current(s,a,height,epoch,mode,j,chain)
        ||!b8_worker_verify_finished_v2(s->keys+32,s->keys+68,s->transcript,1,tag,n)||!live(s,a))goto done;
    ok=b8_worker_channel_init(channel,s->context,s->keys+72,s->keys,s->keys+32,s->keys+64,s->keys+68,1,
        s->last,s->last,a->current->effective_epoch,a->current->valid_until_height);
    if(ok&&mode==2&&!current(s,a,height,epoch,mode,j,chain)){b8_worker_channel_clear(channel);ok=0;}
done:build8_worker_pending_v2_clear(s);return ok;
}
int build8_worker_pending_v2_begin(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,uint8_t hello[1722]){
    return begin(s,a,height,epoch,hello,1,NULL,NULL);
}
int build8_worker_pending_v2_accept(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *response,size_t n,uint8_t out[130]){
    return accept(s,a,height,epoch,response,n,out,1,NULL,NULL);
}
int build8_worker_pending_v2_finish(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *tag,size_t n,b8_worker_channel *out){
    return finish(s,a,height,epoch,tag,n,out,1,NULL,NULL);
}
int build8_worker_assignment_pending_v2_begin(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,uint8_t hello[1722]){
    return begin(s,a,height,epoch,hello,0,NULL,NULL);
}
int build8_worker_assignment_pending_v2_accept(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *response,size_t n,uint8_t out[130]){
    return accept(s,a,height,epoch,response,n,out,0,NULL,NULL);
}
int build8_worker_assignment_pending_v2_finish(build8_worker_pending_v2 *s,const build8_worker_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *tag,size_t n,b8_worker_channel *out){
    return finish(s,a,height,epoch,tag,n,out,0,NULL,NULL);
}
int build8_worker_journal_pending_v2_begin(build8_worker_pending_v2 *s,const build8_worker_journal_local_v2 *a,uint64_t height,uint64_t epoch,uint8_t hello[1722]){
    if(!a){build8_worker_pending_v2_clear(s);return 0;}
    return begin(s,&a->base,height,epoch,hello,2,a->journal,a->authority);
}
int build8_worker_journal_pending_v2_accept(build8_worker_pending_v2 *s,const build8_worker_journal_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *raw,size_t n,uint8_t out[130]){
    if(!a){build8_worker_pending_v2_clear(s);return 0;}
    return accept(s,&a->base,height,epoch,raw,n,out,2,a->journal,a->authority);
}
int build8_worker_journal_pending_v2_finish(build8_worker_pending_v2 *s,const build8_worker_journal_local_v2 *a,uint64_t height,uint64_t epoch,
    const uint8_t *raw,size_t n,b8_worker_channel *out){
    if(!a){build8_worker_pending_v2_clear(s);return 0;}
    return finish(s,&a->base,height,epoch,raw,n,out,2,a->journal,a->authority);
}
