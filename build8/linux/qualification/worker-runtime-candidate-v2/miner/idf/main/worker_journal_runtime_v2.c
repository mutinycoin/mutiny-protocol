#include "worker_journal_runtime_v2.h"
#include <string.h>
extern void OPENSSL_cleanse(void *,size_t);
size_t build8_worker_journal_runtime_v2_size(void){return sizeof(build8_worker_journal_runtime_v2);}
size_t build8_worker_journal_runtime_v2_alignment(void){return _Alignof(build8_worker_journal_runtime_v2);}
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
static int ranges(const build8_worker_journal_runtime_v2 *r,const void *out,size_t n){
    if(!r||!r->connection||!r->mining||!r->local)return 0;
    const build8_worker_connection_v2 *c=r->connection;
    const build8_worker_journal_local_v2 *a=r->local;
    if(!a->journal||!a->authority||!a->base.private_store||!a->base.current||!a->base.clock_ms)return 0;
    const void *p[]={r,c,r->mining,a,a->journal,a->authority,a->base.private_store,a->base.current,a->base.node_descriptor,
        a->base.verification_workspace,c->pending,c->rx,c->tx};
    size_t z[]={sizeof *r,sizeof *c,sizeof *r->mining,sizeof *a,sizeof *a->journal,sizeof *a->authority,sizeof *a->base.private_store,
        sizeof *a->base.current,a->base.node_descriptor_length,a->base.verification_workspace_length,build8_worker_pending_v2_size(),16444,16444};
    for(unsigned i=0;i<13;i++){
        /* A legitimate controller close clears its backing pointers. The
         * stable owner/mining/local references still permit safe retirement. */
        if(!p[i]){if(i>=10&&c->phase==0)continue;return 0;}
        for(unsigned k=0;k<i;k++)if(p[k]&&!separate(p[i],z[i],p[k],z[k]))return 0;
        if(out&&(!n||!separate(p[i],z[i],out,n)))return 0;
    }
    return 1;
}
void build8_worker_journal_runtime_v2_close(build8_worker_journal_runtime_v2 *r){
    if(!r)return;
    build8_worker_runtime_close_v2(r->connection,r->mining);OPENSSL_cleanse(r,sizeof *r);
}
static int fail(build8_worker_journal_runtime_v2 *r){build8_worker_journal_runtime_v2_close(r);return 0;}
int build8_worker_journal_runtime_v2_init(build8_worker_journal_runtime_v2 *r,build8_worker_connection_v2 *c,
    build8_mining_control_v2 *m,const build8_worker_journal_local_v2 *a,uint64_t h,uint64_t e){
    /* Temporary local object permits full range checks before writing r. */
    if(!r||!c||!m||!a)return 0;
    build8_worker_journal_runtime_v2 trial={0};trial.connection=c;trial.mining=m;trial.local=a;
    if(!ranges(&trial,r,sizeof *r)||!m->initialized||c->mode!=2||c->journal_local!=a)return 0;
    uint8_t worker[57]={0},id[64]={0};
    uint64_t now=a->base.clock_ms(a->base.platform);
    int ok=now!=UINT64_MAX&&build8_v2_assignment_journal_current(a->base.private_store,a->journal,a->authority,a->base.current,
        a->base.node_descriptor,a->base.node_descriptor_length,h,e,a->base.h256,a->base.h512,
        a->base.verification_workspace,a->base.verification_workspace_length,worker,id)==1
        &&build8_worker_runtime_journal_binding_v2(c,m,a,h,e,now,false);
    if(!ok){OPENSSL_cleanse(worker,sizeof worker);OPENSSL_cleanse(id,sizeof id);build8_worker_runtime_close_v2(c,m);return 0;}
    OPENSSL_cleanse(r,sizeof *r);r->connection=c;r->mining=m;r->local=a;r->height=h;r->epoch=e;r->initialized=true;
    memcpy(r->session,id,sizeof id);OPENSSL_cleanse(worker,sizeof worker);OPENSSL_cleanse(id,sizeof id);return 1;
}
int build8_worker_journal_runtime_v2_gate(build8_worker_journal_runtime_v2 *r,bool maintenance){
    if(!ranges(r,NULL,0))return 0; /* Bad API aliases cannot be safely cleared. */
    if(!r->initialized)return fail(r);
    uint64_t now=r->local->base.clock_ms(r->local->base.platform);
    if(now==UINT64_MAX||!build8_worker_runtime_journal_binding_v2(r->connection,r->mining,r->local,r->height,r->epoch,now,maintenance))return fail(r);
    return 1;
}
int build8_worker_journal_runtime_v2_request(build8_worker_journal_runtime_v2 *r,const uint8_t nonce[32],build8_v2_monotonic_clock clock,void *arg){
    if(!nonce||!clock||!ranges(r,nonce,32))return 0;
    if(!build8_worker_journal_runtime_v2_gate(r,false)||!build8_mining_v2_request(r->mining,nonce,clock,arg)
        ||!build8_worker_journal_runtime_v2_gate(r,false))return fail(r);
    return 1;
}
int build8_worker_journal_runtime_v2_offer(build8_worker_journal_runtime_v2 *r,const uint8_t *raw,size_t n,build8_v2_monotonic_clock clock,void *arg){
    if(!raw||!n||n>16384||!clock||!ranges(r,raw,n))return 0;
    if(!build8_worker_journal_runtime_v2_gate(r,false))return fail(r);
    const build8_worker_local_v2 *a=&r->local->base;
    if(!build8_mining_v2_offer(r->mining,raw,n,a->h256,a->h512,a->verification_workspace,a->verification_workspace_length,clock,arg)
        ||!build8_worker_journal_runtime_v2_gate(r,false))return fail(r);
    return 1;
}
int build8_worker_journal_runtime_v2_nonce(build8_worker_journal_runtime_v2 *r,build8_v2_monotonic_clock clock,void *arg,uint64_t *out){
    if(!out||!clock||!ranges(r,out,sizeof *out))return 0;
    uint64_t nonce=0;
    if(!build8_worker_journal_runtime_v2_gate(r,false)||!build8_mining_v2_nonce(r->mining,clock,arg,&nonce)
        ||!build8_worker_journal_runtime_v2_gate(r,false))return fail(r);
    *out=nonce;return 1;
}
int build8_worker_journal_runtime_v2_found(build8_worker_journal_runtime_v2 *r,const uint8_t observation[32],uint64_t nonce,
    build8_v2_monotonic_clock clock,void *arg,build8_authorized_work *out){
    if(!out||!observation||!clock||!ranges(r,out,sizeof *out)||!ranges(r,observation,32)||!separate(observation,32,out,sizeof *out))return 0;
    build8_authorized_work staged={0};
    if(!build8_worker_journal_runtime_v2_gate(r,false)||!build8_mining_v2_found(r->mining,observation,nonce,clock,arg,&staged)
        ||!build8_worker_journal_runtime_v2_gate(r,false)){OPENSSL_cleanse(&staged,sizeof staged);return fail(r);}
    memcpy(out,&staged,sizeof staged);OPENSSL_cleanse(&staged,sizeof staged);return 1;
}
int build8_worker_journal_runtime_v2_send(build8_worker_journal_runtime_v2 *r,const uint8_t *plain,size_t n){
    if(!plain||!n||n>16384||!ranges(r,plain,n))return BUILD8_CONNECTION_CLOSED;
    if(!build8_worker_journal_runtime_v2_gate(r,false))return BUILD8_CONNECTION_CLOSED;
    uint64_t now=r->local->base.clock_ms(r->local->base.platform);
    int result=build8_worker_connection_journal_v2_send(r->connection,r->session,r->height,r->epoch,now,plain,n);
    if(!result||!build8_worker_journal_runtime_v2_gate(r,false)){fail(r);return BUILD8_CONNECTION_CLOSED;}
    return result;
}
int build8_worker_journal_runtime_v2_step(build8_worker_journal_runtime_v2 *r,build8_worker_stream_v2 *s,
    build8_v2_monotonic_clock clock,build8_worker_stream_read_v2 read,build8_worker_stream_write_v2 write,void *arg,
    uint8_t *plain,size_t cap,size_t *written){
    if(!s||!plain||!written||!cap||cap>16384||!ranges(r,s,sizeof *s)||!ranges(r,plain,cap)||!ranges(r,written,sizeof *written)
        ||!separate(s,sizeof *s,plain,cap)||!separate(s,sizeof *s,written,sizeof *written)||!separate(plain,cap,written,sizeof *written))return 0;
    if(!build8_worker_journal_runtime_v2_gate(r,false)){*written=0;OPENSSL_cleanse(plain,cap);return 0;}
    int result=build8_worker_stream_journal_v2_step(s,r->connection,r->mining,r->local,r->session,r->height,r->epoch,clock,read,write,arg,plain,cap,written);
    if(!result||!build8_worker_journal_runtime_v2_gate(r,false)){*written=0;OPENSSL_cleanse(plain,cap);build8_worker_stream_v2_close(s,r->connection,r->mining);return fail(r);}
    return result;
}
