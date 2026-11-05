#include "worker_runtime_guard_v2.h"
#include <string.h>
void build8_worker_runtime_close_v2(build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining){
    build8_mining_v2_session(mining,false);build8_worker_connection_v2_close(connection);
}
static int guard(build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining,
    const uint8_t context[64],uint64_t height,uint64_t epoch,uint64_t now,bool maintenance,int journal){
    if(!mining||!mining->initialized){build8_worker_runtime_close_v2(connection,mining);return 0;}
    if(maintenance){
        build8_mining_v2_maintenance(mining,true);build8_worker_connection_v2_close(connection);return 0;
    }
    build8_mining_v2_maintenance(mining,false);
    if(now<mining->last_clock)mining->clock_fault=true;
    if(mining->clock_fault){build8_worker_runtime_close_v2(connection,mining);return 0;}
    int authenticated=journal?build8_worker_connection_journal_v2_authenticated(connection,context,height,epoch,now):build8_worker_connection_v2_authenticated(connection,context,height,epoch,now);
    if(height!=mining->context.height||epoch<mining->effective_epoch){
        build8_mining_v2_session(mining,false);return 0;
    }
    build8_mining_v2_session(mining,authenticated!=0);return authenticated;
}
static int binding(build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining,
    const build8_worker_local_v2 *local,const uint8_t worker[57],uint64_t height,uint64_t epoch,uint64_t now,bool maintenance,int journal){
    uint8_t id[32],context[64];
    if(maintenance||!mining||!mining->initialized||!local||!local->current||!worker
        ||!build8_enrollment_v2_worker_id(local->current,worker,local->h256,id))goto fail;
    const build8_enrollment_v2_context *e=local->current;
    const build8_work_context *w=&mining->context;
    if(memcmp(w->genesis,e->genesis,32)||memcmp(w->fingerprint,e->fingerprint,32)
        ||memcmp(w->license,e->license,32)||memcmp(w->coordinator,e->coordinator,32)
        ||memcmp(w->worker,id,32)||w->assignment!=e->assignment_generation
        ||mining->effective_epoch!=e->effective_epoch||mining->valid_until_height!=e->valid_until_height
        ||!build8_worker_session_context_v2(e,worker,local->node_descriptor,local->node_descriptor_length,
            local->h256,local->h512,context))goto fail;
    if(guard(connection,mining,context,height,epoch,now,false,journal))return 1;
fail:
    if(maintenance)build8_mining_v2_maintenance(mining,true);
    build8_worker_runtime_close_v2(connection,mining);return 0;
}

int build8_worker_runtime_guard_v2(build8_worker_connection_v2 *c,build8_mining_control_v2 *m,const uint8_t id[64],uint64_t h,uint64_t e,uint64_t now,bool maintenance){return guard(c,m,id,h,e,now,maintenance,0);}
int build8_worker_runtime_binding_v2(build8_worker_connection_v2 *c,build8_mining_control_v2 *m,const build8_worker_local_v2 *a,const uint8_t worker[57],uint64_t h,uint64_t e,uint64_t now,bool maintenance){return binding(c,m,a,worker,h,e,now,maintenance,0);}
static int journal_ranges(build8_worker_connection_v2 *c,build8_mining_control_v2 *m,const build8_worker_journal_local_v2 *a){
    if(!c||!m||!a||!a->journal||!a->authority||!a->base.private_store||!a->base.current)return 0;
    const void *p[]={c,m,a,a->journal,a->authority,a->base.private_store,a->base.current,a->base.node_descriptor,a->base.verification_workspace,c->pending,c->rx,c->tx};
    size_t n[]={sizeof *c,sizeof *m,sizeof *a,sizeof *a->journal,sizeof *a->authority,sizeof *a->base.private_store,sizeof *a->base.current,
        a->base.node_descriptor_length,a->base.verification_workspace_length,build8_worker_pending_v2_size(),16444,16444};
    for(unsigned i=0;i<12;i++){
        if(!p[i])return 0;
        uintptr_t x=(uintptr_t)p[i];if(n[i]>UINTPTR_MAX-x)return 0;
        for(unsigned k=0;k<i;k++){uintptr_t y=(uintptr_t)p[k];if(!(x+n[i]<=y||y+n[k]<=x))return 0;}
    }
    return 1;
}
int build8_worker_runtime_journal_binding_v2(build8_worker_connection_v2 *c,build8_mining_control_v2 *m,
    const build8_worker_journal_local_v2 *a,uint64_t h,uint64_t e,uint64_t now,bool maintenance){
    uint8_t worker[57]={0},id[64]={0};int ok=0;
    /* Invalid overlapping local API ranges refuse before writes/cleansing. */
    if(!journal_ranges(c,m,a))return 0;
    /* A latched maintenance event must not be undone by an ordinary frame
     * call passing false; fresh explicit owner/session initialization needed. */
    maintenance=maintenance||m->maintenance;
    if(!c||!m||!a||c->mode!=2||c->journal_local!=a||maintenance)goto fail;
    if(!build8_v2_assignment_journal_current(a->base.private_store,a->journal,a->authority,a->base.current,
        a->base.node_descriptor,a->base.node_descriptor_length,h,e,a->base.h256,a->base.h512,
        a->base.verification_workspace,a->base.verification_workspace_length,worker,id))goto fail;
    ok=binding(c,m,&a->base,worker,h,e,now,false,1);
fail:
    /* Public derived outputs only. Private backend stays read-only. */
    memset(worker,0,sizeof worker);memset(id,0,sizeof id);
    if(!ok){if(maintenance)build8_mining_v2_maintenance(m,true);build8_worker_runtime_close_v2(c,m);}
    return ok;
}
