#include "worker_stream_v2.h"
#include <string.h>
extern void OPENSSL_cleanse(void *,size_t);
size_t build8_worker_stream_v2_size(void){return sizeof(build8_worker_stream_v2);}
void build8_worker_stream_v2_init(build8_worker_stream_v2 *s){if(s){OPENSSL_cleanse(s,sizeof *s);s->started=true;}}
void build8_worker_stream_v2_close(build8_worker_stream_v2 *s,build8_worker_connection_v2 *c,build8_mining_control_v2 *m){
    build8_worker_runtime_close_v2(c,m);if(s)OPENSSL_cleanse(s,sizeof *s);
}
static int tick(build8_worker_stream_v2 *s,build8_worker_connection_v2 *c,const uint8_t context[64],
    uint64_t height,uint64_t epoch,build8_v2_monotonic_clock clock,void *arg,uint64_t *now,int journal){
    if(!clock(arg,now)||*now<s->last_clock)return 0;
    s->last_clock=*now;return journal?build8_worker_connection_journal_v2_tick(c,context,height,epoch,*now):build8_worker_connection_v2_tick(c,context,height,epoch,*now);
}
static int step(build8_worker_stream_v2 *s,build8_worker_connection_v2 *c,build8_mining_control_v2 *m,
    const build8_worker_local_v2 *local,const uint8_t context[64],uint64_t height,uint64_t epoch,
    build8_v2_monotonic_clock clock,build8_worker_stream_read_v2 read,build8_worker_stream_write_v2 write,void *arg,
    uint8_t *plain,size_t capacity,size_t *written,const build8_worker_journal_local_v2 *journal){
    /* These are local owner API arguments, not peer-provided pointers. */
    if(!s||!c||!local||!context||!clock||!read||!write||!plain||!written||!capacity||capacity>16384)goto fail;
    *written=0;OPENSSL_cleanse(plain,capacity);
    if(!s->started||s->offset>s->used||s->used>sizeof s->input)goto fail;
    uint64_t now=0;if(!tick(s,c,context,height,epoch,clock,arg,&now,journal!=NULL))goto fail;
    size_t n=0;const uint8_t *out=journal?build8_worker_connection_journal_v2_out(c,context,height,epoch,now,&n):build8_worker_connection_v2_out(c,&n);
    /* Once confirmed, an occupied or blocked transmit queue cannot starve
     * inbound control frames. Handshake phases retain their required order. */
    int active=journal?build8_worker_connection_journal_v2_authenticated(c,context,height,epoch,now):build8_worker_connection_v2_authenticated(c,context,height,epoch,now);
    /* An authority denial may have cleared the queued out pointer's object.
     * Do not write even cleansed queued bytes after that denial. */
    if(journal&&(c->mode!=2||!tick(s,c,context,height,epoch,clock,arg,&now,1)))goto fail;
    if(out&&!(active&&s->prefer_read)){
        size_t want=n>1024?1024:n;int sent=write(arg,out,want);
        if(sent<0||(size_t)sent>want||!tick(s,c,context,height,epoch,clock,arg,&now,journal!=NULL))goto fail;
        if(sent&&!(journal?build8_worker_connection_journal_v2_sent(c,context,height,epoch,now,(size_t)sent):build8_worker_connection_v2_sent(c,(size_t)sent)))goto fail;
        s->prefer_read=true;
        return BUILD8_CONNECTION_MORE;
    }
    s->prefer_read=false;
    if(s->offset==s->used){
        s->offset=s->used=0;int got=read(arg,s->input,sizeof s->input);
        if(got<0||(size_t)got>sizeof s->input||!tick(s,c,context,height,epoch,clock,arg,&now,journal!=NULL))goto fail;
        if(!got)return BUILD8_CONNECTION_MORE;
        s->used=(size_t)got;
    }
    size_t consumed=0;
    int result=journal?build8_worker_connection_journal_v2_receive(c,journal,context,height,epoch,now,
        s->input+s->offset,s->used-s->offset,&consumed,plain,capacity,written):
        build8_worker_connection_v2_receive(c,local,context,height,epoch,now,s->input+s->offset,s->used-s->offset,&consumed,plain,capacity,written);
    if(!result||!consumed||consumed>s->used-s->offset||!tick(s,c,context,height,epoch,clock,arg,&now,journal!=NULL))goto fail;
    OPENSSL_cleanse(s->input+s->offset,consumed);s->offset+=consumed;
    return result;
fail:
    if(written)*written=0;
    if(plain&&capacity<=16384)OPENSSL_cleanse(plain,capacity);
    build8_worker_stream_v2_close(s,c,m);return BUILD8_CONNECTION_CLOSED;
}

int build8_worker_stream_v2_step(build8_worker_stream_v2 *s,build8_worker_connection_v2 *c,build8_mining_control_v2 *m,
    const build8_worker_local_v2 *a,const uint8_t context[64],uint64_t h,uint64_t e,build8_v2_monotonic_clock clock,
    build8_worker_stream_read_v2 read,build8_worker_stream_write_v2 write,void *arg,uint8_t *plain,size_t cap,size_t *written){
    return step(s,c,m,a,context,h,e,clock,read,write,arg,plain,cap,written,NULL);
}
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
int build8_worker_stream_journal_v2_step(build8_worker_stream_v2 *s,build8_worker_connection_v2 *c,build8_mining_control_v2 *m,
    const build8_worker_journal_local_v2 *a,const uint8_t context[64],uint64_t h,uint64_t e,build8_v2_monotonic_clock clock,
    build8_worker_stream_read_v2 read,build8_worker_stream_write_v2 write,void *arg,uint8_t *plain,size_t cap,size_t *written){
    /* Validate nested local/storage/owner/output ranges before touching outputs.
     * Bad API ranges refuse unchanged, never clear an overlapping private key. */
    if(!s||!c||!m||!a||!a->journal||!a->authority||!a->base.private_store||!a->base.current
        ||!a->base.node_descriptor||!a->base.verification_workspace||!context||!plain||!written||!cap||cap>16384)return 0;
    const void *p[]={s,c,m,a,a->journal,a->authority,a->base.private_store,a->base.current,a->base.node_descriptor,
        a->base.verification_workspace,c->pending,c->rx,c->tx,context,plain,written};
    size_t n[]={sizeof *s,sizeof *c,sizeof *m,sizeof *a,sizeof *a->journal,sizeof *a->authority,sizeof *a->base.private_store,
        sizeof *a->base.current,a->base.node_descriptor_length,a->base.verification_workspace_length,
        build8_worker_pending_v2_size(),16444,16444,64,cap,sizeof *written};
    for(unsigned i=0;i<16;i++){
        if(!p[i])return 0;
        for(unsigned j=0;j<i;j++)if(!separate(p[i],n[i],p[j],n[j]))return 0;
    }
    if(c->mode!=2||c->journal_local!=a){build8_worker_stream_v2_close(s,c,m);return 0;}
    return step(s,c,m,&a->base,context,h,e,clock,read,write,arg,plain,cap,written,a);
}
