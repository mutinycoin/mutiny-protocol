#include "worker_connection_v2.h"
#include <string.h>
extern void OPENSSL_cleanse(void *,size_t);
static int journal_local_separate(build8_worker_connection_v2 *,void *,size_t,uint8_t *,uint8_t *,const build8_worker_journal_local_v2 *);
static int journal_current(build8_worker_connection_v2 *,const uint8_t[64],uint64_t,uint64_t,uint64_t *);
static int journal_argument(const build8_worker_connection_v2 *,const void *,size_t);
enum {SEND_HELLO=1,WAIT_RESPONSE=2,SEND_FINISH=3,WAIT_FINISH=4,ACTIVE=5};
size_t build8_worker_connection_v2_size(void){return sizeof(build8_worker_connection_v2);}
size_t build8_worker_connection_v2_alignment(void){return _Alignof(build8_worker_connection_v2);}
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
void build8_worker_connection_v2_close(build8_worker_connection_v2 *s){
    if(!s)return;
    build8_worker_pending_v2_clear(s->pending);build8_worker_receive_v2_clear(&s->receive);b8_worker_channel_clear(&s->channel);
    if(s->rx)OPENSSL_cleanse(s->rx,16444);
    if(s->tx)OPENSSL_cleanse(s->tx,16444);
    OPENSSL_cleanse(s,sizeof *s);
}
static int connection_start(build8_worker_connection_v2 *s,void *pending,size_t pn,uint8_t *rx,uint8_t *tx,
    const build8_worker_local_v2 *a,uint64_t h,uint64_t e,const build8_worker_journal_local_v2 *j){
    if(!s||!a||(j?(!a->private_store||a->public_store||!journal_local_separate(s,pending,pn,rx,tx,j)):(a->private_store||a->public_store))||!a->node_descriptor_length||a->node_descriptor_length>2048
        ||a->verification_workspace_length<4127||a->verification_workspace_length>65536)return 0;
    const void *p[]={s,pending,rx,tx,a,a->current,a->node_descriptor,a->verification_workspace};
    size_t n[]={sizeof *s,pn,16444,16444,sizeof *a,a->current?sizeof *a->current:0,a->node_descriptor_length,a->verification_workspace_length};
    for(unsigned i=0;i<8;i++){
        if(!p[i])return 0;
        for(unsigned j=0;j<i;j++)if(!separate(p[i],n[i],p[j],n[j]))return 0;
    }
    OPENSSL_cleanse(s,sizeof *s);s->mode=j?2u:0u;s->journal_local=j;s->rx=rx;s->tx=tx;OPENSSL_cleanse(tx,16444);
    s->pending=build8_worker_pending_v2_init(pending,pn);
    if(!s->pending||!(j?build8_worker_journal_pending_v2_begin(s->pending,j,h,e,tx):build8_worker_v2_handshake_begin(s->pending,a,h,e,tx))){build8_worker_connection_v2_close(s);return 0;}
    OPENSSL_cleanse(rx,16444);s->phase=SEND_HELLO;s->tx_length=1722;return 1;
}
static int connection_tick(build8_worker_connection_v2 *s,const uint8_t context[64],uint64_t h,uint64_t e,uint64_t now){
    if(!s)return 0;
    if(s->mode==2&&!journal_current(s,context,h,e,&now)){build8_worker_connection_v2_close(s);return 0;}
    int ok=s->phase==ACTIVE?b8_worker_channel_expire(&s->channel,context,h,e,now)
        :s->phase>=SEND_HELLO&&s->phase<=WAIT_FINISH&&build8_worker_pending_v2_expire(s->pending,now);
    if(!ok)build8_worker_connection_v2_close(s);
    return ok;
}
static const uint8_t *connection_out(const build8_worker_connection_v2 *s,size_t *n){
    if(!s||!n||!separate(s,sizeof *s,n,sizeof *n))return NULL;
    if((s->rx&&!separate(s->rx,16444,n,sizeof *n))||(s->tx&&!separate(s->tx,16444,n,sizeof *n))
        ||(s->pending&&!separate(s->pending,build8_worker_pending_v2_size(),n,sizeof *n)))return NULL;
    *n=0;if((s->phase!=SEND_HELLO&&s->phase!=SEND_FINISH&&s->phase!=ACTIVE)||!s->tx||s->tx_sent>=s->tx_length)return NULL;
    *n=s->tx_length-s->tx_sent;return s->tx+s->tx_sent;
}
static int connection_authenticated(build8_worker_connection_v2 *s,const uint8_t context[64],uint64_t h,uint64_t e,uint64_t now){
    return connection_tick(s,context,h,e,now)&&s->phase==ACTIVE;
}
static int connection_sent(build8_worker_connection_v2 *s,size_t n){
    if(!s)return 0;
    if((s->phase!=SEND_HELLO&&s->phase!=SEND_FINISH&&s->phase!=ACTIVE)||!n||s->tx_sent>s->tx_length||n>s->tx_length-s->tx_sent){build8_worker_connection_v2_close(s);return 0;}
    s->tx_sent+=n;if(s->tx_sent<s->tx_length)return 1;
    OPENSSL_cleanse(s->tx,16444);s->tx_sent=s->tx_length=0;
    if(s->phase==ACTIVE)return 1;
    unsigned kind=s->phase==SEND_HELLO?BUILD8_WORKER_RX_RESPONSE:BUILD8_WORKER_RX_FINISHED;
    s->phase=s->phase==SEND_HELLO?WAIT_RESPONSE:WAIT_FINISH;
    if(!build8_worker_receive_v2_init(&s->receive,s->rx,16444,kind)){build8_worker_connection_v2_close(s);return 0;}return 1;
}
static int connection_send(build8_worker_connection_v2 *s,const uint8_t context[64],uint64_t h,uint64_t e,uint64_t now,const uint8_t *plain,size_t n){
    if(!s)return BUILD8_CONNECTION_CLOSED;
    if(s->mode==2&&(!journal_argument(s,context,64)||!journal_argument(s,plain,n))){build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;}
    if(!context||!separate(s,sizeof *s,context,64)||!separate(s->rx,16444,context,64)
        ||!separate(s->tx,16444,context,64)||!separate(s->pending,build8_worker_pending_v2_size(),context,64)){
        build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;
    }
    if(s->phase!=ACTIVE||!connection_tick(s,context,h,e,now)){build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;}
    if(s->tx_length)return BUILD8_CONNECTION_BUSY;
    if(!plain||!context||!n||n>16384||!separate(s,sizeof *s,plain,n)||!separate(s,sizeof *s,context,64)
        ||!separate(s->rx,16444,plain,n)||!separate(s->rx,16444,context,64)
        ||!separate(s->pending,build8_worker_pending_v2_size(),plain,n)||!separate(s->pending,build8_worker_pending_v2_size(),context,64)){
        build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;
    }
    size_t length=0;
    if(!b8_worker_seal(&s->channel,context,h,e,now,plain,n,s->tx,16444,&length)){build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;}
    if(s->mode==2&&!connection_tick(s,context,h,e,now)){return BUILD8_CONNECTION_CLOSED;}
    s->tx_length=length;s->tx_sent=0;return BUILD8_CONNECTION_SEND;
}
static int connection_receive(build8_worker_connection_v2 *s,const build8_worker_local_v2 *a,const uint8_t context[64],
    uint64_t h,uint64_t e,uint64_t now,const uint8_t *wire,size_t n,size_t *consumed,uint8_t *plain,size_t capacity,size_t *written){
    if(!s)return 0;
    if(s->mode==2&&(!journal_argument(s,context,64)||!journal_argument(s,wire,n)||!journal_argument(s,consumed,sizeof *consumed)
        ||!journal_argument(s,plain,capacity)||!journal_argument(s,written,sizeof *written))){build8_worker_connection_v2_close(s);return 0;}
    if(!consumed||!written||!plain||!capacity||capacity>16384||!a||(s->mode==2?(!a->private_store||a->public_store||!s->journal_local||a!=&s->journal_local->base):(a->private_store||a->public_store))
        ||!a->node_descriptor_length||a->node_descriptor_length>2048||a->verification_workspace_length<4127
        ||a->verification_workspace_length>65536){build8_worker_connection_v2_close(s);return 0;}
    const void *p[]={s,a,context,wire,consumed,plain,written,s->rx,s->tx,s->pending,a->current,a->node_descriptor,a->verification_workspace};
    size_t z[]={sizeof *s,sizeof *a,64,n,sizeof *consumed,capacity,sizeof *written,16444,16444,build8_worker_pending_v2_size(),
        a->current?sizeof *a->current:0,a->node_descriptor_length,a->verification_workspace_length};
    for(unsigned i=0;i<13;i++){
        if(!p[i]){build8_worker_connection_v2_close(s);return 0;}
        for(unsigned j=0;j<i;j++)if(!separate(p[i],z[i],p[j],z[j])){build8_worker_connection_v2_close(s);return 0;}
    }
    *written=*consumed=0;OPENSSL_cleanse(plain,capacity);
    if(!connection_tick(s,context,h,e,now))return 0;
    if(s->phase!=WAIT_RESPONSE&&s->phase!=WAIT_FINISH&&s->phase!=ACTIVE){build8_worker_connection_v2_close(s);return 0;}
    if(!build8_worker_receive_v2_feed(&s->receive,wire,n,consumed)){build8_worker_connection_v2_close(s);return 0;}
    if(!s->receive.ready)return BUILD8_CONNECTION_MORE;
    size_t length=0;const uint8_t *message=build8_worker_receive_v2_message(&s->receive,&length);int result=0;
    if(s->phase==WAIT_RESPONSE){
        if(s->mode==2?build8_worker_journal_pending_v2_accept(s->pending,s->journal_local,h,e,message,length,s->tx):build8_worker_v2_handshake_accept(s->pending,a,h,e,message,length,s->tx)){
            s->phase=SEND_FINISH;s->tx_length=130;s->tx_sent=0;result=BUILD8_CONNECTION_SEND;
        }
    }else if(s->phase==WAIT_FINISH){
        if(s->mode==2?build8_worker_journal_pending_v2_finish(s->pending,s->journal_local,h,e,message,length,&s->channel):build8_worker_v2_handshake_finish(s->pending,a,h,e,message,length,&s->channel)){
            s->phase=ACTIVE;result=BUILD8_CONNECTION_CONFIRMED;
        }
    }else if(b8_worker_open(&s->channel,context,h,e,now,message,length,plain,capacity,written))result=BUILD8_CONNECTION_MESSAGE;
    if(!result||(s->mode==2&&!connection_tick(s,context,h,e,now))){*written=0;OPENSSL_cleanse(plain,capacity);build8_worker_connection_v2_close(s);return 0;}
    build8_worker_receive_v2_clear(&s->receive);
    if(s->phase==ACTIVE&&!build8_worker_receive_v2_init(&s->receive,s->rx,16444,BUILD8_WORKER_RX_FRAME)){
        *written=0;OPENSSL_cleanse(plain,capacity);build8_worker_connection_v2_close(s);return 0;
    }return result;
}


/* Separate journal mode, never inferred from a packet or legacy NULL backend.
 * Local objects are immutable owner-task configuration for this lifetime.
 * Reconfiguration needs close and a fresh begin. No persisted private ABI. */
static int journal_local_separate(build8_worker_connection_v2 *s,void *pending,size_t pn,uint8_t *rx,uint8_t *tx,
    const build8_worker_journal_local_v2 *j){
    if(!j||!j->journal||!j->authority||!j->base.private_store||j->base.public_store||!j->base.current
        ||!j->base.node_descriptor||!j->base.node_descriptor_length||j->base.node_descriptor_length>2048
        ||!j->base.verification_workspace||j->base.verification_workspace_length<4127
        ||j->base.verification_workspace_length>65536||!j->base.clock_ms)return 0;
    const void *local[]={j,j->journal,j->authority,j->base.private_store,j->base.current,j->base.node_descriptor,j->base.verification_workspace};
    size_t lengths[]={sizeof *j,sizeof *j->journal,sizeof *j->authority,sizeof *j->base.private_store,
        sizeof *j->base.current,j->base.node_descriptor_length,j->base.verification_workspace_length};
    const void *owned[]={s,pending,rx,tx};size_t sizes[]={sizeof *s,pn,16444,16444};
    for(unsigned i=0;i<7;i++){
        for(unsigned k=0;k<4;k++)if(!owned[k]||!separate(local[i],lengths[i],owned[k],sizes[k]))return 0;
        for(unsigned k=0;k<i;k++)if(!separate(local[i],lengths[i],local[k],lengths[k]))return 0;
    }
    return 1;
}
static int journal_current(build8_worker_connection_v2 *s,const uint8_t context[64],uint64_t h,uint64_t e,uint64_t *now){
    if(!s||s->mode!=2||!s->journal_local||!context||!now||!journal_argument(s,context,64))return 0;
    const build8_worker_journal_local_v2 *j=s->journal_local;
    if(!journal_local_separate(s,s->pending,build8_worker_pending_v2_size(),s->rx,s->tx,j))return 0;
    uint8_t worker[57]={0},id[64]={0};
    int ok=build8_v2_assignment_journal_current(j->base.private_store,j->journal,j->authority,j->base.current,
        j->base.node_descriptor,j->base.node_descriptor_length,h,e,j->base.h256,j->base.h512,
        j->base.verification_workspace,j->base.verification_workspace_length,worker,id)==1&&!memcmp(id,context,64);
    uint64_t sampled=j->base.clock_ms(j->base.platform);
    if(sampled==UINT64_MAX||sampled<*now)ok=0;
    OPENSSL_cleanse(worker,sizeof worker);OPENSSL_cleanse(id,sizeof id);
    if(ok)*now=sampled;
    return ok;
}
static int journal_argument(const build8_worker_connection_v2 *s,const void *p,size_t n){
    if(!s||!p||!n||!s->journal_local)return 0;
    const build8_worker_journal_local_v2 *j=s->journal_local;
    if(!j->journal||!j->authority||!j->base.private_store||!j->base.current)return 0;
    const void *v[]={s,s->pending,s->rx,s->tx,j,j->journal,j->authority,j->base.private_store,j->base.current,j->base.node_descriptor,j->base.verification_workspace};
    size_t z[]={sizeof *s,build8_worker_pending_v2_size(),16444,16444,sizeof *j,sizeof *j->journal,sizeof *j->authority,
        sizeof *j->base.private_store,sizeof *j->base.current,j->base.node_descriptor_length,j->base.verification_workspace_length};
    for(unsigned i=0;i<11;i++)if(!v[i]||!separate(p,n,v[i],z[i]))return 0;
    return 1;
}
static int legacy(build8_worker_connection_v2 *s){
    if(!s||s->mode!=0){if(s)build8_worker_connection_v2_close(s);return 0;}return 1;
}
static int journal_mode(build8_worker_connection_v2 *s){
    if(!s||s->mode!=2||!s->journal_local){if(s)build8_worker_connection_v2_close(s);return 0;}return 1;
}
int build8_worker_connection_v2_start(build8_worker_connection_v2 *s,void *p,size_t n,uint8_t *rx,uint8_t *tx,
    const build8_worker_local_v2 *a,uint64_t h,uint64_t e){return connection_start(s,p,n,rx,tx,a,h,e,NULL);}
int build8_worker_connection_v2_tick(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now){return legacy(s)&&connection_tick(s,c,h,e,now);}
int build8_worker_connection_v2_authenticated(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now){return legacy(s)&&connection_authenticated(s,c,h,e,now);}
const uint8_t *build8_worker_connection_v2_out(const build8_worker_connection_v2 *s,size_t *n){return s&&s->mode==0?connection_out(s,n):NULL;}
int build8_worker_connection_v2_sent(build8_worker_connection_v2 *s,size_t n){return legacy(s)&&connection_sent(s,n);}
int build8_worker_connection_v2_send(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,const uint8_t *p,size_t n){return legacy(s)?connection_send(s,c,h,e,now,p,n):BUILD8_CONNECTION_CLOSED;}
int build8_worker_connection_v2_receive(build8_worker_connection_v2 *s,const build8_worker_local_v2 *a,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,const uint8_t *p,size_t n,size_t *used,uint8_t *out,size_t cap,size_t *written){return legacy(s)?connection_receive(s,a,c,h,e,now,p,n,used,out,cap,written):BUILD8_CONNECTION_CLOSED;}
int build8_worker_connection_journal_v2_start(build8_worker_connection_v2 *s,void *p,size_t n,uint8_t *rx,uint8_t *tx,const build8_worker_journal_local_v2 *a,uint64_t h,uint64_t e){return a?connection_start(s,p,n,rx,tx,&a->base,h,e,a):0;}
int build8_worker_connection_journal_v2_tick(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now){return journal_mode(s)&&connection_tick(s,c,h,e,now);}
int build8_worker_connection_journal_v2_authenticated(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now){return journal_mode(s)&&connection_authenticated(s,c,h,e,now);}
const uint8_t *build8_worker_connection_journal_v2_out(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,size_t *n){
    if(!journal_mode(s))return NULL;
    if(!journal_argument(s,n,sizeof *n)||!separate(c,64,n,sizeof *n)){build8_worker_connection_v2_close(s);return NULL;}
    return connection_tick(s,c,h,e,now)?connection_out(s,n):NULL;
}
int build8_worker_connection_journal_v2_sent(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,size_t n){return journal_mode(s)&&connection_tick(s,c,h,e,now)&&connection_sent(s,n);}
int build8_worker_connection_journal_v2_send(build8_worker_connection_v2 *s,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,const uint8_t *p,size_t n){return journal_mode(s)?connection_send(s,c,h,e,now,p,n):BUILD8_CONNECTION_CLOSED;}
int build8_worker_connection_journal_v2_receive(build8_worker_connection_v2 *s,const build8_worker_journal_local_v2 *a,const uint8_t c[64],uint64_t h,uint64_t e,uint64_t now,const uint8_t *p,size_t n,size_t *used,uint8_t *out,size_t cap,size_t *written){
    if(!journal_mode(s))return BUILD8_CONNECTION_CLOSED;
    if(!a||a!=s->journal_local){build8_worker_connection_v2_close(s);return BUILD8_CONNECTION_CLOSED;}
    return connection_receive(s,&a->base,c,h,e,now,p,n,used,out,cap,written);
}
