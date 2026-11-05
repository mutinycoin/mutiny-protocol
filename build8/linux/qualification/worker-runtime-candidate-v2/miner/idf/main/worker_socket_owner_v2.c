#include "worker_socket_owner_v2.h"
#include "lwip/sockets.h"
#include <errno.h>
extern void OPENSSL_cleanse(void *,size_t);
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return a&&b&&an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
int build8_worker_socket_owner_v2_init(build8_worker_socket_owner_v2 *s,int fd){
    if(!s||s->initialized)return 0;
    build8_worker_socket_io_v2 io;
    if(!build8_worker_socket_io_v2_init(&io,fd))return 0;
    s->io=io;s->close_error=0;s->closed=false;s->initialized=true;return 1;
}
int build8_worker_socket_owner_v2_read(void *arg,uint8_t *out,size_t n){
    build8_worker_socket_owner_v2 *s=arg;
    if(!s||!s->initialized||s->closed||s->close_error||!separate(s,sizeof *s,out,n))return -1;
    return build8_worker_socket_io_v2_read(&s->io,out,n);
}
int build8_worker_socket_owner_v2_write(void *arg,const uint8_t *in,size_t n){
    build8_worker_socket_owner_v2 *s=arg;
    if(!s||!s->initialized||s->closed||s->close_error||!separate(s,sizeof *s,in,n))return -1;
    return build8_worker_socket_io_v2_write(&s->io,in,n);
}
typedef struct {build8_worker_socket_owner_v2 *owner;build8_v2_monotonic_clock clock;void *clock_arg;} step_io;
static int step_clock(void *arg,uint64_t *now){step_io *io=arg;return io->clock&&io->clock(io->clock_arg,now);}
static int step_read(void *arg,uint8_t *out,size_t n){return build8_worker_socket_owner_v2_read(((step_io *)arg)->owner,out,n);}
static int step_write(void *arg,const uint8_t *in,size_t n){return build8_worker_socket_owner_v2_write(((step_io *)arg)->owner,in,n);}
int build8_worker_socket_owner_v2_step(build8_worker_socket_owner_v2 *s,
    build8_worker_stream_v2 *stream,build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining,
    const build8_worker_local_v2 *local,const uint8_t context[64],uint64_t height,uint64_t epoch,
    build8_v2_monotonic_clock clock,void *clock_arg,uint8_t *plain,size_t capacity,size_t *written){
    if(!s||!s->initialized||s->closed||s->close_error||s->io.fd<0){
        if(written)*written=0;
        if(plain&&capacity<=16384)OPENSSL_cleanse(plain,capacity);
        (void)build8_worker_socket_owner_v2_retire(s,stream,connection,mining);
        return BUILD8_CONNECTION_CLOSED;
    }
    step_io io={s,clock,clock_arg};
    int result=build8_worker_stream_v2_step(stream,connection,mining,local,context,height,epoch,
        step_clock,step_read,step_write,&io,plain,capacity,written);
    if(result==BUILD8_CONNECTION_CLOSED)
        (void)build8_worker_socket_owner_v2_retire(s,stream,connection,mining);
    return result;
}
int build8_worker_socket_owner_v2_retire(build8_worker_socket_owner_v2 *s,
    build8_worker_stream_v2 *stream,build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining){
    const void *p[]={s,stream,connection,mining};size_t n[]={sizeof *s,sizeof *stream,sizeof *connection,sizeof *mining};
    for(unsigned i=0;i<4;i++){
        if(!p[i])return 0;
        for(unsigned j=0;j<i;j++)if(!separate(p[i],n[i],p[j],n[j]))return 0;
    }
    const void *b[]={connection->rx,connection->tx,connection->pending};
    size_t bn[]={16444,16444,build8_worker_pending_v2_size()};
    for(unsigned i=0;i<3;i++)if(b[i]){
        for(unsigned j=0;j<4;j++)if(!separate(b[i],bn[i],p[j],n[j]))return 0;
        for(unsigned j=0;j<i;j++)if(b[j]&&!separate(b[i],bn[i],b[j],bn[j]))return 0;
    }
    build8_worker_stream_v2_close(stream,connection,mining);
    if(!s->initialized)return 0;
    if(s->closed)return s->close_error==0;
    int fd=s->io.fd;s->io.fd=-1;s->closed=true;
    if(fd<0){s->close_error=EBADF;return 0;}
    if(close(fd)!=0){s->close_error=errno?errno:EIO;return 0;}
    return 1;
}
int build8_worker_socket_owner_journal_v2_step(build8_worker_socket_owner_v2 *s,
    build8_worker_stream_v2 *stream,build8_worker_connection_v2 *connection,build8_mining_control_v2 *mining,
    const build8_worker_journal_local_v2 *local,const uint8_t context[64],uint64_t height,uint64_t epoch,
    build8_v2_monotonic_clock clock,void *clock_arg,uint8_t *plain,size_t capacity,size_t *written){
    if(!s||!local||!stream||!connection||!mining||!context||!plain||!written||!capacity||capacity>16384)return 0;
    const void *p[]={stream,connection,mining,local,local->journal,local->authority,local->base.private_store,
        local->base.current,local->base.node_descriptor,local->base.verification_workspace,context,plain,written};
    size_t n[]={sizeof *stream,sizeof *connection,sizeof *mining,sizeof *local,sizeof *local->journal,sizeof *local->authority,
        sizeof *local->base.private_store,sizeof *local->base.current,local->base.node_descriptor_length,
        local->base.verification_workspace_length,64,capacity,sizeof *written};
    for(unsigned i=0;i<13;i++)if(!p[i]||!separate(s,sizeof *s,p[i],n[i]))return 0;
    if(!s->initialized||s->closed||s->close_error||s->io.fd<0){
        *written=0;OPENSSL_cleanse(plain,capacity);
        (void)build8_worker_socket_owner_v2_retire(s,stream,connection,mining);return 0;
    }
    step_io io={s,clock,clock_arg};
    int result=build8_worker_stream_journal_v2_step(stream,connection,mining,local,context,height,epoch,
        step_clock,step_read,step_write,&io,plain,capacity,written);
    if(!result)(void)build8_worker_socket_owner_v2_retire(s,stream,connection,mining);
    return result;
}
int build8_worker_socket_owner_v2_maintenance(build8_worker_socket_owner_v2 *s,
    build8_worker_stream_v2 *stream,build8_worker_connection_v2 *connection,
    build8_worker_accounting_v2 *accounting,build8_mining_control_v2 *mining,build8_v2_domain_hash hash){
    if(!s||!stream||!connection||!accounting||!mining)return 0;
    const void *p[]={s,stream,connection,mining,connection->rx,connection->tx,connection->pending};
    size_t n[]={sizeof *s,sizeof *stream,sizeof *connection,sizeof *mining,16444,16444,build8_worker_pending_v2_size()};
    for(unsigned i=0;i<7;i++)if(p[i]&&!separate(accounting,sizeof *accounting,p[i],n[i]))return 0;
    build8_mining_v2_maintenance(mining,true);
    if(!build8_worker_socket_owner_v2_retire(s,stream,connection,mining))return 0;
    return build8_worker_maintenance_v2_prepare(connection,accounting,mining,hash);
}
