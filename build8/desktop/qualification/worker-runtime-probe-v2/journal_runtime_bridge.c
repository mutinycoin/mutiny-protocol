/* PUBLIC TEST-only callback I/O over the actual production C stream/controller.
 * No fd/device/NVS/entropy provider qualification. Own canonical authority is
 * supplied by the independent Rust verified-chain adapter, never these buffers. */
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_journal_runtime_v2.h"
#ifdef BUILD8_QUAL_POSIX_SOCKET
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.h"
#include <fcntl.h>
#include <errno.h>
#endif
#include <assert.h>
#include <string.h>
typedef struct {
    build8_worker_connection_v2 connection;
    build8_mining_control_v2 mining;
    build8_worker_stream_v2 stream;
    build8_worker_journal_runtime_v2 runtime;
    const build8_worker_journal_local_v2 *local;
    uint8_t session[64],rx[16444],tx[16444],in[65536],out[65536];
    size_t in_length,in_offset,out_length;
    uint64_t height,epoch;
    unsigned fault,reads,writes,partial_reads,partial_writes;
#ifdef BUILD8_QUAL_POSIX_SOCKET
    build8_worker_socket_owner_v2 socket;
    int socket_original_fd;
#endif
} test_owner;
size_t build8_qual_journal_owner_size(void){return sizeof(test_owner);}
size_t build8_qual_journal_owner_alignment(void){return _Alignof(test_owner);}
static int clock_ms(void *arg,uint64_t *out){
    test_owner *s=arg;*out=s->local->base.clock_ms(s->local->base.platform);return s->fault!=3&&*out!=UINT64_MAX;
}
static int read_io(void *arg,uint8_t *out,size_t capacity){
    test_owner *s=arg;assert(++s->reads<=1&&capacity<=1024);
    if(s->fault==1)return -1;
    if(s->fault==2)return (int)capacity+1;
    size_t n=s->in_length-s->in_offset;if(n>capacity)n=capacity;
    if(!s->partial_reads&&n>17){n=17;s->partial_reads++;}
    memcpy(out,s->in+s->in_offset,n);s->in_offset+=n;return (int)n;
}
static int write_io(void *arg,const uint8_t *raw,size_t n){
    test_owner *s=arg;assert(++s->writes<=1&&n<=1024);
    if(s->fault==6)return -1;
    if(s->fault==7)return (int)n+1;
    if(s->fault==8)return 0;
    if(!s->partial_writes&&n>1){n--;s->partial_writes++;}
    assert(n<=sizeof s->out-s->out_length);memcpy(s->out+s->out_length,raw,n);s->out_length+=n;return (int)n;
}
int build8_qual_journal_owner_init(test_owner *s,const build8_worker_journal_local_v2 *a,void *pending,size_t pn,
    const build8_work_context *work,const uint8_t session[64],uint64_t height,uint64_t epoch){
    assert(s&&a&&work&&session);memset(s,0,sizeof *s);s->local=a;s->height=height;s->epoch=epoch;memcpy(s->session,session,64);
    assert(work->height==height);
    if(!build8_mining_v2_init(&s->mining,work,a->base.current->effective_epoch,a->base.current->valid_until_height,0))return 0;
    build8_mining_v2_run(&s->mining,true);build8_worker_stream_v2_init(&s->stream);
    return build8_worker_connection_journal_v2_start(&s->connection,pending,pn,s->rx,s->tx,a,height,epoch);
}
void build8_qual_journal_owner_input(test_owner *s,const uint8_t *raw,size_t n){
    assert(s->in_offset==s->in_length&&n<=sizeof s->in);memcpy(s->in,raw,n);s->in_length=n;s->in_offset=0;
}
size_t build8_qual_journal_owner_output(test_owner *s,uint8_t *out,size_t n){
    assert(s->out_length<=n);n=s->out_length;memcpy(out,s->out,n);memset(s->out,0,n);s->out_length=0;return n;
}
#ifdef BUILD8_QUAL_POSIX_SOCKET
/* Successful attachment transfers sole fd ownership to the actual production owner. */
int build8_qual_journal_owner_socket(test_owner *s,int fd){
    if(!s||!build8_worker_socket_owner_v2_init(&s->socket,fd))return 0;
    s->socket_original_fd=fd;return 1;
}
static int socket_read(void *arg,uint8_t *out,size_t n){return build8_worker_socket_owner_v2_read(&((test_owner *)arg)->socket,out,n);}
static int socket_write(void *arg,const uint8_t *raw,size_t n){return build8_worker_socket_owner_v2_write(&((test_owner *)arg)->socket,raw,n);}
int build8_qual_journal_owner_socket_closed(test_owner *s){
    if(!s||!s->socket.initialized||!s->socket.closed||s->socket.close_error||s->socket.io.fd!=-1)return 0;
    errno=0;return fcntl(s->socket_original_fd,F_GETFD)==-1&&errno==EBADF;
}
#endif
int build8_qual_journal_owner_step(test_owner *s,uint8_t *plain,size_t cap,size_t *written){
#ifdef BUILD8_QUAL_POSIX_SOCKET
    if(s->socket.initialized){
        int result=s->runtime.initialized?
            build8_worker_journal_runtime_v2_step(&s->runtime,&s->stream,clock_ms,socket_read,socket_write,s,plain,cap,written):
            build8_worker_socket_owner_journal_v2_step(&s->socket,&s->stream,&s->connection,&s->mining,s->local,
                s->session,s->height,s->epoch,clock_ms,s,plain,cap,written);
        if(!result)(void)build8_worker_socket_owner_v2_retire(&s->socket,&s->stream,&s->connection,&s->mining);
        return result;
    }
#endif
    s->reads=s->writes=0;
    int result=s->runtime.initialized?build8_worker_journal_runtime_v2_step(&s->runtime,&s->stream,clock_ms,read_io,write_io,s,plain,cap,written):
        build8_worker_stream_journal_v2_step(&s->stream,&s->connection,&s->mining,s->local,s->session,s->height,s->epoch,
            clock_ms,read_io,write_io,s,plain,cap,written);
    assert(s->reads+s->writes<=1);return result;
}
int build8_qual_journal_owner_confirm(test_owner *s){
    return build8_worker_journal_runtime_v2_init(&s->runtime,&s->connection,&s->mining,s->local,s->height,s->epoch);
}
int build8_qual_journal_owner_send(test_owner *s,const uint8_t *raw,size_t n){return build8_worker_journal_runtime_v2_send(&s->runtime,raw,n);}
int build8_qual_journal_owner_request(test_owner *s,const uint8_t nonce[32]){return build8_worker_journal_runtime_v2_request(&s->runtime,nonce,clock_ms,s);}
int build8_qual_journal_owner_offer(test_owner *s,const uint8_t *raw,size_t n){return build8_worker_journal_runtime_v2_offer(&s->runtime,raw,n,clock_ms,s);}
int build8_qual_journal_owner_nonce(test_owner *s,uint64_t *out){return build8_worker_journal_runtime_v2_nonce(&s->runtime,clock_ms,s,out);}
int build8_qual_journal_owner_found(test_owner *s,const uint8_t id[32],uint64_t nonce){
    build8_authorized_work out={0};int result=build8_worker_journal_runtime_v2_found(&s->runtime,id,nonce,clock_ms,s,&out);
    if(result)assert(out.nonce_end==nonce&&s->mining.accounting&&!s->mining.work_valid&&!s->mining.job_live);return result;
}
void build8_qual_journal_owner_fault(test_owner *s,unsigned fault){s->fault=fault;}
void build8_qual_journal_owner_maintenance(test_owner *s){build8_mining_v2_maintenance(&s->mining,true);}
void build8_qual_journal_owner_accounting(test_owner *s){build8_mining_v2_accounting(&s->mining,true);}
unsigned build8_qual_journal_owner_flags(test_owner *s){return (s->mining.run?1u:0u)|(s->mining.accounting?2u:0u)|(s->mining.session?4u:0u)|(s->mining.request_pending?8u:0u)|(s->mining.work_valid?16u:0u);}
uint64_t build8_qual_journal_owner_ticket(test_owner *s){return s->mining.last_ticket;}
void build8_qual_journal_owner_close(test_owner *s){
#ifdef BUILD8_QUAL_POSIX_SOCKET
    if(s->socket.initialized)(void)build8_worker_socket_owner_v2_retire(&s->socket,&s->stream,&s->connection,&s->mining);
    else
#endif
    build8_worker_stream_v2_close(&s->stream,&s->connection,&s->mining);
    build8_worker_journal_runtime_v2_close(&s->runtime);
}
int build8_qual_journal_owner_cleared(test_owner *s){
    const uint8_t *p=(const uint8_t *)&s->connection;for(size_t i=0;i<sizeof s->connection;i++)if(p[i])return 0;
    for(size_t i=0;i<sizeof s->rx;i++)if(s->rx[i]||s->tx[i])return 0;return !s->mining.session&&!s->mining.work_valid;
}
int build8_qual_journal_owner_legacy_bypass(test_owner *s){return build8_worker_connection_v2_tick(&s->connection,s->session,s->height,s->epoch,0);}
