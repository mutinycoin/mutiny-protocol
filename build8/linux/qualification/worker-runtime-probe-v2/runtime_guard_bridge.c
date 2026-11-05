/* Synthetic control-state exercise only. Real signed work qualification is
 * separate; these helpers neither create work nor claim mining eligibility. */
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_runtime_guard_v2.h"
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_stream_v2.h"
#include <assert.h>
#include <string.h>
static build8_mining_control_v2 test_mining;
void build8_qual_runtime_init(void){
    build8_work_context context={0};context.height=1;context.assignment=1;context.last_ticket=77;
    assert(build8_mining_v2_init(&test_mining,&context,0,0,0));
    build8_mining_v2_run(&test_mining,true);
}
int build8_qual_runtime_guard(build8_worker_connection_v2 *s,const uint8_t context[64],uint64_t h,uint64_t now,int maintenance){
    return build8_worker_runtime_guard_v2(s,&test_mining,context,h,0,now,maintenance!=0);
}
void build8_qual_runtime_accounting(void){build8_mining_v2_accounting(&test_mining,true);}
static int later_clock(void *arg,uint64_t *out){(void)arg;*out=100;return 1;}
void build8_qual_runtime_later_clock(void){
    uint8_t nonce[32]={1};assert(test_mining.accounting);
    assert(!build8_mining_v2_request(&test_mining,nonce,later_clock,NULL));
    assert(test_mining.last_clock==100);
}
unsigned build8_qual_runtime_flags(void){
    assert(test_mining.last_ticket==77);
    return (test_mining.run?1:0)|(test_mining.accounting?2:0)|(test_mining.session?4:0)
        |(test_mining.request_pending?8:0)|(test_mining.work_valid?16:0)|(test_mining.maintenance?32:0)|(test_mining.clock_fault?64:0);
}
int build8_qual_runtime_binding(build8_worker_connection_v2 *s,const build8_worker_local_v2 *local,
    const uint8_t worker[57],const uint8_t worker_id[32],unsigned mutation){
    build8_work_context context={0};const build8_enrollment_v2_context *e=local->current;
    memcpy(context.genesis,e->genesis,32);memcpy(context.fingerprint,e->fingerprint,32);
    memcpy(context.license,e->license,32);memcpy(context.coordinator,e->coordinator,32);
    memcpy(context.worker,worker_id,32);context.assignment=e->assignment_generation;
    context.height=1;context.last_ticket=77;context.genesis_timestamp=1000;
    memset(context.parent,4,32);memset(context.target,255,32);
    assert(build8_mining_v2_init(&test_mining,&context,e->effective_epoch,e->valid_until_height,0));
    build8_mining_v2_run(&test_mining,true);build8_mining_v2_accounting(&test_mining,true);
    build8_worker_local_v2 changed=*local;build8_enrollment_v2_context binding=*e;changed.current=&binding;
    switch(mutation){
    case 0:break;
    case 1:test_mining.context.genesis[0]^=1;break;
    case 2:test_mining.context.fingerprint[0]^=1;break;
    case 3:test_mining.context.license[0]^=1;break;
    case 4:test_mining.context.worker[0]^=1;break;
    case 5:test_mining.context.coordinator[0]^=1;break;
    case 6:test_mining.context.assignment++;break;
    case 7:test_mining.effective_epoch++;break;
    case 8:test_mining.valid_until_height++;break;
    /* Matching mining fields are insufficient when the session's exact
     * enrollment context has changed outside those fields. */
    case 9:binding.owner_generation++;break;
    case 10:binding.configuration_generation++;break;
    case 11:binding.device_mac[0]^=1;break;
    case 12:binding.owner_descriptor[0]^=1;break;
    case 13:test_mining.context.height++;break;
    default:assert(0);
    }
    int result=build8_worker_runtime_binding_v2(s,&test_mining,&changed,worker,1,0,0,false);
    assert(build8_qual_runtime_flags()==(unsigned)(result?7:3));return result;
}
static int work_clock(void *arg,uint64_t *out){(void)arg;*out=0;return 1;}
void build8_qual_runtime_request(uint8_t value){
    uint8_t nonce[32];memset(nonce,value,32);
    assert(test_mining.session&&test_mining.last_ticket==77);
    build8_mining_v2_accounting(&test_mining,false);
    assert(build8_mining_v2_request(&test_mining,nonce,work_clock,NULL));
}
int build8_qual_runtime_reject_signed_work(const build8_worker_local_v2 *local,const uint8_t *wire,size_t n){
    uint8_t nonce[32];memset(nonce,9,32);
    int accepted=build8_mining_v2_assign(&test_mining,nonce,0,1000,wire,n,local->h256,local->h512,
        local->verification_workspace,local->verification_workspace_length,work_clock,NULL);
    assert(!accepted&&test_mining.last_ticket==77&&!test_mining.work_valid&&!test_mining.request_pending);
    return !accepted;
}
int build8_qual_runtime_signed_work(const build8_worker_local_v2 *local,const uint8_t *wire,size_t n){
    uint8_t nonce[32];memset(nonce,10,32);
    if(!build8_mining_v2_assign(&test_mining,nonce,0,1000,wire,n,local->h256,local->h512,
        local->verification_workspace,local->verification_workspace_length,work_clock,NULL))return 0;
    assert(test_mining.last_ticket==78);
    uint64_t issued=0;
    assert(build8_mining_v2_nonce(&test_mining,work_clock,NULL,&issued)&&issued==7);
    assert(build8_mining_v2_nonce(&test_mining,work_clock,NULL,&issued)&&issued==8);
    assert(!build8_mining_v2_nonce(&test_mining,work_clock,NULL,&issued));
    uint8_t authority[32];memcpy(authority,test_mining.work.authority,32);build8_authorized_work out;
    assert(build8_mining_v2_found(&test_mining,authority,8,work_clock,NULL,&out));
    assert(out.ticket==78&&out.nonce_end==8&&test_mining.accounting&&!test_mining.work_valid&&!test_mining.job_live);
    /* This exercises admission/retirement, not a PoW success or finality claim. */
    return 1;
}

/* Public synthetic nonblocking stream. No file descriptor or radio access. */
static build8_worker_stream_v2 stream;
static uint8_t stream_in[65536],stream_out[65536];
static size_t stream_in_n,stream_in_pos,stream_out_n;
static unsigned stream_fault,stream_reads,stream_writes;
static uint64_t stream_now;
static int stream_clock(void *arg,uint64_t *out){(void)arg;*out=stream_now;return stream_fault!=3;}
static int stream_read(void *arg,uint8_t *out,size_t n){
    (void)arg;stream_reads++;assert(stream_reads<=1&&n<=1024);
    if(stream_fault==1)return -1;
    if(stream_fault==2)return (int)n+1;
    if(stream_fault==4){stream_now=3600000;return 0;}
    size_t take=stream_in_n-stream_in_pos;if(take>n)take=n;
    /* Real fragmented response, followed by coalesced small application frames. */
    if(stream_fault==5&&take>17)take=17;
    memcpy(out,stream_in+stream_in_pos,take);stream_in_pos+=take;return (int)take;
}
static int stream_write(void *arg,const uint8_t *in,size_t n){
    (void)arg;stream_writes++;assert(stream_writes<=1&&n<=1024);
    if(stream_fault==6)return -1;
    if(stream_fault==7)return (int)n+1;
    if(stream_fault==8)return 0;
    size_t take=n>31?31:n;assert(take<=sizeof stream_out-stream_out_n);
    memcpy(stream_out+stream_out_n,in,take);stream_out_n+=take;return (int)take;
}
void build8_qual_stream_init(void){
    build8_worker_stream_v2_init(&stream);stream_in_n=stream_in_pos=stream_out_n=0;
    stream_fault=stream_reads=stream_writes=0;stream_now=0;
}
void build8_qual_stream_input(const uint8_t *in,size_t n){
    assert(stream_in_pos==stream_in_n&&n<=sizeof stream_in);
    memcpy(stream_in,in,n);stream_in_n=n;stream_in_pos=0;
}
size_t build8_qual_stream_output(uint8_t *out,size_t capacity){
    assert(stream_out_n<=capacity);size_t n=stream_out_n;
    memcpy(out,stream_out,n);memset(stream_out,0,n);stream_out_n=0;return n;
}
void build8_qual_stream_fault(unsigned fault,uint64_t now){stream_fault=fault;stream_now=now;}
int build8_qual_stream_step(build8_worker_connection_v2 *c,const build8_worker_local_v2 *local,const uint8_t context[64],uint8_t *plain,size_t capacity,size_t *written){
    stream_reads=stream_writes=0;
    int result=build8_worker_stream_v2_step(&stream,c,&test_mining,local,context,1,0,
        stream_clock,stream_read,stream_write,NULL,plain,capacity,written);
    assert(stream_reads+stream_writes<=1);
    if(!result){const uint8_t *p=(const uint8_t *)&stream;for(size_t i=0;i<sizeof stream;i++)assert(!p[i]);}
    return result;
}
#ifdef BUILD8_QUAL_POSIX_SOCKET
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_socket_io_v2.h"
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.h"
#include <unistd.h>
#include <errno.h>
static build8_worker_socket_owner_v2 socket_owner;
int build8_qual_stream_socket_init(int fd){return build8_worker_socket_owner_v2_init(&socket_owner,fd);}
int build8_qual_stream_socket_step(build8_worker_connection_v2 *c,const build8_worker_local_v2 *local,const uint8_t context[64],uint8_t *plain,size_t capacity,size_t *written){
    int result=build8_worker_socket_owner_v2_step(&socket_owner,&stream,c,&test_mining,local,context,1,0,
        stream_clock,NULL,plain,capacity,written);
    if(!result)assert(socket_owner.closed&&socket_owner.io.fd==-1&&!socket_owner.close_error);
    return result;
}
int build8_qual_socket_owner_retirement(int fd,unsigned fault){
    build8_worker_socket_owner_v2 owner={0};assert(build8_worker_socket_owner_v2_init(&owner,fd));
    assert(!build8_worker_socket_owner_v2_init(&owner,fd));
    build8_worker_stream_v2 buffered;memset(&buffered,0,sizeof buffered);memset(buffered.input,0x55,sizeof buffered.input);
    buffered.used=17;buffered.started=true;
    uint8_t rx[16444],tx[16444];memset(rx,0x33,sizeof rx);memset(tx,0x66,sizeof tx);
    build8_worker_connection_v2 connection={0};connection.rx=rx;connection.tx=tx;
    build8_mining_control_v2 mining;build8_work_context context={0};context.height=1;context.assignment=1;context.last_ticket=77;
    assert(build8_mining_v2_init(&mining,&context,0,0,0));
    build8_mining_v2_run(&mining,true);build8_mining_v2_session(&mining,true);build8_mining_v2_accounting(&mining,true);
    assert(build8_worker_socket_owner_v2_read(&owner,(uint8_t *)&owner,sizeof owner)==-1);
    assert(build8_worker_socket_owner_v2_write(&owner,(const uint8_t *)&owner,sizeof owner)==-1);
    assert(!build8_worker_socket_owner_v2_retire(&owner,(build8_worker_stream_v2 *)&owner,&connection,&mining));
    assert(owner.io.fd==fd&&!owner.closed&&mining.session&&rx[0]==0x33);
    uint8_t byte=0x42;assert(build8_worker_socket_owner_v2_read(&owner,&byte,1)==0);
    assert(build8_worker_socket_owner_v2_write(&owner,&byte,1)==1);
    if(fault)assert(close(fd)==0); /* fault injection: owner invariant violation */
    assert(build8_worker_socket_owner_v2_retire(&owner,&buffered,&connection,&mining)==!fault);
    assert(owner.closed&&owner.io.fd==-1&&owner.close_error==(fault?EBADF:0));
    assert(mining.run&&mining.accounting&&!mining.session&&mining.last_ticket==77);
    const uint8_t *parts[]={rx,tx,(const uint8_t *)&buffered,(const uint8_t *)&connection};
    const size_t sizes[]={sizeof rx,sizeof tx,sizeof buffered,sizeof connection};
    for(unsigned j=0;j<4;j++)for(size_t i=0;i<sizes[j];i++)assert(parts[j][i]==0);
    assert(build8_worker_socket_owner_v2_read(&owner,&byte,1)==-1);
    assert(build8_worker_socket_owner_v2_write(&owner,&byte,1)==-1);
    assert(!build8_worker_socket_owner_v2_init(&owner,fd));
    assert(build8_worker_socket_owner_v2_retire(&owner,&buffered,&connection,&mining)==!fault);
    return 1;
}
#endif
