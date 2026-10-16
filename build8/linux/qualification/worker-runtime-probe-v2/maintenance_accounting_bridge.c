/* Actual owner/controller/connection/NVS adapter; public synthetic RAM storage.
 * No SDK page/GC model here (separate NVS fault matrix covers that layer). */
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_maintenance_v2.h"
#include "../worker-runtime-candidate-v2/miner/idf/main/observation_v2_nvs.h"
#include "../worker-runtime-candidate-v2/miner/idf/main/maintenance_v2.h"
#include <string.h>
extern int build8_release_mbed_hash256(const char *,const uint8_t *,size_t,uint8_t *);
extern int build8_release_mbed_hash512(const char *,const uint8_t *,size_t,uint8_t *);
extern void build8_qual_observation_reset(void);
extern void build8_qual_observation_fault(int);
extern size_t build8_qual_observation_length(unsigned);
#define H256 build8_release_mbed_hash256
#define H512 build8_release_mbed_hash512
#define CHECK(x) do {if(!(x))return __LINE__;} while(0)
static int tick(void *p,uint64_t *out){*out=(*(uint64_t *)p)++;return 1;}
int build8_qual_maintenance_accounting(const uint8_t *authority,size_t an,const uint8_t *descriptor,size_t dn,
    const uint8_t *receipt,size_t rn,const uint8_t coordinator[32]){
    build8_qual_observation_reset();CHECK(build8_maintenance_v2_init());
    SemaphoreHandle_t guard=build8_maintenance_v2_guard();CHECK(!build8_maintenance_v2_owned());
    build8_observation_scope_v2 scope;memset(scope.genesis,1,32);memset(scope.fingerprint,2,32);
    memset(scope.license,6,32);memset(scope.worker,7,32);
    build8_work_context p={0};memcpy(p.genesis,scope.genesis,32);memcpy(p.fingerprint,scope.fingerprint,32);
    memcpy(p.license,scope.license,32);memcpy(p.worker,scope.worker,32);memcpy(p.coordinator,coordinator,32);
    memset(p.parent,3,32);memset(p.target,255,32);p.height=1;p.genesis_timestamp=1000;p.assignment=1;
    build8_mining_control_v2 c;build8_worker_accounting_v2 a={0};build8_worker_connection_v2 connection={0};
    CHECK(build8_mining_v2_init(&c,&p,0,0,100));CHECK(build8_worker_accounting_v2_init(&a,&c,&scope));
    build8_mining_v2_run(&c,true);build8_mining_v2_session(&c,true);
    CHECK(!build8_observation_v2_nvs_backend());
    CHECK(!build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    CHECK(c.maintenance&&c.run&&!c.session&&c.accounting);
    CHECK(xSemaphoreTake(guard,0));
    CHECK(build8_observation_v2_nvs_provision(&scope,H256));
    const build8_observation_store_v2 *store=build8_observation_v2_nvs_backend();CHECK(store);
    CHECK(build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    CHECK(build8_qual_observation_length(2)==73&&!build8_qual_observation_length(0)&&!build8_qual_observation_length(1));
    CHECK(c.maintenance&&c.run&&!c.session&&!c.accounting);
    uint8_t request[73],fresh[32]={1},id[32],ws[8192];uint64_t now=100,nonce;
    CHECK(!build8_worker_accounting_v2_request(&a,&c,store,H256,fresh,tick,&now,request));
    build8_mining_v2_maintenance(&c,false);CHECK(!c.session);
    build8_mining_v2_session(&c,true);
    CHECK(build8_worker_accounting_v2_request(&a,&c,store,H256,fresh,tick,&now,request));
    CHECK(build8_mining_v2_assign(&c,fresh,1,1000,authority,an,H256,H512,ws,sizeof ws,tick,&now));
    CHECK(build8_mining_v2_nonce(&c,tick,&now,&nonce));memcpy(id,c.work.authority,32);
    CHECK(build8_worker_accounting_v2_found(&a,&c,id,nonce,tick,&now));
    build8_qual_observation_fault(1);
    CHECK(!build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    CHECK(a.pending_length&&c.accounting&&c.run&&c.maintenance&&!c.session);
    build8_qual_observation_fault(0);
    CHECK(!build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    CHECK(!a.pending_length&&c.accounting); /* durable pending cannot be parked */
    CHECK(build8_qual_observation_length(0)||build8_qual_observation_length(1));
    CHECK(build8_worker_accounting_v2_receipt(&a,&c,store,receipt,rn,descriptor,dn,H256,H512,ws,sizeof ws));
    CHECK(!c.accounting&&c.maintenance&&c.run);
    build8_qual_observation_fault(1);
    CHECK(!build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    CHECK(c.accounting&&c.maintenance&&c.run);
    build8_qual_observation_fault(0);
    CHECK(build8_worker_maintenance_v2_prepare(&connection,&a,&c,H256));
    build8_observation_state_v2 state;
    CHECK(build8_observation_v2_nvs_restore(&scope,H256,&state));
    CHECK(state.sequence==1&&state.total==1&&!state.pending_length&&!memcmp(state.chain,receipt+246,32));
    CHECK(build8_qual_observation_length(2)==73&&!build8_qual_observation_length(0)&&!build8_qual_observation_length(1));
    CHECK(xSemaphoreGive(guard));
    CHECK(!build8_observation_v2_nvs_backend());
    CHECK(!build8_worker_accounting_v2_sync(&a,&c,store,H256)&&c.accounting);
    CHECK(xSemaphoreTake(guard,0));CHECK(build8_worker_accounting_v2_sync(&a,&c,store,H256)&&!c.accounting);
    CHECK(c.run&&c.maintenance&&!c.session);CHECK(xSemaphoreGive(guard));return 0;
}
#ifdef BUILD8_QUAL_POSIX_SOCKET
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.h"
#include <unistd.h>
int build8_qual_socket_maintenance(int fd,unsigned fault){
    CHECK(fault<=2);build8_qual_observation_reset();CHECK(build8_maintenance_v2_init());
    SemaphoreHandle_t guard=build8_maintenance_v2_guard();CHECK(xSemaphoreTake(guard,0));
    build8_observation_scope_v2 scope;memset(scope.genesis,1,32);memset(scope.fingerprint,2,32);
    memset(scope.license,6,32);memset(scope.worker,7,32);
    build8_work_context p={0};memcpy(p.genesis,scope.genesis,32);memcpy(p.fingerprint,scope.fingerprint,32);
    memcpy(p.license,scope.license,32);memcpy(p.worker,scope.worker,32);p.height=1;p.assignment=1;p.last_ticket=77;
    build8_mining_control_v2 c;build8_worker_accounting_v2 a={0};build8_worker_connection_v2 connection={0};
    build8_worker_stream_v2 stream;memset(&stream,0,sizeof stream);memset(stream.input,0x44,sizeof stream.input);stream.used=19;
    CHECK(build8_mining_v2_init(&c,&p,0,0,0));CHECK(build8_worker_accounting_v2_init(&a,&c,&scope));
    build8_mining_v2_run(&c,true);build8_mining_v2_session(&c,true);
    CHECK(build8_observation_v2_nvs_provision(&scope,H256));
    build8_worker_socket_owner_v2 owner={0};CHECK(build8_worker_socket_owner_v2_init(&owner,fd));
    if(fault==1)CHECK(close(fd)==0);
    int ok=build8_worker_socket_owner_v2_maintenance(&owner,&stream,&connection,&a,&c,fault==2?NULL:H256);
    CHECK(ok==(fault==0)&&owner.closed&&owner.io.fd==-1);
    CHECK(c.run&&c.maintenance&&!c.session&&c.last_ticket==77&&!a.pending_length);
    for(size_t i=0;i<sizeof stream;i++)CHECK(((const uint8_t *)&stream)[i]==0);
    if(fault){CHECK(!build8_qual_observation_length(2)&&build8_qual_observation_length(0));}
    else CHECK(build8_qual_observation_length(2)==73&&!build8_qual_observation_length(0));
    if(fault==1){
        CHECK(!build8_worker_socket_owner_v2_maintenance(&owner,&stream,&connection,&a,&c,H256));
        CHECK(!build8_qual_observation_length(2));
    }
    CHECK(xSemaphoreGive(guard));return 0;
}
#endif
