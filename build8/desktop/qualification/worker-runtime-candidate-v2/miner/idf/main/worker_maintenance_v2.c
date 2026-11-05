#include "worker_maintenance_v2.h"
#include "observation_v2_nvs.h"
#include "maintenance_v2.h"
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return a&&b&&an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
int build8_worker_maintenance_v2_prepare(build8_worker_connection_v2 *connection,
    build8_worker_accounting_v2 *accounting,build8_mining_control_v2 *mining,build8_v2_domain_hash hash){
    if(!connection||!accounting||!mining||!separate(connection,sizeof *connection,accounting,sizeof *accounting)
       ||!separate(connection,sizeof *connection,mining,sizeof *mining)
       ||!separate(accounting,sizeof *accounting,mining,sizeof *mining))return 0;
    build8_mining_v2_maintenance(mining,true);
    build8_worker_connection_v2_close(connection);
    if(!build8_maintenance_v2_owned())return 0;
    const build8_observation_store_v2 *store=build8_observation_v2_nvs_backend();
    if(!store||!build8_worker_accounting_v2_sync(accounting,mining,store,hash)
       ||accounting->pending_length||mining->accounting)return 0;
    if(!build8_observation_v2_nvs_park(&accounting->scope,hash)){
        build8_mining_v2_accounting(mining,true);return 0;
    }
    return 1;
}
