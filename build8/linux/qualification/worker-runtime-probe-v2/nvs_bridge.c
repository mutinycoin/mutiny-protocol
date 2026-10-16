/* Qualification only: actual adapters, modeled locks and synthetic RAM NVS.
 * No production source links this file. Private/enrollment writes and device
 * entropy abort. Only the separate PUBLIC observation namespace is writable. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define guard worker_guard
#include "../worker-runtime-candidate-v2/miner/idf/main/worker_v2_nvs.c"
#undef guard
#define guard enrollment_guard
#include "../worker-runtime-candidate-v2/miner/idf/main/enrollment_v2_nvs.c"
#undef guard
typedef struct {int held;} test_mutex;
static test_mutex mutexes[4];static unsigned used;
static SemaphoreHandle_t maintenance;
static const build8_v2_private_backend *synthetic_private;
static const build8_v2_store *synthetic_public;
static uint8_t observation[3][941];static size_t observation_n[3];static int observation_fault;
static unsigned observation_key(const char *k){
    if(!strcmp(k,"checkpoint0"))return 0;if(!strcmp(k,"checkpoint1"))return 1;
    assert(!strcmp(k,"parked"));return 2;
}
void build8_qual_observation_reset(void){memset(observation,0,sizeof observation);memset(observation_n,0,sizeof observation_n);observation_fault=0;}
void build8_qual_observation_fault(int fault){observation_fault=fault;}
size_t build8_qual_observation_length(unsigned slot){assert(slot<3);return observation_n[slot];}
SemaphoreHandle_t xSemaphoreCreateMutex(void){assert(used<4);return &mutexes[used++];}
int xSemaphoreTake(SemaphoreHandle_t p,unsigned wait){assert(!wait);test_mutex *m=p;if(m->held)return 0;m->held=1;return 1;}
int xSemaphoreGive(SemaphoreHandle_t p){test_mutex *m=p;assert(m->held);m->held=0;return 1;}
int build8_maintenance_v2_init(void){if(!maintenance)maintenance=xSemaphoreCreateMutex();return 1;}
SemaphoreHandle_t build8_maintenance_v2_guard(void){return maintenance;}
int build8_maintenance_v2_owned(void){return maintenance&&((test_mutex *)maintenance)->held;}
esp_err_t nvs_flash_init(void){return ESP_OK;}
esp_err_t nvs_open(const char *name,int mode,nvs_handle_t *handle){
    if(!strcmp(name,"build8_obs_v2")){
        assert(build8_maintenance_v2_owned()&&(mode==NVS_READONLY||mode==NVS_READWRITE));
        *handle=2;return ESP_OK;
    }
    assert(!strcmp(name,"build8_v2")&&mode==NVS_READONLY&&synthetic_private&&synthetic_public);
    assert(build8_maintenance_v2_owned()&&((test_mutex *)enrollment_guard)->held);
    *handle=1;return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t handle,const char *key,void *out,size_t *length){
    if(handle==2){
        assert(build8_maintenance_v2_owned()&&out&&length);unsigned i=observation_key(key);
        if(!observation_n[i])return ESP_ERR_NVS_NOT_FOUND;
        if(*length<observation_n[i])return 2;
        memcpy(out,observation[i],observation_n[i]);*length=observation_n[i];return ESP_OK;
    }
    assert(handle==1&&out&&length);int result;
    if(!strcmp(key,"candidate"))result=synthetic_private->read(synthetic_private->context,out,*length,length);
    else {unsigned which=!strcmp(key,"binding")?0:1;assert(which==0||!strcmp(key,"active"));
        result=synthetic_public->read(synthetic_public->context,which,out,*length,length);}
    return result==1?ESP_OK:result==0?ESP_ERR_NVS_NOT_FOUND:2;
}
void nvs_close(nvs_handle_t handle){assert(handle==1||handle==2);}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *o,size_t n){
    if(h!=2)abort();assert(build8_maintenance_v2_owned()&&o&&n<=941);
    if(observation_fault)return 2;unsigned i=observation_key(k);memcpy(observation[i],o,n);observation_n[i]=n;return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h,const char *k){
    if(h!=2)abort();assert(build8_maintenance_v2_owned());if(observation_fault)return 2;
    unsigned i=observation_key(k);if(!observation_n[i])return ESP_ERR_NVS_NOT_FOUND;
    memset(observation[i],0,sizeof observation[i]);observation_n[i]=0;return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h){if(h!=2)abort();assert(build8_maintenance_v2_owned());return observation_fault?2:ESP_OK;}
void bootloader_random_enable(void){abort();}
void bootloader_random_disable(void){abort();}
void esp_fill_random(void *p,size_t n){(void)p;(void)n;abort();}
int build8_qual_bind_nvs(const build8_v2_private_backend *p,const build8_v2_store *s){
    assert(session_backend.read==read_private&&!session_backend.write&&!session_backend.entropy);
    assert(session_store.read==read_value&&!session_store.write);
    synthetic_private=p;synthetic_public=s;return build8_worker_v2_init_before_radio();
}
void build8_qual_unbind_nvs(void){
    assert(!build8_maintenance_v2_owned()&&!((test_mutex *)enrollment_guard)->held);
    synthetic_private=NULL;synthetic_public=NULL;
}
