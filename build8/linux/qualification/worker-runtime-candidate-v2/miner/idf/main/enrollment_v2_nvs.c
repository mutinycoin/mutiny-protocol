/* Public V2 enrollment activation only. Existing V1 namespaces are never opened.
 * The immutable private candidate must be restored by the identity layer before
 * these entry points receive its trusted expected context. Not linked into V1. */
#include "enrollment_v2_nvs.h"
#include "maintenance_v2.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
static SemaphoreHandle_t guard;
static const char *key_name(unsigned key){return key==0?"binding":key==1?"active":NULL;}
static int read_value(void *unused,unsigned key,uint8_t *out,size_t capacity,size_t *length) {
    (void)unused;const char *name=key_name(key);if(!name||!out||!length)return -1;
    nvs_handle_t handle;esp_err_t err=nvs_open("build8_v2",NVS_READONLY,&handle);
    if(err==ESP_ERR_NVS_NOT_FOUND)return 0;
    if(err!=ESP_OK)return -1;
    size_t n=capacity;err=nvs_get_blob(handle,name,out,&n);nvs_close(handle);
    if(err==ESP_ERR_NVS_NOT_FOUND)return 0;
    if(err!=ESP_OK||n>capacity)return -1;
    *length=n;return 1;
}
static int write_value(void *unused,unsigned key,const uint8_t *value,size_t length) {
    (void)unused;const char *name=key_name(key);
    if(!name||!value||(key==0&&(length==0||length>2048))||(key==1&&length!=40))return 0;
    nvs_handle_t handle;if(nvs_open("build8_v2",NVS_READWRITE,&handle)!=ESP_OK)return 0;
    esp_err_t err=nvs_set_blob(handle,name,value,length);
    if(err==ESP_OK)err=nvs_commit(handle);
    nvs_close(handle);return err==ESP_OK;
}
static const build8_v2_store store={NULL,read_value,write_value};
static const build8_v2_store session_store={NULL,read_value,NULL};
int build8_v2_nvs_init(void) {
    /* Single startup task only. A failed allocation never opens a write path. */
    if(guard)return 1;
    guard=xSemaphoreCreateMutex();return guard!=NULL;
}
int build8_v2_nvs_restore(const uint8_t *expected,size_t en,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    if(!build8_maintenance_v2_owned()||!guard||xSemaphoreTake(guard,0)!=pdTRUE)return BUILD8_V2_FAULT;
    int result=build8_v2_restore(&store,expected,en,owner,on,h256,h512,workspace,wn);
    xSemaphoreGive(guard);return result;
}
int build8_v2_nvs_activate(const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    if(!build8_maintenance_v2_owned()||!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    int result=build8_v2_activate(&store,raw,n,expected,en,owner,on,h256,h512,workspace,wn);
    xSemaphoreGive(guard);return result;
}
int build8_v2_nvs_sign_session(const build8_v2_private_backend *backend,const build8_enrollment_v2_context *context,
    uint64_t height,uint64_t epoch,const uint8_t transcript[64],build8_v2_domain_hash h256,
    build8_v2_domain_hash h512,void *workspace,size_t wn,uint8_t signature[114]) {
    if(!signature)return 0;
    memset(signature,0,114);
    if(!build8_maintenance_v2_owned()||!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    int result=build8_v2_candidate_sign_session(backend,&session_store,context,height,epoch,transcript,h256,h512,workspace,wn,signature);
    xSemaphoreGive(guard);return result;
}
int build8_v2_nvs_handshake(unsigned phase,build8_worker_pending_v2 *pending,const build8_worker_local_v2 *local,
    uint64_t height,uint64_t epoch,const uint8_t *wire,size_t n,void *out) {
    if(!local||!local->private_store||local->public_store||phase>2||!out
        ||!build8_maintenance_v2_owned()||!guard||xSemaphoreTake(guard,0)!=pdTRUE) {
        build8_worker_pending_v2_clear(pending);return 0;
    }
    build8_worker_local_v2 actual=*local;actual.public_store=&session_store;
    int result=0;
    if(phase==0&&!wire&&!n)result=build8_worker_pending_v2_begin(pending,&actual,height,epoch,out);
    else if(phase==1)result=build8_worker_pending_v2_accept(pending,&actual,height,epoch,wire,n,out);
    else if(phase==2)result=build8_worker_pending_v2_finish(pending,&actual,height,epoch,wire,n,out);
    if(!result)build8_worker_pending_v2_clear(pending);
    xSemaphoreGive(guard);return result;
}
