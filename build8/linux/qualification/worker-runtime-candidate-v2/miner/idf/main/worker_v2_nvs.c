/* Separate V2 namespace; no V1 seed import, NVS erase, host key injection or
 * secret export. Plain NVS is not claimed hardware-non-exportable storage. */
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
/* This entropy integration is qualified only against the original ESP32 SAR
 * source. SDK bring-up can replace enable/disable with no-op stubs. Refuse
 * such a build instead of treating esp_fill_random alone as true entropy. */
#if !defined(CONFIG_IDF_TARGET_ESP32) || !CONFIG_IDF_TARGET_ESP32
#error BUILD8_WORKER_ENTROPY_REQUIRES_QUALIFIED_ESP32
#endif
#if defined(CONFIG_ESP_BRINGUP_BYPASS_RANDOM_SETTING) && CONFIG_ESP_BRINGUP_BYPASS_RANDOM_SETTING
#error BUILD8_WORKER_ENTROPY_BYPASS_FORBIDDEN
#endif
#endif
#include "worker_v2_nvs.h"
#include "enrollment_v2_nvs.h"
#include "maintenance_v2.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_random.h"
#include "bootloader_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <stdatomic.h>
#include <string.h>
static SemaphoreHandle_t guard;
static atomic_bool peripherals_started;
static int read_private(void *unused,uint8_t *out,size_t capacity,size_t *length) {
    (void)unused;nvs_handle_t handle;esp_err_t err=nvs_open("build8_v2",NVS_READONLY,&handle);
    if(err==ESP_ERR_NVS_NOT_FOUND)return 0;
    if(err!=ESP_OK)return -1;
    size_t n=capacity;err=nvs_get_blob(handle,"candidate",out,&n);
    if(err==ESP_ERR_NVS_NOT_FOUND) {
        /* Public V2 records can exist only after a private candidate was
         * created. Missing/corrupt private storage must not become permission
         * to generate a replacement identity after enrollment. */
        const char *public_keys[2]={"binding","active"};
        for(unsigned i=0;i<2;i++) {
            size_t length=0;
            esp_err_t present=nvs_get_blob(handle,public_keys[i],NULL,&length);
            if(present!=ESP_ERR_NVS_NOT_FOUND) {nvs_close(handle);return -1;}
        }
        nvs_close(handle);return 0;
    }
    nvs_close(handle);
    if(err!=ESP_OK||n>capacity)return -1;
    *length=n;return 1;
}
static int write_private(void *unused,const uint8_t *raw,size_t n) {
    (void)unused;if(!raw||n>BUILD8_V2_PRIVATE_RECORD_MAX)return 0;
    nvs_handle_t handle;if(nvs_open("build8_v2",NVS_READWRITE,&handle)!=ESP_OK)return 0;
    esp_err_t err=nvs_set_blob(handle,"candidate",raw,n);
    if(err==ESP_OK)err=nvs_commit(handle);
    nvs_close(handle);return err==ESP_OK;
}
static int entropy(void *unused,uint8_t *out,size_t n) {
    (void)unused;if(!out||n!=57||atomic_load(&peripherals_started))return 0;
    /* Only startup/enrollment task may run before the peripheral latch. The
     * application must not initialize RF/ADC/I2S concurrently with this call. */
    bootloader_random_enable();esp_fill_random(out,n);bootloader_random_disable();return 1;
}
static const build8_v2_private_backend backend={NULL,read_private,write_private,entropy};
/* Session code receives no identity creation/write or pre-radio SAR callback. */
static const build8_v2_private_backend session_backend={NULL,read_private,NULL,NULL};
int build8_worker_v2_init_before_radio(void) {
    if(atomic_load(&peripherals_started))return 0;
    if(guard)return 1;
    if(nvs_flash_init()!=ESP_OK||!build8_v2_nvs_init())return 0;
    if(!build8_maintenance_v2_init())return 0;
    guard=build8_maintenance_v2_guard();return guard!=NULL;
}
int build8_worker_v2_peripherals_started(void) {
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    atomic_store(&peripherals_started,1);xSemaphoreGive(guard);return 1;
}
int build8_worker_v2_prepare(const build8_enrollment_v2_context *context,const uint8_t *owner,size_t n,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    int ok=build8_v2_candidate_prepare(&backend,context,owner,n,h256,h512,out);
    xSemaphoreGive(guard);return ok;
}
int build8_worker_v2_public(build8_v2_domain_hash h256,build8_v2_domain_hash h512,build8_v2_public_candidate *out) {
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    int ok=build8_v2_candidate_public(&backend,h256,h512,out);xSemaphoreGive(guard);return ok;
}
int build8_worker_v2_activate(const uint8_t *raw,size_t n,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    build8_v2_public_candidate candidate;
    int ok=build8_v2_candidate_public(&backend,h256,h512,&candidate)
        &&build8_v2_nvs_activate(raw,n,candidate.unsigned_binding,candidate.unsigned_length,
            candidate.owner_descriptor,candidate.owner_length,h256,h512,workspace,wn);
    xSemaphoreGive(guard);return ok;
}
int build8_worker_v2_status(build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return BUILD8_V2_FAULT;
    build8_v2_public_candidate candidate;int state=BUILD8_V2_FAULT;
    if(build8_v2_candidate_public(&backend,h256,h512,&candidate))
        state=build8_v2_nvs_restore(candidate.unsigned_binding,candidate.unsigned_length,
            candidate.owner_descriptor,candidate.owner_length,h256,h512,workspace,wn);
    xSemaphoreGive(guard);return state;
}
int build8_worker_v2_sign_session(const build8_enrollment_v2_context *context,uint64_t height,uint64_t epoch,
    const uint8_t transcript[64],build8_v2_domain_hash h256,build8_v2_domain_hash h512,
    void *workspace,size_t wn,uint8_t signature[114]) {
    if(!signature)return 0;
    memset(signature,0,114);
    if(!guard||xSemaphoreTake(guard,0)!=pdTRUE)return 0;
    int ok=build8_v2_nvs_sign_session(&session_backend,context,height,epoch,transcript,h256,h512,workspace,wn,signature);
    xSemaphoreGive(guard);return ok;
}
static int handshake(unsigned phase,build8_worker_pending_v2 *pending,const build8_worker_local_v2 *local,
    uint64_t height,uint64_t epoch,const uint8_t *wire,size_t n,void *out) {
    if(!local||local->private_store||local->public_store||!guard||xSemaphoreTake(guard,0)!=pdTRUE) {
        build8_worker_pending_v2_clear(pending);return 0;
    }
    build8_worker_local_v2 actual=*local;actual.private_store=&session_backend;
    int result=build8_v2_nvs_handshake(phase,pending,&actual,height,epoch,wire,n,out);
    xSemaphoreGive(guard);return result;
}
int build8_worker_v2_handshake_begin(build8_worker_pending_v2 *pending,const build8_worker_local_v2 *local,
    uint64_t height,uint64_t epoch,uint8_t out[1722]) {
    return handshake(0,pending,local,height,epoch,NULL,0,out);
}
int build8_worker_v2_handshake_accept(build8_worker_pending_v2 *pending,const build8_worker_local_v2 *local,
    uint64_t height,uint64_t epoch,const uint8_t *wire,size_t n,uint8_t out[130]) {
    return handshake(1,pending,local,height,epoch,wire,n,out);
}
int build8_worker_v2_handshake_finish(build8_worker_pending_v2 *pending,const build8_worker_local_v2 *local,
    uint64_t height,uint64_t epoch,const uint8_t *wire,size_t n,b8_worker_channel *out) {
    return handshake(2,pending,local,height,epoch,wire,n,out);
}
