#include "observation_v2_nvs.h"
#include "maintenance_v2.h"
#include "nvs.h"
#include "esp_rom_crc.h"
#include <string.h>
/* Two alternating records retain the previous generation while NVS replaces
 * the inactive key. Never overwrite the sole newest checkpoint. CRC is only a
 * local corruption check, not authentication or rollback protection. The core
 * independently verifies the scope and SHA-256 state checksum after reading.
 * No selector blob or automatic namespace reset is used. */
#define ENVELOPE_MAX (22u+BUILD8_OBSERVATION_STATE_V2_MAX)
static const char *keys[2]={"checkpoint0","checkpoint1"};
static const uint8_t magic[8]={'B','8','O','B','S','2',0,1};
static uint64_t get64(const uint8_t *p){uint64_t v=0;for(unsigned i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));}
static uint32_t get32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static int select_record(nvs_handle_t h,uint8_t out[ENVELOPE_MAX],size_t *length,uint64_t *generation,unsigned *slot){
    uint8_t other[ENVELOPE_MAX];*generation=0;*length=0;*slot=0;
    for(unsigned i=0;i<2;i++){
        size_t n=sizeof other;esp_err_t err=nvs_get_blob(h,keys[i],other,&n);
        if(err==ESP_ERR_NVS_NOT_FOUND)continue;
        if(err!=ESP_OK||n<397||n>sizeof other||memcmp(other,magic,8))return -1;
        uint64_t g=get64(other+8);size_t size=((size_t)other[16]<<8)|other[17];
        if(!g||size<375||size>BUILD8_OBSERVATION_STATE_V2_MAX||n!=size+22
            ||esp_rom_crc32_le(0,other,n-4)!=get32(other+n-4))return -1;
        if(g==*generation&&(n!=*length||memcmp(other,out,n)))return -1;
        if(g>*generation){memcpy(out,other,n);*length=n;*generation=g;*slot=i;}
    }
    return *generation?1:0;
}
static int read_value(void *unused,uint8_t *out,size_t capacity,size_t *length){
    (void)unused;
    if(!out||!length||capacity>BUILD8_OBSERVATION_STATE_V2_MAX||!build8_maintenance_v2_owned())return -1;
    *length=0;nvs_handle_t handle;
    esp_err_t err=nvs_open("build8_obs_v2",NVS_READONLY,&handle);
    if(err==ESP_ERR_NVS_NOT_FOUND)return 0;
    if(err!=ESP_OK)return -1;
    uint8_t record[ENVELOPE_MAX];size_t n;uint64_t generation;unsigned slot;
    int status=select_record(handle,record,&n,&generation,&slot);
    uint8_t parked[73];size_t pn=sizeof parked;
    err=nvs_get_blob(handle,"parked",parked,&pn);nvs_close(handle);
    if(status<0||(err!=ESP_OK&&err!=ESP_ERR_NVS_NOT_FOUND))return -1;
    if(err==ESP_OK){
        if(pn!=sizeof parked||parked[0]!=4)return -1;
        uint64_t ps=get64(parked+1),fs=status==1?get64(record+18+133):0;
        if(status==1&&fs==ps&&memcmp(parked+9,record+18+149,32))return -1;
        if(status==0||ps>fs){
            if(capacity<sizeof parked)return -1;
            memcpy(out,parked,sizeof parked);*length=sizeof parked;return 1;
        }
    }
    if(status!=1)return status;
    n-=22;if(n>capacity)return -1;
    memcpy(out,record+18,n);*length=n;return 1;
}
static int write_value(void *unused,const uint8_t *raw,size_t length){
    (void)unused;
    if(!raw||length<375||length>BUILD8_OBSERVATION_STATE_V2_MAX||!build8_maintenance_v2_owned())return 0;
    nvs_handle_t handle;
    if(nvs_open("build8_obs_v2",NVS_READWRITE,&handle)!=ESP_OK)return 0;
    uint8_t record[ENVELOPE_MAX];size_t n;uint64_t generation;unsigned slot;
    int status=select_record(handle,record,&n,&generation,&slot);
    if(status<0||generation==UINT64_MAX){nvs_close(handle);return 0;}
    if(status==1&&n==length+22&&!memcmp(record+18,raw,length)){nvs_close(handle);return 1;}
    unsigned next=status==1?1u-slot:0;
    memcpy(record,magic,8);put64(record+8,generation+1);
    record[16]=(uint8_t)(length>>8);record[17]=(uint8_t)length;memcpy(record+18,raw,length);
    n=18+length;uint32_t crc=esp_rom_crc32_le(0,record,n);
    for(unsigned i=0;i<4;i++)record[n+i]=(uint8_t)(crc>>(24-8*i));
    esp_err_t err=nvs_set_blob(handle,keys[next],record,n+4);
    if(err==ESP_OK)err=nvs_commit(handle);
    nvs_close(handle);return err==ESP_OK;
}
static const build8_observation_store_v2 store={NULL,read_value,write_value};
const build8_observation_store_v2 *build8_observation_v2_nvs_backend(void){
    return build8_maintenance_v2_owned()?&store:NULL;
}
int build8_observation_v2_nvs_provision(const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash){
    return build8_maintenance_v2_owned()&&build8_observation_store_v2_initialize(&store,scope,hash);
}
int build8_observation_v2_nvs_restore(const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash,build8_observation_state_v2 *out){
    return build8_maintenance_v2_owned()&&build8_observation_store_v2_restore(&store,scope,hash,out);
}
int build8_observation_v2_nvs_park(const build8_observation_scope_v2 *scope,build8_v2_domain_hash hash){
    if(!build8_maintenance_v2_owned())return 0;
    uint8_t compact[73],check[73];
    if(!build8_observation_store_v2_compact(&store,scope,hash,compact))return 0;
    nvs_handle_t handle;if(nvs_open("build8_obs_v2",NVS_READWRITE,&handle)!=ESP_OK)return 0;
    esp_err_t err=nvs_set_blob(handle,"parked",compact,sizeof compact);
    if(err==ESP_OK)err=nvs_commit(handle);
    size_t n=sizeof check;
    if(err!=ESP_OK||nvs_get_blob(handle,"parked",check,&n)!=ESP_OK||n!=sizeof check||memcmp(compact,check,n)){
        nvs_close(handle);return 0;
    }
    /* Both full records are redundant only after exact durable compact copy.
     * Any reset during reclamation retains that same checkpoint. */
    for(unsigned i=0;i<2;i++){
        err=nvs_erase_key(handle,keys[i]);
        if(err!=ESP_ERR_NVS_NOT_FOUND&&(err!=ESP_OK||nvs_commit(handle)!=ESP_OK)){
            nvs_close(handle);return 0;
        }
    }
    nvs_close(handle);build8_observation_state_v2 restored;
    return build8_observation_store_v2_restore(&store,scope,hash,&restored)
        &&restored.sequence==get64(compact+1)&&restored.total==restored.sequence
        &&!restored.pending_length&&!memcmp(restored.chain,compact+9,32);
}
int build8_observation_v2_nvs_queue(const build8_observation_scope_v2 *scope,const uint8_t *raw,size_t n,const uint8_t coordinator[32],build8_v2_domain_hash hash){
    return build8_maintenance_v2_owned()&&build8_observation_store_v2_queue(&store,scope,raw,n,coordinator,hash);
}
int build8_observation_v2_nvs_receipt(const build8_observation_scope_v2 *scope,const uint8_t *raw,size_t n,const uint8_t *descriptor,size_t dn,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn){
    return build8_maintenance_v2_owned()&&build8_observation_store_v2_receipt(&store,scope,raw,n,descriptor,dn,h256,h512,workspace,wn);
}
