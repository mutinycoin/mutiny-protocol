#include "worker_finished_v2.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"
#include <string.h>
static int buffers(const uint8_t *key,const uint8_t *prefix,const uint8_t *th,const uint8_t *tag){
    const void *p[]={key,prefix,th,tag};size_t n[]={32,4,64,16};
    for(unsigned i=0;i<4;i++){
        uintptr_t a=(uintptr_t)p[i];if(!p[i]||n[i]>UINTPTR_MAX-a)return 0;
        for(unsigned j=0;j<i;j++){uintptr_t b=(uintptr_t)p[j];if(!(a+n[i]<=b||b+n[j]<=a))return 0;}
    }return 1;
}
static int finish(const uint8_t key[32],const uint8_t prefix[4],const uint8_t th[64],uint8_t sender,uint8_t tag[16],int verify){
    static const uint8_t domain[]="MUTINY-BUILD8-WORKER-SESSION-FINISHED-V2";
    uint8_t nonce[12]={0},aad[sizeof domain+1+64],dummy=0;
    memcpy(nonce,prefix,4);memcpy(aad,domain,sizeof domain);aad[sizeof domain]=sender;memcpy(aad+sizeof domain+1,th,64);
    mbedtls_chachapoly_context c;mbedtls_chachapoly_init(&c);int result=mbedtls_chachapoly_setkey(&c,key);
    if(!result){
        if(verify)result=mbedtls_chachapoly_auth_decrypt(&c,0,nonce,aad,sizeof aad,tag,&dummy,&dummy);
        else result=mbedtls_chachapoly_encrypt_and_tag(&c,0,nonce,aad,sizeof aad,&dummy,&dummy,tag);
    }
    mbedtls_chachapoly_free(&c);mbedtls_platform_zeroize(nonce,sizeof nonce);mbedtls_platform_zeroize(aad,sizeof aad);
    return result==0;
}
int b8_worker_finished_v2(const uint8_t key[32],const uint8_t prefix[4],const uint8_t th[64],uint8_t sender,uint8_t tag[16]){
    if(!buffers(key,prefix,th,tag))return 0;
    memset(tag,0,16);if(sender>1)return 0;
    if(!finish(key,prefix,th,sender,tag,0)){mbedtls_platform_zeroize(tag,16);return 0;}return 1;
}
int b8_worker_verify_finished_v2(const uint8_t key[32],const uint8_t prefix[4],const uint8_t th[64],uint8_t sender,const uint8_t *tag,size_t n){
    if(n!=16||sender>1||!buffers(key,prefix,th,tag))return 0;
    uint8_t copy[16];memcpy(copy,tag,16);int ok=finish(key,prefix,th,sender,copy,1);
    mbedtls_platform_zeroize(copy,sizeof copy);return ok;
}
