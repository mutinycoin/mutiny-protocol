#include "worker_frame_v2.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#define MAGIC UINT32_C(0x42385732)
#define MAX_FRAMES UINT64_C(1048576)
#define MAX_BYTES UINT64_C(67108864)
static const uint8_t domain[]="MUTINY-BUILD8-WORKER-SESSION-FRAME-V2";
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
static uint64_t read64(const uint8_t *p){uint64_t n=0;for(unsigned i=0;i<8;i++)n=(n<<8)|p[i];return n;}
static void put64(uint8_t *p,uint64_t n){for(int i=7;i>=0;i--){p[i]=(uint8_t)n;n>>=8;}}
size_t b8_worker_channel_size(void){return sizeof(b8_worker_channel);}
size_t b8_worker_channel_alignment(void){return _Alignof(b8_worker_channel);}
void b8_worker_channel_clear(b8_worker_channel *s){if(s)mbedtls_platform_zeroize(s,sizeof *s);}
int b8_worker_channel_init(b8_worker_channel *s,const uint8_t context[64],const uint8_t id[32],
    const uint8_t tx[32],const uint8_t rx[32],const uint8_t tp[4],const uint8_t rp[4],
    uint8_t worker,uint64_t confirmed,uint64_t now,uint64_t effective,uint64_t until){
    if(!s)return 0;
    if(!context||!id||!tx||!rx||!tp||!rp||worker>1||now<confirmed||now-confirmed>=60000){b8_worker_channel_clear(s);return 0;}
    /* Copy before clearing permits a trusted caller to move an overlapping
     * temporary descriptor. The snapshot is always erased before return. */
    b8_worker_channel copy={0};
    memcpy(copy.context,context,64);memcpy(copy.id,id,32);memcpy(copy.tx_key,tx,32);memcpy(copy.rx_key,rx,32);
    memcpy(copy.tx_prefix,tp,4);memcpy(copy.rx_prefix,rp,4);copy.worker=worker;
    copy.confirmed_ms=confirmed;copy.last_ms=now;copy.next_tx=copy.next_rx=1;
    copy.effective_epoch=effective;copy.until_height=until;copy.active=MAGIC;
    b8_worker_channel_clear(s);memcpy(s,&copy,sizeof copy);mbedtls_platform_zeroize(&copy,sizeof copy);return 1;
}
/* until_height is the binding's valid_until_height: the consensus INCLUSION deadline of the
 * assignment operation, not a session lifetime (Order Q17; P-LANE-DESIGN-V1 11.2 b and
 * amendment AM-7; same rule as Rust worker_context_v2 Context::matches_current). It is
 * recorded and never ends the channel; any binding change still does, through the current
 * ContextID, which commits the complete binding. */
static int live(b8_worker_channel *s,const uint8_t context[64],uint64_t height,uint64_t epoch,uint64_t now){
    if(s->active!=MAGIC||memcmp(context,s->context,64)||!height||epoch<s->effective_epoch
       ||now<s->last_ms||now<s->confirmed_ms
       ||now-s->confirmed_ms>=3600000)return 0;
    s->last_ms=now;return 1;
}
static int buffers(b8_worker_channel *s,const uint8_t *context,const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *written){
    if(!s||!context||!in||!out||!written||cap>B8_WORKER_FRAME_MAX||n>B8_WORKER_FRAME_MAX)return 0;
    const void *p[]={s,context,in,out,written};size_t z[]={sizeof *s,64,n,cap,sizeof *written};
    for(unsigned i=0;i<5;i++)for(unsigned j=i+1;j<5;j++)if(!separate(p[i],z[i],p[j],z[j]))return 0;
    return 1;
}
int b8_worker_channel_expire(b8_worker_channel *s,const uint8_t context[64],uint64_t height,uint64_t epoch,uint64_t now){
    if(s&&context&&separate(s,sizeof *s,context,64)&&live(s,context,height,epoch,now))return 1;
    b8_worker_channel_clear(s);return 0;
}
int b8_worker_seal(b8_worker_channel *s,const uint8_t context[64],uint64_t height,uint64_t epoch,uint64_t now,
    const uint8_t *plain,size_t n,uint8_t *out,size_t cap,size_t *written){
    int ok=0;
    if(!buffers(s,context,plain,n,out,cap,written)){b8_worker_channel_clear(s);return 0;}
    *written=0;mbedtls_platform_zeroize(out,cap);
    if(!live(s,context,height,epoch,now)||!n||n>B8_WORKER_PAYLOAD_MAX||cap<44+n+16
       ||!s->next_tx||s->next_tx>MAX_FRAMES||s->tx_bytes>MAX_BYTES-n)goto failed;
    uint8_t nonce[12]={0},aad[sizeof domain+44];
    out[0]=2;out[1]=(uint8_t)!s->worker;memcpy(out+2,s->id,32);put64(out+34,s->next_tx);
    out[42]=(uint8_t)(n>>8);out[43]=(uint8_t)n;
    memcpy(nonce,s->tx_prefix,4);put64(nonce+4,s->next_tx);memcpy(aad,domain,sizeof domain);memcpy(aad+sizeof domain,out,44);
    mbedtls_chachapoly_context c;mbedtls_chachapoly_init(&c);
    int result=mbedtls_chachapoly_setkey(&c,s->tx_key);
    if(!result)result=mbedtls_chachapoly_encrypt_and_tag(&c,n,nonce,aad,sizeof aad,plain,out+44,out+44+n);
    mbedtls_chachapoly_free(&c);mbedtls_platform_zeroize(nonce,sizeof nonce);mbedtls_platform_zeroize(aad,sizeof aad);
    if(result)goto failed;
    s->next_tx++;s->tx_bytes+=n;*written=44+n+16;ok=1;
failed:
    if(!ok){mbedtls_platform_zeroize(out,cap);b8_worker_channel_clear(s);}return ok;
}
int b8_worker_open(b8_worker_channel *s,const uint8_t context[64],uint64_t height,uint64_t epoch,uint64_t now,
    const uint8_t *frame,size_t n,uint8_t *out,size_t cap,size_t *written){
    int ok=0;
    if(!buffers(s,context,frame,n,out,cap,written)){b8_worker_channel_clear(s);return 0;}
    *written=0;mbedtls_platform_zeroize(out,cap);
    if(!live(s,context,height,epoch,now)||n<61||n>B8_WORKER_FRAME_MAX||frame[0]!=2||frame[1]!=s->worker
       ||memcmp(frame+2,s->id,32)||!s->next_rx||s->next_rx>MAX_FRAMES||read64(frame+34)!=s->next_rx)goto failed;
    size_t bytes=((size_t)frame[42]<<8)|frame[43];
    if(!bytes||bytes>B8_WORKER_PAYLOAD_MAX||n!=44+bytes+16||cap<bytes||s->rx_bytes>MAX_BYTES-bytes)goto failed;
    uint8_t nonce[12]={0},aad[sizeof domain+44];
    memcpy(nonce,s->rx_prefix,4);put64(nonce+4,s->next_rx);memcpy(aad,domain,sizeof domain);memcpy(aad+sizeof domain,frame,44);
    mbedtls_chachapoly_context c;mbedtls_chachapoly_init(&c);
    int result=mbedtls_chachapoly_setkey(&c,s->rx_key);
    if(!result)result=mbedtls_chachapoly_auth_decrypt(&c,bytes,nonce,aad,sizeof aad,frame+44+bytes,frame+44,out);
    mbedtls_chachapoly_free(&c);mbedtls_platform_zeroize(nonce,sizeof nonce);mbedtls_platform_zeroize(aad,sizeof aad);
    if(result)goto failed;
    s->next_rx++;s->rx_bytes+=bytes;*written=bytes;ok=1;
failed:
    if(!ok){mbedtls_platform_zeroize(out,cap);b8_worker_channel_clear(s);}return ok;
}
