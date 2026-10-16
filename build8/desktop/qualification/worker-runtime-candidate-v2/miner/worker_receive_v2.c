#include "worker_receive_v2.h"
#include <string.h>
extern void OPENSSL_cleanse(void *,size_t);
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
void build8_worker_receive_v2_clear(build8_worker_receive_v2 *s){
    if(!s)return;
    if(s->storage&&s->capacity<=BUILD8_WORKER_RECEIVE_MAX&&separate(s,sizeof *s,s->storage,s->capacity))OPENSSL_cleanse(s->storage,s->capacity);
    OPENSSL_cleanse(s,sizeof *s);
}
int build8_worker_receive_v2_init(build8_worker_receive_v2 *s,uint8_t *p,size_t capacity,unsigned kind){
    if(!s)return 0;
    size_t required=kind==BUILD8_WORKER_RX_RESPONSE?3050:kind==BUILD8_WORKER_RX_FINISHED?16:kind==BUILD8_WORKER_RX_FRAME?BUILD8_WORKER_RECEIVE_MAX:0;
    /* First initialization need not read uninitialized state. Reinitialization
     * requires clear first, so prior storage never loses its erasure owner. */
    if(!p||!required||capacity<required||capacity>BUILD8_WORKER_RECEIVE_MAX||!separate(s,sizeof *s,p,capacity)){OPENSSL_cleanse(s,sizeof *s);return 0;}
    OPENSSL_cleanse(s,sizeof *s);OPENSSL_cleanse(p,capacity);s->storage=p;s->capacity=capacity;s->kind=kind;s->target=kind==BUILD8_WORKER_RX_FRAME?44:required;return 1;
}
int build8_worker_receive_v2_feed(build8_worker_receive_v2 *s,const uint8_t *p,size_t n,size_t *consumed){
    if(!s)return 0;
    if(!p||!consumed||!s->storage||!s->capacity||s->capacity>BUILD8_WORKER_RECEIVE_MAX||s->ready
        ||s->kind<1||s->kind>3||!s->target||s->target>s->capacity||s->used>s->target
        ||!separate(s,sizeof *s,s->storage,s->capacity)||!separate(s,sizeof *s,p,n)||!separate(s,sizeof *s,consumed,sizeof *consumed)
        ||!separate(s->storage,s->capacity,p,n)||!separate(s->storage,s->capacity,consumed,sizeof *consumed)||!separate(p,n,consumed,sizeof *consumed)){
        build8_worker_receive_v2_clear(s);return 0;
    }
    *consumed=0;
    while(n&&s->used<s->target){
        size_t take=s->target-s->used;if(take>n)take=n;
        memcpy(s->storage+s->used,p,take);s->used+=take;p+=take;n-=take;*consumed+=take;
        if(s->kind==BUILD8_WORKER_RX_FRAME&&s->used==44&&s->target==44){
            size_t bytes=((size_t)s->storage[42]<<8)|s->storage[43];
            if(s->storage[0]!=2||s->storage[1]!=1||!bytes||bytes>16384){build8_worker_receive_v2_clear(s);return 0;}
            s->target=44+bytes+16;
        }
    }
    s->ready=s->used==s->target;return 1;
}
const uint8_t *build8_worker_receive_v2_message(const build8_worker_receive_v2 *s,size_t *n){
    if(!s||!n||!separate(s,sizeof *s,n,sizeof *n)||!s->storage||!separate(s->storage,s->capacity,n,sizeof *n))return NULL;
    *n=0;if(!s->ready||s->used!=s->target||!s->target||s->target>s->capacity||s->capacity>BUILD8_WORKER_RECEIVE_MAX)return NULL;
    *n=s->used;return s->storage;
}
