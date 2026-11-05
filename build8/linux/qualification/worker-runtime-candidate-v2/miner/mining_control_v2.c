#include "mining_control_v2.h"
#include <string.h>

static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&(x+an<=y||y+bn<=x);
}
void build8_mining_v2_retire(build8_mining_control_v2 *c){
    if(c){c->work_valid=false;c->job_live=false;c->request_pending=false;memset(&c->work,0,sizeof c->work);}
}
int build8_mining_v2_init(build8_mining_control_v2 *c,const build8_work_context *p,
    uint64_t effective,uint64_t until,uint64_t now){
    if(!c||!p||!separate(c,sizeof *c,p,sizeof *p))return 0;
    memset(c,0,sizeof *c);
    if(!p->height||!p->assignment)return 0;
    c->context=*p;c->effective_epoch=effective;c->valid_until_height=until;
    c->last_clock=now;c->last_ticket=p->last_ticket;c->initialized=true;return 1;
}
void build8_mining_v2_run(build8_mining_control_v2 *c,bool run){
    if(c){if(c->run!=run)build8_mining_v2_retire(c);c->run=run;}
}
void build8_mining_v2_session(build8_mining_control_v2 *c,bool live){
    /* Call false on every disconnect/rekey before opening the next session. */
    if(c){live=live&&!c->maintenance;if(!live||c->session!=live)build8_mining_v2_retire(c);c->session=live;}
}
void build8_mining_v2_maintenance(build8_mining_control_v2 *c,bool active){
    if(c){
        if(active){build8_mining_v2_retire(c);c->session=false;}
        c->maintenance=active;
    }
}
void build8_mining_v2_accounting(build8_mining_control_v2 *c,bool pending){
    if(c){if(pending)build8_mining_v2_retire(c);c->accounting=pending;}
}
static int sample(build8_mining_control_v2 *c,build8_v2_monotonic_clock clock,
    void *arg,uint64_t *now){
    if(!c||!c->initialized||c->clock_fault)return 0;
    if(!clock||!clock(arg,now)||*now<c->last_clock){
        c->clock_fault=true;build8_mining_v2_retire(c);return 0;
    }
    c->last_clock=*now;
    if(c->job_live&&*now>=c->deadline)build8_mining_v2_retire(c);
    return 1;
}
static int ready(const build8_mining_control_v2 *c){
    return c->initialized&&c->run&&c->session&&!c->accounting&&!c->clock_fault&&!c->maintenance;
}
int build8_mining_v2_request(build8_mining_control_v2 *c,const uint8_t nonce[32],
    build8_v2_monotonic_clock clock,void *arg){
    if(!c||!nonce||!separate(c,sizeof *c,nonce,32))return 0;
    uint64_t now=0;
    if(!sample(c,clock,arg,&now)||!ready(c)||c->work_valid||c->request_pending)return 0;
    uint8_t any=0;for(size_t i=0;i<32;i++)any|=nonce[i];
    if(!any||!memcmp(c->request_nonce,nonce,32))return 0;
    build8_mining_v2_retire(c);
    memcpy(c->request_nonce,nonce,32);c->request_started=now;c->request_pending=true;return 1;
}
int build8_mining_v2_assign(build8_mining_control_v2 *c,const uint8_t nonce[32],
    uint64_t epoch,uint64_t lifetime,const uint8_t *wire,size_t n,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *ws,size_t wn,
    build8_v2_monotonic_clock clock,void *arg){
    if(!c||!nonce||!wire||!ws||!separate(c,sizeof *c,nonce,32)
       ||!separate(c,sizeof *c,wire,n)||!separate(c,sizeof *c,ws,wn))return 0;
    uint64_t now=0;
    if(!sample(c,clock,arg,&now)||!ready(c)||!c->request_pending
       ||memcmp(nonce,c->request_nonce,32))return 0;
    c->request_pending=false;
    if(!lifetime||lifetime>60000||c->request_started>UINT64_MAX-lifetime
       ||now>=c->request_started+lifetime||epoch<c->effective_epoch)return 0;
    build8_work_context pinned=c->context;
    pinned.last_ticket=c->last_ticket;
    build8_authorized_work work;
    if(!build8_decode_authorized_work_v2(wire,n,&pinned,h256,h512,ws,wn,&work)
       ||work.epoch!=epoch)return 0;
    /* Consume verified tickets even when verification used up the deadline. */
    c->last_ticket=work.ticket;
    if(!sample(c,clock,arg,&now)||!ready(c)||now>=c->request_started+lifetime)return 0;
    c->work=work;c->deadline=c->request_started+lifetime;c->next_nonce=work.nonce_start;
    c->work_valid=true;c->job_live=true;return 1;
}
static uint64_t offer64(const uint8_t *p){
    uint64_t value=0;for(size_t i=0;i<8;i++)value=(value<<8)|p[i];return value;
}
int build8_mining_v2_offer(build8_mining_control_v2 *c,const uint8_t *raw,size_t n,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *ws,size_t wn,
    build8_v2_monotonic_clock clock,void *arg){
    if(!c||!raw||!ws||n<53||n>8244||wn<4127||wn>65536
       ||!separate(c,sizeof *c,raw,n)||!separate(c,sizeof *c,ws,wn)
       ||!separate(raw,n,ws,wn)||raw[0]!=5||raw[1]!=2)return 0;
    size_t length=((size_t)raw[50]<<8)|raw[51];
    if(!length||length>8192||n!=52+length)return 0;
    return build8_mining_v2_assign(c,raw+2,offer64(raw+34),offer64(raw+42),
        raw+52,length,h256,h512,ws,wn,clock,arg);
}
int build8_mining_v2_nonce(build8_mining_control_v2 *c,build8_v2_monotonic_clock clock,
    void *arg,uint64_t *nonce){
    if(!c||!nonce||!separate(c,sizeof *c,nonce,sizeof *nonce))return 0;
    uint64_t now=0;
    if(!sample(c,clock,arg,&now)||!ready(c)||!c->work_valid)return 0;
    *nonce=c->next_nonce;
    if(c->next_nonce==c->work.nonce_end)c->work_valid=false;
    else c->next_nonce++; /* Strictly below inclusive end, so cannot wrap. */
    return 1;
}
int build8_mining_v2_found(build8_mining_control_v2 *c,const uint8_t authority[32],
    uint64_t nonce,build8_v2_monotonic_clock clock,void *arg,build8_authorized_work *out){
    if(!c||!authority||!out||!separate(c,sizeof *c,authority,32)
       ||!separate(c,sizeof *c,out,sizeof *out)||!separate(authority,32,out,sizeof *out))return 0;
    uint64_t now=0;
    if(!sample(c,clock,arg,&now)||!ready(c)||!c->job_live
       ||memcmp(authority,c->work.authority,32)||nonce<c->work.nonce_start||nonce>c->work.nonce_end
       ||!(nonce<c->next_nonce||(!c->work_valid&&nonce==c->work.nonce_end)))return 0;
    *out=c->work;c->accounting=true;build8_mining_v2_retire(c);return 1;
}
