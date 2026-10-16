#include "handshake_frames_v2.h"
#include <string.h>
#define MAGIC UINT32_C(0x42384832)
#define PAYLOAD 186u
#define HEADER 69u
#define LIFETIME_MS UINT64_C(600000)
static size_t message_size(uint8_t kind) {
    switch(kind){case 1:return 1822;case 2:return 3050;case 3:return 1410;case 4:return 16;default:return 0;}
}
static int nonzero(const uint8_t *p,size_t n){uint8_t x=0;size_t i;for(i=0;i<n;i++)x|=p[i];return x!=0;}
size_t b8_handshake_size(void){return sizeof(b8_handshake_reassembler);}
size_t b8_handshake_alignment(void){return _Alignof(b8_handshake_reassembler);}
void b8_handshake_clear(b8_handshake_reassembler *s){if(s)memset(s,0,sizeof(*s));}
int b8_handshake_init(b8_handshake_reassembler *s,const uint8_t tag[16],const uint8_t *peers,size_t count) {
    size_t i,j;
    if(!s)return B8_FRAME_CONTEXT;
    b8_handshake_clear(s);
    if(!tag || !peers || !count || count>B8_HANDSHAKE_MAX_PEERS || !nonzero(tag,16))return B8_FRAME_CONTEXT;
    for(i=0;i<count;i++){
        if(!nonzero(peers+i*32,32))return B8_FRAME_CONTEXT;
        for(j=0;j<i;j++)if(!memcmp(peers+i*32,peers+j*32,32))return B8_FRAME_CONTEXT;
    }
    memcpy(s->tag,tag,16);memcpy(s->peers,peers,count*32);s->peer_count=(uint16_t)count;s->initialized=MAGIC;
    return B8_FRAME_OK;
}
void b8_handshake_expire(b8_handshake_reassembler *s,uint64_t now) {
    size_t i;if(!s || s->initialized!=MAGIC)return;
    for(i=0;i<B8_HANDSHAKE_MAX_FLIGHTS;i++) {
        b8_handshake_flight *f=&s->flights[i];
        if(f->active && (now<f->started_ms || now-f->started_ms>LIFETIME_MS))memset(f,0,sizeof(*f));
    }
}
size_t b8_handshake_pending(const b8_handshake_reassembler *s) {
    size_t i,n=0;if(!s || s->initialized!=MAGIC)return 0;
    for(i=0;i<B8_HANDSHAKE_MAX_FLIGHTS;i++)n+=s->flights[i].active!=0;
    return n;
}
int b8_handshake_receive(b8_handshake_reassembler *s,uint64_t now,uint8_t expected,
    const uint8_t *frame,size_t length,uint8_t peer[32],uint8_t message[3050],size_t *out_length) {
    size_t i,total,count,index,n,offset,slot=B8_HANDSHAKE_MAX_FLIGHTS,empty=B8_HANDSHAKE_MAX_FLIGHTS;
    b8_handshake_flight *f;
    if(peer)memset(peer,0,32);
    if(message)memset(message,0,3050);
    if(out_length)*out_length=0;
    if(!s || s->initialized!=MAGIC || !s->peer_count || s->peer_count>B8_HANDSHAKE_MAX_PEERS || !peer || !message || !out_length || !message_size(expected))return B8_FRAME_CONTEXT;
    b8_handshake_expire(s,now);
    if(!frame || length<70 || length>255 || frame[0]!=2 || !(total=message_size(frame[1])))return B8_FRAME_ENCODING;
    if(frame[1]!=expected || memcmp(frame+2,s->tag,16))return B8_FRAME_CONTEXT;
    for(i=0;i<s->peer_count;i++)if(!memcmp(frame+18,s->peers[i],32))break;
    if(i==s->peer_count)return B8_FRAME_CONTEXT;
    if(!nonzero(frame+50,16))return B8_FRAME_ENCODING;
    count=(total+PAYLOAD-1)/PAYLOAD;index=frame[66];n=frame[68];offset=index*PAYLOAD;
    if(frame[67]!=count || index>=count || n!=(total-offset<PAYLOAD?total-offset:PAYLOAD) || length!=HEADER+n)return B8_FRAME_ENCODING;
    for(i=0;i<B8_HANDSHAKE_MAX_FLIGHTS;i++) {
        if(!s->flights[i].active)empty=i;
        else if(!memcmp(s->flights[i].peer,frame+18,32)){slot=i;break;}
    }
    if(slot==B8_HANDSHAKE_MAX_FLIGHTS) {
        if(empty==B8_HANDSHAKE_MAX_FLIGHTS)return B8_FRAME_LIMIT;
        slot=empty;f=&s->flights[slot];memset(f,0,sizeof(*f));f->active=1;f->kind=expected;f->started_ms=now;
        memcpy(f->peer,frame+18,32);memcpy(f->id,frame+50,16);
    }
    f=&s->flights[slot];
    if(f->kind!=expected || memcmp(f->id,frame+50,16))return B8_FRAME_CONTEXT;
    if(f->received&(UINT32_C(1)<<index)) {
        return memcmp(f->message+offset,frame+HEADER,n)?B8_FRAME_CONTEXT:B8_FRAME_OK;
    }
    memcpy(f->message+offset,frame+HEADER,n);f->received|=UINT32_C(1)<<index;
    if(f->received==((UINT32_C(1)<<count)-1)) {
        memcpy(peer,f->peer,32);memcpy(message,f->message,total);*out_length=total;memset(f,0,sizeof(*f));
    }
    return B8_FRAME_OK;
}
int b8_handshake_fragment(const uint8_t tag[16],const uint8_t peer[32],const uint8_t id[16],
    uint8_t kind,const uint8_t *message,size_t length,uint8_t index,uint8_t out[255],size_t *out_length) {
    size_t count,n,offset=(size_t)index*PAYLOAD;
    if(out)memset(out,0,255);
    if(out_length)*out_length=0;
    if(!out || !out_length || !tag || !peer || !id || !message || !nonzero(tag,16) ||
        !nonzero(peer,32) || !nonzero(id,16) || !length || length!=message_size(kind))return B8_FRAME_ENCODING;
    count=(length+PAYLOAD-1)/PAYLOAD;if(index>=count)return B8_FRAME_ENCODING;
    n=length-offset;if(n>PAYLOAD)n=PAYLOAD;
    out[0]=2;out[1]=kind;memcpy(out+2,tag,16);memcpy(out+18,peer,32);memcpy(out+50,id,16);
    out[66]=index;out[67]=(uint8_t)count;out[68]=(uint8_t)n;memcpy(out+HEADER,message+offset,n);
    *out_length=HEADER+n;return B8_FRAME_OK;
}
