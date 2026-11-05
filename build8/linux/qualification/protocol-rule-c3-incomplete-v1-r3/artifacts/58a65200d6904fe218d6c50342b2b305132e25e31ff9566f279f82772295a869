#include "frame_v2.h"
#include <string.h>

#define B8_FRAME_MAGIC UINT32_C(0x42384632)
#define B8_FRAME_LIMIT_FRAMES UINT64_C(1048576)
#define B8_FRAME_LIMIT_BYTES UINT64_C(67108864)
#define B8_FRAME_LIFETIME_MS UINT64_C(3600000)

static void wipe(void *p, size_t n) {
    volatile uint8_t *q=(volatile uint8_t *)p;
    while(n--) *q++=0;
}
static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0]<<8) | p[1]);
}
static uint64_t be64(const uint8_t *p) {
    uint64_t n=0; size_t i;
    for(i=0;i<8;i++) n=(n<<8)|p[i];
    return n;
}
static void put16(uint8_t *p,uint16_t n) { p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n; }
static void put64(uint8_t *p,uint64_t n) {
    int i;for(i=7;i>=0;i--) { p[i]=(uint8_t)n;n>>=8; }
}
static int nonzero(const uint8_t *p,size_t n) {
    uint8_t v=0; size_t i;
    for(i=0;i<n;i++) v|=p[i];
    return v!=0;
}
size_t b8_frame_receiver_size(void) { return sizeof(b8_frame_receiver); }
size_t b8_frame_receiver_alignment(void) { return _Alignof(b8_frame_receiver); }
void b8_frame_receiver_clear(b8_frame_receiver *s) {
    if(s) wipe(s,sizeof(*s));
}
int b8_frame_receiver_init(b8_frame_receiver *s,const uint8_t tag[16],
    const uint8_t id[32],const uint8_t rx_prefix[4],uint8_t direction,uint64_t now) {
    if(!s) return B8_FRAME_CONTEXT;
    b8_frame_receiver_clear(s);
    if(!tag || !id || !rx_prefix || direction>1 || !nonzero(tag,16) || !nonzero(id,32))
        return B8_FRAME_CONTEXT;
    memcpy(s->tag,tag,16); memcpy(s->id,id,32); memcpy(s->rx_prefix,rx_prefix,4);
    s->direction=direction; s->started_ms=now; s->initialized=B8_FRAME_MAGIC;
    return B8_FRAME_OK;
}
int b8_frame_receive(b8_frame_receiver *s,uint64_t now,const uint8_t *frame,
    size_t length,b8_frame_open_aead authenticate,void *provider,
    b8_frame_metadata *metadata,uint8_t plaintext[140],size_t *plaintext_length) {
    uint8_t scratch[140]={0}, nonce[12]={0};
    uint64_t sequence,age,jump; uint16_t n,index,count,object_index;
    int result=B8_FRAME_ENCODING;
    if(metadata) memset(metadata,0,sizeof(*metadata));
    if(plaintext) wipe(plaintext,140);
    if(plaintext_length) *plaintext_length=0;
    if(!s || s->initialized!=B8_FRAME_MAGIC || !metadata || !plaintext ||
        !plaintext_length || !authenticate) return B8_FRAME_CONTEXT;
    if(now<s->started_ms || now-s->started_ms>B8_FRAME_LIFETIME_MS)
        return B8_FRAME_EXPIRED;
    if(!frame || length<116 || length>255 || frame[0]!=2 ||
        frame[2]!=(uint8_t)(1-s->direction) || frame[3]!=0)
        return B8_FRAME_ENCODING;
    if(memcmp(frame+4,s->tag,16) || memcmp(frame+20,s->id,32))
        return B8_FRAME_CONTEXT;
    sequence=be64(frame+52);
    if(!sequence || sequence>B8_FRAME_LIMIT_FRAMES || s->rx_frames>=B8_FRAME_LIMIT_FRAMES)
        return B8_FRAME_LIMIT;
    n=be16(frame+97); index=be16(frame+92); count=be16(frame+94);
    if(!n || n>140 || length!=(size_t)115+n || frame[1]<1 || frame[1]>5 ||
        !nonzero(frame+60,32) || !count || count>16384 || index>=count || frame[96]>16)
        return B8_FRAME_ENCODING;
    if(s->rx_bytes>B8_FRAME_LIMIT_BYTES-n || s->object_count>B8_FRAME_OBJECTS)
        return B8_FRAME_LIMIT;
    for(object_index=0;object_index<s->object_count;object_index++)
        if(!memcmp(s->objects[object_index],frame+60,32)) break;
    if(object_index==s->object_count && s->object_count==B8_FRAME_OBJECTS)
        return B8_FRAME_LIMIT;
    if(sequence<=s->highest) {
        age=s->highest-sequence;
        if(age>=128 || (age<64 ? ((s->seen_low>>age)&1) : ((s->seen_high>>(age-64))&1)))
            return B8_FRAME_REPLAY;
    }
    memcpy(nonce,s->rx_prefix,4); memcpy(nonce+4,frame+52,8);
    if(authenticate(provider,nonce,frame,frame+99,(size_t)n+16,scratch)!=1) {
        result=B8_FRAME_CRYPTO;
        goto cleanup;
    }
    if(sequence>s->highest) {
        jump=sequence-s->highest;
        if(jump>=128) { s->seen_high=0; s->seen_low=1; }
        else if(jump>=64) { s->seen_high=s->seen_low<<(jump-64); s->seen_low=1; }
        else { s->seen_high=(s->seen_high<<jump)|(s->seen_low>>(64-jump));
            s->seen_low=(s->seen_low<<jump)|1; }
        s->highest=sequence;
    } else {
        age=s->highest-sequence;
        if(age<64) s->seen_low|=UINT64_C(1)<<age;
        else s->seen_high|=UINT64_C(1)<<(age-64);
    }
    s->rx_frames++; s->rx_bytes+=n;
    if(object_index==s->object_count) {
        memcpy(s->objects[object_index],frame+60,32); s->object_count++;
    }
    metadata->kind=frame[1]; memcpy(metadata->object,frame+60,32);
    metadata->fragment=index; metadata->count=count; metadata->hops=frame[96];
    memcpy(plaintext,scratch,n); *plaintext_length=n;
    result=B8_FRAME_OK;
cleanup:
    wipe(scratch,sizeof(scratch)); wipe(nonce,sizeof(nonce));
    return result;
}

size_t b8_frame_sender_size(void) { return sizeof(b8_frame_sender); }
size_t b8_frame_sender_alignment(void) { return _Alignof(b8_frame_sender); }
void b8_frame_sender_clear(b8_frame_sender *s) { if(s)wipe(s,sizeof(*s)); }
int b8_frame_sender_init(b8_frame_sender *s,const uint8_t tag[16],const uint8_t id[32],
    const uint8_t prefix[4],uint8_t direction,uint64_t now) {
    if(!s)return B8_FRAME_CONTEXT;
    b8_frame_sender_clear(s);
    if(!tag || !id || !prefix || direction>1 || !nonzero(tag,16) || !nonzero(id,32))
        return B8_FRAME_CONTEXT;
    memcpy(s->tag,tag,16);memcpy(s->id,id,32);memcpy(s->tx_prefix,prefix,4);
    s->direction=direction;s->started_ms=now;s->next=1;s->initialized=B8_FRAME_MAGIC;
    return B8_FRAME_OK;
}
int b8_frame_seal(b8_frame_sender *s,uint64_t now,const b8_frame_metadata *m,
    const uint8_t *plain,size_t length,b8_frame_seal_aead encrypt,void *provider,
    uint8_t frame[255],size_t *frame_length) {
    uint8_t scratch[255]={0},nonce[12]={0};uint16_t object_index;uint64_t sequence;
    int result=B8_FRAME_CRYPTO;
    if(frame)wipe(frame,255);
    if(frame_length)*frame_length=0;
    if(!s || s->initialized!=B8_FRAME_MAGIC || !frame || !frame_length || !encrypt)
        return B8_FRAME_CONTEXT;
    if(now<s->started_ms || now-s->started_ms>B8_FRAME_LIFETIME_MS)
        return B8_FRAME_EXPIRED;
    if(!m || !plain || !length || length>140 || m->kind<1 || m->kind>5 ||
        !nonzero(m->object,32) || !m->count || m->count>16384 || m->fragment>=m->count || m->hops>16)
        return B8_FRAME_ENCODING;
    if(!s->next || s->next>B8_FRAME_LIMIT_FRAMES || s->tx_bytes>B8_FRAME_LIMIT_BYTES-length ||
        s->object_count>B8_FRAME_OBJECTS) return B8_FRAME_LIMIT;
    for(object_index=0;object_index<s->object_count;object_index++)
        if(!memcmp(s->objects[object_index],m->object,32))break;
    if(object_index==s->object_count && s->object_count==B8_FRAME_OBJECTS)
        return B8_FRAME_LIMIT;
    /* Reserve before entering a provider that can fail. */
    sequence=s->next++;s->tx_bytes+=length;
    if(object_index==s->object_count){memcpy(s->objects[object_index],m->object,32);s->object_count++;}
    scratch[0]=2;scratch[1]=m->kind;scratch[2]=s->direction;
    memcpy(scratch+4,s->tag,16);memcpy(scratch+20,s->id,32);put64(scratch+52,sequence);
    memcpy(scratch+60,m->object,32);put16(scratch+92,m->fragment);put16(scratch+94,m->count);
    scratch[96]=m->hops;put16(scratch+97,(uint16_t)length);
    memcpy(nonce,s->tx_prefix,4);put64(nonce+4,sequence);
    if(encrypt(provider,nonce,scratch,plain,length,scratch+99)==1) {
        *frame_length=115+length;memcpy(frame,scratch,*frame_length);result=B8_FRAME_OK;
    }
    wipe(scratch,sizeof(scratch));wipe(nonce,sizeof(nonce));return result;
}
