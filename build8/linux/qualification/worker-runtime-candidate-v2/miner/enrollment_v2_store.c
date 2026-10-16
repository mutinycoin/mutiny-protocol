#include "enrollment_v2_store.h"
#include <string.h>
static const uint8_t storage_magic[8]={'B','8','V','2','B','N','D',2};
/* The three fixed signature byte strings occupy 116+1283+116 bytes. All
 * signature/codec checks still run over the reconstructed original binding. */
static size_t binding_prefix(size_t en,uint8_t out[4]){
    if(!en||en>512)return 0;
    out[0]=0x84;
    if(en<24){out[1]=(uint8_t)(0x40|en);return 2;}
    if(en<256){out[1]=0x58;out[2]=(uint8_t)en;return 3;}
    out[1]=0x59;out[2]=(uint8_t)(en>>8);out[3]=(uint8_t)en;return 4;
}
static int read_binding(const build8_v2_store *s,const uint8_t *expected,size_t en,uint8_t out[2048],size_t *length){
    uint8_t prefix[4];size_t pn=binding_prefix(en,prefix),n=0;
    if(!expected||!pn)return -1;
    int status=s->read(s->context,0,out,2048,&n);
    if(status!=1)return status==0?0:-1;
    if(n!=BUILD8_V2_STORED_BINDING_BYTES||memcmp(out,storage_magic,8))return -1;
    memmove(out+pn+en,out+8,1515);memcpy(out,prefix,pn);memcpy(out+pn,expected,en);
    *length=pn+en+1515;return 1;
}
static int pack_binding(const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,uint8_t out[2048]){
    uint8_t prefix[4];size_t pn=binding_prefix(en,prefix);
    if(!raw||!expected||!pn||n!=pn+en+1515||memcmp(raw,prefix,pn)||memcmp(raw+pn,expected,en))return 0;
    memcpy(out,storage_magic,8);memcpy(out+8,raw+pn+en,1515);return 1;
}
static int marker(const uint8_t *binding,size_t n,build8_v2_domain_hash hash,uint8_t out[40]) {
    static const uint8_t version[8]={'B','8','V','2','A','C','T',1};
    memcpy(out,version,8);return hash("MUTINY-BUILD8-ENROLLMENT-ACTIVATION-V2",binding,n,out+8);
}
static int verify(const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,int genesis) {
    return genesis?build8_enrollment_v2_verify(raw,n,expected,en,owner,on,1,h256,h512,workspace,wn)
        :build8_enrollment_v2_assignment_verify(raw,n,expected,en,owner,on,h256,h512,workspace,wn);
}
static int restore(const build8_v2_store *s,const uint8_t *expected,size_t en,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,int genesis) {
    if(!s||!s->read||!expected||!owner||!h256||!h512||!workspace)return BUILD8_V2_FAULT;
    if(!genesis&&!build8_enrollment_v2_assignment_context_valid(expected,en,owner,on,h256))return BUILD8_V2_FAULT;
    uint8_t committed[40],wanted[40],binding[2048];size_t mn=0,bn=0;
    int status=s->read(s->context,1,committed,sizeof committed,&mn);
    if(status==0)return BUILD8_V2_PENDING;
    if(status!=1||mn!=sizeof committed)return BUILD8_V2_FAULT;
    if(read_binding(s,expected,en,binding,&bn)!=1||bn>sizeof binding
        ||!verify(binding,bn,expected,en,owner,on,h256,h512,workspace,wn,genesis)
        ||!marker(binding,bn,h256,wanted)||memcmp(committed,wanted,sizeof wanted))return BUILD8_V2_FAULT;
    return BUILD8_V2_ACTIVE;
}
static int activate(const build8_v2_store *s,const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn,int genesis) {
    if(!s||!s->read||!s->write||!verify(raw,n,expected,en,owner,on,h256,h512,workspace,wn,genesis))return 0;
    int state=restore(s,expected,en,owner,on,h256,h512,workspace,wn,genesis);
    if(state==BUILD8_V2_FAULT)return 0;
    uint8_t check[2048],activation[40];size_t cn=0;
    int status=read_binding(s,expected,en,check,&cn);
    if(status<0||status>1||cn>sizeof check)return 0;
    if(state==BUILD8_V2_ACTIVE)return status==1&&cn==n&&!memcmp(check,raw,n);
    /* A previously written signed candidate is immutable. Never replace a
     * different/corrupt candidate as an implicit recovery operation. */
    if(status==1&&(cn!=n||memcmp(check,raw,n)))return 0;
    if(status==0&&(!pack_binding(raw,n,expected,en,check)||!s->write(s->context,0,check,BUILD8_V2_STORED_BINDING_BYTES)))return 0;
    cn=0;
    if(read_binding(s,expected,en,check,&cn)!=1||cn!=n||cn>sizeof check||memcmp(check,raw,n)
        ||!verify(check,cn,expected,en,owner,on,h256,h512,workspace,wn,genesis)
        ||!marker(check,cn,h256,activation))return 0;
    if(!s->write(s->context,1,activation,sizeof activation))return 0;
    return restore(s,expected,en,owner,on,h256,h512,workspace,wn,genesis)==BUILD8_V2_ACTIVE;
}
int build8_v2_restore(const build8_v2_store *s,const uint8_t *expected,size_t en,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    return restore(s,expected,en,owner,on,h256,h512,workspace,wn,1);
}
int build8_v2_activate(const build8_v2_store *s,const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    return activate(s,raw,n,expected,en,owner,on,h256,h512,workspace,wn,1);
}
int build8_v2_assignment_restore(const build8_v2_store *s,const uint8_t *expected,size_t en,const uint8_t *owner,size_t on,
    build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    return restore(s,expected,en,owner,on,h256,h512,workspace,wn,0);
}
int build8_v2_assignment_activate(const build8_v2_store *s,const uint8_t *raw,size_t n,const uint8_t *expected,size_t en,
    const uint8_t *owner,size_t on,build8_v2_domain_hash h256,build8_v2_domain_hash h512,void *workspace,size_t wn) {
    return activate(s,raw,n,expected,en,owner,on,h256,h512,workspace,wn,0);
}
