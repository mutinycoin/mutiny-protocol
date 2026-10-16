#ifndef BUILD8_ENROLLMENT_V2_NVS_H
#define BUILD8_ENROLLMENT_V2_NVS_H
#include "enrollment_v2_store.h"
#include "worker_v2_candidate.h"
#include "worker_handshake_v2.h"
/* Pre-Genesis integration candidate. Startup-only init after successful NVS
 * initialization; never erases/reformats storage. No private identity API. */
int build8_v2_nvs_init(void);
int build8_v2_nvs_restore(const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
int build8_v2_nvs_activate(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
/* Identity-layer internal adapter. Requires maintenance ownership; keeps the
 * public store locked during private restoration, owner validation and signing. */
int build8_v2_nvs_sign_session(const build8_v2_private_backend *,const build8_enrollment_v2_context *,
    uint64_t,uint64_t,const uint8_t [64],build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t [114]);
/* Identity-layer internal dispatch. Maintenance must already be owned. No
 * caller-supplied public store; holds enrollment lock for the complete flight.
 * phase 0=begin, 1=accept, 2=finish; all other values fail closed. */
int build8_v2_nvs_handshake(unsigned,build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,const uint8_t *,size_t,void *);
#endif
